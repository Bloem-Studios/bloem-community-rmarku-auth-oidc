package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

const discoveryTimeout = 15 * time.Second

// provider implements auth_provider.v1 as a generic OpenID Connect client.
// It is OAuth-only: Authenticate (password login) is unimplemented.
type provider struct {
	pluginv1.UnimplementedAuthProviderServer

	logger     hclog.Logger
	httpClient *http.Client

	mu           sync.Mutex
	cfg          config
	oidcProvider *oidc.Provider

	// refreshTokens is a best-effort in-process cache of the most recent
	// refresh_token per subject, since the host does not currently persist
	// or round-trip refresh_state for RefreshSession. It is lost on plugin
	// restart; see README for the limitation.
	refreshTokens map[string]string
}

func newProvider(logger hclog.Logger) *provider {
	return &provider{
		logger:        logger,
		httpClient:    &http.Client{Timeout: discoveryTimeout},
		cfg:           defaultConfig(),
		refreshTokens: make(map[string]string),
	}
}

// setConfig replaces the active configuration. Any cached discovery document
// is dropped so the next request re-discovers against the (possibly new)
// issuer.
func (p *provider) setConfig(cfg config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = cfg
	p.oidcProvider = nil
}

func (p *provider) snapshotConfig() config {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg
}

// discover lazily fetches and caches {issuer}/.well-known/openid-configuration.
// A discovery failure is not cached, so the next call retries.
func (p *provider) discover(ctx context.Context, cfg config) (*oidc.Provider, error) {
	p.mu.Lock()
	cached := p.oidcProvider
	p.mu.Unlock()
	if cached != nil {
		return cached, nil
	}

	discoverCtx, cancel := context.WithTimeout(oidc.ClientContext(ctx, p.httpClient), discoveryTimeout)
	defer cancel()
	discovered, err := oidc.NewProvider(discoverCtx, cfg.issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", cfg.issuerURL, err)
	}

	p.mu.Lock()
	p.oidcProvider = discovered
	p.mu.Unlock()
	return discovered, nil
}

func (p *provider) oauthConfig(op *oidc.Provider, cfg config, redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.clientID,
		ClientSecret: cfg.clientSecret,
		Endpoint:     op.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       cfg.scopes,
	}
}

// Authenticate handles password-based login. This plugin is OAuth-only.
func (p *provider) Authenticate(context.Context, *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "oidc-auth-provider is OAuth-only; password login is not supported")
}

// InitAuthorize builds the authorization-code URL for the configured
// provider, generating a fresh PKCE verifier (when require_pkce) and nonce
// per attempt. Both are returned in provider_state for the host to round-trip
// on ExchangeCode.
func (p *provider) InitAuthorize(ctx context.Context, req *pluginv1.InitAuthorizeRequest) (*pluginv1.InitAuthorizeResponse, error) {
	cfg := p.snapshotConfig()
	if !cfg.isConfigured() {
		return nil, status.Error(codes.FailedPrecondition, "oidc-auth-provider is not configured: set issuer_url and client_id")
	}
	op, err := p.discover(ctx, cfg)
	if err != nil {
		p.logger.Warn("oidc discovery failed", "err", err)
		return nil, status.Errorf(codes.Unavailable, "oidc discovery failed: %v", err)
	}

	nonce := oauth2.GenerateVerifier()

	oauthCfg := p.oauthConfig(op, cfg, req.GetRedirectUri())
	authOpts := []oauth2.AuthCodeOption{oidc.Nonce(nonce)}

	stateFields := map[string]any{
		"nonce": nonce,
	}
	if cfg.requirePKCE {
		verifier := oauth2.GenerateVerifier()
		authOpts = append(authOpts, oauth2.S256ChallengeOption(verifier))
		stateFields["code_verifier"] = verifier
	}

	providerState, err := structpb.NewStruct(stateFields)
	if err != nil {
		return nil, fmt.Errorf("oidc: encode provider_state: %w", err)
	}

	return &pluginv1.InitAuthorizeResponse{
		AuthorizeUrl:  oauthCfg.AuthCodeURL(req.GetState(), authOpts...),
		ProviderState: providerState,
	}, nil
}

// ExchangeCode redeems the authorization code, verifies the returned ID
// token, and maps its claims (merged with userinfo, when available) to the
// host's identity shape.
func (p *provider) ExchangeCode(ctx context.Context, req *pluginv1.ExchangeCodeRequest) (*pluginv1.AuthenticateResponse, error) {
	cfg := p.snapshotConfig()
	if !cfg.isConfigured() {
		return nil, status.Error(codes.FailedPrecondition, "oidc-auth-provider is not configured: set issuer_url and client_id")
	}
	op, err := p.discover(ctx, cfg)
	if err != nil {
		p.logger.Warn("oidc discovery failed", "err", err)
		return nil, status.Errorf(codes.Unavailable, "oidc discovery failed: %v", err)
	}

	state := req.GetProviderState().AsMap()
	nonce, _ := state["nonce"].(string)

	exchangeOpts := []oauth2.AuthCodeOption{}
	if verifier, ok := state["code_verifier"].(string); ok && verifier != "" {
		exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(verifier))
	} else if cfg.requirePKCE {
		return nil, status.Error(codes.InvalidArgument, "oidc: missing code_verifier in provider_state")
	}

	oauthCfg := p.oauthConfig(op, cfg, req.GetRedirectUri())
	token, err := oauthCfg.Exchange(ctx, req.GetCode(), exchangeOpts...)
	if err != nil {
		p.logger.Warn("oidc token exchange failed", "err", err)
		return nil, status.Errorf(codes.Unauthenticated, "oidc token exchange failed: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, status.Error(codes.Unauthenticated, "oidc: token response did not include an id_token")
	}

	idToken, err := op.Verifier(&oidc.Config{ClientID: cfg.clientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "oidc: id_token verification failed: %v", err)
	}
	if nonce != "" && idToken.Nonce != nonce {
		return nil, status.Error(codes.Unauthenticated, "oidc: id_token nonce mismatch")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: decode id_token claims: %w", err)
	}
	p.mergeUserInfo(ctx, op, oauthCfg, token, idToken.Subject, claims)

	return p.finishAuth(cfg, claims, token)
}

// mergeUserInfo augments claims with the provider's userinfo endpoint,
// filling in any claim not already present in the ID token. It never
// overrides ID token claims, and a userinfo failure or subject mismatch is
// logged and ignored: the ID token alone is a valid identity assertion.
func (p *provider) mergeUserInfo(
	ctx context.Context,
	op *oidc.Provider,
	oauthCfg *oauth2.Config,
	token *oauth2.Token,
	subject string,
	claims map[string]any,
) {
	if op.UserInfoEndpoint() == "" {
		return
	}
	userInfo, err := op.UserInfo(ctx, oauthCfg.TokenSource(ctx, token))
	if err != nil {
		p.logger.Warn("oidc userinfo request failed", "err", err)
		return
	}
	if userInfo.Subject != "" && userInfo.Subject != subject {
		p.logger.Warn("oidc userinfo subject mismatch; ignoring", "id_token_sub", subject, "userinfo_sub", userInfo.Subject)
		return
	}
	var extra map[string]any
	if err := userInfo.Claims(&extra); err != nil {
		p.logger.Warn("oidc userinfo claims decode failed", "err", err)
		return
	}
	for k, v := range extra {
		if _, exists := claims[k]; !exists {
			claims[k] = v
		}
	}
}

// finishAuth maps decoded claims to the host's identity shape, enforces
// allowed_groups, and caches the refresh token (if any) for RefreshSession.
// Shared by ExchangeCode and RefreshSession, which differ only in how they
// obtain the token and claims.
func (p *provider) finishAuth(cfg config, claims map[string]any, token *oauth2.Token) (*pluginv1.AuthenticateResponse, error) {
	response, groups, err := mapClaims(cfg, claims)
	if err != nil {
		return nil, err
	}
	if !groupAllowed(cfg.allowedGroups, groups) {
		return nil, status.Error(codes.PermissionDenied, "oidc: user's groups are not in allowed_groups")
	}
	p.storeRefreshToken(response.GetExternalSubject(), token.RefreshToken)
	return response, nil
}

func (p *provider) storeRefreshToken(subject, refreshToken string) {
	if refreshToken == "" {
		return
	}
	p.mu.Lock()
	p.refreshTokens[subject] = refreshToken
	p.mu.Unlock()
}

// RefreshSession uses the token endpoint's refresh_token grant. It only
// succeeds for a subject whose refresh token this process still holds in
// memory (see refreshTokens), or one supplied directly in refresh_state.
func (p *provider) RefreshSession(ctx context.Context, req *pluginv1.RefreshSessionRequest) (*pluginv1.AuthenticateResponse, error) {
	cfg := p.snapshotConfig()
	if !cfg.isConfigured() {
		return nil, status.Error(codes.FailedPrecondition, "oidc-auth-provider is not configured: set issuer_url and client_id")
	}

	refreshToken, _ := req.GetRefreshState().AsMap()["refresh_token"].(string)
	if refreshToken == "" {
		p.mu.Lock()
		refreshToken = p.refreshTokens[req.GetExternalSubject()]
		p.mu.Unlock()
	}
	if refreshToken == "" {
		return nil, status.Error(codes.Unimplemented, "oidc-auth-provider has no refresh token for this session")
	}

	op, err := p.discover(ctx, cfg)
	if err != nil {
		p.logger.Warn("oidc discovery failed", "err", err)
		return nil, status.Errorf(codes.Unavailable, "oidc discovery failed: %v", err)
	}

	oauthCfg := p.oauthConfig(op, cfg, "")
	tokenSource := oauthCfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	token, err := tokenSource.Token()
	if err != nil {
		p.logger.Warn("oidc token refresh failed", "err", err)
		return nil, status.Errorf(codes.Unauthenticated, "oidc token refresh failed: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, status.Error(codes.Unauthenticated, "oidc: refresh response did not include an id_token")
	}
	idToken, err := op.Verifier(&oidc.Config{ClientID: cfg.clientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "oidc: id_token verification failed: %v", err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: decode id_token claims: %w", err)
	}

	return p.finishAuth(cfg, claims, token)
}
