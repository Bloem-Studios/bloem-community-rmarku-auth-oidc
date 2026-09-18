package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

const testKeyID = "test-key"

// fakeIdP is a minimal OpenID Connect provider used to exercise discovery,
// PKCE, id_token verification, and userinfo merging end to end without a
// real IdP.
type fakeIdP struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey

	// Set by the test between InitAuthorize and ExchangeCode.
	expectedChallenge string
	subject           string
	nonce             string
	extraClaims       map[string]any
	userInfoClaims    map[string]any
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	f := &fakeIdP{privateKey: key, subject: "user-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/jwks", f.handleJWKS)
	mux.HandleFunc("/token", f.handleToken)
	mux.HandleFunc("/userinfo", f.handleUserInfo)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIdP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                 f.server.URL,
		"authorization_endpoint": f.server.URL + "/authorize",
		"token_endpoint":         f.server.URL + "/token",
		"jwks_uri":               f.server.URL + "/jwks",
		"userinfo_endpoint":      f.server.URL + "/userinfo",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (f *fakeIdP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &f.privateKey.PublicKey, KeyID: testKeyID, Algorithm: "RS256", Use: "sig"},
	}}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

func (f *fakeIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if f.expectedChallenge != "" {
		verifier := r.PostForm.Get("code_verifier")
		if verifier == "" || s256Challenge(verifier) != f.expectedChallenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
	}

	idToken := f.signIDToken(w, r)
	if idToken == "" {
		return
	}

	resp := map[string]any{
		"access_token": "test-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeIdP) signIDToken(w http.ResponseWriter, _ *http.Request) string {
	now := time.Now()
	claims := map[string]any{
		"iss": f.server.URL,
		"aud": "silo-client",
		"sub": f.subject,
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
	if f.nonce != "" {
		claims["nonce"] = f.nonce
	}
	for k, v := range f.extraClaims {
		claims[k] = v
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return ""
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: f.privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", testKeyID),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return ""
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return ""
	}
	serialized, err := jws.CompactSerialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return ""
	}
	return serialized
}

func (f *fakeIdP) handleUserInfo(w http.ResponseWriter, _ *http.Request) {
	claims := map[string]any{"sub": f.subject}
	for k, v := range f.userInfoClaims {
		claims[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(claims)
}

func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func testProviderConfig(issuerURL string) config {
	cfg := defaultConfig()
	cfg.issuerURL = issuerURL
	cfg.clientID = "silo-client"
	return cfg
}

func TestInitAuthorizeThenExchangeCode_Success(t *testing.T) {
	idp := newFakeIdP(t)
	p := newProvider(hclog.NewNullLogger())
	p.setConfig(testProviderConfig(idp.server.URL))
	ctx := t.Context()

	initResp, err := p.InitAuthorize(ctx, &pluginv1.InitAuthorizeRequest{
		RedirectUri: "https://silo.example.com/callback",
		State:       "state-abc",
	})
	if err != nil {
		t.Fatalf("InitAuthorize: %v", err)
	}

	authorizeURL, err := url.Parse(initResp.GetAuthorizeUrl())
	if err != nil {
		t.Fatalf("parse authorize_url: %v", err)
	}
	q := authorizeURL.Query()
	if q.Get("state") != "state-abc" {
		t.Errorf("state = %q", q.Get("state"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") == "" {
		t.Errorf("code_challenge missing from authorize_url")
	}
	if q.Get("nonce") == "" {
		t.Errorf("nonce missing from authorize_url")
	}

	state := initResp.GetProviderState().AsMap()
	verifier, _ := state["code_verifier"].(string)
	nonce, _ := state["nonce"].(string)
	if verifier == "" || nonce == "" {
		t.Fatalf("provider_state missing code_verifier/nonce: %v", state)
	}
	if nonce != q.Get("nonce") {
		t.Errorf("provider_state nonce %q != authorize_url nonce %q", nonce, q.Get("nonce"))
	}

	idp.expectedChallenge = q.Get("code_challenge")
	idp.nonce = nonce
	idp.subject = "user-1"
	idp.extraClaims = map[string]any{
		"preferred_username": "jdoe",
		"email":              "jane@example.com",
		"name":               "Jane Doe",
		"groups":             []string{"engineering"},
	}

	resp, err := p.ExchangeCode(ctx, &pluginv1.ExchangeCodeRequest{
		Code:          "test-code",
		State:         "state-abc",
		RedirectUri:   "https://silo.example.com/callback",
		ProviderState: initResp.GetProviderState(),
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if resp.GetExternalSubject() != "user-1" {
		t.Errorf("ExternalSubject = %q", resp.GetExternalSubject())
	}
	if resp.GetDisplayName() != "jdoe" {
		t.Errorf("DisplayName = %q, want username claim", resp.GetDisplayName())
	}
	if resp.GetEmail() != "jane@example.com" {
		t.Errorf("Email = %q", resp.GetEmail())
	}
	groups, _ := resp.GetClaims().AsMap()["groups"].([]any)
	if len(groups) != 1 || groups[0] != "engineering" {
		t.Errorf("claims[groups] = %v", resp.GetClaims().AsMap()["groups"])
	}
}

func TestExchangeCode_PKCEMismatchFails(t *testing.T) {
	idp := newFakeIdP(t)
	p := newProvider(hclog.NewNullLogger())
	p.setConfig(testProviderConfig(idp.server.URL))
	ctx := t.Context()

	initResp, err := p.InitAuthorize(ctx, &pluginv1.InitAuthorizeRequest{
		RedirectUri: "https://silo.example.com/callback",
		State:       "state-abc",
	})
	if err != nil {
		t.Fatalf("InitAuthorize: %v", err)
	}
	authorizeURL, _ := url.Parse(initResp.GetAuthorizeUrl())
	idp.expectedChallenge = authorizeURL.Query().Get("code_challenge")

	// Tamper the verifier the host round-trips so it no longer matches the
	// challenge the fake IdP recorded.
	tampered, err := structpb.NewStruct(map[string]any{
		"code_verifier": "wrong-verifier-wrong-verifier-wrong-verifier-00",
		"nonce":         initResp.GetProviderState().AsMap()["nonce"],
	})
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}

	_, err = p.ExchangeCode(ctx, &pluginv1.ExchangeCodeRequest{
		Code:          "test-code",
		State:         "state-abc",
		RedirectUri:   "https://silo.example.com/callback",
		ProviderState: tampered,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("ExchangeCode error = %v, want Unauthenticated", err)
	}
}

func TestExchangeCode_AllowedGroupsDenies(t *testing.T) {
	idp := newFakeIdP(t)
	cfg := testProviderConfig(idp.server.URL)
	cfg.allowedGroups = []string{"admins"}
	p := newProvider(hclog.NewNullLogger())
	p.setConfig(cfg)
	ctx := t.Context()

	initResp, err := p.InitAuthorize(ctx, &pluginv1.InitAuthorizeRequest{
		RedirectUri: "https://silo.example.com/callback",
		State:       "state-abc",
	})
	if err != nil {
		t.Fatalf("InitAuthorize: %v", err)
	}
	authorizeURL, _ := url.Parse(initResp.GetAuthorizeUrl())
	idp.expectedChallenge = authorizeURL.Query().Get("code_challenge")
	idp.nonce, _ = initResp.GetProviderState().AsMap()["nonce"].(string)
	idp.extraClaims = map[string]any{"groups": []string{"engineering"}}

	_, err = p.ExchangeCode(ctx, &pluginv1.ExchangeCodeRequest{
		Code:          "test-code",
		State:         "state-abc",
		RedirectUri:   "https://silo.example.com/callback",
		ProviderState: initResp.GetProviderState(),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ExchangeCode error = %v, want PermissionDenied", err)
	}
}

func TestInitAuthorize_Unconfigured(t *testing.T) {
	p := newProvider(hclog.NewNullLogger())
	_, err := p.InitAuthorize(t.Context(), &pluginv1.InitAuthorizeRequest{RedirectUri: "https://silo.example.com/callback"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("InitAuthorize error = %v, want FailedPrecondition", err)
	}
}

func TestAuthenticate_Unimplemented(t *testing.T) {
	p := newProvider(hclog.NewNullLogger())
	_, err := p.Authenticate(t.Context(), &pluginv1.AuthenticateRequest{Username: "jdoe", Password: "secret"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("Authenticate error = %v, want Unimplemented", err)
	}
}

func TestRefreshSession_NoRefreshTokenUnimplemented(t *testing.T) {
	idp := newFakeIdP(t)
	p := newProvider(hclog.NewNullLogger())
	p.setConfig(testProviderConfig(idp.server.URL))

	_, err := p.RefreshSession(t.Context(), &pluginv1.RefreshSessionRequest{ExternalSubject: "user-1"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("RefreshSession error = %v, want Unimplemented", err)
	}
}
