package main

import (
	"fmt"
	"maps"

	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/Bloem-Studios/bloem-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// protocolClaims are OIDC/OAuth mechanics rather than user identity; they are
// dropped from the AuthenticateResponse claims struct so the host only sees
// identity data. "sub" is deliberately not listed here: it is kept as the
// canonical subject claim rather than being stripped and re-added.
var protocolClaims = map[string]struct{}{
	"nonce":   {},
	"at_hash": {},
	"c_hash":  {},
	"aud":     {},
	"iss":     {},
	"exp":     {},
	"iat":     {},
	"nbf":     {},
}

// mapClaims turns decoded ID token (and, when available, userinfo) claims
// into the AuthenticateResponse shape the host expects. display_name carries
// the username claim — not the human display name — because the host's
// auto-provisioning uses it as the base for the Silo username
// (silo-server internal/auth/plugin_provider.go autoProvisionUser). The human
// name and groups are surfaced via claims for callers that want them, and
// groups are put there specifically so a future host-side role mapper
// (silo-server#554) can consume them.
func mapClaims(cfg config, claims map[string]any) (response *pluginv1.AuthenticateResponse, groups []string, err error) {
	subject := stringClaim(claims, "sub")
	if subject == "" {
		return nil, nil, fmt.Errorf("oidc: id token has no sub claim")
	}

	username := stringClaim(claims, cfg.usernameClaim)
	if username == "" {
		username = subject
	}
	email := stringClaim(claims, cfg.emailClaim)
	displayName := stringClaim(claims, cfg.displayClaim)
	groups = groupsClaim(claims, cfg.groupsClaim)

	normalized := map[string]any{
		"username": username,
	}
	if displayName != "" {
		normalized["name"] = displayName
	}
	if email != "" {
		normalized["email"] = email
	}
	if len(groups) > 0 {
		normalized["groups"] = stringsToAny(groups)
	}

	merged := mergeClaims(normalized, claims)
	for key := range protocolClaims {
		delete(merged, key)
	}

	claimsStruct, err := structpb.NewStruct(merged)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc: encode claims: %w", err)
	}

	return &pluginv1.AuthenticateResponse{
		ExternalSubject: subject,
		DisplayName:     username,
		Email:           email,
		Claims:          claimsStruct,
	}, groups, nil
}

// mergeClaims returns a copy of base with every key from extra that base
// does not already define. base's values take precedence.
func mergeClaims(base, extra map[string]any) map[string]any {
	out := maps.Clone(extra)
	maps.Copy(out, base)
	return out
}

func stringClaim(claims map[string]any, key string) string {
	if key == "" {
		return ""
	}
	v, ok := claims[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// groupsClaim reads a claim that may be a JSON array of strings or, for IdPs
// that emit a single group as a bare string, a scalar. Duplicates are
// dropped while preserving first-seen order.
func groupsClaim(claims map[string]any, key string) []string {
	if key == "" {
		return nil
	}
	raw, ok := claims[key]
	if !ok {
		return nil
	}

	var values []string
	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				values = append(values, s)
			}
		}
	case string:
		if v != "" {
			values = append(values, v)
		}
	}

	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// groupAllowed reports whether groups intersects allowed. An empty allowed
// list means every authenticated user is permitted.
func groupAllowed(allowed, groups []string) bool {
	if len(allowed) == 0 {
		return true
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		allowedSet[a] = struct{}{}
	}
	for _, g := range groups {
		if _, ok := allowedSet[g]; ok {
			return true
		}
	}
	return false
}

func stringsToAny(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}
