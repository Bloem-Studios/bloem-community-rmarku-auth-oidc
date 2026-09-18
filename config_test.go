package main

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

func configEntry(t *testing.T, key string, values map[string]any) *pluginv1.ConfigEntry {
	t.Helper()
	s, err := structpb.NewStruct(values)
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}
	return &pluginv1.ConfigEntry{Key: key, Value: s}
}

func TestParseConfig_AbsentEntryYieldsDefaultsUnconfigured(t *testing.T) {
	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.isConfigured() {
		t.Fatalf("expected unconfigured config, got %+v", cfg)
	}
	if got, want := cfg.scopes, []string{"openid", "profile", "email"}; !reflect.DeepEqual(got, want) {
		t.Errorf("scopes = %v, want %v", got, want)
	}
	if cfg.usernameClaim != "preferred_username" {
		t.Errorf("usernameClaim = %q", cfg.usernameClaim)
	}
	if !cfg.requirePKCE {
		t.Errorf("requirePKCE = false, want true (default on)")
	}
}

func TestParseConfig_RequiredFieldsAndScopeHandling(t *testing.T) {
	entries := []*pluginv1.ConfigEntry{
		configEntry(t, "oidc", map[string]any{
			"issuer_url": "https://auth.example.com/",
			"client_id":  "silo",
			"scopes":     "profile email",
		}),
	}
	cfg, err := parseConfig(entries)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if !cfg.isConfigured() {
		t.Fatalf("expected configured, got %+v", cfg)
	}
	if cfg.issuerURL != "https://auth.example.com" {
		t.Errorf("issuerURL = %q, want trailing slash trimmed", cfg.issuerURL)
	}
	// "openid" must always be present even when the admin's scopes value omits it.
	if got, want := cfg.scopes, []string{"openid", "profile", "email"}; !reflect.DeepEqual(got, want) {
		t.Errorf("scopes = %v, want %v", got, want)
	}
}

func TestParseConfig_RequirePKCEDisabled(t *testing.T) {
	entries := []*pluginv1.ConfigEntry{
		configEntry(t, "oidc", map[string]any{
			"issuer_url":   "https://auth.example.com",
			"client_id":    "silo",
			"require_pkce": false,
		}),
	}
	cfg, err := parseConfig(entries)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.requirePKCE {
		t.Errorf("requirePKCE = true, want false")
	}
}

func TestParseConfig_AllowedGroups(t *testing.T) {
	entries := []*pluginv1.ConfigEntry{
		configEntry(t, "oidc", map[string]any{
			"issuer_url":     "https://auth.example.com",
			"client_id":      "silo",
			"allowed_groups": "admins, media-users, ",
		}),
	}
	cfg, err := parseConfig(entries)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if got, want := cfg.allowedGroups, []string{"admins", "media-users"}; !reflect.DeepEqual(got, want) {
		t.Errorf("allowedGroups = %v, want %v", got, want)
	}
}

func TestParseConfig_ClaimMappingOverrides(t *testing.T) {
	entries := []*pluginv1.ConfigEntry{
		configEntry(t, "oidc", map[string]any{
			"issuer_url":         "https://auth.example.com",
			"client_id":          "silo",
			"username_claim":     "upn",
			"email_claim":        "mail",
			"display_name_claim": "displayName",
			"groups_claim":       "roles",
		}),
	}
	cfg, err := parseConfig(entries)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.usernameClaim != "upn" || cfg.emailClaim != "mail" || cfg.displayClaim != "displayName" || cfg.groupsClaim != "roles" {
		t.Errorf("claim mapping not applied: %+v", cfg)
	}
}

func TestParseConfig_WrongTypeRejected(t *testing.T) {
	tests := map[string]map[string]any{
		"issuer_url not a string": {"issuer_url": 42, "client_id": "silo"},
		"require_pkce not a bool": {"issuer_url": "https://auth.example.com", "client_id": "silo", "require_pkce": "yes"},
		"allowed_groups not a string": {
			"issuer_url": "https://auth.example.com", "client_id": "silo", "allowed_groups": []any{"admins"},
		},
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			entries := []*pluginv1.ConfigEntry{configEntry(t, "oidc", values)}
			if _, err := parseConfig(entries); err == nil {
				t.Fatalf("parseConfig: expected error")
			}
		})
	}
}

func TestParseConfig_IgnoresEntriesForOtherKeys(t *testing.T) {
	entries := []*pluginv1.ConfigEntry{
		configEntry(t, "unrelated", map[string]any{"issuer_url": "https://ignored.example.com"}),
	}
	cfg, err := parseConfig(entries)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.isConfigured() {
		t.Fatalf("expected unconfigured config, got %+v", cfg)
	}
}
