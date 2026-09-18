package main

import (
	"reflect"
	"testing"
)

func testConfig() config {
	cfg := defaultConfig()
	cfg.issuerURL = "https://auth.example.com"
	cfg.clientID = "silo"
	return cfg
}

func TestMapClaims_UsernamePrecedenceAndFields(t *testing.T) {
	cfg := testConfig()
	claims := map[string]any{
		"sub":                "abc123",
		"preferred_username": "jdoe",
		"name":               "Jane Doe",
		"email":              "jane@example.com",
		"nonce":              "should-be-stripped",
		"at_hash":            "should-be-stripped",
	}

	resp, _, err := mapClaims(cfg, claims)
	if err != nil {
		t.Fatalf("mapClaims: %v", err)
	}

	if resp.GetExternalSubject() != "abc123" {
		t.Errorf("ExternalSubject = %q", resp.GetExternalSubject())
	}
	// DisplayName carries the username claim, not the human name — the host
	// uses it as the auto-provisioned Silo username.
	if resp.GetDisplayName() != "jdoe" {
		t.Errorf("DisplayName = %q, want username claim", resp.GetDisplayName())
	}
	if resp.GetEmail() != "jane@example.com" {
		t.Errorf("Email = %q", resp.GetEmail())
	}

	claimsMap := resp.GetClaims().AsMap()
	if claimsMap["name"] != "Jane Doe" {
		t.Errorf("claims[name] = %v", claimsMap["name"])
	}
	if claimsMap["username"] != "jdoe" {
		t.Errorf("claims[username] = %v", claimsMap["username"])
	}
	for _, protocolKey := range []string{"nonce", "at_hash"} {
		if _, present := claimsMap[protocolKey]; present {
			t.Errorf("claims[%s] should have been stripped", protocolKey)
		}
	}
}

func TestMapClaims_UsernameFallsBackToSubject(t *testing.T) {
	cfg := testConfig()
	claims := map[string]any{"sub": "abc123"}

	resp, _, err := mapClaims(cfg, claims)
	if err != nil {
		t.Fatalf("mapClaims: %v", err)
	}
	if resp.GetDisplayName() != "abc123" {
		t.Errorf("DisplayName = %q, want subject fallback", resp.GetDisplayName())
	}
}

func TestMapClaims_MissingSubjectErrors(t *testing.T) {
	cfg := testConfig()
	if _, _, err := mapClaims(cfg, map[string]any{"preferred_username": "jdoe"}); err == nil {
		t.Fatalf("expected error for missing sub claim")
	}
}

func TestMapClaims_GroupsAsList(t *testing.T) {
	cfg := testConfig()
	claims := map[string]any{
		"sub":    "abc123",
		"groups": []any{"admins", "media-users", "admins"},
	}
	resp, _, err := mapClaims(cfg, claims)
	if err != nil {
		t.Fatalf("mapClaims: %v", err)
	}
	claimsMap := resp.GetClaims().AsMap()
	groups, ok := claimsMap["groups"].([]any)
	if !ok {
		t.Fatalf("claims[groups] type = %T", claimsMap["groups"])
	}
	got := make([]string, len(groups))
	for i, g := range groups {
		got[i] = g.(string)
	}
	if want := []string{"admins", "media-users"}; !reflect.DeepEqual(got, want) {
		t.Errorf("groups = %v, want %v (deduplicated)", got, want)
	}
}

func TestMapClaims_GroupsAsScalarString(t *testing.T) {
	cfg := testConfig()
	claims := map[string]any{"sub": "abc123", "groups": "admins"}
	resp, _, err := mapClaims(cfg, claims)
	if err != nil {
		t.Fatalf("mapClaims: %v", err)
	}
	claimsMap := resp.GetClaims().AsMap()
	groups, ok := claimsMap["groups"].([]any)
	if !ok || len(groups) != 1 || groups[0] != "admins" {
		t.Errorf("claims[groups] = %v", claimsMap["groups"])
	}
}

func TestMapClaims_GroupsAbsent(t *testing.T) {
	cfg := testConfig()
	resp, _, err := mapClaims(cfg, map[string]any{"sub": "abc123"})
	if err != nil {
		t.Fatalf("mapClaims: %v", err)
	}
	if _, present := resp.GetClaims().AsMap()["groups"]; present {
		t.Errorf("claims[groups] should be absent when the claim is missing")
	}
}

func TestGroupAllowed(t *testing.T) {
	tests := []struct {
		name    string
		allowed []string
		groups  []string
		want    bool
	}{
		{name: "empty allowed list permits everyone", allowed: nil, groups: nil, want: true},
		{name: "intersection permits", allowed: []string{"admins", "users"}, groups: []string{"users"}, want: true},
		{name: "no intersection denies", allowed: []string{"admins"}, groups: []string{"users"}, want: false},
		{name: "no groups denies when restricted", allowed: []string{"admins"}, groups: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := groupAllowed(tt.allowed, tt.groups); got != tt.want {
				t.Errorf("groupAllowed(%v, %v) = %v, want %v", tt.allowed, tt.groups, got, tt.want)
			}
		})
	}
}
