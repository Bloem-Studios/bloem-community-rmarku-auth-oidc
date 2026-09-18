package main

import (
	"fmt"
	"slices"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// configKey is the global_config_schema entry this plugin reads its settings
// from. See manifest.json.
const configKey = "oidc"

// config is the plugin's resolved settings for one installation. A plugin
// process serves exactly one installation, so this is process-global state
// rather than something keyed by installation ID.
type config struct {
	issuerURL     string
	clientID      string
	clientSecret  string
	scopes        []string
	usernameClaim string
	emailClaim    string
	displayClaim  string
	groupsClaim   string
	requirePKCE   bool
	allowedGroups []string
}

// defaultConfig returns the settings a bare admin_form submission (or an
// absent one, before the admin has configured anything) resolves to for every
// field except the required issuer_url/client_id.
func defaultConfig() config {
	return config{
		scopes:        []string{"openid", "profile", "email"},
		usernameClaim: "preferred_username",
		emailClaim:    "email",
		displayClaim:  "name",
		groupsClaim:   "groups",
		requirePKCE:   true,
	}
}

// isConfigured reports whether the required fields have been set. Configure
// is called once at plugin startup with whatever the host currently has
// stored, which may be empty before an admin fills in the form.
func (c config) isConfigured() bool {
	return c.issuerURL != "" && c.clientID != ""
}

// parseConfig reads the "oidc" global config entry out of a Configure
// request and resolves it against defaultConfig. entries with no "oidc" key
// (e.g. a fresh install) yield defaultConfig with issuer_url/client_id empty,
// which isConfigured reports as not ready.
// simpleStringFields are the admin_form fields that resolve to a single
// config string, optionally post-processed (e.g. issuer_url's trailing
// slash). Fields needing other types (scopes, require_pkce, allowed_groups)
// are handled separately in parseConfig.
func simpleStringFields(cfg *config) []struct {
	key       string
	dest      *string
	transform func(string) string
} {
	return []struct {
		key       string
		dest      *string
		transform func(string) string
	}{
		{"issuer_url", &cfg.issuerURL, func(v string) string { return strings.TrimRight(v, "/") }},
		{"client_id", &cfg.clientID, nil},
		{"client_secret", &cfg.clientSecret, nil},
		{"username_claim", &cfg.usernameClaim, nil},
		{"email_claim", &cfg.emailClaim, nil},
		{"display_name_claim", &cfg.displayClaim, nil},
		{"groups_claim", &cfg.groupsClaim, nil},
	}
}

func parseConfig(entries []*pluginv1.ConfigEntry) (config, error) {
	cfg := defaultConfig()

	for _, entry := range entries {
		if entry.GetKey() != configKey {
			continue
		}
		values := entry.GetValue().AsMap()

		for _, f := range simpleStringFields(&cfg) {
			v, err := stringField(values, f.key)
			if err != nil {
				return config{}, err
			}
			if v == "" {
				continue
			}
			if f.transform != nil {
				v = f.transform(v)
			}
			*f.dest = v
		}

		if v, err := stringField(values, "scopes"); err != nil {
			return config{}, err
		} else if v != "" {
			cfg.scopes = strings.Fields(v)
		}

		if raw, ok := values["require_pkce"]; ok {
			b, ok := raw.(bool)
			if !ok {
				return config{}, fmt.Errorf("oidc config: require_pkce must be a boolean")
			}
			cfg.requirePKCE = b
		}

		v, err := stringField(values, "allowed_groups")
		if err != nil {
			return config{}, fmt.Errorf("oidc config: allowed_groups: %w", err)
		}
		if v != "" {
			cfg.allowedGroups = splitAllowedGroups(v)
		}
	}

	cfg.scopes = ensureScope(cfg.scopes, "openid")

	return cfg, nil
}

func stringField(values map[string]any, key string) (string, error) {
	raw, ok := values[key]
	if !ok || raw == nil {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("oidc config: %s must be a string", key)
	}
	return strings.TrimSpace(s), nil
}

// splitAllowedGroups parses the comma-separated allowed_groups admin_form
// value, trimming whitespace and dropping empty entries.
func splitAllowedGroups(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func ensureScope(scopes []string, want string) []string {
	if slices.Contains(scopes, want) {
		return scopes
	}
	return append([]string{want}, scopes...)
}
