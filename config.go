package main

import (
	"fmt"
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
func parseConfig(entries []*pluginv1.ConfigEntry) (config, error) {
	cfg := defaultConfig()

	for _, entry := range entries {
		if entry.GetKey() != configKey {
			continue
		}
		values := entry.GetValue().AsMap()

		if v, err := stringField(values, "issuer_url"); err != nil {
			return config{}, err
		} else if v != "" {
			cfg.issuerURL = strings.TrimRight(strings.TrimSpace(v), "/")
		}
		if v, err := stringField(values, "client_id"); err != nil {
			return config{}, err
		} else if v != "" {
			cfg.clientID = v
		}
		if v, err := stringField(values, "client_secret"); err != nil {
			return config{}, err
		} else if v != "" {
			cfg.clientSecret = v
		}
		if v, err := stringField(values, "scopes"); err != nil {
			return config{}, err
		} else if v != "" {
			cfg.scopes = splitScopes(v)
		}
		if v, err := stringField(values, "username_claim"); err != nil {
			return config{}, err
		} else if v != "" {
			cfg.usernameClaim = v
		}
		if v, err := stringField(values, "email_claim"); err != nil {
			return config{}, err
		} else if v != "" {
			cfg.emailClaim = v
		}
		if v, err := stringField(values, "display_name_claim"); err != nil {
			return config{}, err
		} else if v != "" {
			cfg.displayClaim = v
		}
		if v, err := stringField(values, "groups_claim"); err != nil {
			return config{}, err
		} else if v != "" {
			cfg.groupsClaim = v
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

func splitScopes(raw string) []string {
	fields := strings.Fields(raw)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func ensureScope(scopes []string, want string) []string {
	for _, s := range scopes {
		if s == want {
			return scopes
		}
	}
	return append([]string{want}, scopes...)
}
