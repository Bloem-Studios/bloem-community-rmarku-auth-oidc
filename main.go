// Command silo-plugin-auth-oidc is a generic, vendor-agnostic OpenID Connect
// auth_provider.v1 plugin for Silo. It works against any identity provider
// that publishes {issuer}/.well-known/openid-configuration: Authelia,
// Authentik, Keycloak, Zitadel, Pocket ID, Auth0, and others. See README.md
// for a worked Authelia example.
package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/hashicorp/go-hclog"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
)

//go:embed manifest.json
var manifestJSON []byte

// version is set at build time via -ldflags "-X main.version=...".
var version string

// runtimeServer answers GetManifest with the embedded manifest and forwards
// Configure to the auth provider. It embeds pluginv1.UnimplementedRuntimeServer
// directly rather than runtimedefault.Server so this plugin has no dependency
// on RuntimeHost broker wiring it doesn't use.
type runtimeServer struct {
	pluginv1.UnimplementedRuntimeServer

	manifest *pluginv1.PluginManifest
	provider *provider
}

func (s *runtimeServer) GetManifest(context.Context, *pluginv1.GetManifestRequest) (*pluginv1.GetManifestResponse, error) {
	return &pluginv1.GetManifestResponse{Manifest: s.manifest}, nil
}

// Configure applies the "oidc" global config entry. It is tolerant of an
// absent entry (a fresh install before the admin has filled in the form) so
// the plugin process still starts; every AuthProvider RPC rejects with
// FailedPrecondition until issuer_url and client_id are set.
func (s *runtimeServer) Configure(_ context.Context, req *pluginv1.ConfigureRequest) (*pluginv1.ConfigureResponse, error) {
	cfg, err := parseConfig(req.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("configure silo-plugin-auth-oidc: %w", err)
	}
	s.provider.setConfig(cfg)
	return &pluginv1.ConfigureResponse{}, nil
}

func loadManifest() (*pluginv1.PluginManifest, error) {
	manifest, err := publicmanifest.Load(manifestJSON)
	if err != nil {
		return nil, fmt.Errorf("load embedded manifest: %w", err)
	}

	if version != "" {
		manifest.Version = version
	}

	executablePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable path: %w", err)
	}
	binaryData, err := os.ReadFile(executablePath)
	if err != nil {
		return nil, fmt.Errorf("read executable %q: %w", executablePath, err)
	}
	checksum := sha256.Sum256(binaryData)
	manifest.Checksum = hex.EncodeToString(checksum[:])

	return manifest, nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{Name: "silo-plugin-auth-oidc", Output: os.Stderr})

	manifest, err := loadManifest()
	if err != nil {
		panic(err)
	}

	authProvider := newProvider(logger)

	runtime.Serve(runtime.ServeConfig{
		Logger: logger,
		Servers: runtime.CapabilityServers{
			Runtime:      &runtimeServer{manifest: manifest, provider: authProvider},
			AuthProvider: authProvider,
		},
	})
}
