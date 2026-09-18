# Contributing to the OIDC Auth Provider Plugin

This is an independent, community-maintained Silo plugin — not (yet) an
official [Silo-Server](https://github.com/Silo-Server) repository. If it
gets adopted into the org, the
[Silo contribution guide](https://github.com/Silo-Server/.github/blob/main/CONTRIBUTING.md)
would apply on top of this. Until then, this document is the whole story.

## Before you start

Open an [issue](https://github.com/rmarku/silo-plugin-auth-oidc/issues)
before changing claim mapping, discovery/token handling, configuration, or
the advertised capability. This repository owns OIDC provider behavior;
plugin contracts belong in
[`silo-plugin-sdk`](https://github.com/Silo-Server/silo-plugin-sdk), and
host-side auth orchestration belongs in
[`silo-server`](https://github.com/Silo-Server/silo-server).

## Development setup

Use the Go version declared in `go.mod`. A local `go.work` may point at a
sibling SDK checkout while developing both repositories, but committed code
and CI must resolve the tagged SDK dependency with `GOWORK=off`. Never commit
real IdP credentials, captured tokens, or a local filesystem `replace`
directive.

## Validate your change

```sh
GOWORK=off go test ./...
GOWORK=off go vet ./...
GOWORK=off go build ./...
GOWORK=off go run . manifest >/dev/null
gofmt -l .
```

The manifest command must exit successfully. `gofmt -l .` should print
nothing; if it reports unrelated pre-existing drift, none of the Go files
touched by your change may appear in the output. Add focused coverage for
claim mapping, PKCE handling, and identity-provider error handling when
those behaviors change.

## Open the pull request

Use a Conventional Commit title, explain any auth-flow or compatibility
risk, and paste the actual validation results.
