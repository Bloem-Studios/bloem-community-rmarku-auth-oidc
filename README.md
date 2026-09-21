## Bloem community build

This is Bloem's community build of [rmarku/silo-plugin-auth-oidc](https://github.com/rmarku/silo-plugin-auth-oidc) by **rmarku**
(contributors: rmarku). It is ported to the Bloem plugin SDK and listed in the
Bloem community plugin catalog. All credit for the plugin goes to its author; please
report plugin behavior issues upstream. See [NOTICE](NOTICE) for provenance.

---

# OIDC Auth Provider Plugin for Silo

A generic, vendor-agnostic `auth_provider.v1` plugin for
[Silo](https://github.com/Silo-Server/silo-server) that authenticates users
through any identity provider publishing
`{issuer_url}/.well-known/openid-configuration` — Authelia, Authentik,
Keycloak, Zitadel, Pocket ID, Auth0, and others. There is nothing
provider-specific in the code; every difference between IdPs is expressed as
configuration (claim names, scopes, PKCE requirement).

It implements the OAuth authorization-code half of `auth_provider.v1`:

- `InitAuthorize` builds the authorization URL with PKCE (S256).
- `ExchangeCode` redeems the code, verifies the `id_token` against the
  provider's JWKS, and maps claims to Silo's identity shape.
- `RefreshSession` uses the token endpoint's `refresh_token` grant when a
  refresh token is available.
- `Authenticate` (password login) returns `Unimplemented` — this plugin is
  OAuth-only.

This is a community plugin, not (yet) an official first-party Silo plugin.
It follows the layout and CI conventions of the org's first-party plugins
(e.g. [`silo-plugin-metadata-tvdb`](https://github.com/Silo-Server/silo-plugin-metadata-tvdb))
so it can be adopted into the org with minimal changes if that's ever wanted.

## Setup

Install the plugin binary in Silo, set its config (below), and enable
**OpenID Connect** as a login method. The login page then shows a "Sign in
with OpenID Connect" button.

A plugin process serves exactly one installation, so install the plugin once
per identity provider if you need to authenticate against more than one.

## Config

| Field | Required | Default | Description |
|---|---|---|---|
| `issuer_url` | yes | — | Base URL of the identity provider. Discovery is fetched from `{issuer_url}/.well-known/openid-configuration`. |
| `client_id` | yes | — | OAuth client ID registered with the identity provider. |
| `client_secret` | no | — | Leave blank for a public client. |
| `scopes` | no | `openid profile email` | Space-separated OAuth scopes. `openid` is always included even if omitted. |
| `username_claim` | no | `preferred_username` | ID token / userinfo claim used as the Silo username. See below. |
| `email_claim` | no | `email` | Claim mapped to `AuthenticateResponse.email`. |
| `display_name_claim` | no | `name` | Claim surfaced as `claims.name` (the human display name). |
| `groups_claim` | no | `groups` | Claim surfaced as `claims.groups`, read as either a JSON array of strings or a single string. |
| `require_pkce` | no | `true` | Use PKCE (S256) on the authorization-code flow. Disable only for a provider that rejects it. |
| `allowed_groups` | no | — | Comma-separated list of groups. When set, login is denied unless the user's groups claim intersects this list. |

### Why `username_claim` becomes `display_name`

Silo's host uses `AuthenticateResponse.display_name` as the base for the
auto-provisioned Silo username (see `silo-server`
`internal/auth/plugin_provider.go` `autoProvisionUser`), not as the
human-readable name. This plugin therefore sends the *username* claim
(default `preferred_username`) as `display_name`, and puts the human name
separately in `claims.name`.

### Groups and role mapping

`claims.groups` is populated for any consumer that wants it, including a
future host-side role mapper. Silo does not yet consume group claims to
assign roles — that is tracked as
[silo-server#554](https://github.com/Silo-Server/silo-server/issues/554) and
is not implemented here. Today, `allowed_groups` is the only group-based
control this plugin enforces: it restricts *who can log in*, not what role
they get.

## Worked example: Authelia

Assume Authelia is reachable at `https://auth.example.com` and Silo at
`https://silo.example.com`.

1. Register a client in Authelia's configuration:

   ```yaml
   identity_providers:
     oidc:
       clients:
         - client_id: silo
           client_name: Silo
           client_secret: '$pbkdf2-sha512$...'  # hashed, per Authelia's docs
           public: false
           authorization_policy: one_factor
           redirect_uris:
             - https://silo.example.com/api/v1/auth/oauth/<install_id>/callback
           scopes:
             - openid
             - profile
             - email
             - groups
           pkce_challenge_method: S256
   ```

   `<install_id>` is the numeric plugin installation ID Silo assigns; the
   admin UI shows the exact callback URL for the installation once it exists.

2. Install this plugin in Silo and set its config:

   | Field | Value |
   |---|---|
   | `issuer_url` | `https://auth.example.com` |
   | `client_id` | `silo` |
   | `client_secret` | the plaintext secret you hashed above |
   | `scopes` | `openid profile email groups` |
   | `groups_claim` | `groups` |

3. Enable **OpenID Connect** as a login method.

The same pattern applies to any other OIDC-compliant IdP: register a
confidential (or public) client with the callback URL above, point
`issuer_url` at its discovery document, and adjust the claim-mapping fields
to match what that IdP actually emits (e.g. Keycloak's default username
claim is also `preferred_username`; some IdPs use `upn` or `email` instead).

## Known limitations

- `RefreshSession` only works while the plugin process that handled the
  original `ExchangeCode` is still running: refresh tokens are cached
  in-memory, not persisted, because the host does not yet have a channel to
  store and round-trip `refresh_state` for this flow.
- The `linking` flag on `InitAuthorizeRequest` (linking an OAuth identity to
  an existing Silo account) is accepted but not acted on; the host does not
  populate it yet either.
- No icon asset ships with this plugin; the "Sign in with X" button uses
  Silo's runtime-config `display_name`/`icon_url_path` (set per installation)
  with the manifest's `display_name` as a fallback.

## Dependency Model

This repository consumes `github.com/Silo-Server/silo-plugin-sdk` as a
normal Go module dependency. CI and release builds run with `GOWORK=off` and
expect the SDK version in `go.mod` to resolve from a published semver tag.

For local multi-repository development, use a `go.work` file that points at
a sibling SDK checkout. Do not commit machine-local filesystem
replacements.

## Development

```sh
go test ./...
go build .
```

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

`silo-plugin-auth-oidc` is licensed under `AGPL-3.0-or-later`. See
[LICENSE](LICENSE).
