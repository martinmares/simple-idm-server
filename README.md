# Simple IDM

Simple IDM is a Rust-based OAuth2/OIDC identity stack for small and medium environments that need:

- OAuth2/OIDC SSO
- compact JWT tokens
- group and claim mapping
- legacy application SSO through reverse proxy headers
- direct AD/LDAP auth proxy for small internal apps without OIDC
- SSH certificate login
- delegated authentication through Google/OIDC or AD/LDAP
- browser-based and terminal administration

The repository is a Cargo workspace with multiple binaries and shared core crates.

## Components

- `simple-idm-server` - OAuth2/OIDC server, Admin API and Admin Web UI
- `simple-idm-ctl` - CLI and TUI administration client
- `simple-idm-oauth2-proxy` - OIDC auth adapter for trusted headers, nginx `auth_request`, and single-upstream reverse proxy mode
- `simple-idm-ad-proxy` - AD/LDAP login adapter for nginx `auth_request` and trusted headers
- `simple-idm-oidc-metadata-proxy` - read-only OIDC discovery/JWKS proxy for exposing trusted token metadata across network boundaries
- `simple-idm-token-proxy` - localhost bearer-token proxy and authenticated runtime asset fetcher
- `simple-idm-ssh-login` - SSH certificate login client
- `simple-idm-ssh-signer` - SSH certificate signer service
- `simple-idm-core` - shared server/core library
- `simple-idm-ad-auth` - AD/LDAP password verification and profile/role fetch
- `simple-idm-ldap-sync` - external role to local group mapping engine

## Main Features

- OAuth2 Authorization Code Flow with PKCE
- OAuth2 Device Authorization Flow
- OAuth2 Client Credentials Flow for M2M clients
- OIDC discovery and JWKS endpoints
- refresh tokens and SSO sessions
- local password auth with Argon2 password hashes
- tenant-level TOTP MFA, one-time recovery codes, and audited admin reset for locally managed accounts
- federated login through upstream Google/OIDC providers
- AD/LDAP delegated password auth through `ad_ldap` identity providers
- AD/LDAP role sync and mapping to local groups
- nested groups and effective group expansion
- virtual groups and configurable group claim output
- per-client claim maps and group filtering
- Admin Web UI based on Tabler
- CLI for login, session management, and automation
- soft delete model for admin-managed entities

## Requirements

- Rust stable
- PostgreSQL 14+
- `sqlx-cli`
- RSA key pair for JWT signing
- `IDP_SECRETS_MASTER_KEY` if you store identity provider secrets

Install `sqlx-cli`:

```bash
cargo install sqlx-cli --no-default-features --features postgres
```

## Quick Start

Create database:

```bash
createdb simple_idm
```

Generate keys:

```bash
./scripts/generate_keys.sh
```

Configure:

```bash
cp .env.example .env
```

Run migrations:

```bash
cargo sqlx migrate run
```

Run server:

```bash
cargo run -p simple-idm-server --bin simple-idm-server
```

Default local URL:

```text
http://localhost:8080
```

Admin Web UI:

```text
http://localhost:8080/admin/ui
```

## Configuration

Important environment variables:

```env
SERVER_HOST=127.0.0.1
SERVER_PORT=8080
DATABASE_URL=postgres://postgres:postgres@localhost/simple_idm

JWT_ISSUER=http://localhost:8080
JWT_PRIVATE_KEY_PATH=./keys/private.pem
JWT_PUBLIC_KEY_PATH=./keys/public.pem
JWT_KEY_ID=default-key-2025
ACCESS_TOKEN_EXPIRY_SECONDS=3600
REFRESH_TOKEN_EXPIRY_SECONDS=2592000

ADMIN_ROOT_TOKEN=

AUTH_ALLOW_USERNAME_LOGIN=true
ALLOWED_EMAIL_DOMAINS=

ONBOARDING_TOKEN_TTL_SECONDS=86400
ONBOARDING_TOKEN_CLEANUP_INTERVAL_SECONDS=3600
IDP_SECRETS_MASTER_KEY=

UI_BRAND_NAME=Cloud App
UI_BRAND_DOMAIN=
UI_PAGE_TITLE=Simple IDM
```

UI customization is intentionally limited to these text labels. Colors, layout,
dark/light behavior, and bundled assets are kept consistent across Simple
services through the embedded Tabler Admin UI assets.

`JWT_ISSUER` is important. It is used as the public issuer URL and as the base for generated callback URLs. In production it should be the external HTTPS URL, for example:

```env
JWT_ISSUER=https://sso.example.com
```

### Secret Encryption

Identity and authenticator secrets are encrypted in the database:

- OIDC client secrets
- Google client secrets
- AD/LDAP bind passwords
- pending and active TOTP seeds

Set:

```env
IDP_SECRETS_MASTER_KEY=<base64_32B_key>
```

Generate a key:

```bash
openssl rand -base64 32
```

Stored values use:

```text
EncSimple[@api=2.0:@box=<base64(nonce||ciphertext||tag)>]
```

Do not rotate `IDP_SECRETS_MASTER_KEY` without re-encrypting existing secrets.

## Callback URLs

### Simple IDM as OAuth2/OIDC Provider

For normal OAuth2 clients, callback URLs are the client `redirect_uris` registered in `Clients`.

Example:

```text
https://app.example.com/auth/callback
http://127.0.0.1:55236/callback
```

The server validates the `redirect_uri` from `/oauth2/authorize` against the registered client.

### Federated Onboarding Callback

Used when an admin sends an invitation to link a local Simple IDM user to an upstream identity provider.

Format:

```text
{JWT_ISSUER}/federated/onboarding/{provider_slug}/callback
```

Example:

```text
https://sso.example.com/federated/onboarding/google/callback
```

Register this URL in the upstream provider, for example in Google OAuth Client settings.

### Federated Login Callback

Used when Simple IDM delegates a normal interactive login to an upstream OIDC provider.

Format:

```text
{JWT_ISSUER}/oauth2/federated/{provider_slug}/callback
```

Example:

```text
https://sso.example.com/oauth2/federated/google/callback
```

Register this URL in the upstream provider if the provider is used for normal login, not only onboarding.

### AD/LDAP

AD/LDAP has no OAuth callback URL. It uses direct LDAPS/StartTLS bind from Simple IDM to the configured LDAP server.

AD onboarding page:

```text
{origin}/ad/onboarding?token=...
```

This page accepts AD login/password, verifies them through the selected `ad_ldap` provider, fetches profile/roles and stores the synced state.

### Device Flow

Device flow has no callback URL.

Relevant endpoints:

```text
POST /oauth2/device/authorize
GET  /device
POST /oauth2/device/verify
POST /oauth2/device/token
```

User verification URL:

```text
{JWT_ISSUER}/device
{JWT_ISSUER}/device?user_code=XXXX-XXXX
```

## Identity Providers

Identity providers are configured in Admin Web UI:

```text
Admin UI -> Identity providers
```

Supported provider types:

- `google`
- `oidc`
- `ad_ldap`

### Google / OIDC Providers

These providers use OAuth2/OIDC redirect flow.

Typical fields:

- slug
- issuer
- client ID
- client secret
- scopes
- optional hosted domain
- optional explicit authorization/token/JWKS URLs

For Google:

```text
issuer: https://accounts.google.com
scopes: openid profile email
```

Usually leave Authorization URL, Token URL and JWKS URL empty; discovery will resolve them from the issuer.

### AD/LDAP Provider

AD/LDAP is also configured as an identity provider, with:

```text
provider_type: ad_ldap
```

Typical fields:

- host
- port
- base DN
- user filter
- TLS mode: `ldaps` or `starttls`
- timeout
- allow insecure TLS for testing
- bind DN/login
- bind password
- accepted domains
- role sync settings

Example user filter:

```text
(|(mail={login})(sAMAccountName={login})(userPrincipalName={login}))
```

The user must have:

```text
auth_mode = ad
auth_provider_id = <ad_ldap provider id>
```

AD/LDAP role sync stores external roles per provider and maps them to local groups through AD role mappings.

## Authentication Modes

Users can use:

- `local` - password hash is stored locally using Argon2
- `federated` - identity is verified through Google/OIDC provider
- `ad` - password is verified through a configured AD/LDAP provider

For `federated`, the user is linked by invitation and then approved by an admin. The final binding is based on upstream `issuer + subject`, not just email.

For `ad`, the selected `auth_provider_id` decides which AD/LDAP provider is used for password verification, onboarding and role sync.

## Managed Tenant MFA

Simple IDM applies its own MFA policy only to `local` accounts. Accounts using
`federated` or `ad` authentication continue to rely on the upstream identity
provider or AD for MFA. This avoids stacking two unrelated second-factor
challenges and keeps the trust boundary explicit.

Each tenant has one of these policies, configurable in **Admin UI → Tenants**:

| Policy | Local account without TOTP | Local account with active TOTP | Federated / AD account |
|---|---|---|---|
| `disabled` | password only | password only | upstream authentication |
| `optional` | password only | password + TOTP or recovery code | upstream authentication |
| `required` | browser enrollment is required | password + TOTP or recovery code | upstream authentication |

`optional` does not force a new enrollment. It is useful for staged rollout or
for preserving MFA on accounts that already enrolled. Set the tenant to
`required` when every local account must enroll at its next browser sign-in.

Enrollment uses standard TOTP and works with Microsoft Authenticator, Google
Authenticator, and compatible applications. After confirming the first code,
the user receives ten one-time recovery codes. Only Argon2 hashes of recovery
codes are stored, and the codes cannot be displayed again.

An administrator can use **Reset MFA** on a local user. The operation revokes
the authenticator and recovery codes, removes pending MFA transactions, closes
the user's SSO sessions, and writes an audit event. Under a `required` policy,
the next browser login starts a fresh enrollment. TOTP seeds are never exposed
in the Admin UI.

Authorization Code Flow records the authentication method in `amr` and the
assurance level in `acr`. Successful MFA produces `amr` containing `pwd` plus
`otp` (or `recovery`) and `acr=urn:simple-idm:acr:mfa`; these values are retained
across authorization codes and refresh tokens. Device Flow accepts an existing
TOTP or recovery code, but intentionally cannot enroll a new authenticator: a
user without one must first complete a browser login.

Operational requirements:

- run migration `041_add_managed_tenant_mfa.sql` before deploying the new binary;
- configure `IDP_SECRETS_MASTER_KEY`, which also encrypts TOTP seeds;
- keep server clocks synchronized because TOTP is time based;
- protect database backups and the encryption key separately;
- start with `disabled`, validate browser and recovery flows, then switch the
  intended managed tenant to `required`.

## Passkeys (in progress)

The WebAuthn service is currently internal: HTTP registration, sign-in and UI
are not available yet. Configure `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGINS`
(optionally `WEBAUTHN_RP_NAME`) to validate the relying party at startup. For
example, use `WEBAUTHN_RP_ID=idm.example.com` with
`WEBAUTHN_ORIGINS=https://idm.example.com`. The RP ID must remain stable or
previously registered passkeys will stop working. Migration 042 defaults tenant
`passkey_policy` to `disabled`. See `docs/PASSKEY_IMPLEMENTATION_PLAN.cs.md`.

## Authentication Throttling


Repeated authentication failures are tracked in the `auth_throttle` database table.
The lockout survives service restarts by default, so restart loops cannot bypass
brute-force protection.

Runtime knobs:

```text
AUTH_PROTECTION_ENABLED=true
AUTH_FAILURE_WINDOW_SECONDS=900
AUTH_MAX_FAILURES=5
AUTH_LOCKOUT_SECONDS=900
```

For development or emergency recovery only, the table can be cleared on server
startup:

```text
AUTH_THROTTLE_CLEAR_ON_START=true
```

This is intentionally unsafe for production. When enabled, startup logs emit a
`SECURITY WARNING` and the admin Web UI shows a prominent warning banner.

## OAuth2 Endpoints

OIDC discovery:

```text
GET /.well-known/openid-configuration
GET /.well-known/jwks.json
```

Authorization Code Flow:

```text
GET  /oauth2/authorize
POST /oauth2/login
POST /oauth2/token
```

Client Credentials:

```text
POST /oauth2/client_credentials/token
```

Device Flow:

```text
POST /oauth2/device/authorize
GET  /device
POST /oauth2/device/verify
POST /oauth2/device/token
```

UserInfo:

```text
GET /oauth2/userinfo
```

Token introspection/revocation:

```text
POST /oauth2/introspect
POST /oauth2/revoke
```

## Admin UI

Admin Web UI:

```text
/admin/ui
```

Main sections:

- Dashboard
- Users
- Groups
- Memberships
- Clients
- Identity providers
- Client claims
- Group claims

The Admin UI uses an admin session cookie. For development, `ADMIN_ROOT_TOKEN` can be used to log in.

## Admin CLI

Build:

```bash
cargo build -p simple-idm-ctl
```

Login through browser:

```bash
simple-idm-ctl login --url https://sso.example.com
```

Login through device flow:

```bash
simple-idm-ctl login --url https://sso.example.com --device
```

Tenant hint:

```bash
simple-idm-ctl login --url https://sso.example.com --tenant acme
```

Session commands:

```bash
simple-idm-ctl status
simple-idm-ctl sessions list
simple-idm-ctl sessions use production
simple-idm-ctl logout
```

## OAuth2 Proxy

`simple-idm-oauth2-proxy` protects applications that do not implement their own
OAuth2/OIDC login flow.

Ingress/auth-request architecture:

```text
browser -> nginx -> simple-idm-oauth2-proxy -> legacy app
```

Small reverse-proxy architecture:

```text
browser -> simple-idm-oauth2-proxy -> app
```

The reverse proxy mode is a focused single-upstream OIDC adapter, not a general
nginx/Traefik replacement. Use nginx, Traefik, HAProxy, or OpenShift Route for
TLS termination, edge hardening, buffering, request limits, or complex routing.
The practical production pattern is often:

```text
browser -> nginx TLS edge -> simple-idm-oauth2-proxy -> app
```

In that setup nginx keeps certificate automation and edge hardening, while
`simple-idm-oauth2-proxy` owns SSO login, logout, session cookies, trusted
identity headers, and HTTP/1.1/WebSocket forwarding to one upstream app.

It can inject headers such as:

```text
X-Auth-Subject
X-Auth-User
X-Auth-Email
X-Auth-Groups
```

`X-Auth-Subject` is the stable OIDC `sub` claim and should be used for audit
and durable identity. `X-Auth-User` is display/login oriented.

See:

```text
docs/OAUTH2_PROXY.md
docs/multi-oauth/
```

## SSH Certificates

The SSH stack consists of:

- `simple-idm-ssh-login`
- `simple-idm-ssh-signer`

Basic flow:

```text
simple-idm-ssh-login -> Simple IDM OIDC login -> SSH signer -> OpenSSH certificate
```

Typical SSHD server config:

```text
TrustedUserCAKeys /etc/ssh/simple-idm-ssh-signer.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

Local Linux account access is controlled by OpenSSH principals. Simple IDM groups can produce SSH principals such as:

```text
ssh:principal:mares
ssh:role:linux-admin
```

## Groups and Claims

Groups can be nested and are evaluated as direct/effective memberships.

Client settings control group claim output:

- `groups_claim_mode = none`
- `groups_claim_mode = direct`
- `groups_claim_mode = effective`
- `ignore_virtual_groups = true|false`

Claim maps allow per-client custom claims:

- single value
- array value
- group-specific claim mapping

This is useful for reducing JWT size and translating internal groups to application-specific roles.

## Group Patterns

Group patterns automatically assign groups to users.

Pattern examples:

```text
ssh:*
*:admin
ssh:*:admin
exact-match
```

Priority rules:

- lower number means higher priority
- patterns are evaluated in priority order

Example:

```text
Priority 1:  ssh:*            include
Priority 2:  ssh:role:admin   exclude
Priority 10: encjson:*        include
```

Config:

```env
GROUP_PATTERNS_SYNC_INTERVAL_SECONDS=300
```

## Soft Delete

Admin operations use soft delete where possible. Deleted rows are marked and can be hidden from normal UI/API views.

Optional purge:

```env
SOFT_DELETE_PURGE_ENABLED=false
SOFT_DELETE_PURGE_INTERVAL_SECONDS=3600
SOFT_DELETE_RETENTION_DAYS=30
```

## SQLx Offline Mode

The workspace uses SQLx compile-time query metadata.

After SQL or migration changes:

```bash
cargo sqlx migrate run
cargo sqlx prepare --workspace
git add .sqlx migrations
```

Build without database:

```bash
SQLX_OFFLINE=true cargo build --workspace
```

## Development

Run checks:

```bash
cargo check --workspace --all-targets
cargo test --workspace
```

Run server:

```bash
cargo run -p simple-idm-server --bin simple-idm-server
```

## License

MIT

## Author

Martin Mareš
