# Simple IDM

All 13 crates share one version through `version.workspace = true`.
Use `just release-version 0.12.2` for the next release; see the
[release guide](docs/RELEASING.md) for GitHub and GitLab pipelines.

For Linux installation with a dedicated service user, linger, and a systemd
user unit, see the [step-by-step Linux bootstrap guide (Czech)](docs/LINUX_SYSTEMD_BOOTSTRAP.cs.md).

For a read-only Google Workspace user export and a preview-first CLI import,
see the [Directory export/import guide (Czech)](docs/GOOGLE_WORKSPACE_EXPORT.cs.md).

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
- `simple-idm-token-proxy` - localhost bearer-token proxy and authenticated runtime asset fetcher, with configurable environment-to-`X-*` header mappings ([configuration](docs/TOKEN_PROXY.md))
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
- nested virtual bundles, regular leaf groups and configurable group claim output
- per-client claim maps and group filtering
- Admin Web UI based on Tabler
- CLI for login, session management, and automation
- soft delete model for admin-managed entities

## Requirements

- Rust stable
- PostgreSQL 14+
- `sqlx-cli`
- RSA key pair for JWT signing
- `IDP_SECRETS_MASTER_KEY` if you store identity provider secrets or enable TOTP MFA

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

For regular browser sign-in, select `Continue with Google` (or your OIDC
provider's name) on the OAuth2 login page. Only active Google/OIDC providers
in the OAuth client's tenant are offered. The password form is for local
and AD/LDAP accounts; never enter your Google password there. Invitations
are for initial identity linking, not regular sign-in.

For `ad`, the selected `auth_provider_id` decides which AD/LDAP provider is used for password verification, onboarding and role sync.

## Managed Tenant MFA

Simple IDM applies its own MFA policy only to `local` accounts. Accounts using
`federated` or `ad` authentication continue to rely on the upstream identity
provider or AD for MFA. This avoids stacking two unrelated second-factor
challenges and keeps the trust boundary explicit.

Each tenant has one of these policies, configurable in **Admin UI → Tenants**:

Migration `044_add_domain_auth_policies.sql` adds optional email-domain overrides
in **Tenants / domains → Edit domain**. MFA accepts `inherit`, `disabled`,
`optional`, or `required`; passkeys accept `inherit`, `disabled`, or `allowed`.
`inherit` uses the tenant policy; explicit `disabled` overrides an enabled tenant.
Existing domains default to `inherit`. Only active, non-deleted domains in the
user's own tenant participate, using the domain of the user's current email.
Unmanaged domains inherit the tenant policy. Federated/AD users still use their
upstream authentication; these settings do not restrict a domain to local accounts.

For a mixed deployment, keep tenant MFA/passkeys disabled, set `example.org`
to MFA `required` and passkeys `allowed`, and leave `example.com` on `inherit`.
This is independent of the public SSO hostname and WebAuthn RP ID. Enabling MFA
requires `IDP_SECRETS_MASTER_KEY`; passkeys also require the WebAuthn configuration.
Password-only browser sessions and refresh tokens cannot bypass newly required
MFA; passkey sessions cannot continue when passkeys become disabled. Already
issued access tokens remain valid until their normal expiry.

The CLI supports domain policies with `tenants domains create/update` using
`--mfa-policy` and `--passkey-policy`; pass `inherit` to remove an override.

Migration `045_add_domain_authentication_rules.sql` adds a separate
**Authentication policy** to each managed domain: `Unrestricted` (default),
`Local only`, `Federated only`, or `AD/LDAP only`. The last two require an active
provider of the matching type in the same tenant. For example, set `example.com`
to `Federated only` with Google, and `example.org` to `Local only`.
This is an enforced restriction, not automatic account conversion or linking.
Creating/importing users, changing their email/type/provider, and restoring
deleted users must satisfy the active domain rule. A stricter domain rule is
rejected if existing non-deleted accounts (including inactive accounts) conflict.
Deactivated or deleted domains no longer impose a restriction. Deactivating the
prescribed provider blocks authentication until the provider or policy is fixed.
Federated linking still requires a verified `issuer + sub`, never just email.
Existing domains remain unrestricted after migration. CLI flags are
`--authentication-policy unrestricted|local|federated|ad` and `--auth-provider-id`.

| Policy | Local account without TOTP | Local account with active TOTP | Federated / AD account |
|---|---|---|---|
| `disabled` | password only | password only | upstream authentication |
| `optional` | password only | password + TOTP or recovery code | upstream authentication |
| `required` | browser enrollment is required | password + TOTP or recovery code | upstream authentication |

Users can open **`/account/mfa`** or **`/account/security`** directly; no CLI or
external application is needed to sign in first. Without a valid IDM browser
session, these pages lead to `/account/login` and the standard sign-in form.
For a new local account with required MFA, the flow is:

1. Sign in with the account password.
2. Scan the authenticator QR code (or enter the manual setup key).
3. Confirm a current six-digit code; until then, sign-in is not complete.
4. Save the ten recovery codes and continue to the requested settings page.

After an administrator uses **Reset MFA**, the next password sign-in follows
the same enrollment flow. Passkeys are managed separately and are not deleted
by the authenticator reset. For an optional MFA policy, sign-in remains possible
without a factor, and the user starts enrollment from the settings page.

Account sign-in reuses the existing OAuth password/MFA/passkey handlers and
creates only an IDM browser session: no authorization code or API token is
issued. The reserved `simple-idm-account` client is created automatically for
the selected tenant with empty grants/scopes; it needs no manual configuration.
Only `/account/mfa` and `/account/security` are accepted as return destinations.
`/account/login?tenant=<slug>` selects a tenant (the default is `default`).

`optional` does not force a new enrollment. A locally managed user can sign in
normally, open `/account/mfa` (also linked from `/account/security` when
Passkeys are enabled), and enroll an authenticator app without changing the
tenant policy for anyone else. Starting and confirming enrollment require a
session created in the last five minutes. Set the tenant to `required` when
every local account must enroll at its next browser sign-in.

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
- run migration `043_add_mfa_self_enrollment.sql` for optional-policy self-service enrollment;
- configure `IDP_SECRETS_MASTER_KEY`, which also encrypts TOTP seeds;
- keep server clocks synchronized because TOTP is time based;
- protect database backups and the encryption key separately;
- start with `disabled`, validate browser and recovery flows, then switch the
  intended managed tenant to `required`.

## Passkeys (initial implementation)

Run migration `042_add_passkeys.sql`, configure `WEBAUTHN_RP_ID` and
`WEBAUTHN_ORIGINS` (optionally `WEBAUTHN_RP_NAME`), and set the tenant's
`passkey_policy` to `allowed` in **Admin UI → Tenants**. The default is
`disabled`. For example, use `WEBAUTHN_RP_ID=idm.example.com` with
`WEBAUTHN_ORIGINS=https://idm.example.com`. Keep the RP ID stable: changing it
will make existing credentials unusable. Production origins must use HTTPS.

Locally managed users can choose **Continue with passkey** on the OAuth login
page. After signing in, they can open `/account/security` to add, rename or
revoke multiple Passkeys. Changes require a session created in the last five
minutes; sign out and sign in again if it has aged. Password + TOTP remains
available. WebAuthn requires user verification and records `amr=webauthn` with
`acr=urn:simple-idm:acr:phishing-resistant`; a separate TOTP challenge is not
required for that login. The Admin UI shows the active Passkey count and offers
a separate, audited **Reset Passkeys** action that revokes sign-in sessions.

Conditional UI, Passkey-only accounts, tenant policy `required`, per-key admin
revocation and automated browser E2E tests are not yet available. A manual
Chromium virtual-authenticator test covered two registrations, Passkey login,
revocation, re-registration, required-MFA bypass and password + TOTP fallback.
See `docs/PASSKEY_IMPLEMENTATION_PLAN.cs.md` for the remaining work.

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

Install all eight native workspace binaries into `~/.cargo/bin`:

```bash
just install
```

This replaces previously installed versions and reuses the workspace `target`
directory. The workspace root is a virtual manifest, so `cargo install --path .`
does not work; the recipe installs each binary package separately.

Build:

```bash
cargo build -p simple-idm-ctl
```

Login through browser:

```bash
simple-idm-ctl login --url https://sso.example.com
```

Optional browser login hint:

```bash
simple-idm-ctl login --url https://sso.example.com --user user@example.com
```

`--user` sends the OIDC `login_hint`, not a credential. An active federated
account with an approved identity in the client's tenant is routed to its
provider; otherwise the login form is prefilled. Existing SSO sessions still
take precedence. This option cannot be combined with `--device`.

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

### Interactive infrastructure access through a bastion

`simple-idm-bastion` provides an SSO-authenticated host catalog, an interactive
SSH terminal and durable session auditing. The client manages no target SSH
keys or certificates: the bastion obtains a per-session certificate from the
existing signer. An established terminal remains open after certificate expiry.

```sh
simple-idm-ssh-login bastion.datalite.cz
# Explicit form:
simple-idm-ssh-login bastion bastion.datalite.cz
```

See [Bastion deployment and usage](docs/BASTION.md) for client profiles,
OIDC scopes, signer delegation, host authorization, nginx and audit exports.
Implementation status is tracked in the [implementation plan](docs/BASTION_IMPLEMENTATION_PLAN.cs.md).

### Direct SSH certificates

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
ssh:principal:user
ssh:role:linux-admin
```

## Groups and Claims

Virtual bundles can contain regular groups and other virtual bundles. Regular
groups are leaves. Both types can be assigned to users; membership flows only
to descendants, never to parents. Shared descendants use the same UUID.

Client settings control group claim output:

- `groups_claim_mode = none`
- `groups_claim_mode = direct`
- `groups_claim_mode = effective`
- Virtual group names are always excluded from `groups`. The old
  `ignore_virtual_groups` API field is deprecated, accepted but ignored, and
  returned as `true`. Its old stored value is retained for migration auditing.

Claim maps allow per-client custom claims:

- single value
- array value
- group-specific claim mapping

Claim mapping uses all effective internal memberships, including virtual
bundles, for both UUID and name-pattern matching. Client group filters and
`groups_claim_mode` control only the exported `groups`, not claim-map matching.
Each claim map has its own client-specific UUID/pattern rules. For example,
`admin:monitoring -> role=monitoring-admin` works for a member of its parent
`admin:all`, but not for a user assigned only a leaf such as `grafana-admins`.
A client using `groups_claim_mode=none` can still receive custom claims.

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

Archiving a user releases their username within the tenant. A new local account
can reuse that name with a different email and receives a new UUID; the archived
account retains its original username, Google/other identity links, memberships
and audit history. Disabling an account without archiving it still reserves its
username. Restoring an archived account fails if another non-archived account
has taken the name. Email uniqueness and external identity reservations remain
unchanged. Migration `050_release_archived_usernames.sql` applies automatically
when the updated server starts.

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

When upgrading to the security fixes, review [deployment changes](docs/SECURITY_UPGRADE.md)
and the [security audit](docs/security_best_practices_report.md).

Run checks:

```bash
SQLX_OFFLINE=true cargo check --locked --workspace --all-targets
SQLX_OFFLINE=true cargo test --locked --workspace
```

PostgreSQL integration tests run **locally on the developer's machine**, using
Docker Compose. CI runs the checks above with committed SQLx offline metadata;
it does not connect to an external database. Tests marked `#[ignore]` that require
PostgreSQL are run separately:

```bash
# Requires Docker with Compose and sqlx-cli (see prerequisites).
bash scripts/test-postgres.sh
# Alternatively: just test-postgres
```

The script starts a separate Compose project from `docker-compose.test.yml`,
waits for PostgreSQL, applies migrations, and runs the database tests in
`simple-idm-core`. PostgreSQL listens only on loopback at an automatically
assigned port. Its data lives in a temporary container filesystem and is removed
when the script exits, including when a test fails. It does not use the database
or volume from the development `docker-compose.yml`. Test credentials are local
fixtures. The legacy files in the root `tests/` directory are not Cargo test
targets in this virtual workspace and are not covered by this command.

Run server:

```bash
cargo run -p simple-idm-server --bin simple-idm-server
```

## License

MIT

## Commercial Support

This software is provided under the MIT License and comes without warranty
or free community support. Using the software does not require purchasing support.

Commercial support is available from **[DataLite](https://datalite.cz)**, including:

- technical assistance and troubleshooting,
- verified releases and updates,
- bug fixes,
- deployment assistance,
- long-term maintenance.

Contact [DataLite](https://datalite.cz) for commercial support options.
Public issues and external pull requests do not create an obligation to respond,
review, accept contributions, or implement changes. No SLA or release cadence
is promised unless separately agreed.

## Author

Martin Mareš

## Shared virtual group bundles

A virtual group is a reusable bundle of member groups. A regular group may be
included in several bundles, using the same group UUID in every reference:

```text
admin:all      -> gitlab-admins, grafana-admins, registry:admin
admin:selected -> gitlab-admins, grafana-admins
```

A user assigned to `admin:selected` receives only that bundle and its descendants,
not `admin:all` or `registry:admin`. Effective groups and claims deduplicate shared
members. Virtual names are never exported in token `groups`, but both group
types can grant custom claims. Even an empty virtual bundle can grant its mapped claim.
Nested bundles remain supported; self-membership and transitive cycles are rejected,
including concurrent edits. Memberships must remain within the same tenant.

In **Admin UI → Groups**, create a group with **Virtual bundle** checked, then use
**Members** to select its member groups. Expand the member tree to inspect nested
bundles; shared nodes link to their single editor. **Included in** shows parents,
and **Claim mappings** shows relevant clients and direct/pattern sources.
**Memberships** separates direct assignments from effective groups and their sources. Search filters the choices without clearing checked
members. Saving changes only the chosen bundle; empty selection removes its contents.
Only virtual bundles can acquire new children. Existing regular parents remain
readable with their old inheritance and appear with a repair warning. Their
member editor allows removing references only; conversion to virtual is explicit
and changes their token publication. The REST API for child groups remains
available. Changing a virtual bundle with children to regular is rejected.
Archived nodes interrupt inheritance. Archived members are named in a neutral information block
and remain checked in the member editor. Saving preserves their references;
uncheck an archived member to remove its reference explicitly. Restoring a group restores its existing
references and claim mappings; removing a reference never deletes its group.

Migration `051_share_group_memberships.sql` removes the old single-parent limit;
existing relationships are preserved. Relationships removed historically by migration
037 cannot be reconstructed automatically and can now be added back explicitly.

On the user sign-in page, password/TOTP and passkey sign-in are explained separately:
TOTP codes are a second factor after the password; a registered passkey enables
password-free sign-in. Enable passkeys in the tenant policy and register a passkey
at `/account/security` before using **Continue with passkey**.


## Group contract migration (0.13.5)

Before deploying, run the read-only compatibility report against your database:

```sh
psql "$DATABASE_URL" -f scripts/group-contract-audit.sql
```

Review physical parents, clients that used virtual names, pattern maps and
potential scalar-claim conflicts. Inspect application authorization rules too;
IDM cannot detect all consumers of historical virtual names. Migration 052
preserves all historical edges and stored client flags. It adds database guards
for virtual parents, cycles, tenant boundaries and type changes. No group is
automatically converted or deleted.

**Behavior change:** name-pattern claim mapping now sees effective internal
membership, just like UUID mapping. Previously its input was reduced by the
client's `groups` mode, export filter and virtual-name flag. For example, a
pattern `admin:monitoring` now matches that effective virtual membership even
when `groups=none` or the client's export filter includes only `grafana-admins`.
Explicitly review those maps before release; they may newly produce claims.
`effective`, `direct`, `none` and `include_claim_maps` remain supported.

Previously issued JWTs retain their original claims until expiration. UserInfo
reflects those token claims. New authorization-code, refresh and device tokens
use the shared resolver. Changes do not provide immediate token revocation.
Multiple conflicting scalar claim maps retain the existing behavior; the audit
reports potential conflicts for manual correction rather than inventing priorities.
