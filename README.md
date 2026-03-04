# Simple IDM Server

A simple OAuth2/OIDC Identity Provider Server written in Rust.

## Features

- **Machine-to-Machine (M2M)** - OAuth2 Client Credentials Grant
- **User-to-Webserver** - OAuth2 Authorization Code Flow with PKCE + HTML Login Form
- **TV/Device Flow** - OAuth2 Device Authorization Grant (RFC 8628) (experimental)
- **OAuth2 Authentication Proxy** - Add OIDC to legacy applications (nginx auth_request)
- **Custom Claim Mapping** - Similar to Kanidm, allows filtering groups/claims per application
- **Group Patterns** - Automatic group assignment using wildcard patterns (e.g., `ssh:*`)
- **JWT tokens** - RS256 with asymmetric keys
- **Refresh tokens** - For long-term sessions
- **OIDC Discovery** - `/.well-known/openid-configuration`
- **JWKS Endpoint** - `/.well-known/jwks.json`
- **Admin API** - Complete REST API for managing users, groups, clients, and claim maps
- **TUI Client** - Terminal UI for administration (`simple-idm-ctl tui`)
- **Admin Web UI** - Browser-based admin interface (`/admin/ui/*`)

## Requirements

- Rust 1.70+
- PostgreSQL 14+
- OpenSSL (for generating RSA keys)
- **sqlx-cli** (for database migrations and offline mode)

## Quick Start

### 1. Install Dependencies

```bash
# PostgreSQL
# macOS
brew install postgresql

# Linux (Ubuntu/Debian)
sudo apt-get install postgresql

# sqlx-cli (for database migrations)
cargo install sqlx-cli --no-default-features --features postgres
```

### 2. Create Database

```bash
createdb simple_idm
```

### 3. Generate RSA Keys

```bash
./scripts/generate_keys.sh
```

### 4. Configure Environment

```bash
cp .env.example .env
# Edit .env as needed
```

### 5. Run Server

```bash
cargo run
```

The server will run on `http://localhost:8080`.

---

## ⚠️ IMPORTANT: sqlx Offline Mode

This project uses **sqlx offline mode** to allow compilation without a running PostgreSQL database.

### 🔴 BEFORE PUSHING TO GIT/GITLAB:

**YOU MUST UPDATE SQLX METADATA** if you modified any SQL queries:

```bash
# 1. Ensure PostgreSQL is running with the database
docker-compose up -d

# 2. Run migrations (if any)
sqlx migrate run

# 3. Generate metadata
cargo sqlx prepare

# 4. Commit the .sqlx/ directory
git add .sqlx/
git commit -m "chore: update sqlx metadata"
```

### Why?

- The `.sqlx/` directory contains **pre-generated type information** for all SQL queries
- CI/CD can build **without a database connection**
- Compile-time SQL validation is preserved
- **If you forget this step, CI/CD will fail!**

### Building Locally

```bash
# With database (normal development)
cargo build

# Without database (uses offline cache)
SQLX_OFFLINE=true cargo build
```

---

## Configuration

### Environment Variables

#### JWT Configuration

- `JWT_ISSUER` - JWT issuer URL (default: `http://localhost:8080`)
- `JWT_PRIVATE_KEY_PATH` - Path to RSA private key (default: `./keys/private.pem`)
- `JWT_PUBLIC_KEY_PATH` - Path to RSA public key (default: `./keys/public.pem`)
- `JWT_KEY_ID` - Key ID (kid) for JWT header and JWKS (default: `default-key-2025`)
  - Used for key rotation strategy
  - Must be unique for each key pair
  - Included in JWT header and JWKS response
- `ACCESS_TOKEN_EXPIRY_SECONDS` - Access token expiry (default: `3600` = 1 hour)
- `REFRESH_TOKEN_EXPIRY_SECONDS` - Refresh token expiry (default: `2592000` = 30 days)

#### Rate Limiting

The server supports per-endpoint rate limiting with different limits for sensitive endpoints.

- `RATE_LIMIT_REQUESTS_PER_SECOND` - Global rate limit (default: `5`)
- `RATE_LIMIT_BURST_SIZE` - Global burst size (default: `10`)
- `RATE_LIMIT_TOKEN_ENDPOINT_REQUESTS_PER_SECOND` - Rate limit for `/oauth2/token` endpoint (default: `2`)
- `RATE_LIMIT_TOKEN_ENDPOINT_BURST_SIZE` - Burst size for `/oauth2/token` endpoint (default: `5`)

The `/oauth2/token` endpoint has stricter rate limiting by default to prevent brute-force attacks.

#### Other Configuration

- `SERVER_HOST` - Server host (default: `127.0.0.1`)
- `SERVER_PORT` - Server port (default: `8080`)
- `DATABASE_URL` - PostgreSQL connection string
- `ADMIN_ROOT_TOKEN` - Admin API token (optional, for development only)
- `AUTH_ALLOW_USERNAME_LOGIN` - If `false`, interactive login accepts email only (default: `true`)
- `ALLOWED_EMAIL_DOMAINS` - Optional comma-separated whitelist of login email domains (default: empty = allow all)
- `UI_BRAND_NAME` - Company/product name shown on login/reset/error pages (default: `Cloud App`)
- `UI_BRAND_DOMAIN` - Optional domain/tenant hint for login page subtitle (default: empty)
- `UI_THEME` - UI theme preset for auth pages (`blue`, `red`, `white`, `green`, `gold`; default: `blue`)
- `UI_CUSTOM_CSS_PATH` - Optional path to CSS file injected into auth pages at runtime (default: empty)
- `IDP_SECRETS_MASTER_KEY` - Master key for encrypting federated IdP client secrets in DB (`identity_providers.client_secret_encrypted`)

CLI overrides for branding are also available:

- `--ui-brand-name`
- `--ui-brand-domain`
- `--ui-theme`
- `--ui-custom-css-path`

### Federated IdP Secret Encryption

If you use federated login via `identity_providers` (Google/Entra/GitLab OIDC upstream), set:

```bash
IDP_SECRETS_MASTER_KEY=<base64_32B_key>
```

Generate key:

```bash
openssl rand -base64 32
```

Notes:

- New/updated identity provider secrets are stored as:
  `EncSimple[@api=2.0:@box=<base64(nonce||ciphertext||tag)>]`
- Only `EncSimple[...]` format is accepted.
- **Do not rotate `IDP_SECRETS_MASTER_KEY` without re-encrypting existing records**, otherwise decryption fails.

---

## API Endpoints

### Health Check
```
GET /health
```

### Client Credentials (M2M)
```
POST /oauth2/client_credentials/token
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "client_id": "your_client_id",
  "client_secret": "your_client_secret",
  "scope": "api:read api:write"
}
```

### Authorization Code Flow (with HTML Login Form)

#### 1. Authorize (shows HTML login form)
```
GET /oauth2/authorize?response_type=code&client_id=your_client_id&redirect_uri=https://your-app.com/callback&scope=openid%20profile%20email&state=random_state&code_challenge=challenge&code_challenge_method=S256
```

This returns an **HTML login form** where users enter their email or username and password.

#### 2. Login (submitted via HTML form)
```
POST /oauth2/login
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=password123&client_id=your_client_id&redirect_uri=https://your-app.com/callback&code_challenge=challenge&code_challenge_method=S256&state=random_state
```

On success, redirects to:
```
https://your-app.com/callback?code=AUTHORIZATION_CODE&state=random_state
```

### Password Reset (Admin-Initiated)

1. Create reset link (Admin API):
```
POST /admin/users/{id}/password-reset
Authorization: Bearer <ADMIN_TOKEN>
```

Response includes a one-time `reset_url` and `reset_token`.

2. User opens reset page:
```
GET /password/reset?token=RESET_TOKEN
```

3. User submits new password (HTML form):
```
POST /password/reset
Content-Type: application/x-www-form-urlencoded

token=RESET_TOKEN&password=NewPass123&password_confirm=NewPass123
```

## Admin CLI

Build:
```bash
cargo build --bin simple-idm-ctl
```

### Authentication

First, login using OAuth2 (opens browser):
```bash
./target/debug/simple-idm-ctl login --url http://localhost:8080
```

If the same `client_id` exists in multiple tenants, provide tenant hint:
```bash
./target/debug/simple-idm-ctl login --url https://sso.example.com --tenant acme
```

For headless servers, use device flow:
```bash
./target/debug/simple-idm-ctl login --url https://sso.example.com --device --tenant acme
```

The CLI will:
1. Open your browser to the OAuth2 authorization page
2. You login with your credentials (e.g., username: `admin`, password from seed data)
3. After successful login, the session is saved locally
4. All subsequent commands use this session automatically

Session management:
```bash
# Check session status
./target/debug/simple-idm-ctl status

# List all saved sessions
./target/debug/simple-idm-ctl sessions list

# Switch between servers
./target/debug/simple-idm-ctl sessions use production

# Logout (delete session)
./target/debug/simple-idm-ctl logout
```

### Usage Examples

Once logged in, you can use all commands without authentication flags:

```bash
# List users
./target/debug/simple-idm-ctl users list

# Create user
./target/debug/simple-idm-ctl users create \
  --username john --email john@example.com --password 'Secret123!'

# Paging & style
./target/debug/simple-idm-ctl --style sharp users ls --page 1 --limit 10

# Health check
./target/debug/simple-idm-ctl ping

# Output format (JSON)
./target/debug/simple-idm-ctl -o json users list

# TUI (Text UI)
./target/debug/simple-idm-ctl tui
```

Insecure TLS for self-signed certificates:
```bash
./target/debug/simple-idm-ctl --insecure users ls
```

OAuth helpers (for testing OAuth flows):
```bash
./target/debug/simple-idm-ctl oauth authorize-url \
  --client-id webapp --redirect-uri http://localhost:3000/callback

./target/debug/simple-idm-ctl oauth token \
  --client-id webapp --client-secret <SECRET> \
  --code <AUTH_CODE> --redirect-uri http://localhost:3000/callback

./target/debug/simple-idm-ctl oauth userinfo --access-token <ACCESS_TOKEN>
```

**Note:** CLI requires users to be members of the `simple-idm:role:admin` group.

---

## OAuth2 Authentication Proxy

`simple-idm-oauth2-proxy` is an edge authentication proxy that adds OIDC authentication to legacy applications that don't have their own OAuth2/OIDC support.

### Features

- **OIDC Authorization Code Flow + PKCE** - Secure OAuth2 flow
- **Session Management** - In-memory or SQLite persistence
- **Nginx auth_request Integration** - Standard integration with reverse proxy
- **Header Injection** - Pass identity and groups to application
- **Group Claim Support** - Parse groups from JWT (array or string)

### Quick Start

Build the proxy:
```bash
cargo build --release --bin simple-idm-oauth2-proxy
```

Create configuration:
```bash
cp config.example.oauth2-proxy.toml config.oauth2-proxy.toml
# Edit config.oauth2-proxy.toml
```

Run:
```bash
./target/release/simple-idm-oauth2-proxy
```

### Documentation

See detailed documentation in [docs/OAUTH2_PROXY.md](docs/OAUTH2_PROXY.md) including:
- Full configuration options
- Nginx integration example
- Login flow explanation
- Header formats
- Legacy application integration examples

---

#### 3. Token Exchange (exchange code for token)
```
POST /oauth2/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "code": "authorization_code_from_login",
  "redirect_uri": "https://your-app.com/callback",
  "client_id": "your_client_id",
  "client_secret": "your_client_secret",
  "code_verifier": "original_verifier"
}
```

### Device Flow (TV/IoT)

#### 1. Initialize device flow
```
POST /oauth2/device/authorize
Content-Type: application/json

{
  "client_id": "your_client_id",
  "scope": "openid profile"
}

Response:
{
  "device_code": "long_device_code",
  "user_code": "ABCD-1234",
  "verification_uri": "http://localhost:8080/device",
  "verification_uri_complete": "http://localhost:8080/device?user_code=ABCD-1234",
  "expires_in": 600,
  "interval": 5
}
```

#### 2. User verification (on mobile/PC)
```
POST /oauth2/device/verify
Content-Type: application/json

{
  "user_code": "ABCD-1234",
  "username": "user@example.com",
  "password": "password123"
}
```

#### 3. Polling for token (on TV/device)
```
POST /oauth2/device/token
Content-Type: application/json

{
  "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
  "device_code": "long_device_code",
  "client_id": "your_client_id"
}
```

## Database Schema

### Main Tables
- `users` - Users
- `groups` - Groups/roles
- `user_groups` - User membership in groups
- `oauth_clients` - OAuth2 clients (applications)
- `claim_maps` - Custom claim mapping (filtering groups for specific application)
- `authorization_codes` - Temporary authorization codes
- `refresh_tokens` - Refresh tokens
- `device_codes` - Device flow codes

## Custom Claim Mapping

Custom claim mapping allows restricting which groups/permissions are included in the JWT token for a specific application. This is useful for:

1. **Reducing token size** - If you have hundreds of groups but the application needs only a few
2. **Security** - Application sees only relevant permissions
3. **Custom claim names** - You can map groups to custom claim names
4. **Array vs Single values** - Choose whether claim is a single string or array of strings

### Single String Claims

For applications that expect single string values (like Grafana):

```bash
# Map group to single string claim
curl -X POST http://localhost:8080/admin/claim-maps \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "<CLIENT_UUID>",
    "group_id": "<GRAFANA_ADMIN_GROUP_UUID>",
    "claim_name": "grafana_role",
    "claim_value": "Admin"
  }'
```

JWT output:
```json
{
  "sub": "user-id",
  "grafana_role": "Admin",
  "groups": ["grafana:role:Admin"]
}
```

### Array Claims

For applications that expect array of values:

```bash
# Map group to array claim
curl -X POST http://localhost:8080/admin/claim-maps \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "<CLIENT_UUID>",
    "group_id": "<GROUP_UUID>",
    "claim_name": "roles",
    "claim_value": ["developer", "maintainer"]
  }'
```

JWT output:
```json
{
  "sub": "user-id",
  "roles": ["developer", "maintainer"],
  "groups": ["team:backend"]
}
```

### Mixed Claims

If any claim map for a given `claim_name` has `kind='array'`, the output will be an array (merging all values):

```bash
# User has two groups:
# Group A → roles: ["developer"]
# Group B → roles: ["maintainer", "reviewer"]

# JWT will merge and deduplicate:
{
  "roles": ["developer", "maintainer", "reviewer"]
}
```

### Example

User has groups: `admin`, `users`, `billing`, `reports`, `analytics`

For the "Dashboard" application you set claim maps:
- `admin` → `is_admin` (single, value: "true")
- `reports` → `can_view_reports` (single, value: "true")
- `admin` → `roles` (array, value: ["admin", "super-user"])

JWT for this application will contain:
```json
{
  "sub": "user-id",
  "is_admin": "true",
  "can_view_reports": "true",
  "roles": ["admin", "super-user"],
  "groups": ["admin", "reports"]
}
```

## Nested Groups

Groups can contain other groups, creating hierarchical structures. When a user is assigned to a parent group, they automatically inherit membership in all child groups (transitively).

### Example: Team Bundles

Create a "team bundle" that contains multiple application-specific groups:

```bash
# Create groups
simple-idm-ctl groups create --name "gitlab:ns:o2" --description "GitLab namespace O2"
simple-idm-ctl groups create --name "gitlab:role:maintainer" --description "GitLab maintainer role"
simple-idm-ctl groups create --name "team:devops" --description "DevOps team bundle"

# Create nested structure: team:devops contains both groups
simple-idm-ctl groups add-child --parent "team:devops" --child "gitlab:ns:o2"
simple-idm-ctl groups add-child --parent "team:devops" --child "gitlab:role:maintainer"

# Assign user to parent group only
simple-idm-ctl user-groups add --user-id <UUID> --group-id <team:devops_UUID>
```

The user's JWT will automatically include all effective groups:
```json
{
  "groups": ["gitlab:ns:o2", "gitlab:role:maintainer", "team:devops"]
}
```

### CLI Commands

```bash
# Add child group (supports both UUID and name)
simple-idm-ctl groups add-child --parent "team:devops" --child "gitlab:ns:o2"

# Remove child group
simple-idm-ctl groups remove-child --parent "team:devops" --child "gitlab:ns:o2"

# List direct children
simple-idm-ctl groups list-children --parent "team:devops"

# List all transitive children (recursive)
simple-idm-ctl groups list-children --parent "team:devops" --expand
```

### Cycle Detection

The system prevents circular dependencies:
```bash
# This will fail with "cycle_detected" error
simple-idm-ctl groups add-child --parent "A" --child "B"
simple-idm-ctl groups add-child --parent "B" --child "A"
```

### API Endpoints

- `POST /admin/groups/{id}/children` - Add child group
- `GET /admin/groups/{id}/children?expand=true` - List children (direct or transitive)
- `DELETE /admin/groups/{parent_id}/children/{child_id}` - Remove relationship

## Development

### Running Tests
```bash
cargo test
```

### Production Build
```bash
cargo build --release
```

## Group Patterns

Automatically assign groups to users based on wildcard patterns. Useful for managing large numbers of groups systematically.

### How It Works

1. Define patterns for a user (via TUI or API)
2. Background job evaluates patterns every 5 minutes (configurable)
3. Groups matching patterns are automatically assigned/removed

### Pattern Syntax

- `ssh:*` - Matches all groups starting with `ssh:`
- `*:admin` - Matches all groups ending with `:admin`
- `ssh:*:admin` - Matches groups like `ssh:role:admin`, `ssh:principal:admin`
- `exact-match` - Matches only exact group name

### Priority System

Patterns are applied **sequentially** in priority order (lower number = higher priority):

```
Priority 1: ssh:* (include)         → Adds all ssh:* groups
Priority 2: ssh:role:admin (exclude) → Removes ssh:role:admin from result
Priority 10: encjson:* (include)     → Adds all encjson:* groups
```

### Example Usage

#### Via TUI (simple-idm-ctl tui)

1. Navigate to **Users** tab
2. Select user and press **e** (edit)
3. Press **Ctrl+P** to open Patterns Manager
4. Press **n** to create new pattern:
   - Pattern: `ssh:*`
   - Type: Include
   - Priority: 1
5. Press **n** again for exclusion:
   - Pattern: `ssh:role:admin`
   - Type: Exclude
   - Priority: 2

#### Via API

```bash
# Create include pattern
curl -X POST http://localhost:8080/admin/users/{user_id}/group-patterns \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pattern": "ssh:*", "is_include": true, "priority": 1}'

# Create exclude pattern
curl -X POST http://localhost:8080/admin/users/{user_id}/group-patterns \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pattern": "ssh:role:admin", "is_include": false, "priority": 2}'

# List user patterns
curl http://localhost:8080/admin/users/{user_id}/group-patterns \
  -H "Authorization: Bearer $TOKEN"
```

### Configuration

```bash
# .env file
GROUP_PATTERNS_SYNC_INTERVAL_SECONDS=300  # Default: 5 minutes, 0 = disabled

# Optional hard-purge for soft-deleted records
SOFT_DELETE_PURGE_ENABLED=false
SOFT_DELETE_PURGE_INTERVAL_SECONDS=3600
SOFT_DELETE_RETENTION_DAYS=30
```

### TUI Keyboard Shortcuts

- **Ctrl+P** - Open Patterns Manager (in Create/Update User form)
- **n** - New pattern
- **e** - Edit pattern
- **d** - Delete pattern
- **Enter/Esc** - Close manager

## License

AGPLv3 License - see [LICENSE](LICENSE) file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Martin Mareš
