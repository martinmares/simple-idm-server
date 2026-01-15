# Simple IDM Server

A simple OAuth2/OIDC Identity Provider Server written in Rust.

## Features

- **Machine-to-Machine (M2M)** - OAuth2 Client Credentials Grant
- **User-to-Webserver** - OAuth2 Authorization Code Flow with PKCE + HTML Login Form
- **TV/Device Flow** - OAuth2 Device Authorization Grant (RFC 8628) (experimental)
- **Custom Claim Mapping** - Similar to Kanidm, allows filtering groups/claims per application
- **JWT tokens** - RS256 with asymmetric keys
- **Refresh tokens** - For long-term sessions
- **OIDC Discovery** - `/.well-known/openid-configuration`
- **JWKS Endpoint** - `/.well-known/jwks.json`
- **Admin API** - Complete REST API for managing users, groups, clients, and claim maps

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

Usage (flags are required):
```bash
./target/debug/simple-idm-ctl --base-url http://localhost:8080 --token <ADMIN_TOKEN> users list
./target/debug/simple-idm-ctl --base-url http://localhost:8080 --token <ADMIN_TOKEN> users create \
  --username admin --email admin@example.com --password 'Secret123!'
```

Paging & style:
```bash
./target/debug/simple-idm-ctl --base-url http://localhost:8080 --token <ADMIN_TOKEN> \
  --style sharp users ls --page 1 --limit 10
```

Health check:
```bash
./target/debug/simple-idm-ctl --base-url http://localhost:8080 --token <ADMIN_TOKEN> ping
```

Output format:
```bash
./target/debug/simple-idm-ctl --base-url http://localhost:8080 --token <ADMIN_TOKEN> -o json users list
```

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

### Example

User has groups: `admin`, `users`, `billing`, `reports`, `analytics`

For the "Dashboard" application you set claim maps:
- `admin` → `is_admin`
- `reports` → `can_view_reports`

JWT for this application will contain only:
```json
{
  "sub": "user-id",
  "is_admin": true,
  "can_view_reports": true,
  "groups": ["admin", "reports"]
}
```

## Development

### Running Tests
```bash
cargo test
```

### Production Build
```bash
cargo build --release
```
## TODO

- [x] Admin API for managing users, groups and clients
- [x] Web UI for login flow
- [ ] Web UI for device verification
- [x] OIDC Discovery endpoint
- [x] UserInfo endpoint
- [x] Validate redirect_uri and client_id during auth code exchange
- [x] Refresh token rotation + configurable expiry
- [x] JWT audience validation
- [x] Introspection endpoint
- [x] Revocation endpoint
- [x] Admin-initiated password reset flow
- [ ] Publish Docker image
- [ ] Expand integration documentation

### Critical
- [x] Enforce `openid` (and optional `email`/`profile`) scopes on `/oauth2/userinfo`
- [x] Validate `aud` in all access-token protected endpoints (not just userinfo)

### Important
- [ ] Add per-endpoint rate limit tuning (stricter for `/oauth2/token`)
- [ ] Add `kid` support + JWKS key rotation strategy

### Nice to have
- [ ] Web UI for device verification
- [ ] Publish Docker image
- [ ] Expand integration documentation
- [ ] Enrich `user-groups` output with user and group names
- [ ] Enrich `claim-maps` output with client and group names

## License

MIT
