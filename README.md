# Simple IDM Server

A simple OAuth2/OIDC Identity Provider Server written in Rust.

## Features

- **Machine-to-Machine (M2M)** - OAuth2 Client Credentials Grant
- **User-to-Webserver** - OAuth2 Authorization Code Flow with PKCE
- **TV/Device Flow** - OAuth2 Device Authorization Grant (RFC 8628)
- **Custom Claim Mapping** - Similar to Kanidm, allows filtering groups/claims per application
- **JWT tokens** - RS256 with asymmetric keys
- **Refresh tokens** - For long-term sessions

## Requirements

- Rust 1.70+
- PostgreSQL 14+
- OpenSSL (for generating RSA keys)

## Quick Start

### 1. Install Dependencies

```bash
# PostgreSQL
# macOS
brew install postgresql

# Linux (Ubuntu/Debian)
sudo apt-get install postgresql
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

### Authorization Code Flow

#### 1. Authorize (obtaining authorization code)
```
POST /oauth2/authorize
Content-Type: application/json

{
  "response_type": "code",
  "client_id": "your_client_id",
  "redirect_uri": "https://your-app.com/callback",
  "scope": "openid profile email",
  "state": "random_state",
  "code_challenge": "challenge_string",
  "code_challenge_method": "S256"
}
```

#### 2. Login (user login)
```
POST /oauth2/login
Content-Type: application/json

{
  "username": "user@example.com",
  "password": "password123",
  "client_id": "your_client_id",
  "redirect_uri": "https://your-app.com/callback",
  "code_challenge": "challenge_string",
  "code_challenge_method": "S256"
}
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

- [ ] Admin API for managing users, groups and clients
- [ ] Web UI for login flow
- [ ] Web UI for device verification
- [ ] Rate limiting
- [ ] OIDC Discovery endpoint
- [ ] UserInfo endpoint
- [ ] Introspection endpoint
- [ ] Revocation endpoint
- [ ] Docker image
- [ ] Integration documentation

## License

MIT
