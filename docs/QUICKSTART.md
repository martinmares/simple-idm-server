# Quick Start Guide

This guide will walk you through complete setup and testing of simple-idm-server.

## Step 1: Run PostgreSQL

Use Docker Compose:

```bash
docker-compose up -d
```

Or install PostgreSQL locally and create a database:

```bash
createdb simple_idm
```

## Step 2: Generate JWT Keys

```bash
./scripts/generate_keys.sh
```

This will create RSA keys in the `./keys/` directory.

## Step 3: Configuration

Copy and edit the `.env` file:

```bash
cp .env.example .env
```

Basic settings in `.env`:
```
DATABASE_URL=postgres://postgres:postgres@localhost/simple_idm
JWT_ISSUER=http://localhost:8080
```

## Step 4: Run Server

```bash
cargo run
```

The server will run on `http://localhost:8080`.

Migrations will run automatically on startup.

## Step 5: Initialize Test Data

In another terminal:

```bash
psql -U postgres -d simple_idm -f scripts/init_test_data.sql
```

This will create:
- 3 test users (admin, user1, user2)
- 5 groups
- 3 OAuth2 clients

**Password for all users:** `password123`
**Client secret for all clients:** `client_secret_123`

## Testing Flows

### Test 1: Machine-to-Machine (Client Credentials)

```bash
curl -X POST http://localhost:8080/oauth2/client_credentials/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "api_service",
    "client_secret": "client_secret_123",
    "scope": "api:read api:write"
  }'
```

Expected response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api:read api:write"
}
```

### Test 2: User Login Flow (Authorization Code)

#### 2.1 Initiate authorize

```bash
curl "http://localhost:8080/oauth2/authorize?response_type=code&client_id=webapp_dashboard&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email"
```

This returns an HTML login page.

#### 2.2 User login

```bash
curl -X POST http://localhost:8080/oauth2/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=password123&client_id=webapp_dashboard&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email"
```

Response is a redirect to the `redirect_uri` with `code` (and optional `state`) in the query string.

#### 2.3 Exchange code for token

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "abc123...",
    "redirect_uri": "http://localhost:3000/callback",
    "client_id": "webapp_dashboard",
    "client_secret": "client_secret_123"
  }'
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "xyz789...",
  "scope": "openid profile email"
}
```

**NOTE:** JWT contains custom claims! For `admin` user and `webapp_dashboard` client:
```json
{
  "sub": "user-id",
  "email": "admin@example.com",
  "groups": ["admin", "users", "reports", "billing", "analytics"],
  "is_admin": true,
  "can_view_reports": true
}
```

Notice the `is_admin` and `can_view_reports` - these are custom claims from claim maps!

### Test 3: Device Flow (TV)

**Note:** Device flow endpoints are implemented but considered experimental (work in progress).

#### 3.1 Initialize device flow (on TV)

```bash
curl -X POST http://localhost:8080/oauth2/device/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "smart_tv_app",
    "scope": "openid profile"
  }'
```

Response:
```json
{
  "device_code": "long_device_code_xyz",
  "user_code": "ABCD-1234",
  "verification_uri": "http://localhost:8080/device",
  "verification_uri_complete": "http://localhost:8080/device?user_code=ABCD-1234",
  "expires_in": 600,
  "interval": 5
}
```

TV displays: "Go to http://localhost:8080/device and enter code: **ABCD-1234**"

#### 3.2 User verifies on mobile/PC

```bash
curl -X POST http://localhost:8080/oauth2/device/verify \
  -H "Content-Type: application/json" \
  -d '{
    "user_code": "ABCD-1234",
    "username": "admin",
    "password": "password123"
  }'
```

Response:
```json
{
  "success": true,
  "message": "Device authorized successfully"
}
```

#### 3.3 TV polls for token

```bash
curl -X POST http://localhost:8080/oauth2/device/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
    "device_code": "long_device_code_xyz",
    "client_id": "smart_tv_app"
  }'
```

Before authorization returns:
```json
{
  "error": "authorization_pending",
  "error_description": "User has not authorized the device yet"
}
```

After authorization returns:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile"
}
```

## Decoding JWT

Copy the `access_token` and paste it at https://jwt.io

You will see the payload with custom claims:

```json
{
  "sub": "00000000-0000-0000-0000-000000000001",
  "iss": "http://localhost:8080",
  "aud": ["webapp_dashboard"],
  "exp": 1234567890,
  "iat": 1234567890,
  "email": "admin@example.com",
  "groups": ["admin", "users", "reports", "billing", "analytics"],
  "is_admin": true,
  "can_view_reports": true
}
```

## Custom Claim Mapping

Claim mapping filters groups by application. For example:

- **admin** user has 5 groups: admin, users, reports, billing, analytics
- **webapp_dashboard** has claim maps only for: admin → is_admin, reports → can_view_reports
- JWT for webapp_dashboard contains only these 2 custom claims (+ all groups in the `groups` array)

This saves token size and increases security.

## Health Check

```bash
curl http://localhost:8080/health
```

Response: `OK`

## Next Steps

- Add your own users and groups
- Create your own OAuth2 clients
- Configure claim maps for your applications
- Integrate with your services

## Troubleshooting

### Database Errors

```bash
# Restart PostgreSQL
docker-compose restart postgres

# Check logs
docker-compose logs postgres
```

### Key Errors

```bash
# Regenerate keys
rm -rf keys/
./scripts/generate_keys.sh
```

### Port Already in Use

Change `SERVER_PORT` in the `.env` file.
