# M2M (Machine-to-Machine) OAuth2 Client Credentials Flow Tests

Comprehensive integration tests for Machine-to-Machine (M2M) OAuth2 Client Credentials flow implementation in `simple-idm-server`.

## Overview

The file `tests/m2m_tests.rs` contains a complete integration test that:

1. **Starts Docker environment** - Calls `docker-compose up -d` to start PostgreSQL
2. **Waits for PostgreSQL** - Verifies database readiness using health check
3. **Set up database** - Runs migrations and seed script (`scripts/init_test_data.sql`)
4. **Build application** - Runs `cargo build`
5. **Start server** - Starts the application server in the background
6. **Wait for server** - Verifies server health check (`/health`)
7. **Run tests** - Performs 4 key M2M test scenarios
8. **Cleanup** - Stops server and Docker (always, even on failure)

## Requirements

- Docker and docker-compose
- Rust and cargo
- Access to port 5432 (PostgreSQL)
- Access to port 8080 (application server)

## Running Tests

### ⚠️ Important: sqlx Offline Mode

These tests will **automatically start a database**, but the initial compilation uses sqlx offline mode.

```bash
# Run all M2M tests (recommended - uses offline mode for faster compilation)
SQLX_OFFLINE=true cargo test --test m2m_tests

# Run with output (see println!)
SQLX_OFFLINE=true cargo test --test m2m_tests -- --nocapture

# Run with debug logging
SQLX_OFFLINE=true RUST_LOG=debug cargo test --test m2m_tests -- --nocapture

# Alternative: Without offline mode (requires database during compilation)
# This will work but is slower and requires postgres to be already running
cargo test --test m2m_tests
```

**Why SQLX_OFFLINE=true?**
- Faster compilation (no database connection during build)
- Tests will start their own database automatically
- Matches CI/CD behavior

## Test Scenarios

### Test 1: Successful access token acquisition ✅

**What it tests:** Standard happy path - client with valid credentials.

**Details:**
- Client ID: `api_service`
- Client Secret: `client_secret_123`
- Grant Type: `client_credentials`

**Expected result:**
- HTTP 200 OK
- Response contains:
  - `access_token` (JWT)
  - `token_type` = "Bearer"
  - `expires_in` (in seconds)
  - `scope` (returned scope)

**Test calls:**
```bash
POST /oauth2/client_credentials/token
{
  "grant_type": "client_credentials",
  "client_id": "api_service",
  "client_secret": "client_secret_123",
  "scope": "api:read api:write"
}
```

### Test 2: Failure with incorrect client_secret ❌

**What it tests:** Server correctly rejects incorrect credentials.

**Details:**
- Correct Client ID: `api_service`
- Wrong Secret: `wrong_secret` (instead of `client_secret_123`)

**Expected result:**
- HTTP 401 Unauthorized
- Error response:
  ```json
  {
    "error": "invalid_client",
    "error_description": "Invalid client credentials"
  }
  ```

### Test 3: Failure with unknown client_id ❌

**What it tests:** Server correctly rejects non-existent client.

**Details:**
- Non-existent Client ID: `nonexistent_client`
- Any secret

**Expected result:**
- HTTP 401 Unauthorized
- Error response:
  ```json
  {
    "error": "invalid_client",
    "error_description": "Client not found or inactive"
  }
  ```

### Test 4: Verify token format and claims ✅

**What it tests:** The returned JWT token has the correct format and contains all necessary claims.

**Verifies:**
- Token is valid JWT (3 parts separated by dots)
- Payload (part 2) is valid base64 and JSON
- Contains all required claims:
  - `sub` (subject - client ID)
  - `iss` (issuer - "http://localhost:8080")
  - `aud` (audience - array containing client ID)
  - `exp` (expiration - in the future)
  - `iat` (issued at - in the past)
- Token is not yet expired

## Test Data

Data is set up in `scripts/init_test_data.sql`:

### OAuth Clients (Relevant for M2M):
```sql
-- M2M client (client_credentials flow)
('20000000-0000-0000-0000-000000000001', 'api_service',
 '[argon2 hash]', 'API Service M2M',
 ARRAY[]::text[], -- no redirect URIs
 ARRAY['client_credentials'], -- supports ONLY client_credentials
 'api:read api:write', true)
```

### Test Client Credentials:
- **client_id:** `api_service`
- **client_secret:** `client_secret_123` (unhashed - plaintext for testing)
- **Hash:** `$argon2id$v=19$m=65536,t=3,p=4$+t1hwSa3uKlBfxgUbjpi2g$OQu5+EbwAmcVfV2DI8Eodi8gUgPb1pRSzT8T3PMPsjk`
- **Scopes:** `api:read api:write`

## Lifecycle Management

Test automatically manages complete lifecycle:

### Setup phase:
1. `start_docker()` - runs `docker-compose up -d`
2. `wait_for_postgres()` - waits up to 30s for healthy PostgreSQL
3. `setup_database()` - runs migrations and seed data
4. `build_app()` - `cargo build`
5. `start_server()` - starts application in background
6. `wait_for_server()` - waits up to 60s for `/health` endpoint

### Test phase:
- Performs 4 test scenarios
- Each test is independent

### Cleanup phase (guaranteed always):
- Stops server process
- `docker-compose down` - stops and removes containers

## Important Notes

### Ports
- **5432** - PostgreSQL (from docker-compose.yml)
- **8080** - Application server (from config)
- Ensure these ports are available!

### Database URL
Application expects:
```
DATABASE_URL=postgres://postgres:postgres@localhost:5432/simple_idm
```

### JWT Keys
Server expects:
- `./keys/private.pem` - Private RSA key
- `./keys/public.pem` - Public RSA key

Verify they exist. If not, create them:
```bash
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

### Performance
- Tests are slow (server startup takes ~10-15s)
- This is normal for integration tests
- They are designed to verify end-to-end functionality

## Troubleshooting

### "Failed to start Docker"
```bash
# Verify docker-compose.yml
docker-compose -f docker-compose.yml config

# Run manually
docker-compose -f docker-compose.yml up -d
```

### "PostgreSQL failed to start"
```bash
# Verify container
docker ps
docker logs simple-idm-postgres

# Clean up and try again
docker-compose -f docker-compose.yml down -v
docker-compose -f docker-compose.yml up -d
```

### "Server failed to start"
```bash
# Check ports
lsof -i :8080
lsof -i :5432

# Run server manually with debug log
RUST_LOG=debug cargo run
```

### "Health check timeout"
- Server takes longer to startup
- Increase `max_attempts` in `wait_for_server()` in `tests/m2m_tests.rs`

## Code Structure

Test is structured in the following phases:

```rust
struct TestEnvironment {
    server_process: Option<Child>, // Running server process
}

impl TestEnvironment {
    // Setup methods
    async fn start_docker() { ... }
    async fn wait_for_postgres() { ... }
    async fn setup_database() { ... }
    async fn build_app() { ... }
    async fn start_server() { ... }
    async fn wait_for_server() { ... }

    // Cleanup
    async fn cleanup() { ... }
}

// Test entry point
#[tokio::test]
async fn test_m2m_full_integration() { ... }

// Individual test functions
async fn test_successful_token_acquisition() { ... }
async fn test_invalid_client_secret() { ... }
async fn test_nonexistent_client() { ... }
async fn test_token_format_and_claims() { ... }
```

## Dependencies

Tests require the following dev-dependencies (present in Cargo.toml):
- `reqwest` - HTTP client
- `tokio` - Async runtime
- `serde_json` - JSON parsing
- `chrono` - Time handling (for expiration checks)

## Contributing

To add more M2M flow tests:

1. Add a new test to the `run_m2m_tests()` function
2. Create a new test scenario as `async fn test_xxx()`
3. Make sure you return failure/success data
4. Add appropriate assertions

Example new test:
```rust
async fn test_expired_token() {
    println!("Test: Token expiration");
    let client = Client::new();

    // ... make request ...

    // Verify token is expired
    assert!(exp < now, "Token should be expired");

    println!("✅ Test PASSED: Token expiration works\n");
}
```

## Future Extensions

Tests can be extended with:
- ❌ Failure when client is not active (`is_active = false`)
- ❌ Failure when client does not have grant_type "client_credentials"
- ✅ Refresh token handling (if implemented)
- Token introspection
- Token revocation
- Scope validation
- Rate limiting
- Multiple concurrent requests

## Token Information

The returned JWT token contains these claims:

```json
{
  "sub": "20000000-0000-0000-0000-000000000001",  // Client UUID
  "iss": "http://localhost:8080",                  // Issuer
  "aud": ["api_service"],                          // Audience (client_id)
  "exp": 1704067200,                               // Expiration (now + 3600s)
  "iat": 1704063600,                               // Issued at
  "groups": []                                     // Empty for M2M
  // No email for M2M flow
}
```

## Implementation Details

### Client Credentials Handler
Located in `src/oauth2/client_credentials.rs`:

```rust
pub async fn handle_client_credentials(
    State(state): State<Arc<OAuth2State>>,
    Json(req): Json<ClientCredentialsRequest>,
) -> impl IntoResponse
```

Checks:
1. `grant_type == "client_credentials"` ✓
2. Client exists and `is_active == true` ✓
3. `client_secret` hash matches ✓
4. Client supports grant type ✓
5. Create JWT token (no custom claims for M2M) ✓

### Security Features
- Password hashing (argon2)
- JWT with RS256 (RSA)
- Client authentication
- Token expiration
- Scope-based authorization

---

**Updated:** 2026-01-14
**Version:** 1.0
