# Simple IDM SSH Signer

OpenSSH user certificate signer for Simple IDM. Signs short-lived SSH certificates (e.g., 60 minutes) based on OIDC tokens issued by `simple-idm-server`.

## Quick Start

### 1. Generate CA Key

```bash
# Generate Ed25519 CA key (recommended)
ssh-keygen -t ed25519 -f /etc/simple-idm-ssh-signer/ca_key -C "simple-idm-ssh-ca"

# IMPORTANT: Backup ca_key to air-gapped storage!
# Distribute ca_key.pub to all SSH servers
```

### 2. Configure SSH Servers

On each SSH server, add to `/etc/ssh/sshd_config` (or `/etc/ssh/sshd_config.d/99-simple-idm-ssh-signer.conf`):

```
TrustedUserCAKeys /etc/ssh/simple-idm-ssh-signer.pub
```

Read-write for root only `chmod 600 /etc/ssh/sshd_config.d/99-simple-idm-ssh-signer.conf`

Copy `ca_key.pub` to `/etc/ssh/simple-idm-ssh-signer.pub` on all SSH servers.

Restart ssh (on Ubuntu LTS):
```bash
systemctl restart ssh
```

### 3. Configure Signer

Create `/etc/simple-idm-ssh-signer/config.toml`:

```toml
listen_addr = "127.0.0.1:9222"

# OIDC Provider
oidc_issuer = "http://localhost:8080"
expected_audience = "simple-idm-ssh-login"
allowed_algs = ["RS256"]

# CA keys
ca_private_key_path = "/etc/simple-idm-ssh-signer/ca_key"

# Certificate policy
default_ttl_seconds = 3600       # 1 hour
max_ttl_seconds = 28800          # 8 hours
clock_skew_seconds = 30

# Principal limits
max_principals = 32
principal_max_len = 64

# Extensions
permit_port_forwarding = true
permit_agent_forwarding = true
permit_x11_forwarding = false
permit_user_rc = false
```

### 4. Create OAuth Client in Simple IDM

```bash
simple-idm-ctl oauth-clients create \
  --client-id "simple-idm-ssh-login" \
  --name "SSH Login CLI" \
  --grant-types "authorization_code" "urn:ietf:params:oauth:grant-type:device_code" \
  --redirect-uris "http://127.0.0.1:*/callback" \
  --scope "openid profile email groups" \
  --public
```

### 5. Create SSH Groups in Simple IDM

Create groups with SSH namespace prefixes:

```bash
# Direct principal mapping
simple-idm-ctl groups create --name "ssh:principal:alice"
simple-idm-ctl groups create --name "ssh:principal:bob"

# Role mapping
simple-idm-ctl groups create --name "ssh:role:devops"
simple-idm-ctl groups create --name "ssh:role:admin"

# Assign to users
simple-idm-ctl user-groups add --username alice --group "ssh:principal:alice"
simple-idm-ctl user-groups add --username bob --group "ssh:principal:bob"
simple-idm-ctl user-groups add --username alice --group "ssh:role:devops"
```

### 6. Start Signer

```bash
SSH_SIGNER_CONFIG=/etc/simple-idm-ssh-signer/config.toml \
  simple-idm-ssh-signer
```

## API Reference

### POST /ssh/sign

Sign an SSH certificate.

**Request:**
```bash
curl -X POST http://localhost:9222/ssh/sign \
  -H "Authorization: Bearer <id_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host",
    "ttl_seconds": 3600
  }'
```

**Response:**
```json
{
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAAHHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAA....",
  "valid_after": 1730000000,
  "valid_before": 1730003600,
  "principals": ["alice", "role:devops"]
}
```

**Status Codes:**
- `200` - Success
- `400` - Invalid request (bad public key, invalid TTL)
- `401` - Missing or invalid token
- `403` - Token valid but no principals available
- `500` - Server error

### GET /healthz

Health check endpoint.

**Response:** `200 OK`

## Principal Mapping

### Rules

1. **Explicit principals**: `ssh:principal:<name>` → `<name>`
2. **Role principals**: `ssh:role:<role>` → `role:<role>`
3. **Fallback** (if no `ssh:*` groups):
   - `preferred_username` (if present)
   - OR `email` username part (before `@`)
   - OR `sub` (JWT subject)

### Examples

**User with explicit groups:**
```json
{
  "sub": "uuid-123",
  "preferred_username": "alice",
  "groups": ["ssh:principal:alice", "ssh:role:devops", "team:platform"]
}
```
→ Principals: `["alice", "role:devops"]`

**User without SSH groups:**
```json
{
  "sub": "uuid-456",
  "preferred_username": "bob",
  "groups": ["team:engineering"]
}
```
→ Principals: `["bob"]` (fallback)

**User with only email:**
```json
{
  "sub": "uuid-789",
  "email": "charlie@example.com",
  "groups": []
}
```
→ Principals: `["charlie"]` (email fallback)

## Security Notes

### CA Key Protection

- ⚠️ **CRITICAL**: CA private key compromise = pwned all SSH servers!
- Store CA key with `chmod 400`, owner `signer:signer`
- Backup CA key to air-gapped storage
- Consider HSM for production (YubiHSM, AWS CloudHSM)

### Break-Glass

If CA key is compromised:
1. Generate new CA key
2. Distribute new `ca_key.pub` to all SSH servers
3. Update `TrustedUserCAKeys` on all servers
4. Restart sshd on all servers
5. All existing certificates immediately invalidated

### Auditing

All certificate signing events are logged:
```
Certificate signed: sub=uuid-123, principals=["alice", "role:devops"], ttl=3600s
```

Use `RUST_LOG=simple_idm_ssh_signer=info` for audit logging.

### Rate Limiting

TODO: Add rate limiting to prevent DoS on signing endpoint.

## Environment Variables

Override config via env vars:

- `SSH_SIGNER_CONFIG` - Path to config.toml
- `LISTEN_ADDR` - Override listen address
- `OIDC_ISSUER` - Override OIDC issuer
- `EXPECTED_AUDIENCE` - Override expected audience
- `RUST_LOG` - Logging level (e.g., `simple_idm_ssh_signer=debug`)

## Development

### Build

```bash
cargo build --release --bin simple-idm-ssh-signer
```

### Run Tests

```bash
cargo test --lib ssh_signer
```

### Test Manual Signing

```bash
# Generate test key
ssh-keygen -t ed25519 -f /tmp/test_key -N ""

# Get token from simple-idm-server (device flow or browser)
TOKEN="eyJhbG..."

# Sign certificate
curl -X POST http://localhost:9222/ssh/sign \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"public_key\": \"$(cat /tmp/test_key.pub)\"}" | jq -r '.certificate' > /tmp/test_key-cert.pub

# Inspect certificate
ssh-keygen -L -f /tmp/test_key-cert.pub
```

## Troubleshooting

### "CA private key not found"

Ensure `ca_private_key_path` points to valid SSH private key:
```bash
ls -la /etc/simple-idm-ssh-signer/ca_key
ssh-keygen -l -f /etc/simple-idm-ssh-signer/ca_key
```

### "JWT validation failed"

Check:
1. OIDC issuer is correct: `curl http://localhost:8080/.well-known/openid-configuration`
2. Token audience matches `expected_audience`
3. Token not expired
4. JWKS reachable

### "No principals available"

User has no `ssh:principal:*` or `ssh:role:*` groups and fallback failed.

Check user groups:
```bash
simple-idm-ctl user-groups list --username alice
```

### "ssh-keygen failed"

Ensure `ssh-keygen` is installed:
```bash
which ssh-keygen
ssh-keygen -V
```

## License

Same as Simple IDM Server.
