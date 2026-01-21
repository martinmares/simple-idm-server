# OAuth2 Device Authorization Flow

OAuth2 Device Flow (RFC 8628) umožňuje autorizaci zařízení s omezeným vstupem (smart TV, CLI nástroje, IoT zařízení) pomocí sekundárního zařízení (telefon, počítač).

## Přehled Flow

```
┌─────────┐                                    ┌─────────┐
│ Device  │                                    │  User   │
│ (CLI)   │                                    │ Browser │
└────┬────┘                                    └────┬────┘
     │                                               │
     │  1. POST /oauth2/device/authorize            │
     ├──────────────────────────────────►           │
     │                                   │           │
     │  ◄─────────────────────────────── │           │
     │  device_code, user_code,          │           │
     │  verification_uri                 │           │
     │                                   │           │
     │  2. Zobraz user_code              │           │
     │     "Visit http://localhost:8080/device"     │
     │     "Enter code: ABCD-1234"       │           │
     │                                   │           │
     │                                   │  3. Přistup na /device
     │                                   │  ◄────────┤
     │                                   │           │
     │                                   │  4. Zadá user_code + credentials
     │                                   │  ──────────►
     │                                   │           │
     │  5. Polling /oauth2/device/token  │           │
     │  (každých 5s)                     │           │
     ├──────────────────────────────────►│           │
     │  ◄─────────────────────────────── │           │
     │  authorization_pending            │           │
     │                                   │           │
     ├──────────────────────────────────►│           │
     │  ◄─────────────────────────────── │           │
     │  access_token ✓                   │           │
     │                                   │           │
```

## Použití

### 1. Inicializace Device Flow (CLI/Device)

Klient (např. CLI nástroj) zavolá `/oauth2/device/authorize`:

**Request:**
```bash
curl -X POST http://localhost:8080/oauth2/device/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "cli-client",
    "scope": "openid profile email"
  }'
```

**Response:**
```json
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "ABCD-1234",
  "verification_uri": "http://localhost:8080/device",
  "verification_uri_complete": "http://localhost:8080/device?user_code=ABCD-1234",
  "expires_in": 600,
  "interval": 5
}
```

Klient zobrazí uživateli:
```
To sign in, use a web browser to open the page:
  http://localhost:8080/device

And enter the code: ABCD-1234

Waiting for authorization...
```

### 2. Autorizace (User Browser)

Uživatel navštíví URL na svém telefonu/počítači:
- **GET** `http://localhost:8080/device` - zobrazí formulář
- **GET** `http://localhost:8080/device?user_code=ABCD-1234` - předvyplní kód

Zadá:
1. **User code** - `ABCD-1234`
2. **Username** - `john.doe` nebo `john@example.com`
3. **Password** - heslo uživatele

**Submit formuláře:**
```http
POST /device
Content-Type: application/x-www-form-urlencoded

user_code=ABCD-1234&username=john.doe&password=secret123
```

**Response (úspěch):**
HTML stránka s hláškou:
```
✓ Device authorized successfully! You can now return to your device.
```

**Response (chyba):**
HTML formulář s chybovou hláškou:
- "Invalid user code"
- "User code expired"
- "Invalid credentials"
- "Device already authorized"

### 3. Polling pro Token (CLI/Device)

Klient polluje `/oauth2/device/token` každých 5 sekund (hodnota `interval` z kroku 1):

**Request:**
```bash
curl -X POST http://localhost:8080/oauth2/device/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
    "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
    "client_id": "cli-client"
  }'
```

**Response (pending):**
```json
{
  "error": "authorization_pending",
  "error_description": "User has not authorized the device yet"
}
```

Klient čeká `interval` sekund a zkusí znovu.

**Response (úspěch):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
```

**Response (timeout):**
```json
{
  "error": "expired_token",
  "error_description": "Device code expired"
}
```

## Konfigurace OAuth2 Klienta

Pro device flow musí klient mít grant type `urn:ietf:params:oauth:grant-type:device_code`:

```bash
simple-idm-ctl oauth-clients create \
  --client-id cli-client \
  --name "CLI Tool" \
  --grant-types "urn:ietf:params:oauth:grant-type:device_code" \
  --scope "openid profile email" \
  --public
```

Nebo přes Admin API:
```bash
curl -X POST http://localhost:8080/admin/oauth-clients \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "cli-client",
    "name": "CLI Tool",
    "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
    "scope": "openid profile email",
    "is_public": true
  }'
```

## Příklad CLI Klienta (Python)

```python
import requests
import time
import sys

ISSUER = "http://localhost:8080"
CLIENT_ID = "cli-client"

def device_flow():
    # 1. Iniciace device flow
    resp = requests.post(f"{ISSUER}/oauth2/device/authorize", json={
        "client_id": CLIENT_ID,
        "scope": "openid profile email"
    })
    data = resp.json()

    device_code = data["device_code"]
    user_code = data["user_code"]
    verification_uri = data["verification_uri"]
    interval = data["interval"]

    print(f"To sign in, use a web browser to open the page:")
    print(f"  {verification_uri}")
    print(f"\nAnd enter the code: {user_code}")
    print(f"\nWaiting for authorization...")

    # 2. Polling pro token
    while True:
        time.sleep(interval)

        resp = requests.post(f"{ISSUER}/oauth2/device/token", json={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": CLIENT_ID
        })

        if resp.status_code == 200:
            token_data = resp.json()
            access_token = token_data["access_token"]
            print(f"\n✓ Authorization successful!")
            print(f"Access token: {access_token[:50]}...")
            return access_token

        error = resp.json()
        if error["error"] == "authorization_pending":
            sys.stdout.write(".")
            sys.stdout.flush()
        elif error["error"] == "expired_token":
            print(f"\n✗ Device code expired")
            sys.exit(1)
        else:
            print(f"\n✗ Error: {error['error_description']}")
            sys.exit(1)

if __name__ == "__main__":
    device_flow()
```

## Příklad CLI Klienta (Bash)

```bash
#!/bin/bash

ISSUER="http://localhost:8080"
CLIENT_ID="cli-client"

# 1. Iniciace device flow
response=$(curl -s -X POST "$ISSUER/oauth2/device/authorize" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\":\"$CLIENT_ID\",\"scope\":\"openid profile email\"}")

device_code=$(echo "$response" | jq -r '.device_code')
user_code=$(echo "$response" | jq -r '.user_code')
verification_uri=$(echo "$response" | jq -r '.verification_uri')
interval=$(echo "$response" | jq -r '.interval')

echo "To sign in, use a web browser to open the page:"
echo "  $verification_uri"
echo ""
echo "And enter the code: $user_code"
echo ""
echo "Waiting for authorization..."

# 2. Polling pro token
while true; do
  sleep "$interval"

  response=$(curl -s -X POST "$ISSUER/oauth2/device/token" \
    -H "Content-Type: application/json" \
    -d "{\"grant_type\":\"urn:ietf:params:oauth:grant-type:device_code\",\"device_code\":\"$device_code\",\"client_id\":\"$CLIENT_ID\"}")

  error=$(echo "$response" | jq -r '.error // empty')

  if [ -z "$error" ]; then
    access_token=$(echo "$response" | jq -r '.access_token')
    echo ""
    echo "✓ Authorization successful!"
    echo "Access token: ${access_token:0:50}..."
    exit 0
  elif [ "$error" = "authorization_pending" ]; then
    echo -n "."
  elif [ "$error" = "expired_token" ]; then
    echo ""
    echo "✗ Device code expired"
    exit 1
  else
    error_description=$(echo "$response" | jq -r '.error_description')
    echo ""
    echo "✗ Error: $error_description"
    exit 1
  fi
done
```

## Endpointy

### POST /oauth2/device/authorize

Iniciace device flow.

**Request:**
```json
{
  "client_id": "cli-client",
  "scope": "openid profile email"
}
```

**Response:**
```json
{
  "device_code": "...",
  "user_code": "ABCD-1234",
  "verification_uri": "http://localhost:8080/device",
  "verification_uri_complete": "http://localhost:8080/device?user_code=ABCD-1234",
  "expires_in": 600,
  "interval": 5
}
```

### GET /device?user_code=XXXX-XXXX

Zobrazí HTML formulář pro zadání user_code a credentials.

**Query params:**
- `user_code` (optional) - předvyplní user code

**Response:** HTML stránka

### POST /device

Ověří user_code a credentials, autorizuje device.

**Form data:**
- `user_code` - kód z device (XXXX-XXXX)
- `username` - username nebo email
- `password` - heslo

**Response:** HTML stránka s výsledkem (úspěch/chyba)

### POST /oauth2/device/token

Polling endpoint pro získání tokenu.

**Request:**
```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
  "device_code": "...",
  "client_id": "cli-client"
}
```

**Response (pending):**
```json
{
  "error": "authorization_pending",
  "error_description": "User has not authorized the device yet"
}
```

**Response (success):**
```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
```

## Konfigurace

### User Code Formát

- **Formát:** `XXXX-XXXX` (8 znaků, uppercase A-Z a 0-9)
- **Příklady:** `A1B2-C3D4`, `1234-ABCD`, `QWER-5678`

### Timeout a Interval

- **Expiration:** 600 sekund (10 minut)
- **Polling interval:** 5 sekund

Tyto hodnoty jsou zatím hardcoded v `src/oauth2/device_flow.rs`:
```rust
let expires_at = Utc::now() + Duration::minutes(10);
// ...
expires_in: 600,
interval: 5,
```

Pro customizaci přidejte do `.env`:
```env
DEVICE_CODE_EXPIRY_SECONDS=600
DEVICE_CODE_POLLING_INTERVAL_SECONDS=5
```

## Security Considerations

### User Code

- Generován pomocí kryptograficky bezpečného RNG (`rand::rng()`)
- Formát `XXXX-XXXX` poskytuje 36^8 kombinací (2.8 trillion)
- Expiruje po 10 minutách
- Lze použít pouze jednou

### Device Code

- 64 znaků, alfanumerické
- Stored hashed v databázi? (TODO: implementovat hashing)
- Expiruje po 10 minutách
- Smazán po použití

### Rate Limiting

Device flow endpointy jsou chráněny globálním rate limiterem:
- Default: 10 requests/second
- Burst: 50 requests

Pro přísnější limity upravte `.env`:
```env
RATE_LIMIT_REQUESTS_PER_SECOND=10
RATE_LIMIT_BURST_SIZE=50
```

### Brute Force Protection

**TODO:** Implementovat:
- Max attempts na user_code (např. 5 pokusů)
- Lockout po překročení limitů
- CAPTCHA po opakovaných chybách

## Troubleshooting

### "Invalid user code"

- Zkontrolujte, že jste zadali správný formát `XXXX-XXXX`
- User code case-sensitive? (zatím ne, převádí se na uppercase)
- User code může být expirated (10 minut)

### "User code expired"

Device code expiruje po 10 minutách. Začněte flow znovu.

### "Device already authorized"

Tento user_code už byl použit. Každý user_code lze použít pouze jednou.

### Polling nikdy nedostane token

- Zkontrolujte, že uživatel skutečně autorizoval device na `/device`
- Zkontrolujte polling interval (měl by být >= `interval` z response)
- Zkontrolujte database logs: `docker logs simple-idm-db`

### CORS chyby na `/device`

Device verification page (`/device`) je HTML formulář, takže CORS není problém. Pokud implementujete vlastní SPA frontend, přidejte CORS middleware.

## Database Schema

Device codes jsou uloženy v tabulce `device_codes`:

```sql
CREATE TABLE device_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_code TEXT NOT NULL UNIQUE,
    user_code TEXT NOT NULL UNIQUE,
    client_id INTEGER NOT NULL,
    scope TEXT NOT NULL,
    is_authorized BOOLEAN NOT NULL DEFAULT FALSE,
    user_id INTEGER,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_device_codes_device_code ON device_codes(device_code);
CREATE INDEX idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX idx_device_codes_expires_at ON device_codes(expires_at);
```

## Roadmap

- [ ] Device code hashing v databázi
- [ ] Konfigurovatelný timeout a polling interval
- [ ] Brute force protection (max attempts)
- [ ] Rate limiting specifický pro device flow
- [ ] CAPTCHA po opakovaných chybách
- [ ] Admin UI pro správu pending device codes
- [ ] Metrics (počet device flow, success rate, atd.)
- [ ] Cleanup job pro expirované device codes

## Reference

- [RFC 8628: OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [OAuth 2.0 Device Flow - Best Practices](https://oauth.net/2/device-flow/)
