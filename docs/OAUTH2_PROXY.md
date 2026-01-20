# OAuth2 Authentication Proxy

`simple-idm-oauth2-proxy` je edge authentication proxy, který přidává OIDC autentizaci k legacy aplikacím, které nemají vlastní OAuth2/OIDC podporu.

## Funkce

- **OIDC Authorization Code Flow + PKCE** - Bezpečný OAuth2 flow
- **Session Management** - In-memory nebo SQLite persistence
- **Nginx auth_request Integration** - Standardní integrace s reverse proxy
- **Header Injection** - Předání identity a groups do aplikace
- **Group Claim Support** - Parse groups z JWT (array nebo string)
- **Konfigurovatelné Username Claims** - Zkusí `preferred_username`, `email`, `sub` v pořadí

## Architektura

```
User → Nginx (auth_request) → OAuth2 Proxy → Simple IDM (OIDC Provider)
                ↓
          Legacy App (dostane X-Auth-User, X-Auth-Groups headers)
```

## Instalace

### Build

```bash
cargo build --release --bin simple-idm-oauth2-proxy
```

Binary: `target/release/simple-idm-oauth2-proxy`

### Konfigurace

Zkopírujte example config:

```bash
cp config.example.oauth2-proxy.toml config.oauth2-proxy.toml
```

Upravte hodnoty:

```toml
listen_addr = "127.0.0.1:4180"
public_base_url = "https://auth.example.com"
cookie_secret = "CHANGE-ME"  # openssl rand -base64 32
session_max_age = 3600

oidc_issuer = "http://localhost:8080"
client_id = "example-app"
client_secret = "your-secret"
```

### OAuth2 Client v Simple IDM

Vytvořte OAuth2 klienta v Simple IDM:

```bash
simple-idm-ctl oauth-clients create \
    --client-id example-app \
    --name "Example Application" \
    --redirect-uri "https://auth.example.com/callback" \
    --grant-types authorization_code refresh_token \
    --scope "openid profile email"
```

Uložte vygenerovaný `client_secret` do `config.oauth2-proxy.toml`.

## Nginx Konfigurace

```nginx
server {
    listen 443 ssl;
    server_name app.example.com;

    # SSL certificates
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    # Main application
    location / {
        # Auth check
        auth_request /auth;
        auth_request_set $auth_user $upstream_http_x_auth_user;
        auth_request_set $auth_email $upstream_http_x_auth_email;
        auth_request_set $auth_groups $upstream_http_x_auth_groups;

        # Pass headers to backend
        proxy_set_header X-Auth-User $auth_user;
        proxy_set_header X-Auth-Email $auth_email;
        proxy_set_header X-Auth-Groups $auth_groups;

        # Backend application
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Auth subrequest endpoint (internal)
    location /auth {
        internal;
        proxy_pass http://localhost:4180/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header Cookie $http_cookie;
    }

    # OAuth2 flow endpoints (public)
    location /oauth2/ {
        proxy_pass http://localhost:4180;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Cookie $http_cookie;
    }

    # Error page for 401 (redirect to login)
    error_page 401 = @error401;
    location @error401 {
        return 302 https://$host/oauth2/start?rd=$request_uri;
    }
}
```

## Spuštění

```bash
# Production
./target/release/simple-idm-oauth2-proxy

# Development (s debug logováním)
RUST_LOG=simple_idm_oauth2_proxy=debug,tower_http=debug \
    cargo run --bin simple-idm-oauth2-proxy
```

## Endpointy

### GET /healthz

Health check endpoint.

**Response:**
- `200 OK` - Proxy běží

### GET /auth

**Internal endpoint pro nginx auth_request.**

Ověří session cookie a vrátí auth headers.

**Headers (response při 200):**
- `X-Auth-User: username`
- `X-Auth-Email: user@example.com`
- `X-Auth-Groups: group1,group2` (nebo base64 JSON pokud `groups_header_format = "jsonb64"`)

**Response:**
- `200 OK` - Uživatel je autentizován, headers nastaveny
- `401 Unauthorized` - Žádná session nebo expirovaná

### GET /start?rd=<redirect_url>

Spustí OIDC login flow.

**Query params:**
- `rd` - URL pro redirect po úspěšném přihlášení (default: `/`)

**Response:**
- `302 Found` - Redirect na OIDC provider authorize endpoint

### GET /callback?code=<code>&state=<state>

OAuth2 callback endpoint.

Přijme authorization code, vymění za tokeny, vytvoří session.

**Query params:**
- `code` - Authorization code z OIDC provider
- `state` - CSRF token

**Response:**
- `302 Found` - Redirect na původní URL (z flow state)
- `400 Bad Request` - Chybný nebo chybějící parametr
- `500 Internal Server Error` - Selhání token exchange

**Cookies (při úspěchu):**
- `_oauth2_proxy=<session_id>; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`

### POST /logout

Zneplatní session a smaže cookie.

**Response:**
- `200 OK` - HTML page s potvrzením logout

**Cookies:**
- `_oauth2_proxy=; Max-Age=0` (smazání)

## Login Flow (Detail)

1. **Uživatel přistoupí na aplikaci:**
   ```
   GET https://app.example.com/dashboard
   ```

2. **Nginx auth_request check:**
   ```
   GET http://localhost:4180/auth
   Cookie: (žádná nebo expirovaná)
   → 401 Unauthorized
   ```

3. **Nginx redirect na login:**
   ```
   302 Found
   Location: https://app.example.com/oauth2/start?rd=/dashboard
   ```

4. **Proxy spustí OIDC flow:**
   ```
   GET https://app.example.com/oauth2/start?rd=/dashboard
   → Vygeneruje PKCE challenge, nonce, state
   → Uloží flow state do session store
   → 302 Found
   Location: http://localhost:8080/oauth2/authorize?
       response_type=code&
       client_id=example-app&
       redirect_uri=https://app.example.com/oauth2/callback&
       scope=openid+profile+email&
       code_challenge=<challenge>&
       code_challenge_method=S256&
       state=<state>&
       nonce=<nonce>
   Set-Cookie: __oauth_state=<state>; HttpOnly; Max-Age=600
   ```

5. **Uživatel se přihlásí na OIDC provider:**
   ```
   → Simple IDM login page
   → Uživatel zadá credentials
   → Simple IDM vytvoří authorization code
   ```

6. **OIDC provider redirect zpět:**
   ```
   302 Found
   Location: https://app.example.com/oauth2/callback?
       code=<authorization_code>&
       state=<state>
   ```

7. **Proxy vymění code za tokeny:**
   ```
   POST http://localhost:8080/oauth2/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&
   client_id=example-app&
   client_secret=<secret>&
   code=<authorization_code>&
   redirect_uri=https://app.example.com/oauth2/callback&
   code_verifier=<verifier>

   → Response:
   {
       "access_token": "...",
       "id_token": "eyJ...",
       "refresh_token": "...",
       "expires_in": 3600
   }
   ```

8. **Proxy ověří ID token a vytvoří session:**
   ```
   → Ověří JWT signature
   → Ověří nonce
   → Extrahuje claims (sub, preferred_username, email, groups)
   → Vytvoří session v session store
   → 302 Found
   Location: /dashboard
   Set-Cookie: _oauth2_proxy=<session_id>; HttpOnly; Secure; Max-Age=3600
   ```

9. **Uživatel je přesměrován na původní URL:**
   ```
   GET https://app.example.com/dashboard
   Cookie: _oauth2_proxy=<session_id>
   ```

10. **Nginx auth_request check (nyní úspěšný):**
    ```
    GET http://localhost:4180/auth
    Cookie: _oauth2_proxy=<session_id>

    → 200 OK
    X-Auth-User: john.doe
    X-Auth-Email: john.doe@example.com
    X-Auth-Groups: developers,admins
    ```

11. **Aplikace dostane request s auth headers:**
    ```
    GET http://localhost:3000/dashboard
    X-Auth-User: john.doe
    X-Auth-Email: john.doe@example.com
    X-Auth-Groups: developers,admins
    ```

## Session Management

### In-Memory Backend

Default, pro development nebo single-instance deployment.

```toml
session_backend = "memory"
```

**Výhody:**
- Rychlé
- Žádné dependencies

**Nevýhody:**
- Sessions se ztratí při restartu
- Nefunguje s multiple instances (load balancer)

### SQLite Backend

Pro production s persistencí.

```toml
session_backend = "sqlite"
session_sqlite_path = "/var/lib/simple-idm-oauth2-proxy/sessions.db"
```

**Výhody:**
- Persistence přes restarty
- Může fungovat s multiple instances (shared storage)

**Nevýhody:**
- Pomalejší než in-memory
- Potřebuje file system access

**TODO:** SQLite implementace je zatím stub, potřebuje dokončení.

## Environment Variables

Můžete přepsat config pomocí env vars (prefix `OAUTH2_PROXY_`):

```bash
export OAUTH2_PROXY_LISTEN_ADDR=0.0.0.0:4180
export OAUTH2_PROXY_OIDC_ISSUER=https://sso.example.com
export OAUTH2_PROXY_CLIENT_ID=my-app
export OAUTH2_PROXY_CLIENT_SECRET=secret
```

## Group Header Formats

### CSV (default)

```
X-Auth-Groups: developers,admins,gitlab:ns:42
```

Jednoduché, kompatibilní s většinou aplikací.

### JSON Base64

```
X-Auth-Groups: WyJkZXZlbG9wZXJzIiwiYWRtaW5zIiwiZ2l0bGFiOm5zOjQyIl0=
```

Decode:
```bash
echo "WyJkZXZlbG9wZXJzIiwiYWRtaW5zIiwiZ2l0bGFiOm5zOjQyIl0=" | base64 -d
# ["developers","admins","gitlab:ns:42"]
```

Použijte pro groups, které obsahují čárky nebo speciální znaky.

## Troubleshooting

### Proxy vrací 401 i po přihlášení

- Zkontrolujte, že cookie je nastavena správně:
  ```bash
  curl -I https://app.example.com/oauth2/callback?code=...&state=...
  # Mělo by být: Set-Cookie: _oauth2_proxy=...
  ```
- Zkontrolujte, že Nginx předává cookies:
  ```nginx
  proxy_set_header Cookie $http_cookie;
  ```

### Token exchange selhává

- Zkontrolujte `client_secret` v config
- Zkontrolujte `redirect_uri` - musí přesně odpovídat registraci v Simple IDM
- Zkontrolujte network connectivity k OIDC provider

### Groups nejsou v headers

- Zkontrolujte `groups_claim` v config (default: `"groups"`)
- Zkontrolujte, že OIDC provider vrací groups v ID tokenu:
  ```bash
  # Decode ID token (JWT)
  echo "<id_token>" | cut -d. -f2 | base64 -d | jq
  ```
- Simple IDM vrací groups jako array v `groups` claim

### Session se ztratí po restartu

- Použijte SQLite backend místo memory:
  ```toml
  session_backend = "sqlite"
  session_sqlite_path = "/var/lib/simple-idm-oauth2-proxy/sessions.db"
  ```

## Security Considerations

### Cookie Secret

**Důležité:** Změňte `cookie_secret` v production!

```bash
openssl rand -base64 32
```

### HTTPS

Proxy očekává, že běží za HTTPS reverse proxy (Nginx). Cookie má nastaveno `Secure` flag.

Pro local development můžete vypnout:
```toml
cookie_secure = false  # POUZE PRO DEVELOPMENT!
```

### Session Expiry

Default: 1 hodina (`session_max_age = 3600`).

Po expiraci musí uživatel znovu autentizovat.

**TODO:** Implementovat token refresh flow pro prodloužení sessions.

## Integration s Legacy Apps

### PHP

```php
<?php
$username = $_SERVER['HTTP_X_AUTH_USER'] ?? 'anonymous';
$email = $_SERVER['HTTP_X_AUTH_EMAIL'] ?? '';
$groups = explode(',', $_SERVER['HTTP_X_AUTH_GROUPS'] ?? '');

echo "Hello, $username!";
if (in_array('admins', $groups)) {
    echo "You are an admin.";
}
```

### Node.js/Express

```javascript
app.use((req, res, next) => {
    req.user = {
        username: req.headers['x-auth-user'] || 'anonymous',
        email: req.headers['x-auth-email'] || '',
        groups: (req.headers['x-auth-groups'] || '').split(',').filter(Boolean)
    };
    next();
});

app.get('/admin', (req, res) => {
    if (!req.user.groups.includes('admins')) {
        return res.status(403).send('Forbidden');
    }
    res.send('Admin panel');
});
```

### Python/Flask

```python
from flask import Flask, request

app = Flask(__name__)

@app.before_request
def parse_auth_headers():
    request.user = {
        'username': request.headers.get('X-Auth-User', 'anonymous'),
        'email': request.headers.get('X-Auth-Email', ''),
        'groups': request.headers.get('X-Auth-Groups', '').split(',')
    }

@app.route('/admin')
def admin():
    if 'admins' not in request.user['groups']:
        return 'Forbidden', 403
    return 'Admin panel'
```

## Roadmap

- [ ] SQLite session backend implementace
- [ ] Token refresh flow (prodloužení sessions bez re-login)
- [ ] Redis session backend
- [ ] Metrics endpoint (Prometheus)
- [ ] Support pro multiple OIDC providers
- [ ] Group filtering/mapping config
- [ ] Rate limiting na endpoints

## License

Same as Simple IDM Server.
