# Integrace Grafany s simple-idm-server

Tento návod popisuje kompletní nastavení Grafany pro přihlášení přes OAuth2/OIDC s naším simple-idm-server.

## Předpoklady

- simple-idm-server běží na `https://sso.cloud-app.cz`
- Grafana běží na `https://grafana.cloud-app.cz`
- Máš přístup k ADMIN API (ADMIN_ROOT_TOKEN)
- PostgreSQL databáze běží

## Architektura

```
Uživatel → Grafana → sso.cloud-app.cz (Authorization Code Flow)
                  ← JWT token s claims
```

## DŮLEŽITÉ: Chybějící HTML Login Formulář

**POZOR**: Současná verze simple-idm-server používá JSON API místo HTML formuláře!

### Co to znamená:
- Grafana redirectuje uživatele na `/oauth2/authorize`
- Server **NEVRÁTÍ** HTML formulář pro přihlášení
- Místo toho vrací JSON response

### Řešení:
Pro produkční použití musíme přidat HTML login formulář. Zatím můžeš:
1. Testovat s custom frontendem
2. Použít Postman/curl pro testování toku
3. Počkat na implementaci HTML formuláře (doporučeno)

---

## Krok 1: Vytvoření skupin pro Grafana role

```bash
# Admin token z .env souboru
ADMIN_TOKEN="your-admin-root-token-here"
BASE_URL="https://sso.cloud-app.cz"

# 1. Vytvořit skupinu pro Grafana Admins
curl -X POST "${BASE_URL}/admin/groups" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "grafana-admins",
    "description": "Grafana administrators with full access"
  }'

# Poznamenej si ID skupiny z odpovědi, např: {"id": 1, ...}

# 2. Vytvořit skupinu pro Grafana Editors
curl -X POST "${BASE_URL}/admin/groups" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "grafana-editors",
    "description": "Grafana editors with limited access"
  }'

# Poznamenej si ID: {"id": 2, ...}

# 3. Vytvořit skupinu pro Grafana Viewers
curl -X POST "${BASE_URL}/admin/groups" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "grafana-viewers",
    "description": "Grafana read-only viewers"
  }'

# Poznamenej si ID: {"id": 3, ...}
```

## Krok 2: Vytvoření testovacích uživatelů

```bash
# 1. Admin uživatel
curl -X POST "${BASE_URL}/admin/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@cloud-app.cz",
    "password": "SecureAdminPass123!",
    "is_active": true
  }'

# Poznamenej si user_id: {"id": 1, ...}

# 2. Editor uživatel
curl -X POST "${BASE_URL}/admin/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "editor",
    "email": "editor@cloud-app.cz",
    "password": "SecureEditorPass123!",
    "is_active": true
  }'

# user_id: 2

# 3. Viewer uživatel
curl -X POST "${BASE_URL}/admin/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "viewer",
    "email": "viewer@cloud-app.cz",
    "password": "SecureViewerPass123!",
    "is_active": true
  }'

# user_id: 3
```

## Krok 3: Přiřazení uživatelů do skupin

```bash
# Admin do grafana-admins (user_id=1, group_id=1)
curl -X POST "${BASE_URL}/admin/users/1/groups" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "group_id": 1
  }'

# Editor do grafana-editors (user_id=2, group_id=2)
curl -X POST "${BASE_URL}/admin/users/2/groups" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "group_id": 2
  }'

# Viewer do grafana-viewers (user_id=3, group_id=3)
curl -X POST "${BASE_URL}/admin/users/3/groups" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "group_id": 3
  }'
```

## Krok 4: Vytvoření OAuth2 klienta pro Grafanu

```bash
# Vygeneruj client_secret (nebo použij vlastní)
CLIENT_SECRET=$(openssl rand -base64 32)

curl -X POST "${BASE_URL}/admin/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "grafana",
    "client_secret": "'${CLIENT_SECRET}'",
    "name": "Grafana",
    "redirect_uris": [
      "https://grafana.cloud-app.cz/login/generic_oauth"
    ],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "openid profile email groups"
  }'

# DŮLEŽITÉ: Ulož si client_id a client_secret!
echo "Client ID: grafana"
echo "Client Secret: ${CLIENT_SECRET}"
```

## Krok 5: Nastavení claim mappingu (mapování skupin na Grafana role)

```bash
# Poznámka: client_id z předchozího kroku (vždycky tam dej ID, ne string "grafana")
# Získej client ID (numerické):
curl -X GET "${BASE_URL}/admin/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq '.[] | select(.client_id=="grafana") | .id'

# Předpokládejme client id=1, group_id jsme si poznamenali výše

# 1. grafana-admins → grafana_role = Admin
curl -X POST "${BASE_URL}/admin/claim-maps" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": 1,
    "group_id": 1,
    "claim_name": "grafana_role",
    "claim_value": "Admin"
  }'

# 2. grafana-editors → grafana_role = Editor
curl -X POST "${BASE_URL}/admin/claim-maps" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": 1,
    "group_id": 2,
    "claim_name": "grafana_role",
    "claim_value": "Editor"
  }'

# 3. grafana-viewers → grafana_role = Viewer
curl -X POST "${BASE_URL}/admin/claim-maps" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": 1,
    "group_id": 3,
    "claim_name": "grafana_role",
    "claim_value": "Viewer"
  }'
```

## Krok 6: Konfigurace Grafana

### Prostředí: Docker / Docker Compose

Přidej do `grafana.ini` nebo environment variables:

```ini
[auth.generic_oauth]
enabled = true
name = Cloud App SSO
allow_sign_up = true
client_id = grafana
client_secret = <CLIENT_SECRET_Z_KROKU_4>
scopes = openid profile email groups
email_attribute_path = email
login_attribute_path = sub
name_attribute_path = email
role_attribute_path = grafana_role
role_attribute_strict = true

auth_url = https://sso.cloud-app.cz/oauth2/authorize
token_url = https://sso.cloud-app.cz/oauth2/token
api_url = https://sso.cloud-app.cz/oauth2/userinfo

# Auto-mapování rolí z JWT
org_role = Viewer

[auth]
oauth_auto_login = false
disable_login_form = false
```

### Prostředí: Kubernetes / Helm

```yaml
# values.yaml
grafana:
  env:
    GF_AUTH_GENERIC_OAUTH_ENABLED: "true"
    GF_AUTH_GENERIC_OAUTH_NAME: "Cloud App SSO"
    GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP: "true"
    GF_AUTH_GENERIC_OAUTH_CLIENT_ID: "grafana"
    GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET: "<CLIENT_SECRET>"
    GF_AUTH_GENERIC_OAUTH_SCOPES: "openid profile email groups"
    GF_AUTH_GENERIC_OAUTH_AUTH_URL: "https://sso.cloud-app.cz/oauth2/authorize"
    GF_AUTH_GENERIC_OAUTH_TOKEN_URL: "https://sso.cloud-app.cz/oauth2/token"
    GF_AUTH_GENERIC_OAUTH_API_URL: "https://sso.cloud-app.cz/oauth2/userinfo"
    GF_AUTH_GENERIC_OAUTH_EMAIL_ATTRIBUTE_PATH: "email"
    GF_AUTH_GENERIC_OAUTH_LOGIN_ATTRIBUTE_PATH: "sub"
    GF_AUTH_GENERIC_OAUTH_NAME_ATTRIBUTE_PATH: "email"
    GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH: "grafana_role"
    GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT: "true"
```

## Krok 7: Nginx konfigurace pro sso.cloud-app.cz

```nginx
server {
    listen 443 ssl http2;
    server_name sso.cloud-app.cz;

    ssl_certificate /etc/letsencrypt/live/sso.cloud-app.cz/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sso.cloud-app.cz/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# HTTP redirect
server {
    listen 80;
    server_name sso.cloud-app.cz;
    return 301 https://$server_name$request_uri;
}
```

## Krok 8: Testování (po implementaci HTML formuláře)

1. **Otevři Grafanu**: `https://grafana.cloud-app.cz`
2. **Klikni na "Sign in with Cloud App SSO"**
3. **Přesměrování na**: `https://sso.cloud-app.cz/oauth2/authorize?...`
4. **Přihlaš se jako**:
   - Username: `admin`, Password: `SecureAdminPass123!` → dostaneš Admin roli
   - Username: `editor`, Password: `SecureEditorPass123!` → dostaneš Editor roli
   - Username: `viewer`, Password: `SecureViewerPass123!` → dostaneš Viewer roli
5. **Grafana tě přesměruje zpět** s access tokenem

## Jak funguje mapování rolí?

```
Uživatel "admin" → skupina "grafana-admins"
                 → claim_map: grafana_role = "Admin"
                 → JWT obsahuje: {"grafana_role": "Admin"}
                 → Grafana přiřadí Admin roli
```

## Ověření JWT tokenu

Po úspěšném přihlášení můžeš zkontrolovat JWT token:

```bash
# Získej token (simulace)
TOKEN="<access_token_z_grafany>"

# Dekóduj (můžeš použít jwt.io)
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq .

# Měl bys vidět:
{
  "sub": "00000000-0000-0000-0000-000000000001",
  "iss": "https://sso.cloud-app.cz",
  "aud": ["grafana"],
  "exp": 1234567890,
  "iat": 1234567000,
  "email": "admin@cloud-app.cz",
  "groups": ["grafana-admins"],
  "grafana_role": "Admin"  ← Custom claim z claim_map
}
```

## Troubleshooting

### Grafana nevidí role
- Zkontroluj `role_attribute_path = grafana_role` v Grafana konfiguraci
- Ověř, že claim_maps jsou správně vytvořené (viz Krok 5)

### Redirect URI mismatch
- Ujisti se, že v OAuth klientovi je správná URL: `https://grafana.cloud-app.cz/login/generic_oauth`
- Zkontroluj Grafana logy: `docker logs <grafana-container>`

### Uživatel nemá přístup
- Zkontroluj, že je ve správné skupině: `GET /admin/users/<id>/groups`
- Ověř claim mapping: `GET /admin/claim-maps`

### HTML formulář chybí (současný stav)
- Implementace HTML login formuláře je v plánu
- Pro testování můžeš vytvořit vlastní frontend, který volá API
- Nebo počkej na dokončení této funkce

## Bezpečnostní doporučení

1. **Client Secret**: Uchovávej bezpečně (např. v Kubernetes Secrets)
2. **HTTPS**: Vždy používej SSL/TLS
3. **Token Expiry**: Defaultně 1 hodina (3600s)
4. **Refresh Tokens**: Platnost 30 dní
5. **Rate Limiting**: Zvař na nginx úrovni
6. **Monitoring**: Sleduj `/health` endpoint

## Pokročilé: Více organizací v Grafaně

Pokud chceš mapovat skupiny na různé Grafana organizace:

```bash
# Vytvoř claim pro org_id
curl -X POST "${BASE_URL}/admin/claim-maps" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": 1,
    "group_id": 4,
    "claim_name": "org_id",
    "claim_value": "2"
  }'
```

V Grafaně nastav:
```ini
[auth.generic_oauth]
org_attribute_path = org_id
```

## Další kroky

- [ ] Implementovat HTML login formulář
- [ ] Přidat CAPTCHA pro přihlášení
- [ ] Nastavit monitoring (Prometheus)
- [ ] Přidat audit log pro přihlášení
- [ ] Implementovat MFA (2FA)

## Reference

- [Grafana Generic OAuth Documentation](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/generic-oauth/)
- [OAuth 2.0 Authorization Code Flow](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
