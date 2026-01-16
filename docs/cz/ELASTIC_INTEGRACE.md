# Integrace Elasticsearch/Kibana s simple-idm-server

Tento návod popisuje nastavení OIDC pro Elasticsearch/Kibana s naším simple-idm-serverem.

## Předpoklady

- simple-idm-server běží na `https://sso.cloud-app.cz`
- Elasticsearch/Kibana běží na `https://elasticsearch.cloud-app.cz`
- Máš přístup k ADMIN API (ADMIN_ROOT_TOKEN)
- Elasticsearch a Kibana jsou nasazené (Elastic Stack)

## Architektura

```
Uživatel → Kibana → sso.cloud-app.cz (Authorization Code Flow)
                   ← ID token + access token
```

## DŮLEŽITÉ: HTML Login Formulář

Současná verze simple-idm-server vrací HTML login formulář na `GET /oauth2/authorize`
a očekává `application/x-www-form-urlencoded` na `POST /oauth2/login`.

---

## Krok 1: Vytvoření skupin pro role (volitelné)

Pokud chceš mapovat skupiny na role, vytvoř si skupiny (např. `elastic-admins`, `elastic-users`).

```bash
ADMIN_TOKEN="your-admin-root-token-here"
BASE_URL="https://sso.cloud-app.cz"

curl -X POST "${BASE_URL}/admin/groups" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "elastic-admins",
    "description": "Elasticsearch administrators"
  }'

curl -X POST "${BASE_URL}/admin/groups" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "elastic-users",
    "description": "Elasticsearch users"
  }'
```

## Krok 2: Vytvoření testovacího uživatele

```bash
curl -X POST "${BASE_URL}/admin/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "elastic-admin",
    "email": "elastic-admin@cloud-app.cz",
    "password": "SecureElasticPass123!",
    "is_active": true
  }'
```

## Krok 3: Přiřazení uživatele do skupiny (volitelné)

```bash
# Nahraď USER_ID a GROUP_ID z předchozích kroků
curl -X POST "${BASE_URL}/admin/users/USER_ID/groups" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "group_id": "GROUP_ID"
  }'
```

## Krok 4: Vytvoření OAuth2 klienta pro Elasticsearch/Kibana

```bash
CLIENT_SECRET=$(openssl rand -base64 32)

curl -X POST "${BASE_URL}/admin/oauth-clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "elastic",
    "client_secret": "'${CLIENT_SECRET}'",
    "name": "Elastic Stack",
    "redirect_uris": [
      "https://elasticsearch.cloud-app.cz/api/security/oidc/callback"
    ],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "openid profile email groups"
  }'

echo "Client ID: elastic"
echo "Client Secret: ${CLIENT_SECRET}"
```

## Krok 5: Nastavení Elasticsearch OIDC realm

V `elasticsearch.yml`:

```yaml
xpack.security.enabled: true
xpack.security.authc.realms.oidc.simple_idm:
  order: 2
  rp.client_id: "elastic"
  rp.response_type: "code"
  rp.redirect_uri: "https://elasticsearch.cloud-app.cz/api/security/oidc/callback"
  rp.post_logout_redirect_uri: "https://elasticsearch.cloud-app.cz"
  op.issuer: "https://sso.cloud-app.cz"
  op.authorization_endpoint: "https://sso.cloud-app.cz/oauth2/authorize"
  op.token_endpoint: "https://sso.cloud-app.cz/oauth2/token"
  op.userinfo_endpoint: "https://sso.cloud-app.cz/oauth2/userinfo"
  op.jwkset_path: "https://sso.cloud-app.cz/.well-known/jwks.json"
  claims.principal: "sub"
  claims.name: "preferred_username"
  claims.mail: "email"
  claims.groups: "groups"
```

## Krok 6: Nastavení tajného klíče v Elasticsearch keystoru

```bash
# Na serveru Elasticsearch
bin/elasticsearch-keystore add xpack.security.authc.realms.oidc.simple_idm.rp.client_secret
```

## Krok 7: Nastavení Kibana (pokud používáš Kibana)

V `kibana.yml`:

```yaml
server.publicBaseUrl: "https://elasticsearch.cloud-app.cz"

xpack.security.authc.providers:
  oidc.simple_idm:
    order: 0
    realm: "simple_idm"
  basic.basic1:
    order: 1
```

## Krok 8: Ověření

1. Otevři `https://elasticsearch.cloud-app.cz`
2. Měl bys vidět přihlášení přes OIDC
3. Přihlášení přes simple-idm-server

## Troubleshooting

### Redirect URI mismatch
- Zkontroluj přesný match: `https://elasticsearch.cloud-app.cz/api/security/oidc/callback`

### Chybí `openid` scope
- Ujisti se, že klient má scope `openid`

### JWT neobsahuje email
- Přidej `email` do scope a ověř `email` claim v `/oauth2/userinfo`

## Bezpečnostní doporučení

1. **Client Secret** ulož do keystoru
2. **HTTPS** všude
3. **Rate limiting** na reverse proxy
4. **Audit logy** pro přihlášení
