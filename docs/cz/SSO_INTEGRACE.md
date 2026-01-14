# Integrace simple-idm-server jako SSO řešení

> **Poznámka:** Tento dokument je v češtině jako výjimka z pravidla "všechny dokumenty v angličtině".
> Složka `docs/cz/` je JEDINÁ výjimka pro české dokumenty.

## 1. SSO Server (https://sso.cloud-app.cz)

**Ano, bude to SSO server!** Po implementaci Authorization Code Flow:

```
┌─────────────────────────────────────────────────┐
│  https://sso.cloud-app.cz                       │
│  (nginx → simple-idm-server:8080)               │
│                                                  │
│  - /.well-known/openid-configuration            │
│  - /.well-known/jwks.json                       │
│  - /oauth2/authorize   ← Login zde!             │
│  - /oauth2/token                                │
│  - /admin/*            ← Admin API               │
└─────────────────────────────────────────────────┘
```

### Nginx konfigurace:
```nginx
server {
    listen 443 ssl;
    server_name sso.cloud-app.cz;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Konfigurace .env:
```env
JWT_ISSUER=https://sso.cloud-app.cz
```

---

## 2. ArgoCD integrace

**ANO, přesně tohle půjde!** 🚀 ArgoCD má plnou podporu pro OIDC s group mappings.

### ArgoCD konfigurace:

**argocd-cm ConfigMap:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  # OIDC Configuration
  url: https://argocd.cloud-app.cz

  oidc.config: |
    name: Cloud App SSO
    issuer: https://sso.cloud-app.cz
    clientID: argocd_client
    clientSecret: $oidc.argocd.clientSecret
    requestedScopes: ["openid", "profile", "email", "groups"]
    requestedIDTokenClaims: {"groups": {"essential": true}}
```

**argocd-rbac-cm ConfigMap (role mapping):**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-rbac-cm
  namespace: argocd
data:
  policy.default: role:readonly
  policy.csv: |
    # Admins mají plný přístup
    g, admin, role:admin

    # DevOps team má read/write
    g, devops, role:admin

    # Developers mají read-only
    g, developers, role:readonly

  scopes: '[groups, email]'
```

### Vytvoření OAuth2 klienta v Admin API:

```bash
# 1. OAuth2 client pro ArgoCD
curl -X POST https://sso.cloud-app.cz/admin/oauth-clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "argocd_client",
    "client_secret": "strong-secret-here",
    "name": "ArgoCD",
    "redirect_uris": [
      "https://argocd.cloud-app.cz/auth/callback"
    ],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "openid profile email groups"
  }'

# 2. Claim map pro ArgoCD - mapuj groups
curl -X POST https://sso.cloud-app.cz/admin/claim-maps \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "<argocd_client_uuid>",
    "group_id": "<admin_group_uuid>",
    "claim_name": "admin"
  }'
```

### Jak to funguje:
1. User klikne "Login with SSO" v ArgoCD
2. Přesměruje na `https://sso.cloud-app.cz/oauth2/authorize`
3. User se přihlásí (username + password)
4. IDM server vytvoří JWT s `groups: ["admin", "devops"]`
5. ArgoCD přečte groups z JWT tokenu
6. ArgoCD mapuje `admin` → `role:admin` podle RBAC policy

---

## 3. Další aplikace (custom apps)

**Ano, můžeš napojit všechny!**

### Tvoje custom web app (Next.js / Express.js):
```javascript
import passport from 'passport';
import { Strategy as OIDCStrategy } from 'openid-client';

passport.use('oidc', new OIDCStrategy({
  issuer: 'https://sso.cloud-app.cz',
  client_id: 'myapp_client',
  client_secret: 'myapp_secret',
  redirect_uri: 'https://myapp.cloud-app.cz/auth/callback',
  scope: 'openid profile email groups'
}, (tokenset, userinfo, done) => {
  // userinfo obsahuje groups!
  console.log(userinfo.groups); // ["users", "reports"]
  return done(null, userinfo);
}));
```

### Grafana:
```ini
[auth.generic_oauth]
enabled = true
name = Cloud App SSO
allow_sign_up = true
client_id = grafana_client
client_secret = grafana_secret
scopes = openid profile email groups
auth_url = https://sso.cloud-app.cz/oauth2/authorize
token_url = https://sso.cloud-app.cz/oauth2/token
api_url = https://sso.cloud-app.cz/oauth2/userinfo
role_attribute_path = contains(groups[*], 'admin') && 'Admin' || 'Viewer'
```

### Kubernetes Dashboard:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubernetes-dashboard-settings
data:
  oidc-issuer-url: "https://sso.cloud-app.cz"
  oidc-client-id: "k8s-dashboard"
```

---

## 4. Custom Claim Mapping (killer feature!)

**Tohle je tvoje výhoda** - můžeš filtrovat groups per aplikace:

```
User má groups: [admin, users, reports, billing, analytics, devops]

ArgoCD client → claim_maps:
  - admin → admin
  - devops → devops
  → JWT pro ArgoCD: {"groups": ["admin", "devops"]}  // menší token!

Grafana client → claim_maps:
  - admin → is_admin
  - reports → can_view_reports
  → JWT pro Grafanu: {"is_admin": true, "can_view_reports": true}

Billing app → claim_maps:
  - billing → can_access_billing
  → JWT pro billing: {"can_access_billing": true}
```

**Benefit:** JWT tokeny jsou menší, každá aplikace vidí jen relevantní claims!

---

## 5. Co zbývá implementovat:

Pro plnou SSO funkcionalitu potřebuješ:

### Authorization Code Flow:
- `GET /oauth2/authorize` - login stránka + consent
- `POST /oauth2/login` - ověření username/password
- `POST /oauth2/token` - exchange code za token (s PKCE)
- `GET /oauth2/userinfo` - endpoint pro user info (pro Grafanu atd.)

---

## 6. Produkční checklist

Před nasazením do produkce:

### Bezpečnost:
- [ ] Změň `ADMIN_ROOT_TOKEN` na silné heslo
- [ ] Nastav `JWT_ISSUER=https://sso.cloud-app.cz`
- [ ] Použij HTTPS všude (nginx s Let's Encrypt)
- [ ] Rotuj RSA klíče jednou za rok (`scripts/generate_keys.sh`)
- [ ] Nastav firewall - port 8080 jen pro localhost

### Monitoring:
- [ ] Nastav logy (`RUST_LOG=simple_idm_server=info`)
- [ ] Monitoring portu 8080 (healthcheck: `/health`)
- [ ] Alerting při výpadku databáze

### Backup:
- [ ] Zálohuj PostgreSQL databázi denně
- [ ] Zálohuj RSA klíče (`keys/private.pem`, `keys/public.pem`)
- [ ] Zálohuj `.env` soubor

### High Availability (volitelné):
- [ ] PostgreSQL replikace
- [ ] Load balancer před nginx (2+ instance simple-idm-server)
- [ ] Redis pro session storage (pokud bude potřeba)

---

## 7. Troubleshooting

### "Invalid token" chyba v aplikaci:
```bash
# Zkontroluj že aplikace používá správný JWKS
curl https://sso.cloud-app.cz/.well-known/jwks.json

# Zkontroluj že JWT issuer je správný
curl https://sso.cloud-app.cz/.well-known/openid-configuration | jq .issuer
```

### User nevidí groups v aplikaci:
```bash
# Zkontroluj claim maps
curl https://sso.cloud-app.cz/admin/claim-maps \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

# Zkontroluj že user má groups
curl https://sso.cloud-app.cz/admin/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

### Nginx timeout:
```nginx
# Zvětši timeouty v nginx
proxy_connect_timeout 60s;
proxy_send_timeout 60s;
proxy_read_timeout 60s;
```

---

## 8. Příklady použití

### Vytvoření nového uživatele:
```bash
curl -X POST https://sso.cloud-app.cz/admin/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jan.novak",
    "email": "jan.novak@cloud-app.cz",
    "password": "temporary-password-123"
  }'
```

### Přidání uživatele do skupiny:
```bash
curl -X POST https://sso.cloud-app.cz/admin/users/{user_id}/groups \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "group_id": "{admin_group_id}"
  }'
```

### Vytvoření nové aplikace:
```bash
# 1. Vytvoř OAuth client
curl -X POST https://sso.cloud-app.cz/admin/oauth-clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "nova_aplikace",
    "client_secret": "secret-123",
    "name": "Nova Aplikace",
    "redirect_uris": ["https://nova-app.cloud-app.cz/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "openid profile email groups"
  }'

# 2. Nastav claim mapping
curl -X POST https://sso.cloud-app.cz/admin/claim-maps \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "{nova_app_uuid}",
    "group_id": "{users_group_uuid}",
    "claim_name": "can_access"
  }'
```

---

## Kontakt

Pro otázky a problémy:
- GitHub Issues: https://github.com/tvoje-repo/simple-idm-server/issues
- Email: admin@cloud-app.cz
