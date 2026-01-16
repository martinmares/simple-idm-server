# Integrace GitLab s simple-idm-server

Tento návod popisuje nastavení GitLabu pro přihlášení přes OIDC s naším simple-idm-serverem.

## Předpoklady

- simple-idm-server běží na `https://sso.cloud-app.cz`
- GitLab běží na `https://gitlab.cloud-app.cz`
- Máš přístup k ADMIN API (ADMIN_ROOT_TOKEN)
- GitLab Omniauth je povolený

## Architektura

```
Uživatel → GitLab → sso.cloud-app.cz (Authorization Code Flow)
                  ← ID token + access token
```

## DŮLEŽITÉ: HTML Login Formulář

Současná verze simple-idm-server vrací HTML login formulář na `GET /oauth2/authorize`
a očekává `application/x-www-form-urlencoded` na `POST /oauth2/login`.

---

## Krok 1: Vytvoření testovacího uživatele

```bash
ADMIN_TOKEN="your-admin-root-token-here"
BASE_URL="https://sso.cloud-app.cz"

curl -X POST "${BASE_URL}/admin/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "gitlab-admin",
    "email": "gitlab-admin@cloud-app.cz",
    "password": "SecureGitLabPass123!",
    "is_active": true
  }'
```

## Krok 2: Vytvoření OAuth2 klienta pro GitLab

```bash
CLIENT_SECRET=$(openssl rand -base64 32)

curl -X POST "${BASE_URL}/admin/oauth-clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "gitlab",
    "client_secret": "'${CLIENT_SECRET}'",
    "name": "GitLab",
    "redirect_uris": [
      "https://gitlab.cloud-app.cz/users/auth/openid_connect/callback"
    ],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "openid profile email groups"
  }'

echo "Client ID: gitlab"
echo "Client Secret: ${CLIENT_SECRET}"
```

## Volitelné: Claim maps

GitLab pro standardní integraci využívá pouze základní `groups` claim, takže pro většinu konfigurací žádná `claim_map` není potřeba. Simple-idm-server už standardně přidává všechny skupiny do JWT, takže GitLabovi stačí jen správný scope (`openid profile email groups`).

Claim mapy použij jen v případě, že chceš namapovat konkrétní skupinu na jiný claim nebo přidat vlastní claim jménem (např. `grafana_role`). V tom případě vytvoř přes `/admin/claim-maps` záznam s `client_id=gitlab`, `group_id=<id skupiny>` a případně nastav `claim_name`/`claim_value`.

## Krok 3: Konfigurace GitLab (omniauth)

V `gitlab.rb`:

```ruby
gitlab_rails['omniauth_enabled'] = true
gitlab_rails['omniauth_allow_single_sign_on'] = ['openid_connect']
gitlab_rails['omniauth_block_auto_created_users'] = false

gitlab_rails['omniauth_providers'] = [
  {
    name: 'openid_connect',
    label: 'Cloud App SSO',
    args: {
      name: 'openid_connect',
      scope: ['openid', 'profile', 'email', 'groups'],
      response_type: 'code',
      issuer: 'https://sso.cloud-app.cz',
      discovery: true,
      client_options: {
        identifier: 'gitlab',
        secret: '<CLIENT_SECRET>',
        redirect_uri: 'https://gitlab.cloud-app.cz/users/auth/openid_connect/callback'
      },
      uid_field: 'sub',
      pkce: true,
      client_auth_method: 'basic'
    }
  }
]
```

Poté:
```bash
sudo gitlab-ctl reconfigure
```

## Krok 4: Ověření přihlášení

1. Otevři `https://gitlab.cloud-app.cz`
2. Klikni na "Cloud App SSO"
3. Přihlas se pomocí simple-idm-server

## Doporučení k identitám

- `uid_field: sub` používá stabilní UUID (bez kolizí)
- `preferred_username` je vhodné použít pro zobrazení v UI
- `email` musí být unikátní

## Troubleshooting

### Redirect URI mismatch
- Musí být přesně: `https://gitlab.cloud-app.cz/users/auth/openid_connect/callback`

### Chybějící email
- Ujisti se, že scope obsahuje `email`
- Zkontroluj, že `/oauth2/userinfo` vrací `email` claim

### GitLab nevidí OIDC provider
- Ověř `gitlab.rb` a `gitlab-ctl reconfigure`

## Bezpečnostní doporučení

1. **Client Secret** ulož bezpečně (např. GitLab secrets)
2. **HTTPS** všude
3. **Session** nastav podle firemní politiky
4. **Audit logy** pro přihlášení
