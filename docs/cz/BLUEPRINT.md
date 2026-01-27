# Blueprint: Očekávání klienta vs. simple-idm-server

Tento dokument popisuje, co musí typický klient splnit a co mu simple-idm-server poskytne.

## Co musí klient dodat

### 1) Redirect URI(s)
- Klient musí poskytnout **přesné** `redirect_uris`.
- URL musí být kompletní (včetně protokolu).
- Doporučení: žádné wildcardy.

### 2) Typ klienta a grant types
- Klient musí určit, jaký flow chce používat:
  - `authorization_code` (webové aplikace)
  - `refresh_token` (obnova session)
  - `client_credentials` (machine-to-machine)
  - `urn:ietf:params:oauth:grant-type:device_code` (device flow – implementované)

### 3) Scope
- Povinné pro OIDC: `openid`
- Doporučené: `profile`, `email`, `groups`
- Další scope si definuje aplikace (např. `api:read`, `api:write`).

### 4) Způsob identifikace uživatele
- Klient by měl používat `sub` jako stabilní identifikátor.
- Pro zobrazení v UI může použít `preferred_username` nebo `email`.

## Co poskytne simple-idm-server

### 1) Client ID a Client Secret
- Server vydá `client_id` a `client_secret`.
- Secret se zobrazí pouze při vytvoření klienta.
- Secret je potřeba bezpečně uložit.

### 2) OIDC endpoints
- Authorization: `GET /oauth2/authorize`
- Token: `POST /oauth2/token`
- UserInfo: `GET /oauth2/userinfo`
- Discovery: `GET /.well-known/openid-configuration`
- JWKS: `GET /.well-known/jwks.json`

### 3) Claimy v tokenu
- `sub` (UUID)
- `email`
- `preferred_username`
- `groups`
- případné custom claims z `claim_maps`

## Doporučený onboarding flow

1. Klient předá:
   - redirect_uris
   - požadované grant_types
   - požadované scopes
2. Admin vytvoří OAuth klienta v simple-idm-serveru.
3. Admin předá klientovi `client_id` a `client_secret`.
4. Klient nakonfiguruje OIDC provider a otestuje login.

## Bezpečnostní požadavky

- Používej HTTPS vždy.
- U `redirect_uris` musí být přesný match.
- `client_secret` nikdy neukládej do git.
- `sub` je stabilní identifikátor pro mapování uživatelů.

## Typické integrační otázky

- **Je možné použít username místo emailu?** Ano, ale doporučuje se `sub`.
- **Můžu použít vlastní scope?** Ano, pokud ho validuješ na straně aplikace.
- **Device flow?** Ano, je dostupný (device_code grant).
