# Security Controls

Tento dokument popisuje klíčové bezpečnostní kontroly v `simple-idm-server`.

## Ověření tokenů
- Access tokeny se ověřují centrálně přes `verify_access_token(...)`.
- Kontroluje se podpis, `iss`, časové claimy a povinně audience (`aud`).
- Volitelně se vyžadují scope podle endpointu (např. `/oauth2/userinfo` vyžaduje `openid`).

## OAuth2 / OIDC
- Authorization Code flow podporuje PKCE.
- `/oauth2/userinfo` vrací pouze claimy odpovídající scope (`openid`, `email`, `profile`, `groups`).
- Refresh flow nedovoluje rozšíření scope nad původní hodnoty.

## Session cookies
- `auth_session` cookie používá `HttpOnly`, `SameSite=Lax`, `Path=/`.
- `Secure` je řízeno přes:
  - `FORCE_SECURE_COOKIES=true` (doporučeno v produkci),
  - nebo detekcí HTTPS přes `X-Forwarded-Proto` při `TRUST_PROXY_HEADERS=true`.

## CSRF ochrana
- Login POST (`/oauth2/login`) používá double-submit cookie model:
  - skrytý `csrf_token` ve formuláři,
  - `csrf_token` cookie,
  - při nesouladu je login zamítnut.

## Admin API ochrana
- Primární admin oprávnění: skupina `simple-idm:role:admin`.
- Legacy fallbacky jsou defaultně vypnuté:
  - `ALLOW_LEGACY_ADMIN_GROUP=false`,
  - `ALLOW_ADMIN_SUBSTRING_CLAIM=false`.

## Root token v produkci
- Pokud je `APP_ENV=prod|production` a současně je nastaven `ADMIN_ROOT_TOKEN`, server fail-fast odmítne start.

## Bezpečnostní hlavičky
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy` pro login/UI stránky
- `Strict-Transport-Security` pouze v produkci a při HTTPS

## Rate limiting
- Globální limity (`RATE_LIMIT_*`)
- Striktnější limity na token endpoint (`RATE_LIMIT_TOKEN_ENDPOINT_*`)

