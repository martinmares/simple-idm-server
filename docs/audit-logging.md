# Audit Logging

Cíl: forenzní stopa pro autentizaci, autorizaci a admin operace.

## Co se loguje
- Auth flow:
  - login success/fail,
  - token issuance,
  - refresh token rotace,
  - device authorization verify.
- Admin API:
  - create/update/delete uživatelů, skupin, klientů, claim map.
- Bezpečnostní události:
  - neplatný token,
  - neplatná audience,
  - CSRF validation fail,
  - admin access denied.
  - lockout/rate-limit stavy při opakovaných auth selháních.

## Brute-force ochrana
- Per-identity/per-IP ochrana je implementovaná přes tabulku `auth_throttle`.
- Endpointy:
  - `oauth2_login` (form login),
  - `oauth2_token` (token exchange).
  - `oauth2_client_credentials` (M2M token endpoint),
  - `oauth2_device_verify` (device verification login).
- Konfigurační proměnné:
  - `AUTH_PROTECTION_ENABLED`,
  - `AUTH_FAILURE_WINDOW_SECONDS`,
  - `AUTH_MAX_FAILURES`,
  - `AUTH_LOCKOUT_SECONDS`,
  - `AUTH_THROTTLE_CLEAR_ON_START` (pouze development/recovery).

`AUTH_THROTTLE_CLEAR_ON_START=true` při startu serveru smaže tabulku
`auth_throttle`. Default je `false`, protože perzistentní lockout má přežít
restart služby. Pokud je reset zapnutý, server loguje výrazný `SECURITY WARNING`
a admin Web UI zobrazuje červený konfigurační banner.

## Formát
- Strukturované logy přes `tracing` (JSON/plain dle runtime konfigurace).
- Doporučeno ingestovat do SIEM (např. Loki/ELK/Splunk).

## Retence
- Doporučení: minimálně 90 dní online + 1 rok archiv.
- Při vyšších compliance požadavcích prodloužit retenci dle interní politiky.

## Provozní doporučení
- Zapnout korelační identifikátor requestu přes reverse proxy.
- Nemaskované citlivé hodnoty (hesla, secrety, tokeny) nikdy nelogovat.
