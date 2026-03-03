# Delete Policy (GDPR + NIS2 aligned)

Tento dokument zavádí jednotný model mazání v `simple-idm` podobný běžné praxi enterprise IDP:

1. `disable` (okamžitě zneplatní přístup)
2. `soft delete` (`deleted_at`)
3. `hard purge` (asynchronně po retenční době)

## Principy

- API `DELETE` pro business entity provádí **soft delete**.
- Autentizační tok nikdy nepracuje se záznamy, kde `deleted_at IS NOT NULL`.
- Hard delete zůstává jen pro:
  - čistě vazební tabulky (unlink operace),
  - krátkodobé bezpečnostní artefakty (tokeny, kódy, throttling stavy),
  - řízený purge job.

## Matice entit

| Entita | API delete | Runtime viditelnost | Purge doporučení |
|---|---|---|---|
| `users` | soft (`is_active=false`, `deleted_at`) | v login/auth flow filtrovat `deleted_at IS NULL` | 30–90 dní |
| `groups` | soft (`deleted_at`) | filtrovat v claims/group tree | 30–180 dní |
| `oauth_clients` | soft (`is_active=false`, `deleted_at`) | token endpointy filtrují `deleted_at IS NULL` | 90–365 dní |
| `claim_maps` | soft (`deleted_at`) | claims builder filtruje `deleted_at IS NULL` | 90–365 dní |
| `user_group_patterns` | soft (`deleted_at`) | pattern sync filtruje `deleted_at IS NULL` | 30–180 dní |
| `oauth_client_group_patterns` | soft (`deleted_at`) | token filtering filtruje `deleted_at IS NULL` | 30–180 dní |
| `claim_map_patterns` | soft (`deleted_at`) | claims builder filtruje `deleted_at IS NULL` | 30–180 dní |
| `tenants` | soft (`is_active=false`, `deleted_at`) | routing/lookup filtruje `deleted_at IS NULL` | 90–365 dní |
| `tenant_domains` | soft (`is_active=false`, `deleted_at`) | domain resolution filtruje `deleted_at IS NULL` | 30–180 dní |
| `user_groups` | hard unlink | N/A (vazba) | bez retence |
| `group_groups` | hard unlink | N/A (vazba) | bez retence |
| `authorization_codes`, `refresh_tokens`, `device_codes`, `password_reset_tokens`, `auth_throttle` | hard delete/cleanup | krátkodobé security artefakty | dle TTL |

## Implementační stav v tomto commitu

- Přidána migrace `031_add_soft_delete_columns.sql`.
- `DELETE` endpointy business entit přepsány na soft delete.
- Klíčové auth/admin dotazy doplněny o `deleted_at IS NULL`.
- SQLx metadata (`.sqlx`) regenerována.

## GDPR poznámky

- Soft delete není náhrada práva na výmaz; je to provozní/stability mezikrok.
- Purge job musí být navázán na retention politiku a právní důvody uchování.
- Audit záznamy držet separátně, minimalizovat PII.

## NIS2 poznámky

- Soft delete pomáhá auditovatelnosti a incident response.
- Security artefakty (tokeny/kódy) držet krátce a pravidelně čistit.
- Přístupy musí respektovat princip minimálních oprávnění i u „deleted“ objektů.

