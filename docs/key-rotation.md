# Key Rotation

`simple-idm-server` podepisuje JWT privátním klíčem (`JWT_PRIVATE_KEY_PATH`) a publikuje veřejný klíč přes JWKS (`/.well-known/jwks.json`).

## Aktuální stav
- Aktivní podpisový klíč je identifikován přes `JWT_KEY_ID`.
- Aktivní podpis používá `JWT_PRIVATE_KEY_PATH` + `JWT_PUBLIC_KEY_PATH`.
- Ověřování i JWKS umí více klíčů současně přes:
  - `JWT_ADDITIONAL_PUBLIC_KEYS` ve formátu `kid=path,kid2=path2`.
- Díky tomu je podporované overlap okno při rotaci.

## Doporučený rollout rotace (operativní postup)
1. Vygenerovat nový pár klíčů (`private.pem`, `public.pem`).
2. Přidat nový veřejný klíč do `JWT_ADDITIONAL_PUBLIC_KEYS` na všech instancích.
3. Přepnout aktivní podpis: `JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH`, `JWT_KEY_ID`.
4. Restartovat server.
5. Ověřit:
   - JWKS obsahuje nový i starý `kid`,
   - nové tokeny mají nový `kid`,
   - staré tokeny se stále validují.
6. Po vypršení všech starých tokenů odebrat starý klíč z `JWT_ADDITIONAL_PUBLIC_KEYS`.

## Emergency rotation
- Při kompromitaci klíče okamžitě vyměnit klíčový pár a `JWT_KEY_ID`.
- Zkrátit expirace tokenů (dočasně) a provést revoke aktivních refresh tokenů.

## Poznámka
- Pokud token neobsahuje `kid`, server fallbackuje na aktivní veřejný klíč.
