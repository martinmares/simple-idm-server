ALTER TABLE tenant_domains
    ADD COLUMN mfa_policy TEXT NOT NULL DEFAULT 'inherit'
        CHECK (mfa_policy IN ('inherit', 'disabled', 'optional', 'required')),
    ADD COLUMN passkey_policy TEXT NOT NULL DEFAULT 'inherit'
        CHECK (passkey_policy IN ('inherit', 'disabled', 'allowed'));

-- Match only the user's own tenant and currently managed email domain.
CREATE VIEW effective_user_auth_policies AS
SELECT u.id AS user_id, u.tenant_id,
       COALESCE(NULLIF(d.mfa_policy, 'inherit'), t.mfa_policy) AS mfa_policy,
       COALESCE(NULLIF(d.passkey_policy, 'inherit'), t.passkey_policy) AS passkey_policy
FROM users u
JOIN tenants t ON t.id = u.tenant_id
LEFT JOIN tenant_domains d
    ON d.tenant_id = u.tenant_id
    AND lower(d.domain) = lower(split_part(u.email, '@', 2))
    AND d.is_active = true AND d.deleted_at IS NULL
WHERE u.deleted_at IS NULL AND u.is_active = true
    AND t.deleted_at IS NULL AND t.is_active = true;
