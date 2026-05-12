-- Move AD/LDAP from global env config to scoped identity providers.

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_auth_mode_check;

UPDATE users SET auth_mode = 'ad' WHERE auth_mode = 'mixed';
UPDATE users SET auth_mode = 'local' WHERE auth_mode NOT IN ('local', 'federated', 'ad');

ALTER TABLE users
    ADD CONSTRAINT users_auth_mode_check
    CHECK (auth_mode IN ('local', 'federated', 'ad'));

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS auth_provider_id UUID REFERENCES identity_providers(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_users_auth_provider
    ON users(auth_provider_id)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS identity_provider_ad_ldap_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    idp_id UUID NOT NULL UNIQUE REFERENCES identity_providers(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 636,
    base_dn TEXT NOT NULL,
    user_filter TEXT NOT NULL DEFAULT '(|(mail={login})(sAMAccountName={login})(userPrincipalName={login}))',
    tls_mode TEXT NOT NULL DEFAULT 'ldaps',
    timeout_seconds BIGINT NOT NULL DEFAULT 5,
    allow_insecure BOOLEAN NOT NULL DEFAULT false,
    bind_dn TEXT,
    bind_password_encrypted TEXT,
    domains TEXT[] NOT NULL DEFAULT '{}',
    role_sync_enabled BOOLEAN NOT NULL DEFAULT true,
    role_sync_ttl_seconds BIGINT NOT NULL DEFAULT 3600,
    role_sync_timeout_seconds BIGINT NOT NULL DEFAULT 5,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'identity_provider_ad_ldap_tls_mode_check'
    ) THEN
        ALTER TABLE identity_provider_ad_ldap_configs
            ADD CONSTRAINT identity_provider_ad_ldap_tls_mode_check
            CHECK (tls_mode IN ('ldaps', 'starttls'));
    END IF;
END$$;

ALTER TABLE ad_onboarding_tokens
    ADD COLUMN IF NOT EXISTS idp_id UUID REFERENCES identity_providers(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_ad_onboarding_tokens_idp
    ON ad_onboarding_tokens(idp_id);

ALTER TABLE user_external_identities
    ADD COLUMN IF NOT EXISTS idp_id UUID REFERENCES identity_providers(id) ON DELETE CASCADE;

DELETE FROM user_external_identities WHERE source = 'ad' AND idp_id IS NULL;

DROP INDEX IF EXISTS uq_user_external_identities_source_external_active;
DROP INDEX IF EXISTS uq_user_external_identities_source_user_active;

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_external_identities_source_external_active
    ON user_external_identities(tenant_id, idp_id, source, external_user_id)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_external_identities_source_user_active
    ON user_external_identities(tenant_id, idp_id, source, user_id)
    WHERE deleted_at IS NULL;

ALTER TABLE external_role_mappings
    ADD COLUMN IF NOT EXISTS idp_id UUID REFERENCES identity_providers(id) ON DELETE CASCADE;

DROP INDEX IF EXISTS uq_external_role_mappings_active;

CREATE UNIQUE INDEX IF NOT EXISTS uq_external_role_mappings_active
    ON external_role_mappings(tenant_id, idp_id, source, external_role, group_id, mode)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_external_role_mappings_idp_active
    ON external_role_mappings(tenant_id, idp_id, source, priority)
    WHERE deleted_at IS NULL AND is_active = true;

ALTER TABLE user_external_roles
    ADD COLUMN IF NOT EXISTS idp_id UUID REFERENCES identity_providers(id) ON DELETE CASCADE;

-- Previous AD role cache was global. Drop it; users can re-sync through the
-- selected ad_ldap provider.
DELETE FROM user_external_roles WHERE idp_id IS NULL;

ALTER TABLE user_external_roles
    DROP CONSTRAINT IF EXISTS user_external_roles_pkey;

ALTER TABLE user_external_roles
    ADD PRIMARY KEY (user_id, source, idp_id, role_name);

ALTER TABLE user_external_role_sync_state
    ADD COLUMN IF NOT EXISTS idp_id UUID REFERENCES identity_providers(id) ON DELETE CASCADE;

-- No backwards compatibility for the previous global AD config: cached role sync
-- state without provider scope cannot be mapped safely.
DELETE FROM user_external_role_sync_state WHERE idp_id IS NULL;

ALTER TABLE user_external_role_sync_state
    DROP CONSTRAINT IF EXISTS user_external_role_sync_state_pkey;

ALTER TABLE user_external_role_sync_state
    ADD PRIMARY KEY (user_id, source, idp_id);
