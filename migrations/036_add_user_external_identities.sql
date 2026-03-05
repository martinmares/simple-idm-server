-- Store stable external identifiers (AD/LDAP/OIDC subjects) per user.

CREATE TABLE IF NOT EXISTS user_external_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source VARCHAR(64) NOT NULL,               -- e.g. ad, google, entra, gitlab
    external_user_id TEXT NOT NULL,            -- stable external identifier
    external_user_id_type VARCHAR(64),         -- e.g. ad_object_guid, oidc_sub, login_name
    login_name VARCHAR(255),                   -- optional helper login alias (e.g. sAMAccountName)
    upn VARCHAR(255),                          -- optional UPN/email-like external principal
    metadata JSONB,                            -- reserved for provider-specific attributes
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- One active link for (tenant, source, external_user_id)
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_external_identities_source_external_active
    ON user_external_identities(tenant_id, source, external_user_id)
    WHERE deleted_at IS NULL;

-- One active link for (tenant, source, user)
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_external_identities_source_user_active
    ON user_external_identities(tenant_id, source, user_id)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_user_external_identities_user_active
    ON user_external_identities(user_id, source)
    WHERE deleted_at IS NULL;
