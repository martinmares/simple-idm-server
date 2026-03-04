-- External role bridge for delegated AD/LDAP auth

CREATE TABLE IF NOT EXISTS external_role_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source VARCHAR(32) NOT NULL DEFAULT 'ad',
    external_role TEXT NOT NULL,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    mode VARCHAR(16) NOT NULL DEFAULT 'add',
    priority INTEGER NOT NULL DEFAULT 100,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'external_role_mappings_mode_check'
    ) THEN
        ALTER TABLE external_role_mappings
            ADD CONSTRAINT external_role_mappings_mode_check
            CHECK (mode IN ('add', 'remove'));
    END IF;
END$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_external_role_mappings_active
    ON external_role_mappings(tenant_id, source, external_role, group_id, mode)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_external_role_mappings_tenant_active
    ON external_role_mappings(tenant_id, source, priority)
    WHERE deleted_at IS NULL AND is_active = true;

CREATE TABLE IF NOT EXISTS user_external_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source VARCHAR(32) NOT NULL DEFAULT 'ad',
    role_name TEXT NOT NULL,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, source, role_name)
);

CREATE INDEX IF NOT EXISTS idx_user_external_roles_user_source
    ON user_external_roles(user_id, source);

CREATE TABLE IF NOT EXISTS user_external_role_sync_state (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source VARCHAR(32) NOT NULL DEFAULT 'ad',
    last_synced_at TIMESTAMPTZ,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, source)
);
