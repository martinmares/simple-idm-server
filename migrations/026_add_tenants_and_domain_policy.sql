-- Multi-tenant foundation (single-default, multi-ready)
-- This migration is intentionally non-breaking for existing installations.

-- Canonical default tenant ID for existing single-tenant deployments
-- (kept constant to make defaults deterministic across environments).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tenant_mode') THEN
        CREATE TYPE tenant_mode AS ENUM ('single', 'multi');
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY,
    slug VARCHAR(128) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    mode tenant_mode NOT NULL DEFAULT 'single',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

INSERT INTO tenants (id, slug, name, mode, is_active)
VALUES (
    '11111111-1111-1111-1111-111111111111',
    'default',
    'Default Tenant',
    'single',
    true
)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS tenant_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, domain),
    UNIQUE (domain)
);

CREATE INDEX IF NOT EXISTS idx_tenant_domains_tenant_id ON tenant_domains(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_domains_domain ON tenant_domains(domain);

-- Add tenant scope to key auth/policy tables (single-default)
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE claim_maps ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE user_groups ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE group_groups ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE user_group_patterns ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE oauth_client_group_patterns ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE claim_map_patterns ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE users SET tenant_id = '11111111-1111-1111-1111-111111111111' WHERE tenant_id IS NULL;
UPDATE groups SET tenant_id = '11111111-1111-1111-1111-111111111111' WHERE tenant_id IS NULL;
UPDATE oauth_clients SET tenant_id = '11111111-1111-1111-1111-111111111111' WHERE tenant_id IS NULL;
UPDATE claim_maps SET tenant_id = '11111111-1111-1111-1111-111111111111' WHERE tenant_id IS NULL;
UPDATE user_groups SET tenant_id = '11111111-1111-1111-1111-111111111111' WHERE tenant_id IS NULL;
UPDATE group_groups SET tenant_id = '11111111-1111-1111-1111-111111111111' WHERE tenant_id IS NULL;
UPDATE user_group_patterns SET tenant_id = '11111111-1111-1111-1111-111111111111' WHERE tenant_id IS NULL;
UPDATE oauth_client_group_patterns SET tenant_id = '11111111-1111-1111-1111-111111111111' WHERE tenant_id IS NULL;
UPDATE claim_map_patterns SET tenant_id = '11111111-1111-1111-1111-111111111111' WHERE tenant_id IS NULL;

ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE groups ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE oauth_clients ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE claim_maps ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE user_groups ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE group_groups ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE user_group_patterns ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE oauth_client_group_patterns ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE claim_map_patterns ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE users ALTER COLUMN tenant_id SET DEFAULT '11111111-1111-1111-1111-111111111111';
ALTER TABLE groups ALTER COLUMN tenant_id SET DEFAULT '11111111-1111-1111-1111-111111111111';
ALTER TABLE oauth_clients ALTER COLUMN tenant_id SET DEFAULT '11111111-1111-1111-1111-111111111111';
ALTER TABLE claim_maps ALTER COLUMN tenant_id SET DEFAULT '11111111-1111-1111-1111-111111111111';
ALTER TABLE user_groups ALTER COLUMN tenant_id SET DEFAULT '11111111-1111-1111-1111-111111111111';
ALTER TABLE group_groups ALTER COLUMN tenant_id SET DEFAULT '11111111-1111-1111-1111-111111111111';
ALTER TABLE user_group_patterns ALTER COLUMN tenant_id SET DEFAULT '11111111-1111-1111-1111-111111111111';
ALTER TABLE oauth_client_group_patterns ALTER COLUMN tenant_id SET DEFAULT '11111111-1111-1111-1111-111111111111';
ALTER TABLE claim_map_patterns ALTER COLUMN tenant_id SET DEFAULT '11111111-1111-1111-1111-111111111111';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_tenant_id_fkey') THEN
        ALTER TABLE users
            ADD CONSTRAINT users_tenant_id_fkey
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'groups_tenant_id_fkey') THEN
        ALTER TABLE groups
            ADD CONSTRAINT groups_tenant_id_fkey
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'oauth_clients_tenant_id_fkey') THEN
        ALTER TABLE oauth_clients
            ADD CONSTRAINT oauth_clients_tenant_id_fkey
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'claim_maps_tenant_id_fkey') THEN
        ALTER TABLE claim_maps
            ADD CONSTRAINT claim_maps_tenant_id_fkey
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
    END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_groups_tenant_id ON groups(tenant_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_tenant_id ON oauth_clients(tenant_id);
CREATE INDEX IF NOT EXISTS idx_claim_maps_tenant_id ON claim_maps(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_groups_tenant_id ON user_groups(tenant_id);

COMMENT ON TABLE tenants IS 'Top-level tenant/organization records. Single-default, multi-ready.';
COMMENT ON TABLE tenant_domains IS 'Allowed email domains per tenant for identity routing and validation.';
COMMENT ON COLUMN users.tenant_id IS 'Tenant ownership; currently seeded to default for single-tenant compatibility.';
