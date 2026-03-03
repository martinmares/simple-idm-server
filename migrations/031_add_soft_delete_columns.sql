-- Soft-delete support for identity/policy entities
-- Keeps records recoverable and auditable; hard purge can be done by retention job.

ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE claim_maps ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE user_group_patterns ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE oauth_client_group_patterns ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE claim_map_patterns ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE tenant_domains ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);
CREATE INDEX IF NOT EXISTS idx_groups_deleted_at ON groups(deleted_at);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_deleted_at ON oauth_clients(deleted_at);
CREATE INDEX IF NOT EXISTS idx_claim_maps_deleted_at ON claim_maps(deleted_at);
CREATE INDEX IF NOT EXISTS idx_user_group_patterns_deleted_at ON user_group_patterns(deleted_at);
CREATE INDEX IF NOT EXISTS idx_oauth_client_group_patterns_deleted_at ON oauth_client_group_patterns(deleted_at);
CREATE INDEX IF NOT EXISTS idx_claim_map_patterns_deleted_at ON claim_map_patterns(deleted_at);
CREATE INDEX IF NOT EXISTS idx_tenants_deleted_at ON tenants(deleted_at);
CREATE INDEX IF NOT EXISTS idx_tenant_domains_deleted_at ON tenant_domains(deleted_at);
