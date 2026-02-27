-- Make key identity uniqueness tenant-scoped (single-default remains unchanged).

-- Drop legacy global unique constraints from init migration
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_key;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_name_key;

-- Tenant-scoped uniqueness
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_tenant_username ON users(tenant_id, username);
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_tenant_email ON users(tenant_id, email);
CREATE UNIQUE INDEX IF NOT EXISTS uq_groups_tenant_name ON groups(tenant_id, name);
