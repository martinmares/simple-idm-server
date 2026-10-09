-- An archived identity keeps its UUID, original username and linked history,
-- but no longer reserves the username for new accounts in the same tenant.
-- Disabled accounts still reserve their name until explicitly soft-deleted.
DROP INDEX uq_users_tenant_username;

CREATE UNIQUE INDEX uq_users_tenant_username_active
    ON users (tenant_id, username)
    WHERE deleted_at IS NULL;

-- Email uniqueness and external identity bindings are intentionally unchanged.
