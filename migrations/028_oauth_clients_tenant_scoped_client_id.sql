-- Make oauth_clients.client_id unique per tenant (not globally)

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'oauth_clients_client_id_key'
    ) THEN
        ALTER TABLE oauth_clients DROP CONSTRAINT oauth_clients_client_id_key;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_clients_tenant_client_id
    ON oauth_clients(tenant_id, client_id);

CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id_active
    ON oauth_clients(client_id)
    WHERE is_active = true;
