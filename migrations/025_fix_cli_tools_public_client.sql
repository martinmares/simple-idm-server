-- Ensure cli-tools is treated as a public client.
-- Public clients must not have client_secret_hash.
UPDATE oauth_clients
SET
    is_public = true,
    client_secret_hash = NULL
WHERE client_id = 'cli-tools';
