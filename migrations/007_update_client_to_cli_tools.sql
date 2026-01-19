-- Update existing simple-idm-ctl client to cli-tools
UPDATE oauth_clients
SET
    client_id = 'cli-tools',
    name = 'CLI Tools (simple-idm-ctl and custom tools)',
    scope = 'openid profile email groups'
WHERE client_id = 'simple-idm-ctl';

-- If the old client doesn't exist, insert the new one
INSERT INTO oauth_clients (
    id,
    client_id,
    client_secret_hash,
    name,
    redirect_uris,
    grant_types,
    scope,
    is_active,
    created_at
)
SELECT
    gen_random_uuid(),
    'cli-tools',
    '$argon2id$v=19$m=19456,t=2,p=1$VGhpc0lzQUR1bW15U2FsdEZvclB1YmxpY0NsaWVudA$dummy-hash-not-used',
    'CLI Tools (simple-idm-ctl and custom tools)',
    ARRAY['http://localhost:8888/callback', 'http://127.0.0.1:8888/callback'],
    ARRAY['authorization_code', 'refresh_token'],
    'openid profile email groups',
    true,
    NOW()
WHERE NOT EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = 'cli-tools');
