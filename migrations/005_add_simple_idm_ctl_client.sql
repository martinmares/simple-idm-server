-- OAuth2 klient pro simple-idm-ctl CLI
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
) VALUES (
    gen_random_uuid(),
    'simple-idm-ctl',
    '$argon2id$v=19$m=19456,t=2,p=1$VGhpc0lzQUR1bW15U2FsdEZvclB1YmxpY0NsaWVudA$dummy-hash-not-used',
    'simple-idm CLI Tool',
    ARRAY['http://localhost:8888/callback', 'http://127.0.0.1:8888/callback'],
    ARRAY['authorization_code', 'refresh_token'],
    'openid profile email',
    true,
    NOW()
) ON CONFLICT (client_id) DO NOTHING;
