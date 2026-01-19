-- Vytvoření admin skupiny podle naming convention
INSERT INTO groups (id, name, description, created_at) VALUES (
    gen_random_uuid(),
    'simple-idm:role:admin',
    'Simple IDM Administrators - can use CLI tool and access /admin/* endpoints',
    NOW()
) ON CONFLICT (name) DO NOTHING;

-- Vytvoření seed admin usera
-- Heslo: admin (argon2 hash)
-- POZNÁMKA: V produkci změňte heslo po prvním přihlášení!
INSERT INTO users (id, username, email, password_hash, is_active, created_at, updated_at) VALUES (
    gen_random_uuid(),
    'admin',
    'admin@localhost',
    '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3ODkw$5Z0H5cF7uF8JZvJxKqYzN4qYxqKzYqZxKqYzN4qYxqK',
    true,
    NOW(),
    NOW()
) ON CONFLICT (username) DO NOTHING;

-- Přiřazení admin usera do admin skupiny
INSERT INTO user_groups (user_id, group_id)
SELECT u.id, g.id
FROM users u, groups g
WHERE u.username = 'admin' AND g.name = 'simple-idm:role:admin'
ON CONFLICT DO NOTHING;
