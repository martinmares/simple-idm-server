-- Testovací data pro simple-idm-server
-- Pro použití: psql -d simple_idm -f scripts/init_test_data.sql

-- Vyčisti staré testovací data
TRUNCATE users, groups, user_groups, oauth_clients, claim_maps, authorization_codes, refresh_tokens, device_codes CASCADE;

-- Create test users
-- Password: "password123" (argon2 hash)
INSERT INTO users (id, username, email, password_hash, is_active) VALUES
('00000000-0000-0000-0000-000000000001', 'admin', 'admin@example.com',
 '$argon2id$v=19$m=65536,t=3,p=4$ePAK9o/1G5iioJRvvAQSLw$0gCrMTQgancf+oe58JobXiv78J3mqnMINbK0cZmMK0E', true),
('00000000-0000-0000-0000-000000000002', 'user1', 'user1@example.com',
 '$argon2id$v=19$m=65536,t=3,p=4$ePAK9o/1G5iioJRvvAQSLw$0gCrMTQgancf+oe58JobXiv78J3mqnMINbK0cZmMK0E', true),
('00000000-0000-0000-0000-000000000003', 'user2', 'user2@example.com',
 '$argon2id$v=19$m=65536,t=3,p=4$ePAK9o/1G5iioJRvvAQSLw$0gCrMTQgancf+oe58JobXiv78J3mqnMINbK0cZmMK0E', true);

-- Vytvoř skupiny
INSERT INTO groups (id, name, description) VALUES
('10000000-0000-0000-0000-000000000001', 'admin', 'Administrators with full access'),
('10000000-0000-0000-0000-000000000002', 'users', 'Regular users'),
('10000000-0000-0000-0000-000000000003', 'reports', 'Users who can view reports'),
('10000000-0000-0000-0000-000000000004', 'billing', 'Users who can access billing'),
('10000000-0000-0000-0000-000000000005', 'analytics', 'Users who can access analytics');

-- Přiřaď uživatele do skupin
-- admin -> admin, users, reports, billing, analytics
INSERT INTO user_groups (user_id, group_id) VALUES
('00000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000001'),
('00000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000002'),
('00000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000003'),
('00000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000004'),
('00000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000005');

-- user1 -> users, reports
INSERT INTO user_groups (user_id, group_id) VALUES
('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000002'),
('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000003');

-- user2 -> users
INSERT INTO user_groups (user_id, group_id) VALUES
('00000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000002');

-- Create OAuth2 clients
-- Client secret: "client_secret_123" (argon2 hash)
INSERT INTO oauth_clients (id, client_id, client_secret_hash, name, redirect_uris, grant_types, scope, is_active) VALUES
-- M2M client
('20000000-0000-0000-0000-000000000001', 'api_service',
 '$argon2id$v=19$m=65536,t=3,p=4$+t1hwSa3uKlBfxgUbjpi2g$OQu5+EbwAmcVfV2DI8Eodi8gUgPb1pRSzT8T3PMPsjk',
 'API Service M2M',
 ARRAY[]::text[],
 ARRAY['client_credentials'],
 'api:read api:write',
 true),

-- Web application (authorization code flow + password for tests)
('20000000-0000-0000-0000-000000000002', 'webapp_dashboard',
 '$argon2id$v=19$m=65536,t=3,p=4$+t1hwSa3uKlBfxgUbjpi2g$OQu5+EbwAmcVfV2DI8Eodi8gUgPb1pRSzT8T3PMPsjk',
 'Dashboard Web App',
 ARRAY['http://localhost:3000/callback', 'http://localhost:3000/auth/callback'],
 ARRAY['authorization_code', 'refresh_token', 'password'],
 'openid profile email',
 true),

-- TV/Device application
('20000000-0000-0000-0000-000000000003', 'smart_tv_app',
 '$argon2id$v=19$m=65536,t=3,p=4$+t1hwSa3uKlBfxgUbjpi2g$OQu5+EbwAmcVfV2DI8Eodi8gUgPb1pRSzT8T3PMPsjk',
 'Smart TV Application',
 ARRAY[]::text[],
 ARRAY['urn:ietf:params:oauth:grant-type:device_code'],
 'openid profile',
 true);

-- Claim maps pro dashboard aplikaci
-- Dashboard potřebuje jen admin a reports skupiny
INSERT INTO claim_maps (client_id, group_id, claim_name) VALUES
('20000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000001', 'is_admin'),
('20000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000003', 'can_view_reports');

-- Claim maps pro TV aplikaci
-- TV app potřebuje jen users skupinu
INSERT INTO claim_maps (client_id, group_id, claim_name) VALUES
('20000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000002', 'is_user');

SELECT 'Test data initialized successfully!' as status;

-- Vypis přehled
SELECT 'Users:' as info;
SELECT username, email FROM users;

SELECT 'Groups:' as info;
SELECT name, description FROM groups;

SELECT 'OAuth Clients:' as info;
SELECT client_id, name, grant_types FROM oauth_clients;

SELECT 'User Groups:' as info;
SELECT u.username, g.name as group_name
FROM users u
JOIN user_groups ug ON u.id = ug.user_id
JOIN groups g ON ug.group_id = g.id
ORDER BY u.username, g.name;

SELECT 'Claim Maps:' as info;
SELECT oc.name as client_name, g.name as group_name, cm.claim_name
FROM claim_maps cm
JOIN oauth_clients oc ON cm.client_id = oc.id
JOIN groups g ON cm.group_id = g.id
ORDER BY oc.name, g.name;
