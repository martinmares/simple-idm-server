-- CRITICAL indexes pro prevenci full table scans
-- Tyto indexy jsou nezbytné pro základní funkčnost systému
--
-- Poznámka: Některé indexy už existují jako PRIMARY KEY nebo UNIQUE constraints:
--   - oauth_clients.client_id má UNIQUE constraint (oauth_clients_client_id_key)
--   - refresh_tokens.token je PRIMARY KEY
--   - used_refresh_tokens.token je PRIMARY KEY
--   - password_reset_tokens.token_hash má UNIQUE constraint
--   - claim_maps(client_id, group_id) má composite UNIQUE constraint

-- User-Group relationships (časté JOINy při každém login/token)
-- Bez těchto indexů může být full table scan na user_groups při každém loginu!
CREATE INDEX IF NOT EXISTS idx_user_groups_user_id ON user_groups(user_id);
CREATE INDEX IF NOT EXISTS idx_user_groups_group_id ON user_groups(group_id);

-- Authorization codes (lookup při každém authorization code flow)
CREATE UNIQUE INDEX IF NOT EXISTS idx_authorization_codes_code ON authorization_codes(code);

-- Device codes (lookup při device flow polling)
CREATE UNIQUE INDEX IF NOT EXISTS idx_device_codes_device_code ON device_codes(device_code);

-- Refresh tokens - index na user_id pro bulk revoke operations
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
