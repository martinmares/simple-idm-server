-- Performance optimization indexes
-- Composite a partial indexy pro zrychlení častých query patterns
--
-- Poznámka: Některé indexy už existují:
--   - oauth_clients.client_id má UNIQUE constraint (nepotřebujeme composite s is_active)
--   - groups.name má UNIQUE constraint (groups_name_key)
--   - claim_maps(client_id, group_id) má composite UNIQUE (pokrývá i samostatný group_id lookup částečně)

-- Unique constraint na user_groups (předejde duplikátům + composite index pro JOINy)
-- Tento index navíc může nahradit samostatné indexy na user_id a group_id v některých cases
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_groups_unique ON user_groups(user_id, group_id);

-- Claim maps group lookup (pro complex claim resolution když joinujeme přes group_id)
-- Composite UNIQUE na (client_id, group_id) nepokrývá efektivně WHERE group_id = X
CREATE INDEX IF NOT EXISTS idx_claim_maps_group_id ON claim_maps(group_id);

-- Composite index pro často používaný WHERE user_id = X AND expires_at > NOW()
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_expires ON refresh_tokens(user_id, expires_at);

-- Partial index pro aktivní OAuth klienty (pokud máme hodně neaktivních)
-- CREATE INDEX IF NOT EXISTS idx_oauth_clients_active ON oauth_clients(client_id) WHERE is_active = true;
-- Zakomentováno: Aktivuj pouze pokud > 20% klientů je is_active = false

-- Partial index pro aktivní uživatele (pokud je hodně neaktivních)
-- CREATE INDEX IF NOT EXISTS idx_users_username_active ON users(username) WHERE is_active = true;
-- CREATE INDEX IF NOT EXISTS idx_users_email_active ON users(email) WHERE is_active = true;
-- Zakomentováno: Aktivuj pouze pokud > 10% uživatelů je is_active = false
