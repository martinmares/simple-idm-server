-- The default CLI is the designated admin audience. Other clients must be
-- explicitly registered and added to ADMIN_OAUTH_CLIENT_IDS.
UPDATE oauth_clients
SET scope = concat_ws(' ', scope,
    CASE WHEN NOT ('groups' = ANY(string_to_array(scope, ' '))) THEN 'groups' END,
    CASE WHEN NOT ('admin:*' = ANY(string_to_array(scope, ' '))) THEN 'admin:*' END)
WHERE client_id = 'cli-tools'
  AND tenant_id = '11111111-1111-1111-1111-111111111111';
