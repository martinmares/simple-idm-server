-- Existing maps remain available for remediation, but issuance rejects them.
ALTER TABLE claim_maps ADD CONSTRAINT claim_maps_no_reserved_names
CHECK (claim_name NOT IN ('iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'nonce',
    'scope', 'groups', 'amr', 'acr', 'tenant_id', 'credential_version', 'email', 'preferred_username',
    'azp', 'auth_time', 'at_hash', 'c_hash')) NOT VALID;
