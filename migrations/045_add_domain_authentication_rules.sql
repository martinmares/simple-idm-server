ALTER TABLE tenant_domains
    ADD COLUMN authentication_policy TEXT NOT NULL DEFAULT 'unrestricted'
        CHECK (authentication_policy IN ('unrestricted', 'local', 'federated', 'ad')),
    ADD COLUMN auth_provider_id UUID REFERENCES identity_providers(id) ON DELETE RESTRICT,
    ADD CONSTRAINT domain_authentication_provider_check CHECK (
        (authentication_policy IN ('unrestricted', 'local') AND auth_provider_id IS NULL)
        OR (authentication_policy IN ('federated', 'ad') AND auth_provider_id IS NOT NULL)
    );

CREATE FUNCTION authentication_rule_matches(policy TEXT, provider UUID, mode TEXT, user_provider UUID)
RETURNS BOOLEAN LANGUAGE SQL IMMUTABLE AS $$
    SELECT policy = 'unrestricted' OR
        (policy = mode AND (policy = 'local' OR provider = user_provider));
$$;

CREATE FUNCTION domain_authentication_allowed(owner UUID, email TEXT, mode TEXT, provider UUID)
RETURNS BOOLEAN LANGUAGE SQL STABLE AS $$
    SELECT COALESCE(bool_and(
        COALESCE(authentication_rule_matches(d.authentication_policy, d.auth_provider_id, mode, provider), false)
        AND (d.auth_provider_id IS NULL OR EXISTS (
            SELECT 1 FROM identity_providers ip WHERE ip.id = d.auth_provider_id
                AND ip.tenant_id = owner AND ip.is_active AND ip.deleted_at IS NULL
                AND ((d.authentication_policy = 'federated' AND ip.provider_type IN ('google', 'oidc'))
                    OR (d.authentication_policy = 'ad' AND ip.provider_type = 'ad_ldap'))
        ))
    ), true)
    FROM tenant_domains d WHERE d.tenant_id = owner
        AND lower(d.domain) = lower(split_part(email, '@', 2))
        AND d.is_active AND d.deleted_at IS NULL;
$$;

CREATE FUNCTION enforce_user_domain_authentication() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    -- Serialize user assignments and domain policy changes within the tenant.
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text, 45001));
    IF NEW.deleted_at IS NULL AND NOT domain_authentication_allowed(
        NEW.tenant_id, NEW.email, NEW.auth_mode, NEW.auth_provider_id
    ) THEN
        RAISE EXCEPTION 'Account authentication type or provider conflicts with email domain policy'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER enforce_user_domain_authentication
BEFORE INSERT OR UPDATE OF email, tenant_id, auth_mode, auth_provider_id, deleted_at ON users
FOR EACH ROW EXECUTE FUNCTION enforce_user_domain_authentication();

CREATE FUNCTION enforce_domain_authentication_rule() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text, 45001));
    IF NEW.is_active AND NEW.deleted_at IS NULL AND NEW.auth_provider_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM identity_providers ip WHERE ip.id = NEW.auth_provider_id
            AND ip.tenant_id = NEW.tenant_id AND ip.is_active AND ip.deleted_at IS NULL
            AND ((NEW.authentication_policy = 'federated' AND ip.provider_type IN ('google', 'oidc'))
                OR (NEW.authentication_policy = 'ad' AND ip.provider_type = 'ad_ldap'))
    ) THEN
        RAISE EXCEPTION 'Select an active provider of the matching type in the same tenant'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.is_active AND NEW.deleted_at IS NULL AND EXISTS (
        SELECT 1 FROM users u WHERE u.tenant_id = NEW.tenant_id AND u.deleted_at IS NULL
            AND lower(split_part(u.email, '@', 2)) = lower(NEW.domain)
            AND NOT COALESCE(authentication_rule_matches(
                NEW.authentication_policy, NEW.auth_provider_id, u.auth_mode, u.auth_provider_id
            ), false)
    ) THEN
        RAISE EXCEPTION 'Existing accounts conflict with the proposed domain authentication policy; adjust those accounts first'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER enforce_domain_authentication_rule
BEFORE INSERT OR UPDATE ON tenant_domains
FOR EACH ROW EXECUTE FUNCTION enforce_domain_authentication_rule();

CREATE OR REPLACE VIEW effective_user_auth_policies AS
SELECT u.id AS user_id, u.tenant_id,
       COALESCE(NULLIF(d.mfa_policy, 'inherit'), t.mfa_policy) AS mfa_policy,
       COALESCE(NULLIF(d.passkey_policy, 'inherit'), t.passkey_policy) AS passkey_policy
FROM users u
JOIN tenants t ON t.id = u.tenant_id
LEFT JOIN tenant_domains d
    ON d.tenant_id = u.tenant_id
    AND lower(d.domain) = lower(split_part(u.email, '@', 2))
    AND d.is_active AND d.deleted_at IS NULL
WHERE u.deleted_at IS NULL AND u.is_active
    AND t.deleted_at IS NULL AND t.is_active
    AND domain_authentication_allowed(u.tenant_id, u.email, u.auth_mode, u.auth_provider_id);
