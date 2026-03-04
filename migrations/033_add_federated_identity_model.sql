-- Federated identity model (OIDC broker-ready)
-- Keeps current local auth behavior as default.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS auth_mode TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS password_disabled BOOLEAN NOT NULL DEFAULT false;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'users_auth_mode_check'
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT users_auth_mode_check
            CHECK (auth_mode IN ('local', 'federated', 'mixed'));
    END IF;
END$$;

-- Allow federated users to exist without local password hash.
ALTER TABLE users
    ALTER COLUMN password_hash DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_auth_mode ON users(auth_mode);
CREATE INDEX IF NOT EXISTS idx_users_password_disabled ON users(password_disabled);

CREATE TABLE IF NOT EXISTS identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    slug VARCHAR(128) NOT NULL,
    provider_type VARCHAR(64) NOT NULL,
    issuer TEXT NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret_encrypted TEXT NOT NULL,
    auth_url TEXT,
    token_url TEXT,
    jwks_url TEXT,
    scopes TEXT[] NOT NULL DEFAULT ARRAY['openid', 'profile', 'email'],
    hd_domain VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_identity_providers_tenant_slug_active
    ON identity_providers(tenant_id, slug)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_identity_providers_tenant_issuer_client_active
    ON identity_providers(tenant_id, issuer, client_id)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_identity_providers_tenant_active
    ON identity_providers(tenant_id, is_active)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS user_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    idp_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    email_at_link VARCHAR(255),
    email_verified BOOLEAN,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_identities_tenant_idp_subject_active
    ON user_identities(tenant_id, idp_id, subject)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_identities_tenant_issuer_subject_active
    ON user_identities(tenant_id, issuer, subject)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_user_identities_user_active
    ON user_identities(user_id)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_user_identities_tenant_active
    ON user_identities(tenant_id)
    WHERE deleted_at IS NULL;
