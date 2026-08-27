-- MFA for identities managed locally by Simple IDM.
-- Federated identities continue to rely on the upstream identity provider.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS mfa_policy TEXT NOT NULL DEFAULT 'disabled'
    CHECK (mfa_policy IN ('disabled', 'optional', 'required'));

CREATE TABLE IF NOT EXISTS user_authenticators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('totp')),
    label TEXT NOT NULL DEFAULT 'Authenticator app',
    secret_encrypted TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'revoked')),
    verified_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    last_used_step BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_active_totp
    ON user_authenticators(user_id, kind)
    WHERE status IN ('pending', 'active');
CREATE INDEX IF NOT EXISTS idx_user_authenticators_user
    ON user_authenticators(tenant_id, user_id, status);

CREATE TABLE IF NOT EXISTS user_recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    authenticator_id UUID NOT NULL REFERENCES user_authenticators(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_recovery_codes_available
    ON user_recovery_codes(tenant_id, user_id, authenticator_id)
    WHERE used_at IS NULL;

-- Password verification creates a short-lived transaction. The raw browser
-- token is never persisted; only its SHA-256 digest is stored.
CREATE TABLE IF NOT EXISTS mfa_login_transactions (
    token_hash TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    state TEXT,
    code_challenge TEXT,
    code_challenge_method TEXT,
    nonce TEXT,
    stage TEXT NOT NULL CHECK (stage IN ('enroll', 'challenge', 'recovery-codes')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mfa_login_transactions_expiry
    ON mfa_login_transactions(expires_at);

ALTER TABLE authorization_codes
    ADD COLUMN IF NOT EXISTS amr TEXT[] NOT NULL DEFAULT ARRAY['pwd']::TEXT[],
    ADD COLUMN IF NOT EXISTS acr TEXT;

ALTER TABLE authentication_sessions
    ADD COLUMN IF NOT EXISTS amr TEXT[] NOT NULL DEFAULT ARRAY['pwd']::TEXT[],
    ADD COLUMN IF NOT EXISTS acr TEXT;

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS amr TEXT[] NOT NULL DEFAULT ARRAY['pwd']::TEXT[],
    ADD COLUMN IF NOT EXISTS acr TEXT;

ALTER TABLE used_refresh_tokens
    ADD COLUMN IF NOT EXISTS amr TEXT[] NOT NULL DEFAULT ARRAY['pwd']::TEXT[],
    ADD COLUMN IF NOT EXISTS acr TEXT;

ALTER TABLE device_codes
    ADD COLUMN IF NOT EXISTS amr TEXT[] NOT NULL DEFAULT ARRAY['pwd']::TEXT[],
    ADD COLUMN IF NOT EXISTS acr TEXT;

COMMENT ON COLUMN tenants.mfa_policy IS
    'MFA policy for locally managed users: disabled, optional, or required.';
COMMENT ON TABLE user_authenticators IS
    'Encrypted authenticators for locally managed users.';
COMMENT ON TABLE user_recovery_codes IS
    'One-time Argon2-hashed MFA recovery codes.';
