-- Passkeys are separate from TOTP secrets. The WebAuthn public credential and
-- short lived server-side ceremony state are never sent back as browser state.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS passkey_policy TEXT NOT NULL DEFAULT 'disabled'
    CHECK (passkey_policy IN ('disabled', 'allowed'));

CREATE TABLE user_passkeys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    passkey_data JSONB NOT NULL,
    label TEXT NOT NULL,
    transports JSONB,
    backup_eligible BOOLEAN,
    backup_state BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_user_passkeys_active
    ON user_passkeys (tenant_id, user_id) WHERE revoked_at IS NULL;

CREATE TABLE webauthn_registration_transactions (
    token_hash TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ceremony_state JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webauthn_registration_expiry
    ON webauthn_registration_transactions (expires_at);

CREATE TABLE webauthn_authentication_transactions (
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
    ceremony_state JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webauthn_authentication_expiry
    ON webauthn_authentication_transactions (expires_at);
