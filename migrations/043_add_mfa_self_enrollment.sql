-- Limit self-service TOTP enrollment to a recent authenticated session.
-- Attempts are counted in the database so refreshing the setup page cannot reset them.
CREATE TABLE mfa_self_enrollments (
    session_id UUID PRIMARY KEY REFERENCES authentication_sessions(id) ON DELETE CASCADE,
    authenticator_id UUID NOT NULL REFERENCES user_authenticators(id) ON DELETE CASCADE,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_self_enrollments_expiry ON mfa_self_enrollments(expires_at);
