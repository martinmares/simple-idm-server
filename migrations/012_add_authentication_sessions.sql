-- Authentication Sessions table
-- Stores browser sessions for SSO (Single Sign-On)
-- When user logs in once, they don't need to re-enter credentials for other apps

CREATE TABLE authentication_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_token VARCHAR(255) UNIQUE NOT NULL, -- Random token stored in browser cookie
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Optional: override global session expiry per OAuth client
    -- If NULL, uses global AUTH_SESSION_EXPIRY from config
    client_id UUID REFERENCES oauth_clients(id) ON DELETE CASCADE,

    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_auth_sessions_token ON authentication_sessions(session_token);
CREATE INDEX idx_auth_sessions_user_id ON authentication_sessions(user_id);
CREATE INDEX idx_auth_sessions_expires ON authentication_sessions(expires_at);

-- Trigger to update last_used_at on session access
CREATE OR REPLACE FUNCTION update_auth_session_last_used()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_used_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_authentication_sessions_last_used
    BEFORE UPDATE ON authentication_sessions
    FOR EACH ROW
    EXECUTE FUNCTION update_auth_session_last_used();
