CREATE TABLE IF NOT EXISTS auth_throttle (
    endpoint TEXT NOT NULL,
    identity_key TEXT NOT NULL,
    failures INTEGER NOT NULL DEFAULT 0,
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_until TIMESTAMPTZ NULL,
    PRIMARY KEY (endpoint, identity_key)
);

CREATE INDEX IF NOT EXISTS idx_auth_throttle_locked_until
    ON auth_throttle(locked_until);
