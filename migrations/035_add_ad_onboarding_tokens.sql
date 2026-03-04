-- One-time tokens for end-user AD onboarding flow (/ad/onboarding)
CREATE TABLE IF NOT EXISTS ad_onboarding_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ad_onboarding_tokens_user
    ON ad_onboarding_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_ad_onboarding_tokens_exp
    ON ad_onboarding_tokens(expires_at);
