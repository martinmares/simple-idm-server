ALTER TABLE user_identities
    ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'approved',
    ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'user_identities_approval_status_check'
    ) THEN
        ALTER TABLE user_identities
            ADD CONSTRAINT user_identities_approval_status_check
            CHECK (approval_status IN ('pending', 'approved', 'rejected'));
    END IF;
END $$;

UPDATE user_identities
SET approval_status = 'approved',
    approved_at = COALESCE(approved_at, NOW()),
    updated_at = NOW()
WHERE deleted_at IS NULL
  AND approval_status = 'approved'
  AND approved_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_user_identities_user_status_active
    ON user_identities(user_id, approval_status)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS federated_invitation_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    idp_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_federated_invitation_tokens_user
    ON federated_invitation_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_federated_invitation_tokens_idp
    ON federated_invitation_tokens(idp_id);

CREATE INDEX IF NOT EXISTS idx_federated_invitation_tokens_exp
    ON federated_invitation_tokens(expires_at);
