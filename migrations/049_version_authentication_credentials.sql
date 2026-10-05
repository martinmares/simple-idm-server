ALTER TABLE users ADD COLUMN credential_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE authentication_sessions ADD COLUMN credential_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE mfa_login_transactions ADD COLUMN credential_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE webauthn_authentication_transactions ADD COLUMN credential_version BIGINT NOT NULL DEFAULT 0;

CREATE OR REPLACE FUNCTION revoke_user_grants(owner UUID) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    UPDATE users SET credential_version = credential_version + 1 WHERE id = owner;
    DELETE FROM authorization_codes WHERE user_id = owner;
    DELETE FROM refresh_tokens WHERE user_id = owner;
    DELETE FROM authentication_sessions WHERE user_id = owner;
    DELETE FROM device_codes WHERE user_id = owner;
    DELETE FROM mfa_login_transactions WHERE user_id = owner;
    DELETE FROM webauthn_authentication_transactions WHERE user_id = owner;
    DELETE FROM webauthn_registration_transactions WHERE user_id = owner;
END;
$$;
