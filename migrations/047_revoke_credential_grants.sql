-- Serialize revocation with token exchanges through the user's row lock.
CREATE FUNCTION revoke_user_grants(owner UUID) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    PERFORM id FROM users WHERE id = owner FOR UPDATE;
    DELETE FROM authorization_codes WHERE user_id = owner;
    DELETE FROM refresh_tokens WHERE user_id = owner;
    DELETE FROM authentication_sessions WHERE user_id = owner;
    DELETE FROM device_codes WHERE user_id = owner;
    DELETE FROM mfa_login_transactions WHERE user_id = owner;
    DELETE FROM webauthn_authentication_transactions WHERE user_id = owner;
    DELETE FROM webauthn_registration_transactions WHERE user_id = owner;
END;
$$;

CREATE FUNCTION revoke_changed_user_credentials() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.password_hash IS DISTINCT FROM OLD.password_hash
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.password_disabled IS DISTINCT FROM OLD.password_disabled
       OR NEW.is_active IS DISTINCT FROM OLD.is_active
       OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at
       OR NEW.auth_mode IS DISTINCT FROM OLD.auth_mode
       OR NEW.auth_provider_id IS DISTINCT FROM OLD.auth_provider_id THEN
        PERFORM revoke_user_grants(NEW.id);
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER revoke_changed_user_credentials
AFTER UPDATE ON users FOR EACH ROW EXECUTE FUNCTION revoke_changed_user_credentials();

CREATE FUNCTION revoke_changed_authenticator() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status = 'revoked' AND OLD.status <> 'revoked' THEN
        PERFORM revoke_user_grants(NEW.user_id);
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER revoke_changed_authenticator
AFTER UPDATE ON user_authenticators FOR EACH ROW EXECUTE FUNCTION revoke_changed_authenticator();

CREATE FUNCTION revoke_changed_passkey() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL THEN
        PERFORM revoke_user_grants(NEW.user_id);
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER revoke_changed_passkey
AFTER UPDATE ON user_passkeys FOR EACH ROW EXECUTE FUNCTION revoke_changed_passkey();
