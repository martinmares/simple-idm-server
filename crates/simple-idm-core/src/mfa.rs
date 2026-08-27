use crate::auth::{hash_password, verify_password};
use crate::db::models::UserAuthenticator;
use crate::secret_crypto::{decrypt_secret, encrypt_secret};
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Duration, Utc};
use rand::{Rng, RngExt};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use totp_rs::{Builder, Secret, Totp};
use uuid::Uuid;

pub const MFA_TRANSACTION_TTL_SECONDS: i64 = 300;
pub const MAX_MFA_ATTEMPTS: i32 = 8;
pub const RECOVERY_CODE_COUNT: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaPolicy {
    Disabled,
    Optional,
    Required,
}

impl MfaPolicy {
    pub fn parse(value: &str) -> Self {
        match value {
            "required" => Self::Required,
            "optional" => Self::Optional,
            _ => Self::Disabled,
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct MfaLoginTransaction {
    pub token_hash: String,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub stage: String,
    pub attempts: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewMfaTransaction<'a> {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub state: Option<&'a str>,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub stage: &'a str,
}

pub fn transaction_token_hash(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn generate_transaction_token() -> String {
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

pub async fn create_login_transaction(
    pool: &PgPool,
    input: NewMfaTransaction<'_>,
) -> Result<String> {
    // MFA transactions are deliberately short lived. Clean them opportunistically
    // when a new transaction starts so an interrupted browser flow cannot leave
    // unbounded expired state behind.
    sqlx::query("DELETE FROM mfa_login_transactions WHERE expires_at <= NOW()")
        .execute(pool)
        .await?;

    let token = generate_transaction_token();
    let token_hash = transaction_token_hash(&token);
    let expires_at = Utc::now() + Duration::seconds(MFA_TRANSACTION_TTL_SECONDS);

    sqlx::query(
        r#"
        INSERT INTO mfa_login_transactions
          (token_hash, tenant_id, user_id, client_id, redirect_uri, scope, state,
           code_challenge, code_challenge_method, nonce, stage, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(token_hash)
    .bind(input.tenant_id)
    .bind(input.user_id)
    .bind(input.client_id)
    .bind(input.redirect_uri)
    .bind(input.scope)
    .bind(input.state)
    .bind(input.code_challenge)
    .bind(input.code_challenge_method)
    .bind(input.nonce)
    .bind(input.stage)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(token)
}

pub async fn load_login_transaction(pool: &PgPool, token: &str) -> Result<MfaLoginTransaction> {
    let row = sqlx::query_as::<_, MfaLoginTransaction>(
        r#"
        SELECT * FROM mfa_login_transactions
        WHERE token_hash = $1 AND expires_at > NOW() AND attempts < $2
        "#,
    )
    .bind(transaction_token_hash(token))
    .bind(MAX_MFA_ATTEMPTS)
    .fetch_optional(pool)
    .await?;
    row.ok_or_else(|| anyhow!("MFA transaction is invalid or expired"))
}

pub async fn register_failed_attempt(pool: &PgPool, token: &str) {
    let _ = sqlx::query(
        "UPDATE mfa_login_transactions SET attempts = attempts + 1 WHERE token_hash = $1",
    )
    .bind(transaction_token_hash(token))
    .execute(pool)
    .await;
}

pub async fn consume_login_transaction(pool: &PgPool, token: &str) -> Result<MfaLoginTransaction> {
    let row = sqlx::query_as::<_, MfaLoginTransaction>(
        r#"
        DELETE FROM mfa_login_transactions
        WHERE token_hash = $1 AND expires_at > NOW() AND attempts < $2
        RETURNING *
        "#,
    )
    .bind(transaction_token_hash(token))
    .bind(MAX_MFA_ATTEMPTS)
    .fetch_optional(pool)
    .await?;
    row.ok_or_else(|| anyhow!("MFA transaction is invalid or expired"))
}

pub async fn tenant_mfa_policy(pool: &PgPool, tenant_id: Uuid) -> Result<MfaPolicy> {
    let value = sqlx::query_scalar::<_, String>(
        "SELECT mfa_policy FROM tenants WHERE id = $1 AND is_active = true",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;
    Ok(MfaPolicy::parse(&value))
}

pub async fn active_totp_authenticator(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<UserAuthenticator>> {
    Ok(sqlx::query_as::<_, UserAuthenticator>(
        r#"
        SELECT * FROM user_authenticators
        WHERE user_id = $1 AND kind = 'totp' AND status = 'active'
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn pending_totp_authenticator(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<UserAuthenticator>> {
    Ok(sqlx::query_as::<_, UserAuthenticator>(
        r#"
        SELECT * FROM user_authenticators
        WHERE user_id = $1 AND kind = 'totp' AND status = 'pending'
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?)
}

fn build_totp(secret: &[u8], account_name: &str, issuer: &str) -> Result<Totp> {
    Builder::new()
        .with_secret(secret)
        .with_account_name(account_name)
        .with_issuer(Some(issuer))
        .build()
        .map_err(|err| anyhow!("Failed to construct TOTP: {err}"))
}

pub struct TotpEnrollment {
    pub authenticator_id: Uuid,
    pub base32_secret: String,
    pub otpauth_url: String,
}

pub async fn ensure_pending_totp(
    pool: &PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
    account_name: &str,
    issuer: &str,
) -> Result<TotpEnrollment> {
    let existing = sqlx::query_as::<_, UserAuthenticator>(
        r#"
        SELECT * FROM user_authenticators
        WHERE user_id = $1 AND kind = 'totp' AND status = 'pending'
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    let (authenticator_id, secret) = if let Some(existing) = existing {
        let secret = decrypt_secret(&existing.secret_encrypted)
            .context("Failed to decrypt pending TOTP secret")?;
        let secret = Secret::try_from_base32(secret).context("Invalid stored TOTP secret")?;
        (existing.id, secret)
    } else {
        let secret = Secret::generate();
        let encrypted = encrypt_secret(&secret.to_base32())?;
        let id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO user_authenticators
              (tenant_id, user_id, kind, label, secret_encrypted, status)
            VALUES ($1, $2, 'totp', 'Authenticator app', $3, 'pending')
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(encrypted)
        .fetch_one(pool)
        .await?;
        (id, secret)
    };

    let totp = build_totp(secret.as_bytes(), account_name, issuer)?;
    Ok(TotpEnrollment {
        authenticator_id,
        base32_secret: secret.to_base32(),
        otpauth_url: totp.to_url()?,
    })
}

pub async fn verify_totp(
    pool: &PgPool,
    authenticator: &UserAuthenticator,
    token: &str,
) -> Result<bool> {
    let encoded = decrypt_secret(&authenticator.secret_encrypted)?;
    let secret = Secret::try_from_base32(encoded).context("Invalid stored TOTP secret")?;
    let totp = build_totp(secret.as_bytes(), "verification", "Simple IDM")?;
    let Some(step) = totp.check_current(token.trim()) else {
        return Ok(false);
    };
    if authenticator
        .last_used_step
        .is_some_and(|previous| previous >= step as i64)
    {
        return Ok(false);
    }

    let result = sqlx::query(
        r#"
        UPDATE user_authenticators
        SET last_used_at = NOW(), last_used_step = $2, updated_at = NOW()
        WHERE id = $1 AND status IN ('pending', 'active')
          AND (last_used_step IS NULL OR last_used_step < $2)
        "#,
    )
    .bind(authenticator.id)
    .bind(step as i64)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn activate_totp_and_generate_recovery_codes(
    pool: &PgPool,
    authenticator: &UserAuthenticator,
) -> Result<Vec<String>> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE user_authenticators
        SET status = 'active', verified_at = NOW(), updated_at = NOW()
        WHERE id = $1 AND status = 'pending'
        "#,
    )
    .bind(authenticator.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1")
        .bind(authenticator.user_id)
        .execute(&mut *tx)
        .await?;

    let codes = generate_recovery_codes();
    for code in &codes {
        let hash = hash_password(code).map_err(|err| anyhow!(err.to_string()))?;
        sqlx::query(
            r#"
            INSERT INTO user_recovery_codes
              (tenant_id, user_id, authenticator_id, code_hash)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(authenticator.tenant_id)
        .bind(authenticator.user_id)
        .bind(authenticator.id)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(codes)
}

pub fn generate_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let mut bytes = [0u8; 10];
            rand::rng().fill_bytes(&mut bytes);
            const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            let encoded: String = bytes
                .iter()
                .flat_map(|byte| {
                    [
                        ALPHABET[(byte >> 3) as usize] as char,
                        ALPHABET[(byte & 0x1f) as usize] as char,
                    ]
                })
                .collect();
            format!(
                "{}-{}-{}-{}",
                &encoded[0..5],
                &encoded[5..10],
                &encoded[10..15],
                &encoded[15..20]
            )
        })
        .collect()
}

pub async fn consume_recovery_code(pool: &PgPool, user_id: Uuid, code: &str) -> Result<bool> {
    let rows = sqlx::query_as::<_, (Uuid, String)>(
        r#"
        SELECT id, code_hash FROM user_recovery_codes
        WHERE user_id = $1 AND used_at IS NULL
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    for (id, hash) in rows {
        if verify_password(&code.trim().to_ascii_uppercase(), &hash).unwrap_or(false) {
            let result = sqlx::query(
                "UPDATE user_recovery_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL",
            )
            .bind(id)
            .execute(pool)
            .await?;
            return Ok(result.rows_affected() == 1);
        }
    }
    Ok(false)
}

/// Revoke all locally managed MFA material and active login state for a user.
///
/// This is intentionally destructive: the next login follows the tenant policy
/// and, when MFA is required, starts a fresh enrollment.
pub async fn admin_reset_user_mfa(pool: &PgPool, user_id: Uuid) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let local_user = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND auth_mode = 'local' AND deleted_at IS NULL)",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if !local_user {
        return Ok(false);
    }

    sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        r#"
        UPDATE user_authenticators
        SET status = 'revoked', revoked_at = NOW(), updated_at = NOW()
        WHERE user_id = $1 AND status IN ('pending', 'active')
        "#,
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM mfa_login_transactions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM authentication_sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_codes_are_unique_and_human_readable() {
        let codes = generate_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        assert!(codes.iter().all(|code| code.len() == 23));
        let unique = codes.iter().collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), codes.len());
    }

    #[test]
    fn transaction_tokens_are_not_stored_verbatim() {
        let token = generate_transaction_token();
        let hash = transaction_token_hash(&token);
        assert_ne!(token, hash);
        assert_eq!(hash.len(), 64);
    }
}
