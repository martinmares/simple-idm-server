//! Server-side WebAuthn ceremonies for locally managed users.
//!
//! `danger-allow-state-serialisation` is used only to persist ceremony state in
//! PostgreSQL. It must never be sent to a browser or stored in a client cookie.

use crate::config::WebauthnConfig;
use crate::db::models::OAuthClient;
use crate::mfa::{generate_transaction_token, transaction_token_hash};
use crate::oauth2::authorization_code::is_redirect_uri_allowed;
use anyhow::{Context, Result, anyhow, ensure};
use chrono::{Duration, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};

const CEREMONY_TTL_MINUTES: i64 = 5;

pub struct PasskeyService {
    webauthn: Webauthn,
}

#[derive(Debug, serde::Serialize, FromRow)]
pub struct PasskeySummary {
    pub id: Uuid,
    pub label: String,
    pub created_at: chrono::DateTime<Utc>,
    pub last_used_at: Option<chrono::DateTime<Utc>>,
    pub backup_eligible: Option<bool>,
    pub backup_state: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct PendingAuthorization {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

#[derive(FromRow)]
struct StoredPasskey {
    credential_id: Vec<u8>,
    passkey_data: Value,
}

#[derive(FromRow)]
struct RegistrationTransaction {
    tenant_id: Uuid,
    user_id: Uuid,
    ceremony_state: Value,
}

#[derive(FromRow)]
struct AuthenticationTransaction {
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    ceremony_state: Value,
}

impl PasskeyService {
    pub fn new(config: &WebauthnConfig) -> Result<Self> {
        ensure!(!config.rp_id.is_empty(), "WebAuthn RP ID is empty");
        ensure!(!config.origins.is_empty(), "WebAuthn origins are empty");
        let mut origins = Vec::with_capacity(config.origins.len());
        for raw in &config.origins {
            let origin = Url::parse(raw).context("Invalid WebAuthn origin")?;
            let is_loopback = matches!(origin.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
            ensure!(
                origin.scheme() == "https" || (origin.scheme() == "http" && is_loopback),
                "WebAuthn origin must use HTTPS outside localhost"
            );
            ensure!(
                origin.username().is_empty()
                    && origin.password().is_none()
                    && origin.query().is_none()
                    && origin.fragment().is_none()
                    && origin.path() == "/",
                "WebAuthn origin must contain only scheme, host and port"
            );
            origins.push(origin);
        }
        let mut builder = WebauthnBuilder::new(&config.rp_id, &origins[0])
            .context("Invalid WebAuthn RP ID or origin")?
            .rp_name(&config.rp_name);
        for origin in origins.iter().skip(1) {
            builder = builder.append_allowed_origin(origin);
        }
        Ok(Self {
            webauthn: builder.build()?,
        })
    }

    pub fn allows_origin(&self, origin: &str) -> bool {
        self.webauthn
            .get_allowed_origins()
            .iter()
            .any(|allowed| allowed.as_str().trim_end_matches('/') == origin)
    }

    pub async fn list(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<PasskeySummary>> {
        ensure!(
            local_user_allowed(pool, tenant_id, user_id).await?,
            "Passkeys are not allowed for this account"
        );
        Ok(sqlx::query_as(
            "SELECT id, label, created_at, last_used_at, backup_eligible, backup_state FROM user_passkeys WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL ORDER BY created_at DESC",
        )
        .bind(tenant_id).bind(user_id).fetch_all(pool).await?)
    }

    pub async fn rename(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        id: Uuid,
        label: &str,
    ) -> Result<bool> {
        let label = label.trim();
        ensure!(
            !label.is_empty() && label.chars().count() <= 100,
            "Invalid Passkey label"
        );
        ensure!(
            local_user_allowed(pool, tenant_id, user_id).await?,
            "Passkeys are not allowed for this account"
        );
        let changed = sqlx::query(
            "UPDATE user_passkeys SET label = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3 AND user_id = $4 AND revoked_at IS NULL",
        )
        .bind(label).bind(id).bind(tenant_id).bind(user_id).execute(pool).await?.rows_affected();
        Ok(changed == 1)
    }

    pub async fn revoke(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        id: Uuid,
    ) -> Result<bool> {
        let mut tx = pool.begin().await?;
        // Serialize concurrent removals for this user so two requests cannot
        // both remove the last remaining method.
        let password_available: bool = sqlx::query_scalar(
            "SELECT (NOT u.password_disabled AND u.password_hash IS NOT NULL) FROM users u JOIN tenants t ON t.id = u.tenant_id WHERE u.id = $1 AND u.tenant_id = $2 AND u.auth_mode = 'local' AND u.is_active = true AND u.deleted_at IS NULL AND t.is_active = true AND t.passkey_policy = 'allowed' FOR UPDATE OF u",
        )
        .bind(user_id).bind(tenant_id).fetch_optional(&mut *tx).await?
        .ok_or_else(|| anyhow!("Passkeys are not allowed for this account"))?;
        if !password_available {
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM user_passkeys WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL",
            )
            .bind(tenant_id).bind(user_id).fetch_one(&mut *tx).await?;
            ensure!(count > 1, "Cannot remove the last sign-in method");
        }
        let changed = sqlx::query(
            "UPDATE user_passkeys SET revoked_at = NOW(), updated_at = NOW() WHERE id = $1 AND tenant_id = $2 AND user_id = $3 AND revoked_at IS NULL",
        )
        .bind(id).bind(tenant_id).bind(user_id).execute(&mut *tx).await?.rows_affected();
        if changed == 1 {
            sqlx::query(
                "DELETE FROM authentication_sessions WHERE user_id = $1 AND 'webauthn' = ANY(amr)",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM webauthn_authentication_transactions WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(changed == 1)
    }

    pub async fn start_registration(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        email: &str,
        display_name: &str,
    ) -> Result<(String, CreationChallengeResponse)> {
        ensure!(
            local_user_allowed(pool, tenant_id, user_id).await?,
            "Passkeys are not allowed for this account"
        );
        let existing: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT credential_id FROM user_passkeys WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        let exclude = existing.into_iter().map(Into::into).collect();
        let (challenge, ceremony) = self.webauthn.start_passkey_registration(
            user_id,
            email,
            display_name,
            Some(exclude),
        )?;
        let token = generate_transaction_token();
        let state = serde_json::to_value(ceremony)?;
        sqlx::query("DELETE FROM webauthn_registration_transactions WHERE expires_at <= NOW()")
            .execute(pool)
            .await?;
        sqlx::query(
            "INSERT INTO webauthn_registration_transactions (token_hash, tenant_id, user_id, ceremony_state, expires_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(transaction_token_hash(&token)).bind(tenant_id).bind(user_id).bind(state)
        .bind(Utc::now() + Duration::minutes(CEREMONY_TTL_MINUTES))
        .execute(pool).await?;
        Ok((token, challenge))
    }

    pub async fn finish_registration(
        &self,
        pool: &PgPool,
        token: &str,
        tenant_id: Uuid,
        user_id: Uuid,
        label: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<Uuid> {
        let label = label.trim();
        ensure!(
            !label.is_empty() && label.chars().count() <= 100,
            "Invalid Passkey label"
        );
        let transaction = sqlx::query_as::<_, RegistrationTransaction>(
            "DELETE FROM webauthn_registration_transactions WHERE token_hash = $1 AND tenant_id = $2 AND user_id = $3 AND expires_at > NOW() RETURNING tenant_id, user_id, ceremony_state",
        )
        .bind(transaction_token_hash(token)).bind(tenant_id).bind(user_id)
        .fetch_optional(pool).await?.ok_or_else(|| anyhow!("Registration expired or already used"))?;
        ensure!(
            transaction.tenant_id == tenant_id && transaction.user_id == user_id,
            "Registration owner mismatch"
        );
        ensure!(
            local_user_allowed(pool, tenant_id, user_id).await?,
            "Passkeys are not allowed for this account"
        );
        let ceremony: PasskeyRegistration = serde_json::from_value(transaction.ceremony_state)?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &ceremony)?;
        let id = Uuid::new_v4();
        let credential_id: Vec<u8> = passkey.cred_id().as_ref().to_vec();
        let passkey_data = serde_json::to_value(passkey)?;
        sqlx::query(
            "INSERT INTO user_passkeys (id, tenant_id, user_id, credential_id, passkey_data, label) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id).bind(tenant_id).bind(user_id).bind(credential_id)
        .bind(passkey_data).bind(label).execute(pool).await
        .context("Credential ID has already been registered")?;
        Ok(id)
    }

    pub async fn start_authentication(
        &self,
        pool: &PgPool,
        pending: &PendingAuthorization,
    ) -> Result<(String, RequestChallengeResponse)> {
        ensure!(
            local_user_allowed(pool, pending.tenant_id, pending.user_id).await?,
            "Passkeys are not allowed for this account"
        );
        let client: OAuthClient = sqlx::query_as(
            "SELECT * FROM oauth_clients WHERE id = $1 AND tenant_id = $2 AND is_active = true AND deleted_at IS NULL",
        )
        .bind(pending.client_id)
        .bind(pending.tenant_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow!("OAuth client is not active for this tenant"))?;
        ensure!(
            is_redirect_uri_allowed(&client, &pending.redirect_uri),
            "OAuth redirect URI is not allowed"
        );
        let stored: Vec<StoredPasskey> = sqlx::query_as(
            "SELECT credential_id, passkey_data FROM user_passkeys WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(pending.tenant_id).bind(pending.user_id).fetch_all(pool).await?;
        ensure!(
            !stored.is_empty(),
            "No Passkeys are registered for this account"
        );
        let passkeys = stored
            .into_iter()
            .map(|row| serde_json::from_value::<Passkey>(row.passkey_data))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let (challenge, ceremony) = self.webauthn.start_passkey_authentication(&passkeys)?;
        let token = generate_transaction_token();
        sqlx::query("DELETE FROM webauthn_authentication_transactions WHERE expires_at <= NOW()")
            .execute(pool)
            .await?;
        sqlx::query(
            "INSERT INTO webauthn_authentication_transactions (token_hash, tenant_id, user_id, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, nonce, ceremony_state, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(transaction_token_hash(&token)).bind(pending.tenant_id).bind(pending.user_id)
        .bind(pending.client_id).bind(&pending.redirect_uri).bind(&pending.scope)
        .bind(&pending.state).bind(&pending.code_challenge).bind(&pending.code_challenge_method)
        .bind(&pending.nonce).bind(serde_json::to_value(ceremony)?)
        .bind(Utc::now() + Duration::minutes(CEREMONY_TTL_MINUTES))
        .execute(pool).await?;
        Ok((token, challenge))
    }

    pub async fn finish_authentication(
        &self,
        pool: &PgPool,
        token: &str,
        credential: &PublicKeyCredential,
    ) -> Result<PendingAuthorization> {
        let transaction = sqlx::query_as::<_, AuthenticationTransaction>(
            "DELETE FROM webauthn_authentication_transactions WHERE token_hash = $1 AND expires_at > NOW() RETURNING tenant_id, user_id, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, nonce, ceremony_state",
        )
        .bind(transaction_token_hash(token)).fetch_optional(pool).await?
        .ok_or_else(|| anyhow!("Authentication expired or already used"))?;
        ensure!(
            local_user_allowed(pool, transaction.tenant_id, transaction.user_id).await?,
            "Passkeys are not allowed for this account"
        );
        let client: OAuthClient = sqlx::query_as(
            "SELECT * FROM oauth_clients WHERE id = $1 AND tenant_id = $2 AND is_active = true AND deleted_at IS NULL",
        )
        .bind(transaction.client_id)
        .bind(transaction.tenant_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow!("OAuth client is no longer active"))?;
        ensure!(
            is_redirect_uri_allowed(&client, &transaction.redirect_uri),
            "OAuth redirect URI is no longer allowed"
        );
        let ceremony: PasskeyAuthentication = serde_json::from_value(transaction.ceremony_state)?;
        let result = self
            .webauthn
            .finish_passkey_authentication(credential, &ceremony)?;
        ensure!(result.user_verified(), "Passkey did not verify the user");
        let mut db_tx = pool.begin().await?;
        let row: StoredPasskey = sqlx::query_as(
            "SELECT credential_id, passkey_data FROM user_passkeys WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3 AND revoked_at IS NULL FOR UPDATE",
        )
        .bind(transaction.tenant_id).bind(transaction.user_id).bind(result.cred_id().as_ref())
        .fetch_optional(&mut *db_tx).await?.ok_or_else(|| anyhow!("Passkey is no longer active"))?;
        let mut passkey: Passkey = serde_json::from_value(row.passkey_data)?;
        ensure!(
            passkey.update_credential(&result).is_some(),
            "Credential mismatch"
        );
        sqlx::query("UPDATE user_passkeys SET passkey_data = $1, backup_eligible = $2, backup_state = $3, last_used_at = NOW(), updated_at = NOW() WHERE credential_id = $4")
            .bind(serde_json::to_value(passkey)?)
            .bind(result.backup_eligible())
            .bind(result.backup_state())
            .bind(row.credential_id)
            .execute(&mut *db_tx).await?;
        db_tx.commit().await?;
        Ok(PendingAuthorization {
            tenant_id: transaction.tenant_id,
            user_id: transaction.user_id,
            client_id: transaction.client_id,
            redirect_uri: transaction.redirect_uri,
            scope: transaction.scope,
            state: transaction.state,
            code_challenge: transaction.code_challenge,
            code_challenge_method: transaction.code_challenge_method,
            nonce: transaction.nonce,
        })
    }
}

async fn local_user_allowed(pool: &PgPool, tenant_id: Uuid, user_id: Uuid) -> Result<bool> {
    let allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users u JOIN tenants t ON t.id = u.tenant_id WHERE u.id = $1 AND u.tenant_id = $2 AND u.auth_mode = 'local' AND u.is_active = true AND u.deleted_at IS NULL AND t.is_active = true AND t.passkey_policy = 'allowed')",
    )
    .bind(user_id).bind(tenant_id).fetch_one(pool).await?;
    Ok(allowed)
}

/// Revokes every active passkey for a local user without touching TOTP or
/// recovery codes. A password-based sign-in path must remain available.
pub async fn admin_reset_user_passkeys(pool: &PgPool, user_id: Uuid) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let password_available: Option<bool> = sqlx::query_scalar(
        "SELECT (NOT password_disabled AND password_hash IS NOT NULL) FROM users WHERE id = $1 AND auth_mode = 'local' AND is_active = true AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(password_available) = password_available else {
        return Ok(false);
    };
    ensure!(
        password_available,
        "Cannot reset passkeys without another sign-in method"
    );
    let changed = sqlx::query(
        "UPDATE user_passkeys SET revoked_at = NOW(), updated_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Ok(false);
    }
    sqlx::query("DELETE FROM authentication_sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM webauthn_authentication_transactions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM webauthn_registration_transactions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(rp_id: &str, origin: &str) -> WebauthnConfig {
        WebauthnConfig {
            rp_id: rp_id.into(),
            rp_name: "Simple IDM".into(),
            origins: vec![origin.into()],
        }
    }

    #[test]
    fn accepts_matching_https_origin() {
        assert!(PasskeyService::new(&config("example.com", "https://idm.example.com")).is_ok());
    }

    #[test]
    fn rejects_unrelated_rp_id() {
        assert!(PasskeyService::new(&config("other.example", "https://idm.example.com")).is_err());
    }

    #[test]
    fn rejects_http_outside_loopback() {
        assert!(PasskeyService::new(&config("example.com", "http://idm.example.com")).is_err());
    }

    #[test]
    fn rejects_url_with_path_or_userinfo() {
        assert!(
            PasskeyService::new(&config("example.com", "https://idm.example.com/login")).is_err()
        );
        assert!(PasskeyService::new(&config("example.com", "https://u@idm.example.com")).is_err());
    }

    #[test]
    fn origin_comparison_is_exact() {
        let service = PasskeyService::new(&config("example.com", "https://idm.example.com"))
            .expect("valid origin");
        assert!(service.allows_origin("https://idm.example.com"));
        assert!(!service.allows_origin("https://idm.example.com.evil.test"));
        assert!(!service.allows_origin("http://idm.example.com"));
        assert!(!service.allows_origin("https://idm.example.com:8443"));
    }

    #[tokio::test]
    #[ignore = "requires a migrated PostgreSQL DATABASE_URL"]
    async fn postgres_registration_policy_and_admin_reset() {
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        let pool = PgPool::connect(&database_url).await.expect("PostgreSQL");
        let service = PasskeyService::new(&config("localhost", "http://localhost:8080"))
            .expect("WebAuthn service");
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = Uuid::new_v4().simple().to_string();
        let email = format!("passkey-{suffix}@example.test");
        sqlx::query("INSERT INTO tenants (id, slug, name, passkey_policy) VALUES ($1, $2, 'Passkey test', 'allowed')")
            .bind(tenant_id).bind(&suffix).execute(&pool).await.expect("tenant");
        sqlx::query("INSERT INTO users (id, tenant_id, username, email, password_hash) VALUES ($1, $2, $3, $4, 'test-hash')")
            .bind(user_id).bind(tenant_id).bind(&suffix).bind(&email)
            .execute(&pool).await.expect("user");

        let (token, options) = service
            .start_registration(&pool, tenant_id, user_id, &email, &email)
            .await
            .expect("registration start");
        assert!(!options.public_key.challenge.is_empty());
        let stored_hash: String = sqlx::query_scalar(
            "SELECT token_hash FROM webauthn_registration_transactions WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("transaction");
        assert_ne!(token, stored_hash);
        assert_eq!(stored_hash, transaction_token_hash(&token));

        sqlx::query("UPDATE tenants SET passkey_policy = 'disabled' WHERE id = $1")
            .bind(tenant_id)
            .execute(&pool)
            .await
            .expect("disable policy");
        assert!(
            service
                .start_registration(&pool, tenant_id, user_id, &email, &email)
                .await
                .is_err()
        );
        sqlx::query("UPDATE tenants SET passkey_policy = 'allowed' WHERE id = $1")
            .bind(tenant_id)
            .execute(&pool)
            .await
            .expect("enable policy");

        let passkey_id = Uuid::new_v4();
        sqlx::query("INSERT INTO user_passkeys (id, tenant_id, user_id, credential_id, passkey_data, label) VALUES ($1, $2, $3, $4, '{}'::jsonb, 'Test key')")
            .bind(passkey_id).bind(tenant_id).bind(user_id).bind(vec![1_u8, 2, 3, 4])
            .execute(&pool).await.expect("passkey");
        assert!(
            admin_reset_user_passkeys(&pool, user_id)
                .await
                .expect("admin reset")
        );
        let revoked: bool =
            sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM user_passkeys WHERE id = $1")
                .bind(passkey_id)
                .fetch_one(&pool)
                .await
                .expect("revocation status");
        assert!(revoked);
        assert!(
            !admin_reset_user_passkeys(&pool, user_id)
                .await
                .expect("second reset")
        );

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("cleanup user");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .execute(&pool)
            .await
            .expect("cleanup tenant");
    }
}
