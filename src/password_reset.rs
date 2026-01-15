use std::sync::Arc;

use axum::{
    extract::{Form, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx;
use uuid::Uuid;

use crate::auth::password::hash_password;
use crate::oauth2::templates;
use crate::oauth2::OAuth2State;

#[derive(Debug, Deserialize)]
pub struct PasswordResetQuery {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordResetForm {
    pub token: String,
    pub password: String,
    pub password_confirm: String,
}

pub struct PasswordResetTokenInfo {
    pub token: String,
    pub reset_url: String,
    pub expires_at: DateTime<Utc>,
}

pub async fn show_password_reset_form(
    State(state): State<Arc<OAuth2State>>,
    Query(query): Query<PasswordResetQuery>,
) -> impl IntoResponse {
    let token = query.token;

    match fetch_reset_token(&state, &token).await {
        Ok(_) => {
            let html = templates::password_reset_page(&token, None);
            (StatusCode::OK, Html(html)).into_response()
        }
        Err(err) => {
            let html = templates::error_page("invalid_token", &err);
            (StatusCode::BAD_REQUEST, Html(html)).into_response()
        }
    }
}

pub async fn submit_password_reset_form(
    State(state): State<Arc<OAuth2State>>,
    Form(form): Form<PasswordResetForm>,
) -> impl IntoResponse {
    if form.password != form.password_confirm {
        let html = templates::password_reset_page(&form.token, Some("Passwords do not match."));
        return (StatusCode::BAD_REQUEST, Html(html)).into_response();
    }

    let token_hash = hash_token(&form.token);

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            let html = templates::error_page("server_error", "Failed to start password reset.");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response();
        }
    };

    let record = sqlx::query!(
        r#"
        SELECT user_id, expires_at, used_at
        FROM password_reset_tokens
        WHERE token_hash = $1
        FOR UPDATE
        "#,
        token_hash
    )
    .fetch_optional(&mut *tx)
    .await;

    let Some(record) = record.ok().flatten() else {
        let _ = tx.rollback().await;
        let html = templates::error_page("invalid_token", "Reset token is invalid or expired.");
        return (StatusCode::BAD_REQUEST, Html(html)).into_response();
    };

    if record.used_at.is_some() || record.expires_at < Utc::now() {
        let _ = tx.rollback().await;
        let html = templates::error_page("invalid_token", "Reset token is invalid or expired.");
        return (StatusCode::BAD_REQUEST, Html(html)).into_response();
    }

    let password_hash = match hash_password(&form.password) {
        Ok(hash) => hash,
        Err(_) => {
            let _ = tx.rollback().await;
            let html = templates::error_page("server_error", "Failed to hash password.");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response();
        }
    };

    if sqlx::query!(
        r#"
        UPDATE users
        SET password_hash = $1, updated_at = NOW()
        WHERE id = $2
        "#,
        password_hash,
        record.user_id
    )
    .execute(&mut *tx)
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        let html = templates::error_page("server_error", "Failed to update password.");
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response();
    }

    if sqlx::query!(
        r#"
        UPDATE password_reset_tokens
        SET used_at = NOW()
        WHERE token_hash = $1
        "#,
        token_hash
    )
    .execute(&mut *tx)
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        let html = templates::error_page("server_error", "Failed to finalize reset token.");
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response();
    }

    let _ = sqlx::query!(
        r#"
        DELETE FROM password_reset_tokens
        WHERE user_id = $1 AND token_hash <> $2
        "#,
        record.user_id,
        token_hash
    )
    .execute(&mut *tx)
    .await;

    if tx.commit().await.is_err() {
        let html = templates::error_page("server_error", "Failed to finalize password reset.");
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response();
    }

    tracing::info!(user_id = %record.user_id, "Password reset completed");

    let html = templates::password_reset_success_page();
    (StatusCode::OK, Html(html)).into_response()
}

pub async fn create_reset_token_for_user(
    db_pool: &crate::db::DbPool,
    user_id: Uuid,
    issuer: &str,
    expiry_seconds: i64,
) -> Result<PasswordResetTokenInfo, sqlx::Error> {
    let token = generate_token();
    let token_hash = hash_token(&token);
    let expires_at = Utc::now() + Duration::seconds(expiry_seconds);

    sqlx::query!(
        r#"
        INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
        VALUES ($1, $2, $3)
        "#,
        user_id,
        token_hash,
        expires_at
    )
    .execute(db_pool)
    .await?;

    let reset_url = format!("{}/password/reset?token={}", issuer.trim_end_matches('/'), token);

    Ok(PasswordResetTokenInfo {
        token,
        reset_url,
        expires_at,
    })
}

pub async fn cleanup_password_reset_tokens(pool: &crate::db::DbPool) {
    let _ = sqlx::query(
        "DELETE FROM password_reset_tokens WHERE expires_at < NOW() OR used_at IS NOT NULL",
    )
    .execute(pool)
    .await;
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

async fn fetch_reset_token(state: &Arc<OAuth2State>, token: &str) -> Result<(), String> {
    let token_hash = hash_token(token);
    let record = sqlx::query!(
        r#"
        SELECT expires_at, used_at
        FROM password_reset_tokens
        WHERE token_hash = $1
        "#,
        token_hash
    )
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|_| "Reset token is invalid or expired.".to_string())?;

    let Some(record) = record else {
        return Err("Reset token is invalid or expired.".to_string());
    };

    if record.used_at.is_some() || record.expires_at < Utc::now() {
        return Err("Reset token is invalid or expired.".to_string());
    }

    Ok(())
}
