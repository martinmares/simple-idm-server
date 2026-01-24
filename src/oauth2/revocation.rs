use crate::db::models::RefreshToken;
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use sqlx;
use std::sync::Arc;

use super::cleanup::cleanup_refresh_tokens;
use super::client_credentials::OAuth2State;
use super::utils::apply_client_auth;

#[derive(Debug, Deserialize)]
pub struct RevocationRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

pub async fn handle_revoke(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let mut req = match parse_revocation_request(&headers, &body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };

    apply_client_auth(&mut req.client_id, &mut req.client_secret, &headers);

    let client_id = match req.client_id {
        Some(id) => id,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Missing client_id".to_string(),
                }),
            )
                .into_response()
        }
    };

    let client_secret = match req.client_secret {
        Some(secret) => secret,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Missing client_secret".to_string(),
                }),
            )
                .into_response()
        }
    };

    let client = match sqlx::query_as::<_, crate::db::models::OAuthClient>(
        "SELECT * FROM oauth_clients WHERE client_id = $1 AND is_active = true",
    )
    .bind(&client_id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(client)) => client,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Invalid client credentials".to_string(),
                }),
            )
                .into_response()
        }
    };

    // Verify client secret
    match &client.client_secret_hash {
        Some(hash) if crate::auth::verify_password(&client_secret, hash).unwrap_or(false) => {
            // OK
        }
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Invalid client credentials".to_string(),
                }),
            )
                .into_response();
        }
    }

    cleanup_refresh_tokens(&state.db_pool).await;

    if req
        .token_type_hint
        .as_deref()
        .map(|hint| hint != "refresh_token")
        .unwrap_or(false)
    {
        return StatusCode::OK.into_response();
    }

    let refresh_token = match sqlx::query_as::<_, RefreshToken>(
        "SELECT * FROM refresh_tokens WHERE token = $1",
    )
    .bind(&req.token)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(rt)) => rt,
        _ => return StatusCode::OK.into_response(),
    };

    if refresh_token.client_id != client.id {
        return StatusCode::OK.into_response();
    }

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to start transaction".to_string(),
                }),
            )
                .into_response()
        }
    };

    if sqlx::query(
        r#"
        INSERT INTO used_refresh_tokens (token, client_id, user_id, scope, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(&refresh_token.token)
    .bind(refresh_token.client_id)
    .bind(refresh_token.user_id)
    .bind(&refresh_token.scope)
    .bind(refresh_token.expires_at)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to revoke token".to_string(),
            }),
        )
            .into_response();
    }

    if sqlx::query("DELETE FROM refresh_tokens WHERE token = $1")
        .bind(&refresh_token.token)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        let _ = tx.rollback().await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to revoke token".to_string(),
            }),
        )
            .into_response();
    }

    if tx.commit().await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to revoke token".to_string(),
            }),
        )
            .into_response();
    }

    StatusCode::OK.into_response()
}

fn parse_revocation_request(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<RevocationRequest, axum::response::Response> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    let parsed: Result<RevocationRequest, ()> = if content_type.starts_with("application/json") {
        serde_json::from_slice::<RevocationRequest>(body).map_err(|_| ())
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        serde_urlencoded::from_bytes::<RevocationRequest>(body).map_err(|_| ())
    } else if content_type.is_empty() {
        serde_json::from_slice::<RevocationRequest>(body)
            .map_err(|_| ())
            .or_else(|_| serde_urlencoded::from_bytes::<RevocationRequest>(body).map_err(|_| ()))
    } else {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Json(ErrorResponse {
                error: "unsupported_media_type".to_string(),
                error_description: "Expected Content-Type application/json or application/x-www-form-urlencoded".to_string(),
            }),
        )
            .into_response());
    };

    parsed.map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Failed to parse revocation request".to_string(),
            }),
        )
            .into_response()
    })
}
