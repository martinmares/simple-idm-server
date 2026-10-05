use crate::db::DbPool;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub struct UserinfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    #[serde(flatten)]
    pub custom_claims: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

/// Userinfo endpoint per OpenID Connect Core 1.0
///
/// Returns claims about the authenticated user
pub async fn handle_userinfo(
    State(state): State<Arc<super::client_credentials::OAuth2State>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Get Authorization header
    let auth_header = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        Some(h) => h,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: "Missing Authorization header".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Check Bearer token
    if !auth_header.starts_with("Bearer ") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Invalid Authorization header format".to_string(),
            }),
        )
            .into_response();
    }

    let token = &auth_header[7..]; // Skip "Bearer "

    let active_audiences = match load_active_client_ids(&state.db_pool).await {
        Ok(audiences) if !audiences.is_empty() => audiences,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_token".to_string(),
                    error_description: "No active audiences available".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Verify and decode token
    match state
        .jwt_service
        .verify_access_token(token, &active_audiences, &["openid"])
    {
        Ok(claims) => {
            let subject = uuid::Uuid::parse_str(&claims.sub).ok();
            let version = claims
                .custom_claims
                .get("credential_version")
                .and_then(serde_json::Value::as_i64);
            let current: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND credential_version = $2 AND is_active AND deleted_at IS NULL)")
                .bind(subject).bind(version).fetch_one(&state.db_pool).await.unwrap_or(false);
            if !current {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "invalid_token".into(),
                        error_description: "Authentication is no longer valid".into(),
                    }),
                )
                    .into_response();
            }
            let scope = claims.scope.as_deref().unwrap_or("");
            let email = if has_scope(scope, "email") {
                claims.email
            } else {
                None
            };

            let preferred_username = if has_scope(scope, "profile") {
                claims.preferred_username
            } else {
                None
            };

            let groups = if has_scope(scope, "groups") {
                Some(claims.groups)
            } else {
                None
            };

            let userinfo = UserinfoResponse {
                sub: claims.sub,
                email,
                preferred_username,
                groups,
                custom_claims: claims.custom_claims,
            };

            (StatusCode::OK, Json(userinfo)).into_response()
        }
        Err(err) => match err {
            crate::auth::jwt::JwtError::InsufficientScope => (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "insufficient_scope".to_string(),
                    error_description: "Missing required scope: openid".to_string(),
                }),
            )
                .into_response(),
            _ => (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_token".to_string(),
                    error_description: "Invalid or expired token".to_string(),
                }),
            )
                .into_response(),
        },
    }
}

async fn load_active_client_ids(pool: &DbPool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT client_id FROM oauth_clients WHERE is_active = true AND deleted_at IS NULL",
    )
    .fetch_all(pool)
    .await
}

fn has_scope(scope: &str, expected: &str) -> bool {
    scope.split_whitespace().any(|value| value == expected)
}
