use crate::db::DbPool;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
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
                .into_response()
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

    // Verify and decode token
    match state.jwt_service.verify_token(token) {
        Ok(claims) => {
            if claims.aud.is_empty() {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "invalid_token".to_string(),
                        error_description: "Missing token audience".to_string(),
                    }),
                )
                    .into_response();
            }

            let aud_valid = has_valid_audience(&state.db_pool, &claims.aud)
                .await
                .unwrap_or_default();

            if !aud_valid {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "invalid_token".to_string(),
                        error_description: "Invalid token audience".to_string(),
                    }),
                )
                    .into_response();
            }

            let scope = claims.scope.as_deref().unwrap_or("");
            if !has_scope(scope, "openid") {
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "insufficient_scope".to_string(),
                        error_description: "Missing required scope: openid".to_string(),
                    }),
                )
                    .into_response();
            }

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
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "Invalid or expired token".to_string(),
            }),
        )
            .into_response(),
    }
}

async fn has_valid_audience(pool: &DbPool, audiences: &[String]) -> Result<bool, sqlx::Error> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM oauth_clients WHERE client_id = ANY($1) AND is_active = true",
    )
    .bind(audiences)
    .fetch_one(pool)
    .await?;

    Ok(count > 0)
}

fn has_scope(scope: &str, expected: &str) -> bool {
    scope
        .split_whitespace()
        .any(|value| value == expected)
}
