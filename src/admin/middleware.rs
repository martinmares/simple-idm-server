use crate::auth::JwtService;
use crate::config::Config;
use crate::db::DbPool;
use sqlx;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    error_description: String,
}

/// Admin authentication state
#[derive(Clone)]
pub struct AdminAuth {
    pub admin_root_token: Option<String>,
    pub jwt_service: Arc<JwtService>,
    pub db_pool: DbPool,
}

impl AdminAuth {
    pub fn new(config: &Config, jwt_service: Arc<JwtService>, db_pool: DbPool) -> Self {
        Self {
            admin_root_token: config.admin.root_token.clone(),
            jwt_service,
            db_pool,
        }
    }
}

/// Admin authentication middleware
///
/// Validates either:
/// 1. Bearer token with "admin:*" scope (M2M client)
/// 2. Root token from ADMIN_ROOT_TOKEN env var
pub async fn admin_auth_middleware(
    State(admin_auth): State<AdminAuth>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Get Authorization header
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "unauthorized".to_string(),
                    error_description: "Missing Authorization header".to_string(),
                }),
            )
                .into_response()
        })?;

    // Check if it starts with "Bearer "
    if !auth_header.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized".to_string(),
                error_description: "Invalid Authorization header format".to_string(),
            }),
        )
            .into_response());
    }

    let token = &auth_header[7..]; // Skip "Bearer "

    // Strategy 1: Check if it's the root token (development)
    if let Some(ref root_token) = admin_auth.admin_root_token {
        if token == root_token {
            // Root token valid - allow request
            return Ok(next.run(request).await);
        }
    }

    // Strategy 2: Verify JWT token and check for admin permissions
    match admin_auth.jwt_service.verify_token(token) {
        Ok(claims) => {
            if claims.aud.is_empty() {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "unauthorized".to_string(),
                        error_description: "Missing token audience".to_string(),
                    }),
                )
                    .into_response());
            }

            let aud_valid = match sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM oauth_clients WHERE client_id = ANY($1) AND is_active = true",
            )
            .bind(&claims.aud)
            .fetch_one(&admin_auth.db_pool)
            .await
            {
                Ok(count) => count > 0,
                Err(_) => false,
            };

            if !aud_valid {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "unauthorized".to_string(),
                        error_description: "Invalid token audience".to_string(),
                    }),
                )
                    .into_response());
            }

            // Check if token has admin permissions
            // 1. Check groups for "simple-idm:role:admin" group (naming convention)
            if claims.groups.contains(&"simple-idm:role:admin".to_string()) {
                return Ok(next.run(request).await);
            }

            // 2. DEPRECATED: Backward compatibility for old "admin" group
            if claims.groups.contains(&"admin".to_string()) {
                tracing::warn!(
                    "User has deprecated 'admin' group - please migrate to 'simple-idm:role:admin'"
                );
                return Ok(next.run(request).await);
            }

            // 3. Check custom claims for admin-related claims (fallback)
            for (key, _value) in &claims.custom_claims {
                if key.starts_with("admin") || key.contains("admin") {
                    return Ok(next.run(request).await);
                }
            }

            // No admin permissions found
            Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "forbidden".to_string(),
                    error_description: "Insufficient permissions - admin group or admin claims required"
                        .to_string(),
                }),
            )
                .into_response())
        }
        Err(_) => {
            // Invalid JWT token
            Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "unauthorized".to_string(),
                    error_description: "Invalid or expired token".to_string(),
                }),
            )
                .into_response())
        }
    }
}
