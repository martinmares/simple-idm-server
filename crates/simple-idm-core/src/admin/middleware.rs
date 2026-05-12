use crate::auth::JwtService;
use crate::config::Config;
use crate::db::DbPool;
use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use sqlx;
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
    pub allow_legacy_admin_group: bool,
    pub allow_admin_substring_claim: bool,
    pub jwt_service: Arc<JwtService>,
    pub db_pool: DbPool,
}

impl AdminAuth {
    pub fn new(config: &Config, jwt_service: Arc<JwtService>, db_pool: DbPool) -> Self {
        Self {
            admin_root_token: config.admin.root_token.clone(),
            allow_legacy_admin_group: config.admin.allow_legacy_admin_group,
            allow_admin_substring_claim: config.admin.allow_admin_substring_claim,
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
    let active_audiences = match load_active_client_ids(&admin_auth.db_pool).await {
        Ok(list) if !list.is_empty() => list,
        _ => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "unauthorized".to_string(),
                    error_description: "No active audiences available".to_string(),
                }),
            )
                .into_response());
        }
    };

    match admin_auth
        .jwt_service
        .verify_access_token(token, &active_audiences, &[])
    {
        Ok(claims) => {
            // Check if token has admin permissions
            // 1. Check groups for "simple-idm:role:admin" group (naming convention)
            if claims.groups.contains(&"simple-idm:role:admin".to_string()) {
                return Ok(next.run(request).await);
            }

            // 2. Optional backward compatibility for old "admin" group
            if admin_auth.allow_legacy_admin_group && claims.groups.contains(&"admin".to_string()) {
                tracing::warn!(
                    "User has deprecated 'admin' group - please migrate to 'simple-idm:role:admin'"
                );
                return Ok(next.run(request).await);
            }

            // 3. Optional legacy fallback: admin substring in custom claim key
            if admin_auth.allow_admin_substring_claim {
                for key in claims.custom_claims.keys() {
                    if key.starts_with("admin") || key.contains("admin") {
                        return Ok(next.run(request).await);
                    }
                }
            }

            // No admin permissions found
            Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "forbidden".to_string(),
                    error_description:
                        "Insufficient permissions - admin group or admin claims required"
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

async fn load_active_client_ids(db_pool: &DbPool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT client_id FROM oauth_clients WHERE is_active = true AND deleted_at IS NULL",
    )
    .fetch_all(db_pool)
    .await
}
