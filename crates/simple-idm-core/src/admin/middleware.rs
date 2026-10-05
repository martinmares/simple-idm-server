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
    pub oauth_client_ids: Vec<String>,
    pub jwt_service: Arc<JwtService>,
    pub db_pool: DbPool,
}

impl AdminAuth {
    pub fn new(config: &Config, jwt_service: Arc<JwtService>, db_pool: DbPool) -> Self {
        Self {
            admin_root_token: config.admin.root_token.clone(),
            allow_legacy_admin_group: config.admin.allow_legacy_admin_group,
            allow_admin_substring_claim: config.admin.allow_admin_substring_claim,
            oauth_client_ids: std::env::var("ADMIN_OAUTH_CLIENT_IDS")
                .unwrap_or_else(|_| "cli-tools".into())
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
            jwt_service,
            db_pool,
        }
    }
    pub async fn validate_token(&self, token: &str) -> bool {
        if self
            .admin_root_token
            .as_ref()
            .is_some_and(|root| !root.is_empty() && token == root)
        {
            return true;
        }
        let claims =
            match self
                .jwt_service
                .verify_access_token(token, &self.oauth_client_ids, &["admin:*"])
            {
                Ok(claims) => claims,
                Err(_) => return false,
            };
        let default_tenant = uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let subject = match uuid::Uuid::parse_str(&claims.sub) {
            Ok(id) => id,
            Err(_) => return false,
        };
        let valid_client: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM oauth_clients c JOIN tenants t ON t.id = c.tenant_id WHERE c.client_id = ANY($1) AND c.client_id = ANY($2) AND c.tenant_id = $3 AND c.is_active AND c.deleted_at IS NULL AND t.is_active AND t.deleted_at IS NULL AND 'admin:*' = ANY(string_to_array(c.scope, ' ')))")
            .bind(&claims.aud).bind(&self.oauth_client_ids).bind(default_tenant).fetch_one(&self.db_pool).await.unwrap_or(false);
        if !valid_client {
            return false;
        }
        // Only a registered confidential admin client can act without a user.
        let m2m: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM oauth_clients WHERE id = $1 AND client_id = ANY($2) AND tenant_id = $3 AND is_active AND deleted_at IS NULL AND NOT is_public AND 'client_credentials' = ANY(grant_types))")
            .bind(subject).bind(&claims.aud).bind(default_tenant).fetch_one(&self.db_pool).await.unwrap_or(false);
        if m2m {
            return true;
        }
        let Some(version) = claims
            .custom_claims
            .get("credential_version")
            .and_then(serde_json::Value::as_i64)
        else {
            return false;
        };
        let user = match sqlx::query_as::<_, crate::db::models::User>("SELECT * FROM users WHERE id = $1 AND tenant_id = $2 AND is_active AND deleted_at IS NULL AND credential_version = $3")
            .bind(subject).bind(default_tenant).bind(version).fetch_optional(&self.db_pool).await {
            Ok(Some(user)) => user, _ => return false,
        };
        if !crate::auth_policy::accepts_authentication(&self.db_pool, &user, &claims.amr)
            .await
            .unwrap_or(false)
        {
            return false;
        }
        let groups = match crate::auth::get_effective_user_groups(&self.db_pool, subject).await {
            Ok(groups) => groups,
            Err(_) => return false,
        };
        let names = if self.allow_legacy_admin_group {
            vec!["simple-idm:role:admin", "admin"]
        } else {
            vec!["simple-idm:role:admin"]
        };
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM groups WHERE id = ANY($1) AND tenant_id = $2 AND name = ANY($3) AND deleted_at IS NULL AND NOT is_virtual)")
            .bind(groups).bind(default_tenant).bind(names).fetch_one(&self.db_pool).await.unwrap_or(false)
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

    if admin_auth.validate_token(token).await {
        Ok(next.run(request).await)
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized".into(),
                error_description: "Invalid administrator credentials".into(),
            }),
        )
            .into_response())
    }
}
