use crate::audit;
use crate::auth::password::hash_password_async;
use crate::db::{DbPool, models::OAuthClient};
use crate::password_reset::{PasswordResetTokenInfo, create_reset_token_for_user};
use crate::secret_crypto::encrypt_secret;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{self, Row};
use std::env;
use url::Url;
use uuid::Uuid;

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub page: Option<i64>,
    pub limit: Option<i64>,
}

const DEFAULT_PAGE_LIMIT: i64 = 50;
const DEFAULT_TENANT_ID: &str = "11111111-1111-1111-1111-111111111111";

fn default_tenant_id() -> Uuid {
    Uuid::parse_str(DEFAULT_TENANT_ID).expect("DEFAULT_TENANT_ID must be valid UUID")
}

fn pagination_limit_offset(params: &PaginationParams) -> Result<(i64, i64), ErrorResponse> {
    let page = params.page.unwrap_or(1);
    let limit = match (params.page, params.limit) {
        (None, None) => i64::MAX,
        (_, Some(limit)) => limit,
        (Some(_), None) => DEFAULT_PAGE_LIMIT,
    };

    if page < 1 || limit < 1 {
        return Err(ErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "page and limit must be positive integers".to_string(),
        });
    }

    let offset = if limit == i64::MAX {
        0
    } else {
        limit.saturating_mul(page.saturating_sub(1))
    };
    Ok((limit, offset))
}

// User types
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub is_active: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub password: Option<String>,
    pub is_active: Option<bool>,
}

// Group types
#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub is_virtual: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_virtual: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct GroupResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub is_virtual: bool,
}

#[derive(Debug, Serialize)]
pub struct GroupTreeResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub is_virtual: bool,
    pub children: Vec<Uuid>, // IDs of direct children
}

// User-Group assignment
#[derive(Debug, Deserialize)]
pub struct AssignGroupRequest {
    pub group_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct UserGroupListRow {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub group_id: Uuid,
    pub group_name: String,
}

// OAuth Client types
#[derive(Debug, Deserialize)]
pub struct CreateOAuthClientRequest {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scope: String,
    pub is_public: Option<bool>, // true for public clients (no secret required)
    pub groups_claim_mode: Option<String>,
    pub include_claim_maps: Option<bool>,
    pub ignore_virtual_groups: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOAuthClientRequest {
    pub name: Option<String>,
    pub client_secret: Option<String>,
    pub is_public: Option<bool>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub scope: Option<String>,
    pub is_active: Option<bool>,
    pub groups_claim_mode: Option<String>,
    pub include_claim_maps: Option<bool>,
    pub ignore_virtual_groups: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct OAuthClientResponse {
    pub id: Uuid,
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scope: String,
    pub is_active: bool,
    pub is_public: bool,
    pub groups_claim_mode: String,
    pub include_claim_maps: bool,
    pub ignore_virtual_groups: bool,
}

// Tenant types
#[derive(Debug, Deserialize)]
pub struct CreateTenantRequest {
    pub slug: String,
    pub name: String,
    pub mode: Option<String>, // single|multi
    pub is_active: Option<bool>,
    pub mfa_policy: Option<String>,
    pub passkey_policy: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTenantRequest {
    pub slug: Option<String>,
    pub name: Option<String>,
    pub mode: Option<String>, // single|multi
    pub is_active: Option<bool>,
    pub mfa_policy: Option<String>,
    pub passkey_policy: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TenantResponse {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub mode: String,
    pub is_active: bool,
    pub mfa_policy: String,
    pub passkey_policy: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateTenantDomainRequest {
    pub authentication_policy: Option<String>,
    pub auth_provider_id: Option<Uuid>,
    pub mfa_policy: Option<String>,
    pub passkey_policy: Option<String>,
    pub domain: String,
    pub is_primary: Option<bool>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTenantDomainRequest {
    pub authentication_policy: Option<String>,
    pub auth_provider_id: Option<Uuid>,
    pub mfa_policy: Option<String>,
    pub passkey_policy: Option<String>,
    pub domain: Option<String>,
    pub is_primary: Option<bool>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TenantDomainResponse {
    pub authentication_policy: String,
    pub auth_provider_id: Option<Uuid>,
    pub mfa_policy: String,
    pub passkey_policy: String,
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub domain: String,
    pub is_primary: bool,
    pub is_active: bool,
}

// Federated Identity Provider types
#[derive(Debug, Deserialize)]
pub struct CreateIdentityProviderRequest {
    pub tenant_id: Option<Uuid>,
    pub slug: String,
    pub provider_type: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub jwks_url: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub hd_domain: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateIdentityProviderRequest {
    pub slug: Option<String>,
    pub provider_type: Option<String>,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub jwks_url: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub hd_domain: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct IdentityProviderResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub slug: String,
    pub provider_type: String,
    pub issuer: String,
    pub client_id: String,
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub jwks_url: Option<String>,
    pub scopes: Vec<String>,
    pub hd_domain: Option<String>,
    pub is_active: bool,
}

// Claim Map types
#[derive(Debug, Deserialize)]
pub struct CreateClaimMapRequest {
    pub client_id: Uuid,
    pub group_id: Uuid,
    pub claim_name: String,
    // Backward compatible: if claim_value is a string, use 'single' kind
    // If claim_value is an array, use 'array' kind
    #[serde(default)]
    pub claim_value: serde_json::Value, // Can be String or Array
}

#[derive(Debug, Serialize)]
pub struct ClaimMapResponse {
    pub id: Uuid,
    pub client_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<Uuid>, // Optional - can use patterns instead
    pub claim_name: String,
    pub claim_value_kind: String, // 'single' or 'array'
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_value: Option<serde_json::Value>, // String for single, Array for array
}

#[derive(Debug, Serialize)]
pub struct PasswordResetResponse {
    pub user_id: Uuid,
    pub reset_token: String,
    pub reset_url: String,
    pub expires_at: String,
}

fn normalize_tenant_mode(mode: Option<&str>) -> Result<&'static str, ErrorResponse> {
    match mode {
        None => Ok("single"),
        Some("single") => Ok("single"),
        Some("multi") => Ok("multi"),
        Some(_) => Err(ErrorResponse {
            error: "bad_request".to_string(),
            error_description: "mode must be one of: single, multi".to_string(),
        }),
    }
}

fn normalize_mfa_policy(policy: Option<&str>) -> Result<&'static str, ErrorResponse> {
    match policy {
        None | Some("disabled") => Ok("disabled"),
        Some("optional") => Ok("optional"),
        Some("required") => Ok("required"),
        Some(_) => Err(ErrorResponse {
            error: "bad_request".to_string(),
            error_description: "mfa_policy must be one of: disabled, optional, required"
                .to_string(),
        }),
    }
}

fn normalize_passkey_policy(policy: Option<&str>) -> Result<&'static str, ErrorResponse> {
    match policy {
        None | Some("disabled") => Ok("disabled"),
        Some("allowed") => Ok("allowed"),
        Some(_) => Err(ErrorResponse {
            error: "bad_request".to_string(),
            error_description: "passkey_policy must be one of: disabled, allowed".to_string(),
        }),
    }
}

// ============================================================================
// User Handlers
// ============================================================================

pub async fn create_user(
    State(db_pool): State<DbPool>,
    Json(req): Json<CreateUserRequest>,
) -> impl IntoResponse {
    let requested_username = req.username.clone();
    let requested_email = req.email.clone();
    let tenant_id = default_tenant_id();
    let conflict = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM users WHERE tenant_id = $1 AND deleted_at IS NULL AND (email = $2 OR username = $3) LIMIT 1",
    )
    .bind(tenant_id)
    .bind(&req.email)
    .bind(&req.username)
    .fetch_optional(&db_pool)
    .await;

    if let Ok(Some(_)) = conflict {
        audit::emit_event(
            &db_pool,
            "admin.user.create",
            "user",
            None,
            "failure",
            Some(serde_json::json!({
                "reason": "username_or_email_conflict",
                "username": requested_username,
                "email": requested_email,
            })),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".to_string(),
                error_description: "Username or email conflicts with an existing account"
                    .to_string(),
            }),
        )
            .into_response();
    }

    // Hash password
    let password_hash = match crate::auth::password::hash_user_password_async(&req.password).await {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!("Failed to hash password: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to hash password".to_string(),
                }),
            )
                .into_response();
        }
    };

    let is_active = req.is_active.unwrap_or(true);

    // Insert user
    let result = sqlx::query!(
        r#"
        INSERT INTO users (tenant_id, username, email, password_hash, is_active)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, username, email, is_active
        "#,
        tenant_id,
        req.username,
        req.email,
        password_hash,
        is_active
    )
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(user) => {
            audit::emit_event(
                &db_pool,
                "admin.user.create",
                "user",
                Some(user.id),
                "success",
                Some(serde_json::json!({
                    "username": user.username,
                    "email": user.email
                })),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(UserResponse {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    is_active: user.is_active,
                }),
            )
                .into_response()
        }
        Err(e) => {
            audit::emit_event(
                &db_pool,
                "admin.user.create",
                "user",
                None,
                "failure",
                Some(serde_json::json!({
                    "reason": e.to_string(),
                    "username": requested_username,
                    "email": requested_email,
                })),
            )
            .await;
            tracing::error!("Failed to create user: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to create user: {}", e),
                }),
            )
                .into_response()
        }
    }
}

pub async fn create_password_reset(
    State(db_pool): State<DbPool>,
    Path(user_id): Path<Uuid>,
) -> impl IntoResponse {
    let user_exists = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&db_pool)
    .await;

    if let Ok(None) = user_exists {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                error_description: "User not found".to_string(),
            }),
        )
            .into_response();
    }

    let expiry_seconds = env::var("PASSWORD_RESET_TOKEN_EXPIRY_SECONDS")
        .unwrap_or_else(|_| "3600".to_string())
        .parse()
        .unwrap_or(3600);
    let max_per_hour = env::var("PASSWORD_RESET_MAX_PER_HOUR")
        .unwrap_or_else(|_| "5".to_string())
        .parse()
        .unwrap_or(5);
    let recent_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 hour'",
    )
    .bind(user_id)
    .fetch_one(&db_pool)
    .await;

    if let Ok(count) = recent_count {
        if count >= max_per_hour {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: "rate_limited".to_string(),
                    error_description: "Too many reset requests for this user".to_string(),
                }),
            )
                .into_response();
        }
    }
    let issuer = env::var("JWT_ISSUER").unwrap_or_else(|_| "http://localhost:8080".to_string());

    let PasswordResetTokenInfo {
        token,
        reset_url,
        expires_at,
    } = match create_reset_token_for_user(&db_pool, user_id, &issuer, expiry_seconds).await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("Failed to create password reset token: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to create password reset token".to_string(),
                }),
            )
                .into_response();
        }
    };

    tracing::info!(
        user_id = %user_id,
        expires_at = %expires_at,
        "Created password reset token"
    );

    (
        StatusCode::CREATED,
        Json(PasswordResetResponse {
            user_id,
            reset_token: token,
            reset_url,
            expires_at: expires_at.to_rfc3339(),
        }),
    )
        .into_response()
}

pub async fn list_users(
    State(db_pool): State<DbPool>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let tenant_id = default_tenant_id();
    let (limit, offset) = match pagination_limit_offset(&pagination) {
        Ok(pagination) => pagination,
        Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
    };

    let result = sqlx::query!(
        r#"
        SELECT id, username, email, is_active
        FROM users
        WHERE tenant_id = $1 AND deleted_at IS NULL
        ORDER BY username
        LIMIT $2 OFFSET $3
        "#,
        tenant_id,
        limit,
        offset
    )
    .fetch_all(&db_pool)
    .await;

    match result {
        Ok(users) => {
            let users: Vec<UserResponse> = users
                .into_iter()
                .map(|u| UserResponse {
                    id: u.id,
                    username: u.username,
                    email: u.email,
                    is_active: u.is_active,
                })
                .collect();
            (StatusCode::OK, Json(users)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to list users: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to list users".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn update_user(
    State(db_pool): State<DbPool>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<UpdateUserRequest>,
) -> impl IntoResponse {
    let tenant_id = default_tenant_id();
    let email = req.email.clone();
    if let Some(email) = &email {
        let conflict = sqlx::query_scalar::<_, i64>(
            "SELECT 1 FROM users WHERE tenant_id = $1 AND deleted_at IS NULL AND username = $2 AND id <> $3 LIMIT 1",
        )
        .bind(tenant_id)
        .bind(email)
        .bind(user_id)
        .fetch_optional(&db_pool)
        .await;

        if let Ok(Some(_)) = conflict {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: "Email conflicts with an existing username".to_string(),
                }),
            )
                .into_response();
        }
    }

    let password_hash = if let Some(password) = &req.password {
        match crate::auth::password::hash_user_password_async(password).await {
            Ok(hash) => Some(hash),
            Err(e) => {
                tracing::error!("Failed to hash password: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        error_description: "Failed to hash password".to_string(),
                    }),
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    if email.is_none() && password_hash.is_none() && req.is_active.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".to_string(),
                error_description: "No fields to update".to_string(),
            }),
        )
            .into_response();
    }

    let result = sqlx::query!(
        r#"
        UPDATE users
        SET
            email = COALESCE($1, email),
            password_hash = COALESCE($2, password_hash),
            is_active = COALESCE($3, is_active),
            updated_at = NOW()
        WHERE id = $4 AND tenant_id = $5 AND deleted_at IS NULL
        RETURNING id, username, email, is_active
        "#,
        email,
        password_hash,
        req.is_active,
        user_id,
        tenant_id
    )
    .fetch_optional(&db_pool)
    .await;

    match result {
        Ok(Some(user)) => {
            audit::emit_event(
                &db_pool,
                "admin.user.update",
                "user",
                Some(user.id),
                "success",
                None,
            )
            .await;
            (
                StatusCode::OK,
                Json(UserResponse {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    is_active: user.is_active,
                }),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                error_description: "User not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            audit::emit_event(
                &db_pool,
                "admin.user.update",
                "user",
                Some(user_id),
                "failure",
                Some(serde_json::json!({ "reason": e.to_string() })),
            )
            .await;
            tracing::error!("Failed to update user: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to update user".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn delete_user(
    State(db_pool): State<DbPool>,
    Path(user_id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query(
        "UPDATE users SET is_active = false, deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
    )
        .bind(user_id)
        .execute(&db_pool)
        .await;

    match result {
        Ok(result) => {
            if result.rows_affected() == 0 {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        error_description: "User not found".to_string(),
                    }),
                )
                    .into_response()
            } else {
                audit::emit_event(
                    &db_pool,
                    "admin.user.delete",
                    "user",
                    Some(user_id),
                    "success",
                    None,
                )
                .await;
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "User soft-deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
            audit::emit_event(
                &db_pool,
                "admin.user.delete",
                "user",
                Some(user_id),
                "failure",
                Some(serde_json::json!({ "reason": e.to_string() })),
            )
            .await;
            tracing::error!("Failed to delete user: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to delete user".to_string(),
                }),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Group Handlers
// ============================================================================

pub async fn create_group(
    State(db_pool): State<DbPool>,
    Json(req): Json<CreateGroupRequest>,
) -> impl IntoResponse {
    let tenant_id = default_tenant_id();
    let result = sqlx::query!(
        r#"
        INSERT INTO groups (tenant_id, name, description, is_virtual)
        VALUES ($1, $2, $3, $4)
        RETURNING id, name, description, is_virtual
        "#,
        tenant_id,
        req.name,
        req.description,
        req.is_virtual.unwrap_or(false)
    )
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(group) => {
            audit::emit_event(
                &db_pool,
                "admin.group.create",
                "group",
                Some(group.id),
                "success",
                Some(serde_json::json!({ "name": group.name })),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(GroupResponse {
                    id: group.id,
                    name: group.name,
                    description: group.description,
                    is_virtual: group.is_virtual,
                }),
            )
                .into_response()
        }
        Err(e) => {
            audit::emit_event(
                &db_pool,
                "admin.group.create",
                "group",
                None,
                "failure",
                Some(serde_json::json!({ "reason": e.to_string() })),
            )
            .await;
            tracing::error!("Failed to create group: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to create group: {}", e),
                }),
            )
                .into_response()
        }
    }
}

pub async fn update_group(
    State(db_pool): State<DbPool>,
    Path(group_id): Path<Uuid>,
    Json(req): Json<UpdateGroupRequest>,
) -> impl IntoResponse {
    let tenant_id = default_tenant_id();
    if req.name.is_none() && req.description.is_none() && req.is_virtual.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".to_string(),
                error_description: "No fields to update".to_string(),
            }),
        )
            .into_response();
    };

    if let Some(name) = &req.name {
        let conflict = sqlx::query_scalar::<_, i64>(
            "SELECT 1 FROM groups WHERE tenant_id = $1 AND deleted_at IS NULL AND name = $2 AND id <> $3 LIMIT 1",
        )
        .bind(tenant_id)
        .bind(name)
        .bind(group_id)
        .fetch_optional(&db_pool)
        .await;

        if let Ok(Some(_)) = conflict {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: "Group name already exists".to_string(),
                }),
            )
                .into_response();
        }
    }

    let result = sqlx::query!(
        r#"
        UPDATE groups
        SET
            name = COALESCE($1, name),
            description = COALESCE($2, description),
            is_virtual = COALESCE($3, is_virtual)
        WHERE id = $4 AND tenant_id = $5 AND deleted_at IS NULL
        RETURNING id, name, description, is_virtual
        "#,
        req.name,
        req.description,
        req.is_virtual,
        group_id,
        tenant_id
    )
    .fetch_optional(&db_pool)
    .await;

    match result {
        Ok(Some(group)) => {
            audit::emit_event(
                &db_pool,
                "admin.group.update",
                "group",
                Some(group.id),
                "success",
                None,
            )
            .await;
            (
                StatusCode::OK,
                Json(GroupResponse {
                    id: group.id,
                    name: group.name,
                    description: group.description,
                    is_virtual: group.is_virtual,
                }),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                error_description: "Group not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            audit::emit_event(
                &db_pool,
                "admin.group.update",
                "group",
                Some(group_id),
                "failure",
                Some(serde_json::json!({ "reason": e.to_string() })),
            )
            .await;
            tracing::error!("Failed to update group: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to update group".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn list_groups(
    State(db_pool): State<DbPool>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let tenant_id = default_tenant_id();
    let (limit, offset) = match pagination_limit_offset(&pagination) {
        Ok(pagination) => pagination,
        Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
    };

    let result = sqlx::query!(
        r#"
        SELECT id, name, description, is_virtual
        FROM groups
        WHERE tenant_id = $1 AND deleted_at IS NULL
        ORDER BY name
        LIMIT $2 OFFSET $3
        "#,
        tenant_id,
        limit,
        offset
    )
    .fetch_all(&db_pool)
    .await;

    match result {
        Ok(groups) => {
            let groups: Vec<GroupResponse> = groups
                .into_iter()
                .map(|g| GroupResponse {
                    id: g.id,
                    name: g.name,
                    description: g.description,
                    is_virtual: g.is_virtual,
                })
                .collect();
            (StatusCode::OK, Json(groups)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to list groups: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to list groups".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn list_user_groups(
    State(db_pool): State<DbPool>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let tenant_id = default_tenant_id();
    let (limit, offset) = match pagination_limit_offset(&pagination) {
        Ok(pagination) => pagination,
        Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
    };

    let result = sqlx::query!(
        r#"
        SELECT
            ug.user_id,
            u.username,
            u.email,
            ug.group_id,
            g.name as group_name
        FROM user_groups ug
        JOIN users u ON u.id = ug.user_id
        JOIN groups g ON g.id = ug.group_id
        WHERE ug.tenant_id = $1
          AND u.deleted_at IS NULL
          AND g.deleted_at IS NULL
        ORDER BY u.username, g.name
        LIMIT $2 OFFSET $3
        "#,
        tenant_id,
        limit,
        offset
    )
    .fetch_all(&db_pool)
    .await;

    match result {
        Ok(rows) => {
            let rows: Vec<UserGroupListRow> = rows
                .into_iter()
                .map(|row| UserGroupListRow {
                    user_id: row.user_id,
                    username: row.username,
                    email: row.email,
                    group_id: row.group_id,
                    group_name: row.group_name,
                })
                .collect();
            (StatusCode::OK, Json(rows)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to list user groups: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to list user groups".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn delete_group(
    State(db_pool): State<DbPool>,
    Path(group_id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query(
        "UPDATE groups SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
    )
        .bind(group_id)
        .execute(&db_pool)
        .await;

    match result {
        Ok(result) => {
            if result.rows_affected() == 0 {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        error_description: "Group not found".to_string(),
                    }),
                )
                    .into_response()
            } else {
                audit::emit_event(
                    &db_pool,
                    "admin.group.delete",
                    "group",
                    Some(group_id),
                    "success",
                    None,
                )
                .await;
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "Group soft-deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
            audit::emit_event(
                &db_pool,
                "admin.group.delete",
                "group",
                Some(group_id),
                "failure",
                Some(serde_json::json!({ "reason": e.to_string() })),
            )
            .await;
            tracing::error!("Failed to delete group: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to delete group".to_string(),
                }),
            )
                .into_response()
        }
    }
}

// ============================================================================
// User-Group Assignment Handlers
// ============================================================================

pub async fn assign_user_to_group(
    State(db_pool): State<DbPool>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<AssignGroupRequest>,
) -> impl IntoResponse {
    let result = sqlx::query!(
        "INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)",
        user_id,
        req.group_id
    )
    .execute(&db_pool)
    .await;

    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(SuccessResponse {
                message: "User assigned to group successfully".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to assign user to group: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to assign user to group: {}", e),
                }),
            )
                .into_response()
        }
    }
}

pub async fn remove_user_from_group(
    State(db_pool): State<DbPool>,
    Path((user_id, group_id)): Path<(Uuid, Uuid)>,
) -> impl IntoResponse {
    let result = sqlx::query!(
        "DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2",
        user_id,
        group_id
    )
    .execute(&db_pool)
    .await;

    match result {
        Ok(result) => {
            if result.rows_affected() == 0 {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        error_description: "User-group assignment not found".to_string(),
                    }),
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "User removed from group successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
            tracing::error!("Failed to remove user from group: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to remove user from group".to_string(),
                }),
            )
                .into_response()
        }
    }
}

// ============================================================================
// OAuth Client Handlers
// ============================================================================

pub async fn create_oauth_client(
    State(db_pool): State<DbPool>,
    Json(req): Json<CreateOAuthClientRequest>,
) -> impl IntoResponse {
    let requested_client_id = req.client_id.clone();
    let groups_claim_mode = match req.groups_claim_mode.as_deref() {
        None | Some("effective") => "effective",
        Some("direct") => "direct",
        Some("none") => "none",
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: "groups_claim_mode must be one of: effective, direct, none"
                        .to_string(),
                }),
            )
                .into_response();
        }
    };
    let include_claim_maps = req.include_claim_maps.unwrap_or(true);
    let ignore_virtual_groups = req.ignore_virtual_groups.unwrap_or(false);
    let is_public = req.is_public.unwrap_or(false);

    if let Err(resp) = validate_redirect_uris(&req.client_id, &req.redirect_uris) {
        return *resp;
    }

    // Validate: public clients must NOT have secret, confidential clients MUST have secret
    let client_secret_hash = if is_public {
        // Public client - must NOT have secret
        if let Some(ref secret) = req.client_secret {
            if !secret.trim().is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "bad_request".to_string(),
                        error_description: "Public clients cannot have client_secret. Set is_public=false or remove client_secret.".to_string(),
                    }),
                )
                    .into_response();
            }
        }
        None
    } else {
        // Confidential client - MUST have secret
        match &req.client_secret {
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "bad_request".to_string(),
                        error_description:
                            "Confidential clients (is_public=false) must have client_secret"
                                .to_string(),
                    }),
                )
                    .into_response();
            }
            Some(secret) if secret.trim().is_empty() => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "bad_request".to_string(),
                        error_description:
                            "Confidential clients (is_public=false) must have client_secret"
                                .to_string(),
                    }),
                )
                    .into_response();
            }
            Some(secret) => {
                // Hash secret
                match hash_password_async(secret).await {
                    Ok(hash) => Some(hash),
                    Err(e) => {
                        tracing::error!("Failed to hash client secret: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse {
                                error: "server_error".to_string(),
                                error_description: "Failed to hash client secret".to_string(),
                            }),
                        )
                            .into_response();
                    }
                }
            }
        }
    };

    let result = sqlx::query!(
        r#"
        INSERT INTO oauth_clients (
            tenant_id, client_id, client_secret_hash, name, redirect_uris, grant_types, scope, is_active, is_public,
            groups_claim_mode, include_claim_maps, ignore_virtual_groups
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8, $9, $10, $11)
        RETURNING id, client_id, name, redirect_uris, grant_types, scope, is_active, is_public,
            groups_claim_mode, include_claim_maps, ignore_virtual_groups
        "#,
        default_tenant_id(),
        req.client_id,
        client_secret_hash,
        req.name,
        &req.redirect_uris,
        &req.grant_types,
        req.scope,
        is_public,
        groups_claim_mode,
        include_claim_maps,
        ignore_virtual_groups
    )
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(client) => {
            audit::emit_event(
                &db_pool,
                "admin.client.create",
                "oauth_client",
                Some(client.id),
                "success",
                Some(serde_json::json!({ "client_id": client.client_id })),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(OAuthClientResponse {
                    id: client.id,
                    client_id: client.client_id,
                    name: client.name,
                    redirect_uris: client.redirect_uris,
                    grant_types: client.grant_types,
                    scope: client.scope,
                    is_active: client.is_active,
                    is_public: client.is_public,
                    groups_claim_mode: client.groups_claim_mode,
                    include_claim_maps: client.include_claim_maps,
                    ignore_virtual_groups: client.ignore_virtual_groups,
                }),
            )
                .into_response()
        }
        Err(e) => {
            audit::emit_event(
                &db_pool,
                "admin.client.create",
                "oauth_client",
                None,
                "failure",
                Some(serde_json::json!({
                    "reason": e.to_string(),
                    "client_id": requested_client_id
                })),
            )
            .await;
            tracing::error!("Failed to create OAuth client: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to create OAuth client: {}", e),
                }),
            )
                .into_response()
        }
    }
}

pub async fn list_oauth_clients(
    State(db_pool): State<DbPool>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let (limit, offset) = match pagination_limit_offset(&pagination) {
        Ok(pagination) => pagination,
        Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
    };

    let result = sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY name LIMIT $2 OFFSET $3",
    )
    .bind(default_tenant_id())
    .bind(limit)
    .bind(offset)
    .fetch_all(&db_pool)
    .await;

    match result {
        Ok(clients) => {
            let clients: Vec<OAuthClientResponse> = clients
                .into_iter()
                .map(|c| OAuthClientResponse {
                    id: c.id,
                    client_id: c.client_id,
                    name: c.name,
                    redirect_uris: c.redirect_uris,
                    grant_types: c.grant_types,
                    scope: c.scope,
                    is_active: c.is_active,
                    is_public: c.is_public,
                    groups_claim_mode: c.groups_claim_mode,
                    include_claim_maps: c.include_claim_maps,
                    ignore_virtual_groups: c.ignore_virtual_groups,
                })
                .collect();
            (StatusCode::OK, Json(clients)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to list OAuth clients: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to list OAuth clients".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn delete_oauth_client(
    State(db_pool): State<DbPool>,
    Path(client_id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query(
        "UPDATE oauth_clients SET is_active = false, deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
    )
        .bind(client_id)
        .bind(default_tenant_id())
        .execute(&db_pool)
        .await;

    match result {
        Ok(result) => {
            if result.rows_affected() == 0 {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        error_description: "OAuth client not found".to_string(),
                    }),
                )
                    .into_response()
            } else {
                audit::emit_event(
                    &db_pool,
                    "admin.client.delete",
                    "oauth_client",
                    Some(client_id),
                    "success",
                    None,
                )
                .await;
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "OAuth client soft-deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
            audit::emit_event(
                &db_pool,
                "admin.client.delete",
                "oauth_client",
                Some(client_id),
                "failure",
                Some(serde_json::json!({ "reason": e.to_string() })),
            )
            .await;
            tracing::error!("Failed to delete OAuth client: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to delete OAuth client".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn update_oauth_client(
    State(db_pool): State<DbPool>,
    Path(client_id): Path<Uuid>,
    Json(req): Json<UpdateOAuthClientRequest>,
) -> impl IntoResponse {
    if req.name.is_none()
        && req.client_secret.is_none()
        && req.redirect_uris.is_none()
        && req.grant_types.is_none()
        && req.scope.is_none()
        && req.is_active.is_none()
        && req.is_public.is_none()
        && req.groups_claim_mode.is_none()
        && req.include_claim_maps.is_none()
        && req.ignore_virtual_groups.is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".to_string(),
                error_description: "No fields to update".to_string(),
            }),
        )
            .into_response();
    }

    let groups_claim_mode = match req.groups_claim_mode.as_deref() {
        None => None,
        Some("effective") => Some("effective"),
        Some("direct") => Some("direct"),
        Some("none") => Some("none"),
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: "groups_claim_mode must be one of: effective, direct, none"
                        .to_string(),
                }),
            )
                .into_response();
        }
    };

    // Determine new client_secret_hash value
    // - If is_public is being set to true, secret must be NULL
    // - If is_public is being set to false or not changing, use provided secret or keep existing
    let secret_hash = if req.is_public == Some(true) {
        // Public client: force secret to NULL
        if let Some(secret) = &req.client_secret {
            if !secret.trim().is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "bad_request".to_string(),
                        error_description: "Public clients cannot have client_secret".to_string(),
                    }),
                )
                    .into_response();
            }
        }
        Some(None) // Explicitly set to NULL
    } else if let Some(secret) = &req.client_secret {
        // Secret provided: hash it
        match hash_password_async(secret).await {
            Ok(hash) => Some(Some(hash)),
            Err(e) => {
                tracing::error!("Failed to hash client secret: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        error_description: "Failed to hash client secret".to_string(),
                    }),
                )
                    .into_response();
            }
        }
    } else {
        // No secret provided, no is_public change: keep existing
        None
    };

    let redirect_uris = req.redirect_uris.as_deref();
    let grant_types = req.grant_types.as_deref();

    if let Some(uris) = redirect_uris {
        let client = sqlx::query_scalar::<_, String>(
            "SELECT client_id FROM oauth_clients WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL"
        )
        .bind(client_id)
        .bind(default_tenant_id())
        .fetch_optional(&db_pool)
        .await;

        match client {
            Ok(Some(client_id_str)) => {
                if let Err(resp) = validate_redirect_uris(&client_id_str, uris) {
                    return *resp;
                }
            }
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        error_description: "OAuth client not found".to_string(),
                    }),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!("Failed to fetch OAuth client: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        error_description: "Failed to validate redirect_uris".to_string(),
                    }),
                )
                    .into_response();
            }
        }
    }
    // Flatten secret_hash: Option<Option<String>> -> (update_flag, value)
    // - None => don't update (keep existing)
    // - Some(None) => set to NULL (for public clients)
    // - Some(Some(hash)) => set to hash (for confidential clients)
    let (update_secret, secret_value) = match secret_hash {
        Some(Some(hash)) => (true, Some(hash)), // Set new hash
        Some(None) => (true, None),             // Set to NULL
        None => (false, None),                  // Keep existing
    };

    let result = sqlx::query!(
        r#"
        UPDATE oauth_clients
        SET
            name = COALESCE($1, name),
            client_secret_hash = CASE
                WHEN $2 THEN $3
                ELSE client_secret_hash
            END,
            redirect_uris = COALESCE($4, redirect_uris),
            grant_types = COALESCE($5, grant_types),
            scope = COALESCE($6, scope),
            is_active = COALESCE($7, is_active),
            is_public = COALESCE($8, is_public),
            groups_claim_mode = COALESCE($9, groups_claim_mode),
            include_claim_maps = COALESCE($10, include_claim_maps),
            ignore_virtual_groups = COALESCE($11, ignore_virtual_groups)
        WHERE id = $12 AND tenant_id = $13
        RETURNING id, client_id, name, redirect_uris, grant_types, scope, is_active, is_public,
            groups_claim_mode, include_claim_maps, ignore_virtual_groups
        "#,
        req.name,
        update_secret, // $2: bool - should we update secret?
        secret_value,  // $3: Option<String> - new value (NULL or hash)
        redirect_uris,
        grant_types,
        req.scope,
        req.is_active,
        req.is_public,
        groups_claim_mode,
        req.include_claim_maps,
        req.ignore_virtual_groups,
        client_id,
        default_tenant_id()
    )
    .fetch_optional(&db_pool)
    .await;

    match result {
        Ok(Some(client)) => {
            audit::emit_event(
                &db_pool,
                "admin.client.update",
                "oauth_client",
                Some(client.id),
                "success",
                None,
            )
            .await;
            (
                StatusCode::OK,
                Json(OAuthClientResponse {
                    id: client.id,
                    client_id: client.client_id,
                    name: client.name,
                    redirect_uris: client.redirect_uris,
                    grant_types: client.grant_types,
                    scope: client.scope,
                    is_active: client.is_active,
                    is_public: client.is_public,
                    groups_claim_mode: client.groups_claim_mode,
                    include_claim_maps: client.include_claim_maps,
                    ignore_virtual_groups: client.ignore_virtual_groups,
                }),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                error_description: "OAuth client not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            audit::emit_event(
                &db_pool,
                "admin.client.update",
                "oauth_client",
                Some(client_id),
                "failure",
                Some(serde_json::json!({ "reason": e.to_string() })),
            )
            .await;
            tracing::error!("Failed to update OAuth client: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to update OAuth client".to_string(),
                }),
            )
                .into_response()
        }
    }
}

fn validate_redirect_uris(
    _client_id: &str,
    redirect_uris: &[String],
) -> Result<(), Box<axum::response::Response>> {
    for uri in redirect_uris {
        if uri.contains('*') {
            // Parse URL with wildcard replaced temporarily for validation
            let test_uri = uri.replace('*', "8080");
            let url = Url::parse(&test_uri)
                .map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "bad_request".to_string(),
                            error_description: format!("Invalid redirect_uri format: {}", uri),
                        }),
                    )
                        .into_response()
                })
                .map_err(Box::new)?;

            // Check if host is loopback (localhost, 127.0.0.1, ::1)
            let host = url.host_str().unwrap_or("");
            let is_loopback =
                host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1";

            if !is_loopback {
                return Err(Box::new(
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "bad_request".to_string(),
                            error_description: format!(
                                "Wildcard '*' in redirect_uri is only allowed for loopback addresses (localhost, 127.0.0.1, ::1), got: {}",
                                host
                            ),
                        }),
                    )
                        .into_response(),
                ));
            }

            // Ensure wildcard is only in port position
            if !uri.contains(":*/") && !uri.ends_with(":*") {
                return Err(Box::new(
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "bad_request".to_string(),
                            error_description: "Wildcard '*' must be used for port only (e.g., http://localhost:*/callback)".to_string(),
                        }),
                    )
                        .into_response(),
                ));
            }

            continue;
        }

        let url = Url::parse(uri)
            .map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "bad_request".to_string(),
                        error_description: format!("Invalid redirect_uri: {}", uri),
                    }),
                )
                    .into_response()
            })
            .map_err(Box::new)?;

        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(Box::new(
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "bad_request".to_string(),
                        error_description: format!("redirect_uris must be http or https: {}", uri),
                    }),
                )
                    .into_response(),
            ));
        }
    }

    Ok(())
}

// ============================================================================
// Claim Map Handlers
// ============================================================================

pub async fn create_claim_map(
    State(db_pool): State<DbPool>,
    Json(req): Json<CreateClaimMapRequest>,
) -> impl IntoResponse {
    let tenant_id = default_tenant_id();
    let relation_ok = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM oauth_clients oc
            JOIN groups g ON g.id = $2
            WHERE oc.id = $1
              AND oc.tenant_id = $3
              AND g.tenant_id = $3
              AND oc.deleted_at IS NULL
              AND g.deleted_at IS NULL
        )
        "#,
    )
    .bind(req.client_id)
    .bind(req.group_id)
    .bind(tenant_id)
    .fetch_one(&db_pool)
    .await;

    match relation_ok {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: "Client or group not found in current tenant".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to validate tenant relation for claim map: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to validate claim map relation".to_string(),
                }),
            )
                .into_response();
        }
    }

    // Determine kind and values based on input
    let (kind, claim_value_str, claim_value_json) = match &req.claim_value {
        serde_json::Value::String(s) => {
            // Single string value
            ("single", Some(s.clone()), None)
        }
        serde_json::Value::Array(arr) => {
            // Array of strings
            let strings: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();

            if strings.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "bad_request".to_string(),
                        error_description: "claim_value array must contain at least one string"
                            .to_string(),
                    }),
                )
                    .into_response();
            }

            let json_str = serde_json::to_string(&strings).unwrap();
            ("array", None, Some(json_str))
        }
        serde_json::Value::Null => {
            // Null value - use single with null
            ("single", None, None)
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: "claim_value must be a string or array of strings"
                        .to_string(),
                }),
            )
                .into_response();
        }
    };

    let result = sqlx::query_as::<_, crate::db::models::ClaimMap>(
        r#"
        INSERT INTO claim_maps (client_id, group_id, claim_name, claim_value, claim_value_kind, claim_value_json)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, client_id, group_id, claim_name, claim_value, claim_value_kind, claim_value_json, updated_at
        "#,
    )
    .bind(req.client_id)
    .bind(req.group_id)
    .bind(req.claim_name)
    .bind(claim_value_str)
    .bind(kind)
    .bind(claim_value_json)
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(claim_map) => {
            audit::emit_event(
                &db_pool,
                "admin.claim_map.create",
                "claim_map",
                Some(claim_map.id),
                "success",
                Some(serde_json::json!({
                    "claim_name": claim_map.claim_name
                })),
            )
            .await;
            // Build response value based on kind
            let response_value = if claim_map.claim_value_kind == "array" {
                claim_map
                    .claim_value_json
                    .as_ref()
                    .and_then(|json| serde_json::from_str(json).ok())
            } else {
                claim_map
                    .claim_value
                    .as_ref()
                    .map(|s| serde_json::Value::String(s.clone()))
            };

            (
                StatusCode::CREATED,
                Json(ClaimMapResponse {
                    id: claim_map.id,
                    client_id: claim_map.client_id,
                    group_id: claim_map.group_id,
                    claim_name: claim_map.claim_name,
                    claim_value_kind: claim_map.claim_value_kind,
                    claim_value: response_value,
                }),
            )
                .into_response()
        }
        Err(e) => {
            audit::emit_event(
                &db_pool,
                "admin.claim_map.create",
                "claim_map",
                None,
                "failure",
                Some(serde_json::json!({ "reason": e.to_string() })),
            )
            .await;
            tracing::error!("Failed to create claim map: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to create claim map: {}", e),
                }),
            )
                .into_response()
        }
    }
}

pub async fn list_claim_maps(
    State(db_pool): State<DbPool>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let (limit, offset) = match pagination_limit_offset(&pagination) {
        Ok(pagination) => pagination,
        Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
    };

    let result = sqlx::query_as::<_, crate::db::models::ClaimMap>(
        r#"
        SELECT cm.id, cm.client_id, cm.group_id, cm.claim_name, cm.claim_value, cm.claim_value_kind, cm.claim_value_json, cm.updated_at
        FROM claim_maps cm
        JOIN oauth_clients oc ON oc.id = cm.client_id
        JOIN groups g ON g.id = cm.group_id
        WHERE oc.tenant_id = $1
          AND g.tenant_id = $1
          AND cm.deleted_at IS NULL
          AND oc.deleted_at IS NULL
          AND g.deleted_at IS NULL
        ORDER BY claim_name
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(default_tenant_id())
    .bind(limit)
    .bind(offset)
    .fetch_all(&db_pool)
    .await;

    match result {
        Ok(claim_maps) => {
            let claim_maps: Vec<ClaimMapResponse> = claim_maps
                .into_iter()
                .map(|cm| {
                    let response_value = if cm.claim_value_kind == "array" {
                        cm.claim_value_json
                            .as_ref()
                            .and_then(|json| serde_json::from_str(json).ok())
                    } else {
                        cm.claim_value
                            .as_ref()
                            .map(|s| serde_json::Value::String(s.clone()))
                    };

                    ClaimMapResponse {
                        id: cm.id,
                        client_id: cm.client_id,
                        group_id: cm.group_id,
                        claim_name: cm.claim_name,
                        claim_value_kind: cm.claim_value_kind,
                        claim_value: response_value,
                    }
                })
                .collect();
            (StatusCode::OK, Json(claim_maps)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to list claim maps: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to list claim maps".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn delete_claim_map(
    State(db_pool): State<DbPool>,
    Path(claim_map_id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query(
        r#"
        UPDATE claim_maps cm
        SET deleted_at = NOW(), updated_at = NOW()
        FROM oauth_clients oc, groups g
        WHERE cm.id = $1
          AND cm.deleted_at IS NULL
          AND oc.id = cm.client_id
          AND g.id = cm.group_id
          AND oc.tenant_id = $2
          AND g.tenant_id = $2
          AND oc.deleted_at IS NULL
          AND g.deleted_at IS NULL
        "#,
    )
    .bind(claim_map_id)
    .bind(default_tenant_id())
    .execute(&db_pool)
    .await;

    match result {
        Ok(result) => {
            if result.rows_affected() == 0 {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        error_description: "Claim map not found".to_string(),
                    }),
                )
                    .into_response()
            } else {
                audit::emit_event(
                    &db_pool,
                    "admin.claim_map.delete",
                    "claim_map",
                    Some(claim_map_id),
                    "success",
                    None,
                )
                .await;
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "Claim map soft-deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
            audit::emit_event(
                &db_pool,
                "admin.claim_map.delete",
                "claim_map",
                Some(claim_map_id),
                "failure",
                Some(serde_json::json!({ "reason": e.to_string() })),
            )
            .await;
            tracing::error!("Failed to delete claim map: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to delete claim map".to_string(),
                }),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Nested Groups Handlers
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AddChildGroupRequest {
    pub child_group_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct GroupChildResponse {
    pub parent_group_id: Uuid,
    pub child_group_id: Uuid,
    pub child_group_name: String,
    pub child_group_description: Option<String>,
}

// Helper function: Check if adding parent->child would create a cycle
// Returns true if cycle would be created
async fn would_create_cycle(
    db_pool: &DbPool,
    parent_id: Uuid,
    child_id: Uuid,
) -> Result<bool, sqlx::Error> {
    // Strategy: Check if parent is (transitively) a child of child
    // If yes, then adding child->parent would create a cycle

    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![child_id];

    while let Some(current) = stack.pop() {
        if current == parent_id {
            return Ok(true); // Cycle detected
        }

        if visited.contains(&current) {
            continue;
        }
        visited.insert(current);

        // Get all children of current group
        let children = sqlx::query_scalar::<_, Uuid>(
            "SELECT child_group_id FROM group_groups WHERE parent_group_id = $1",
        )
        .bind(current)
        .fetch_all(db_pool)
        .await?;

        stack.extend(children);
    }

    Ok(false)
}

// Helper function: Get all transitive children (descendants) of a group
pub async fn get_transitive_children(
    db_pool: &DbPool,
    group_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let mut all_children = std::collections::HashSet::new();
    let mut stack = vec![group_id];
    let mut visited = std::collections::HashSet::new();

    while let Some(current) = stack.pop() {
        if visited.contains(&current) {
            continue;
        }
        visited.insert(current);

        let children = sqlx::query_scalar::<_, Uuid>(
            "SELECT child_group_id FROM group_groups WHERE parent_group_id = $1",
        )
        .bind(current)
        .fetch_all(db_pool)
        .await?;

        for child in children {
            if child != group_id {
                all_children.insert(child);
            }
            stack.push(child);
        }
    }

    Ok(all_children.into_iter().collect())
}

pub async fn add_child_group(
    State(db_pool): State<DbPool>,
    Path(parent_id): Path<Uuid>,
    Json(req): Json<AddChildGroupRequest>,
) -> impl IntoResponse {
    let child_id = req.child_group_id;

    // Validate that both groups exist
    let parent_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(parent_id)
    .fetch_one(&db_pool)
    .await;

    let child_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(child_id)
    .fetch_one(&db_pool)
    .await;

    match (parent_exists, child_exists) {
        (Ok(false), _) | (_, Ok(false)) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    error_description: "Parent or child group not found".to_string(),
                }),
            )
                .into_response();
        }
        (Err(e), _) | (_, Err(e)) => {
            tracing::error!("Failed to check group existence: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to validate groups".to_string(),
                }),
            )
                .into_response();
        }
        _ => {}
    }

    // Check for cycle
    match would_create_cycle(&db_pool, parent_id, child_id).await {
        Ok(true) => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "cycle_detected".to_string(),
                    error_description:
                        "Adding this relationship would create a cycle in the group hierarchy"
                            .to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to check for cycles: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to validate group hierarchy".to_string(),
                }),
            )
                .into_response();
        }
        Ok(false) => {}
    }

    // Insert the relationship
    let result = sqlx::query!(
        "INSERT INTO group_groups (parent_group_id, child_group_id) VALUES ($1, $2)",
        parent_id,
        child_id
    )
    .execute(&db_pool)
    .await;

    match result {
        Ok(_) => {
            // Fetch child group details for response
            let child = sqlx::query!(
                "SELECT id, name, description FROM groups WHERE id = $1 AND deleted_at IS NULL",
                child_id
            )
            .fetch_one(&db_pool)
            .await;

            match child {
                Ok(group) => (
                    StatusCode::CREATED,
                    Json(GroupChildResponse {
                        parent_group_id: parent_id,
                        child_group_id: group.id,
                        child_group_name: group.name,
                        child_group_description: group.description,
                    }),
                )
                    .into_response(),
                Err(e) => {
                    tracing::error!("Failed to fetch child group: {:?}", e);
                    (
                        StatusCode::CREATED,
                        Json(SuccessResponse {
                            message: "Child group added successfully".to_string(),
                        }),
                    )
                        .into_response()
                }
            }
        }
        Err(sqlx::Error::Database(ref db_err))
            if db_err.constraint() == Some("group_groups_pkey") =>
        {
            (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "already_exists".to_string(),
                    error_description: "This group relationship already exists".to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to add child group: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to add child group".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn remove_child_group(
    State(db_pool): State<DbPool>,
    Path((parent_id, child_id)): Path<(Uuid, Uuid)>,
) -> impl IntoResponse {
    let result =
        sqlx::query("DELETE FROM group_groups WHERE parent_group_id = $1 AND child_group_id = $2")
            .bind(parent_id)
            .bind(child_id)
            .execute(&db_pool)
            .await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        error_description: "Group relationship not found".to_string(),
                    }),
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "Child group removed successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
            tracing::error!("Failed to remove child group: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to remove child group".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn list_child_groups(
    State(db_pool): State<DbPool>,
    Path(parent_id): Path<Uuid>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let expand = params.get("expand").map(|v| v == "true").unwrap_or(false);

    if expand {
        // Get all transitive children
        match get_transitive_children(&db_pool, parent_id).await {
            Ok(child_ids) => {
                if child_ids.is_empty() {
                    return (StatusCode::OK, Json(serde_json::json!([]))).into_response();
                }

                // Fetch group details for all children
                let children = sqlx::query_as::<_, (Uuid, String, Option<String>, bool)>(
            "SELECT id, name, description, is_virtual FROM groups WHERE id = ANY($1) AND deleted_at IS NULL ORDER BY name"
        )
        .bind(&child_ids)
        .fetch_all(&db_pool)
        .await;

                match children {
                    Ok(groups) => {
                        let response: Vec<GroupResponse> = groups
                            .into_iter()
                            .map(|(id, name, description, is_virtual)| GroupResponse {
                                id,
                                name,
                                description,
                                is_virtual,
                            })
                            .collect();
                        (StatusCode::OK, Json(response)).into_response()
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch child groups: {:?}", e);
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse {
                                error: "server_error".to_string(),
                                error_description: "Failed to fetch child groups".to_string(),
                            }),
                        )
                            .into_response()
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to get transitive children: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        error_description: "Failed to expand child groups".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    } else {
        // Get only direct children
        let result = sqlx::query_as::<_, (Uuid, String, Option<String>, bool)>(
            r#"
            SELECT g.id, g.name, g.description, g.is_virtual
            FROM groups g
            INNER JOIN group_groups gg ON g.id = gg.child_group_id
            WHERE gg.parent_group_id = $1
            ORDER BY g.name
            "#,
        )
        .bind(parent_id)
        .fetch_all(&db_pool)
        .await;

        match result {
            Ok(groups) => {
                let response: Vec<GroupResponse> = groups
                    .into_iter()
                    .map(|(id, name, description, is_virtual)| GroupResponse {
                        id,
                        name,
                        description,
                        is_virtual,
                    })
                    .collect();
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(e) => {
                tracing::error!("Failed to list child groups: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        error_description: "Failed to list child groups".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }
}

// ============================================================================
// User Group Patterns Management
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateUserGroupPatternRequest {
    pub pattern: String,
    pub is_include: Option<bool>,
    pub priority: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct UserGroupPatternResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub pattern: String,
    pub is_include: bool,
    pub priority: i32,
    pub created_at: String,
}

/// Create a new group pattern for a user
/// POST /admin/users/{id}/group-patterns
pub async fn create_user_group_pattern(
    State(db_pool): State<DbPool>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<CreateUserGroupPatternRequest>,
) -> impl IntoResponse {
    let is_include = req.is_include.unwrap_or(true);
    let priority = req.priority.unwrap_or(0);

    let result = sqlx::query!(
        r#"
        INSERT INTO user_group_patterns (user_id, pattern, is_include, priority)
        VALUES ($1, $2, $3, $4)
        RETURNING id, user_id, pattern, is_include, priority, created_at
        "#,
        user_id,
        req.pattern,
        is_include,
        priority
    )
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(row) => {
            let response = UserGroupPatternResponse {
                id: row.id,
                user_id: row.user_id,
                pattern: row.pattern,
                is_include: row.is_include,
                priority: row.priority,
                created_at: row.created_at.to_rfc3339(),
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to create user group pattern: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to create pattern: {}", e),
                }),
            )
                .into_response()
        }
    }
}

/// List all group patterns for a user
/// GET /admin/users/{id}/group-patterns
pub async fn list_user_group_patterns(
    State(db_pool): State<DbPool>,
    Path(user_id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query!(
        r#"
        SELECT id, user_id, pattern, is_include, priority, created_at
        FROM user_group_patterns
        WHERE user_id = $1
          AND deleted_at IS NULL
        ORDER BY priority ASC, created_at ASC
        "#,
        user_id
    )
    .fetch_all(&db_pool)
    .await;

    match result {
        Ok(rows) => {
            let patterns: Vec<UserGroupPatternResponse> = rows
                .into_iter()
                .map(|row| UserGroupPatternResponse {
                    id: row.id,
                    user_id: row.user_id,
                    pattern: row.pattern,
                    is_include: row.is_include,
                    priority: row.priority,
                    created_at: row.created_at.to_rfc3339(),
                })
                .collect();
            (StatusCode::OK, Json(patterns)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to list user group patterns: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to list patterns".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Update a group pattern
/// PUT /admin/users/{user_id}/group-patterns/{pattern_id}
#[derive(Debug, Deserialize)]
pub struct UpdateUserGroupPatternRequest {
    pub pattern: Option<String>,
    pub is_include: Option<bool>,
    pub priority: Option<i32>,
}

pub async fn update_user_group_pattern(
    State(db_pool): State<DbPool>,
    Path((user_id, pattern_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateUserGroupPatternRequest>,
) -> impl IntoResponse {
    // Verify the pattern belongs to the user
    let exists = sqlx::query!(
        "SELECT id FROM user_group_patterns WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL",
        pattern_id,
        user_id
    )
    .fetch_optional(&db_pool)
    .await;

    match exists {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    error_description: "Pattern not found or does not belong to user".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to check pattern existence: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Database error".to_string(),
                }),
            )
                .into_response();
        }
        Ok(Some(_)) => {
            // Continue with update
        }
    }

    // Build dynamic update query
    let mut updates = vec![];
    if req.pattern.is_some() {
        updates.push("pattern = COALESCE($3, pattern)");
    }
    if req.is_include.is_some() {
        updates.push("is_include = COALESCE($4, is_include)");
    }
    if req.priority.is_some() {
        updates.push("priority = COALESCE($5, priority)");
    }

    if updates.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".to_string(),
                error_description: "No fields to update".to_string(),
            }),
        )
            .into_response();
    }

    let result = sqlx::query!(
        r#"
        UPDATE user_group_patterns
        SET pattern = COALESCE($3, pattern),
            is_include = COALESCE($4, is_include),
            priority = COALESCE($5, priority)
        WHERE id = $1 AND user_id = $2
        RETURNING id, user_id, pattern, is_include, priority, created_at
        "#,
        pattern_id,
        user_id,
        req.pattern,
        req.is_include,
        req.priority
    )
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(row) => {
            let response = UserGroupPatternResponse {
                id: row.id,
                user_id: row.user_id,
                pattern: row.pattern,
                is_include: row.is_include,
                priority: row.priority,
                created_at: row.created_at.to_rfc3339(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to update user group pattern: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to update pattern: {}", e),
                }),
            )
                .into_response()
        }
    }
}

/// Delete a group pattern
/// DELETE /admin/users/{user_id}/group-patterns/{pattern_id}
pub async fn delete_user_group_pattern(
    State(db_pool): State<DbPool>,
    Path((user_id, pattern_id)): Path<(Uuid, Uuid)>,
) -> impl IntoResponse {
    let result = sqlx::query!(
        "UPDATE user_group_patterns SET deleted_at = NOW() WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL",
        pattern_id,
        user_id
    )
    .execute(&db_pool)
    .await;

    match result {
        Ok(result) => {
            if result.rows_affected() == 0 {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        error_description: "Pattern not found or does not belong to user"
                            .to_string(),
                    }),
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "Pattern soft-deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
            tracing::error!("Failed to delete user group pattern: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to delete pattern".to_string(),
                }),
            )
                .into_response()
        }
    }
}

// ============================================================================
// OAuth Client Group Patterns Management
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateClientGroupPatternRequest {
    pub pattern: String,
    pub is_include: Option<bool>,
    pub priority: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct ClientGroupPatternResponse {
    pub id: Uuid,
    pub client_id: Uuid,
    pub pattern: String,
    pub is_include: bool,
    pub priority: i32,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateClientGroupPatternRequest {
    pub pattern: Option<String>,
    pub is_include: Option<bool>,
    pub priority: Option<i32>,
}

/// Create a new group pattern for an OAuth client
/// POST /admin/oauth-clients/{id}/group-patterns
pub async fn create_client_group_pattern(
    State(db_pool): State<DbPool>,
    Path(client_id): Path<Uuid>,
    Json(req): Json<CreateClientGroupPatternRequest>,
) -> impl IntoResponse {
    let is_include = req.is_include.unwrap_or(true);
    let priority = req.priority.unwrap_or(0);

    let result = sqlx::query!(
        r#"
        INSERT INTO oauth_client_group_patterns (client_id, pattern, is_include, priority)
        VALUES ($1, $2, $3, $4)
        RETURNING id, client_id, pattern, is_include, priority, created_at
        "#,
        client_id,
        req.pattern,
        is_include,
        priority
    )
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(row) => {
            let response = ClientGroupPatternResponse {
                id: row.id,
                client_id: row.client_id,
                pattern: row.pattern,
                is_include: row.is_include,
                priority: row.priority,
                created_at: row.created_at.to_rfc3339(),
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to create client group pattern: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to create pattern: {}", e),
                }),
            )
                .into_response()
        }
    }
}

/// List all group patterns for an OAuth client
/// GET /admin/oauth-clients/{id}/group-patterns
pub async fn list_client_group_patterns(
    State(db_pool): State<DbPool>,
    Path(client_id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query!(
        r#"
        SELECT id, client_id, pattern, is_include, priority, created_at
        FROM oauth_client_group_patterns
        WHERE client_id = $1
          AND deleted_at IS NULL
        ORDER BY priority ASC, created_at ASC
        "#,
        client_id
    )
    .fetch_all(&db_pool)
    .await;

    match result {
        Ok(rows) => {
            let patterns: Vec<ClientGroupPatternResponse> = rows
                .into_iter()
                .map(|row| ClientGroupPatternResponse {
                    id: row.id,
                    client_id: row.client_id,
                    pattern: row.pattern,
                    is_include: row.is_include,
                    priority: row.priority,
                    created_at: row.created_at.to_rfc3339(),
                })
                .collect();
            Json(patterns).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to fetch client group patterns: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to fetch patterns".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Update a client group pattern
/// PUT /admin/oauth-clients/{client_id}/group-patterns/{pattern_id}
pub async fn update_client_group_pattern(
    State(db_pool): State<DbPool>,
    Path((client_id, pattern_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateClientGroupPatternRequest>,
) -> impl IntoResponse {
    // Verify pattern belongs to client
    let verify = sqlx::query!(
        "SELECT id FROM oauth_client_group_patterns WHERE id = $1 AND client_id = $2 AND deleted_at IS NULL",
        pattern_id,
        client_id
    )
    .fetch_optional(&db_pool)
    .await;

    match verify {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    error_description: "Pattern not found or does not belong to client".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to verify client group pattern: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to verify pattern".to_string(),
                }),
            )
                .into_response();
        }
        Ok(Some(_)) => {}
    }

    if req.pattern.is_none() && req.is_include.is_none() && req.priority.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".to_string(),
                error_description: "No fields to update".to_string(),
            }),
        )
            .into_response();
    }

    let result = sqlx::query(
        "UPDATE oauth_client_group_patterns SET pattern = COALESCE($1, pattern),
         is_include = COALESCE($2, is_include), priority = COALESCE($3, priority)
         WHERE id = $4 RETURNING id, client_id, pattern, is_include, priority, created_at",
    )
    .bind(req.pattern)
    .bind(req.is_include)
    .bind(req.priority)
    .bind(pattern_id)
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(row) => {
            let response = ClientGroupPatternResponse {
                id: row.get("id"),
                client_id: row.get("client_id"),
                pattern: row.get("pattern"),
                is_include: row.get("is_include"),
                priority: row.get("priority"),
                created_at: row.get::<DateTime<Utc>, _>("created_at").to_rfc3339(),
            };
            Json(response).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to update client group pattern: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to update pattern".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Delete a client group pattern
/// DELETE /admin/oauth-clients/{client_id}/group-patterns/{pattern_id}
pub async fn delete_client_group_pattern(
    State(db_pool): State<DbPool>,
    Path((client_id, pattern_id)): Path<(Uuid, Uuid)>,
) -> impl IntoResponse {
    let result = sqlx::query!(
        "UPDATE oauth_client_group_patterns SET deleted_at = NOW() WHERE id = $1 AND client_id = $2 AND deleted_at IS NULL",
        pattern_id,
        client_id
    )
    .execute(&db_pool)
    .await;

    match result {
        Ok(result) => {
            if result.rows_affected() == 0 {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        error_description: "Pattern not found or does not belong to client"
                            .to_string(),
                    }),
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "Pattern soft-deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
            tracing::error!("Failed to delete client group pattern: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to delete pattern".to_string(),
                }),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Groups Tree Endpoint
// ============================================================================

/// Get all groups with their parent-child relationships in a single request
/// Returns a flat list of groups with each group containing its direct children IDs
pub async fn get_groups_tree(State(db_pool): State<DbPool>) -> impl IntoResponse {
    // Fetch all groups
    let groups_result = sqlx::query!(
        r#"
        SELECT id, name, description, is_virtual
        FROM groups
        WHERE deleted_at IS NULL
        ORDER BY name
        "#
    )
    .fetch_all(&db_pool)
    .await;

    let groups = match groups_result {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("Failed to fetch groups: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to fetch groups".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Fetch all group relationships (parent -> children)
    let relationships_result = sqlx::query!(
        r#"
        SELECT parent_group_id, child_group_id
        FROM group_groups
        "#
    )
    .fetch_all(&db_pool)
    .await;

    let relationships = match relationships_result {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to fetch group relationships: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to fetch group relationships".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Build children map
    let mut children_map: std::collections::HashMap<Uuid, Vec<Uuid>> =
        std::collections::HashMap::new();
    for rel in relationships {
        children_map
            .entry(rel.parent_group_id)
            .or_default()
            .push(rel.child_group_id);
    }

    // Build response
    let tree: Vec<GroupTreeResponse> = groups
        .into_iter()
        .map(|g| {
            let children = children_map.get(&g.id).cloned().unwrap_or_default();
            GroupTreeResponse {
                id: g.id,
                name: g.name,
                description: g.description,
                is_virtual: g.is_virtual,
                children,
            }
        })
        .collect();

    (StatusCode::OK, Json(tree)).into_response()
}

// ============================================================================
// Claim Map Patterns Endpoints
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateClaimMapPatternRequest {
    pub pattern: String,
    pub is_include: bool,
    pub priority: i32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateClaimMapPatternRequest {
    pub pattern: Option<String>,
    pub is_include: Option<bool>,
    pub priority: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct ClaimMapPatternResponse {
    pub id: Uuid,
    pub claim_map_id: Uuid,
    pub pattern: String,
    pub is_include: bool,
    pub priority: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// POST /admin/claim-maps/{id}/patterns
pub async fn create_claim_map_pattern(
    State(db_pool): State<DbPool>,
    Path(claim_map_id): Path<Uuid>,
    Json(req): Json<CreateClaimMapPatternRequest>,
) -> impl IntoResponse {
    // Validate claim_map exists
    let claim_map_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM claim_maps WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(claim_map_id)
    .fetch_one(&db_pool)
    .await;

    match claim_map_exists {
        Ok(false) | Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    error_description: "Claim map not found".to_string(),
                }),
            )
                .into_response();
        }
        _ => {}
    }

    let result = sqlx::query_as!(
        crate::db::models::ClaimMapPattern,
        r#"
        INSERT INTO claim_map_patterns (claim_map_id, pattern, is_include, priority)
        VALUES ($1, $2, $3, $4)
        RETURNING id, claim_map_id, pattern, is_include, priority, created_at
        "#,
        claim_map_id,
        req.pattern,
        req.is_include,
        req.priority
    )
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(pattern) => (
            StatusCode::CREATED,
            Json(ClaimMapPatternResponse {
                id: pattern.id,
                claim_map_id: pattern.claim_map_id,
                pattern: pattern.pattern,
                is_include: pattern.is_include,
                priority: pattern.priority,
                created_at: pattern.created_at,
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to create claim map pattern: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to create pattern: {}", e),
                }),
            )
                .into_response()
        }
    }
}

/// GET /admin/claim-maps/{id}/patterns
pub async fn list_claim_map_patterns(
    State(db_pool): State<DbPool>,
    Path(claim_map_id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query_as!(
        crate::db::models::ClaimMapPattern,
        r#"
        SELECT id, claim_map_id, pattern, is_include, priority, created_at
        FROM claim_map_patterns
        WHERE claim_map_id = $1
          AND deleted_at IS NULL
        ORDER BY priority ASC
        "#,
        claim_map_id
    )
    .fetch_all(&db_pool)
    .await;

    match result {
        Ok(patterns) => {
            let response: Vec<ClaimMapPatternResponse> = patterns
                .into_iter()
                .map(|p| ClaimMapPatternResponse {
                    id: p.id,
                    claim_map_id: p.claim_map_id,
                    pattern: p.pattern,
                    is_include: p.is_include,
                    priority: p.priority,
                    created_at: p.created_at,
                })
                .collect();

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to list claim map patterns: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to list patterns".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// PUT /admin/claim-maps/{claim_map_id}/patterns/{pattern_id}
pub async fn update_claim_map_pattern(
    State(db_pool): State<DbPool>,
    Path((claim_map_id, pattern_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateClaimMapPatternRequest>,
) -> impl IntoResponse {
    // Fetch existing pattern
    let existing = sqlx::query_as!(
        crate::db::models::ClaimMapPattern,
        "SELECT id, claim_map_id, pattern, is_include, priority, created_at FROM claim_map_patterns WHERE id = $1 AND claim_map_id = $2 AND deleted_at IS NULL",
        pattern_id,
        claim_map_id
    )
    .fetch_optional(&db_pool)
    .await;

    let existing = match existing {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    error_description: "Pattern not found or does not belong to claim map"
                        .to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to fetch pattern: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to fetch pattern".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Apply updates
    let new_pattern = req.pattern.unwrap_or(existing.pattern);
    let new_is_include = req.is_include.unwrap_or(existing.is_include);
    let new_priority = req.priority.unwrap_or(existing.priority);

    let result = sqlx::query_as!(
        crate::db::models::ClaimMapPattern,
        r#"
        UPDATE claim_map_patterns
        SET pattern = $1, is_include = $2, priority = $3
        WHERE id = $4 AND claim_map_id = $5
        RETURNING id, claim_map_id, pattern, is_include, priority, created_at
        "#,
        new_pattern,
        new_is_include,
        new_priority,
        pattern_id,
        claim_map_id
    )
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(pattern) => (
            StatusCode::OK,
            Json(ClaimMapPatternResponse {
                id: pattern.id,
                claim_map_id: pattern.claim_map_id,
                pattern: pattern.pattern,
                is_include: pattern.is_include,
                priority: pattern.priority,
                created_at: pattern.created_at,
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to update claim map pattern: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to update pattern: {}", e),
                }),
            )
                .into_response()
        }
    }
}

/// DELETE /admin/claim-maps/{claim_map_id}/patterns/{pattern_id}
pub async fn delete_claim_map_pattern(
    State(db_pool): State<DbPool>,
    Path((claim_map_id, pattern_id)): Path<(Uuid, Uuid)>,
) -> impl IntoResponse {
    let result = sqlx::query(
        "UPDATE claim_map_patterns SET deleted_at = NOW() WHERE id = $1 AND claim_map_id = $2 AND deleted_at IS NULL",
    )
    .bind(pattern_id)
    .bind(claim_map_id)
    .execute(&db_pool)
    .await;

    match result {
        Ok(result) => {
            if result.rows_affected() == 0 {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        error_description: "Pattern not found or does not belong to claim map"
                            .to_string(),
                    }),
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "Pattern soft-deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
            tracing::error!("Failed to delete claim map pattern: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to delete pattern".to_string(),
                }),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Tenant Handlers
// ============================================================================

pub async fn create_tenant(
    State(db_pool): State<DbPool>,
    Json(req): Json<CreateTenantRequest>,
) -> impl IntoResponse {
    let mode = match normalize_tenant_mode(req.mode.as_deref()) {
        Ok(mode) => mode,
        Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
    };
    let is_active = req.is_active.unwrap_or(true);
    let mfa_policy = match normalize_mfa_policy(req.mfa_policy.as_deref()) {
        Ok(policy) => policy,
        Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
    };
    let passkey_policy = match normalize_passkey_policy(req.passkey_policy.as_deref()) {
        Ok(policy) => policy,
        Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
    };

    let result = sqlx::query_as::<_, TenantResponse>(
        r#"
        INSERT INTO tenants (id, slug, name, mode, is_active, mfa_policy, passkey_policy)
        VALUES (gen_random_uuid(), $1, $2, $3::tenant_mode, $4, $5, $6)
        RETURNING id, slug, name, mode::text AS mode, is_active, mfa_policy, passkey_policy
        "#,
    )
    .bind(req.slug)
    .bind(req.name)
    .bind(mode)
    .bind(is_active)
    .bind(mfa_policy)
    .bind(passkey_policy)
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(tenant) => (StatusCode::CREATED, Json(tenant)).into_response(),
        Err(e) => {
            tracing::error!("Failed to create tenant: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to create tenant: {}", e),
                }),
            )
                .into_response()
        }
    }
}

pub async fn list_tenants(
    State(db_pool): State<DbPool>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let (limit, offset) = match pagination_limit_offset(&pagination) {
        Ok(pagination) => pagination,
        Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
    };

    let result = sqlx::query_as::<_, TenantResponse>(
        r#"
        SELECT id, slug, name, mode::text AS mode, is_active, mfa_policy, passkey_policy
        FROM tenants
        WHERE deleted_at IS NULL
        ORDER BY slug
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&db_pool)
    .await;

    match result {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list tenants: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to list tenants".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn update_tenant(
    State(db_pool): State<DbPool>,
    Path(tenant_id): Path<Uuid>,
    Json(req): Json<UpdateTenantRequest>,
) -> impl IntoResponse {
    if req.slug.is_none()
        && req.name.is_none()
        && req.mode.is_none()
        && req.is_active.is_none()
        && req.mfa_policy.is_none()
        && req.passkey_policy.is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".to_string(),
                error_description: "No fields to update".to_string(),
            }),
        )
            .into_response();
    }

    let mode = match req.mode.as_deref() {
        None => None,
        Some("single") => Some("single"),
        Some("multi") => Some("multi"),
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: "mode must be one of: single, multi".to_string(),
                }),
            )
                .into_response();
        }
    };

    let mfa_policy = match req.mfa_policy.as_deref() {
        None => None,
        Some(value) => match normalize_mfa_policy(Some(value)) {
            Ok(policy) => Some(policy),
            Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
        },
    };
    let passkey_policy = match req.passkey_policy.as_deref() {
        None => None,
        Some(value) => match normalize_passkey_policy(Some(value)) {
            Ok(policy) => Some(policy),
            Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
        },
    };

    let result = sqlx::query_as::<_, TenantResponse>(
        r#"
        UPDATE tenants
        SET
            slug = COALESCE($1, slug),
            name = COALESCE($2, name),
            mode = COALESCE($3::tenant_mode, mode),
            is_active = COALESCE($4, is_active),
            mfa_policy = COALESCE($5, mfa_policy),
            passkey_policy = COALESCE($6, passkey_policy)
        WHERE id = $7 AND deleted_at IS NULL
        RETURNING id, slug, name, mode::text AS mode, is_active, mfa_policy, passkey_policy
        "#,
    )
    .bind(req.slug)
    .bind(req.name)
    .bind(mode)
    .bind(req.is_active)
    .bind(mfa_policy)
    .bind(passkey_policy)
    .bind(tenant_id)
    .fetch_optional(&db_pool)
    .await;

    match result {
        Ok(Some(tenant)) => (StatusCode::OK, Json(tenant)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                error_description: "Tenant not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to update tenant: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to update tenant: {}", e),
                }),
            )
                .into_response()
        }
    }
}

pub async fn delete_tenant(
    State(db_pool): State<DbPool>,
    Path(tenant_id): Path<Uuid>,
) -> impl IntoResponse {
    if tenant_id == default_tenant_id() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".to_string(),
                error_description: "Default tenant cannot be deleted".to_string(),
            }),
        )
            .into_response();
    }

    let result = sqlx::query("UPDATE tenants SET is_active = false, deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL")
        .bind(tenant_id)
        .execute(&db_pool)
        .await;

    match result {
        Ok(result) => {
            if result.rows_affected() == 0 {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        error_description: "Tenant not found".to_string(),
                    }),
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "Tenant soft-deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
            tracing::error!("Failed to delete tenant: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to delete tenant: {}", e),
                }),
            )
                .into_response()
        }
    }
}

pub async fn create_tenant_domain(
    State(db_pool): State<DbPool>,
    Path(tenant_id): Path<Uuid>,
    Json(req): Json<CreateTenantDomainRequest>,
) -> impl IntoResponse {
    let is_primary = req.is_primary.unwrap_or(false);
    let is_active = req.is_active.unwrap_or(true);
    if let Some(policy) = req.authentication_policy.as_deref() {
        if !matches!(policy, "unrestricted" | "local" | "federated" | "ad") {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".into(),
                    error_description: "Invalid domain authentication policy".into(),
                }),
            )
                .into_response();
        }
    }
    if let Err(e) = crate::auth_policy::validate_domain_overrides(
        req.mfa_policy.as_deref().unwrap_or("inherit"),
        req.passkey_policy.as_deref().unwrap_or("inherit"),
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".into(),
                error_description: e.to_string(),
            }),
        )
            .into_response();
    }
    if matches!(req.mfa_policy.as_deref(), Some("optional" | "required"))
        && crate::secret_crypto::validate_master_key().is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".into(),
                error_description: "Configure IDP_SECRETS_MASTER_KEY before enabling MFA".into(),
            }),
        )
            .into_response();
    }

    let mut tx = match db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Failed to start transaction: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to create tenant domain".to_string(),
                }),
            )
                .into_response();
        }
    };

    if is_primary {
        let _ = sqlx::query("UPDATE tenant_domains SET is_primary = false WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await;
    }

    let result = sqlx::query_as::<_, TenantDomainResponse>(
        r#"
        INSERT INTO tenant_domains (tenant_id, domain, is_primary, is_active, mfa_policy, passkey_policy, authentication_policy, auth_provider_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, tenant_id, domain, is_primary, is_active, mfa_policy, passkey_policy, authentication_policy, auth_provider_id
        "#,
    )
    .bind(tenant_id)
    .bind(req.domain)
    .bind(is_primary)
    .bind(is_active)
    .bind(req.mfa_policy.as_deref().unwrap_or("inherit"))
    .bind(req.passkey_policy.as_deref().unwrap_or("inherit"))
    .bind(req.authentication_policy.as_deref().unwrap_or("unrestricted"))
    .bind(req.auth_provider_id)
    .fetch_one(&mut *tx)
    .await;

    let domain = match result {
        Ok(domain) => domain,
        Err(e) => {
            let _ = tx.rollback().await;
            tracing::error!("Failed to create tenant domain: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to create tenant domain: {}", e),
                }),
            )
                .into_response();
        }
    };

    if let Err(e) = tx.commit().await {
        tracing::error!("Failed to commit transaction: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to create tenant domain".to_string(),
            }),
        )
            .into_response();
    }

    (StatusCode::CREATED, Json(domain)).into_response()
}

pub async fn list_tenant_domains(
    State(db_pool): State<DbPool>,
    Path(tenant_id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query_as::<_, TenantDomainResponse>(
        r#"
        SELECT id, tenant_id, domain, is_primary, is_active, mfa_policy, passkey_policy, authentication_policy, auth_provider_id
        FROM tenant_domains
        WHERE tenant_id = $1 AND deleted_at IS NULL
        ORDER BY is_primary DESC, domain ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&db_pool)
    .await;

    match result {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list tenant domains: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to list tenant domains".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn update_tenant_domain(
    State(db_pool): State<DbPool>,
    Path((tenant_id, domain_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateTenantDomainRequest>,
) -> impl IntoResponse {
    if let Some(policy) = req.authentication_policy.as_deref() {
        if !matches!(policy, "unrestricted" | "local" | "federated" | "ad") {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".into(),
                    error_description: "Invalid domain authentication policy".into(),
                }),
            )
                .into_response();
        }
    }
    if let Err(e) = crate::auth_policy::validate_domain_overrides(
        req.mfa_policy.as_deref().unwrap_or("inherit"),
        req.passkey_policy.as_deref().unwrap_or("inherit"),
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".into(),
                error_description: e.to_string(),
            }),
        )
            .into_response();
    }
    if matches!(req.mfa_policy.as_deref(), Some("optional" | "required"))
        && crate::secret_crypto::validate_master_key().is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".into(),
                error_description: "Configure IDP_SECRETS_MASTER_KEY before enabling MFA".into(),
            }),
        )
            .into_response();
    }
    if req.domain.is_none()
        && req.is_primary.is_none()
        && req.is_active.is_none()
        && req.mfa_policy.is_none()
        && req.passkey_policy.is_none()
        && req.authentication_policy.is_none()
        && req.auth_provider_id.is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".to_string(),
                error_description: "No fields to update".to_string(),
            }),
        )
            .into_response();
    }

    let mut tx = match db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Failed to start transaction: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to update tenant domain".to_string(),
                }),
            )
                .into_response();
        }
    };

    if req.is_primary == Some(true) {
        let _ = sqlx::query(
            "UPDATE tenant_domains SET is_primary = false WHERE tenant_id = $1 AND id <> $2",
        )
        .bind(tenant_id)
        .bind(domain_id)
        .execute(&mut *tx)
        .await;
    }

    let result = sqlx::query_as::<_, TenantDomainResponse>(
        r#"
        UPDATE tenant_domains
        SET
            domain = COALESCE($1, domain),
            is_primary = COALESCE($2, is_primary),
            is_active = COALESCE($3, is_active),
            mfa_policy = COALESCE($6, mfa_policy),
            passkey_policy = COALESCE($7, passkey_policy),
            authentication_policy = COALESCE($8, authentication_policy),
            auth_provider_id = CASE WHEN $8 IN ('unrestricted', 'local') THEN NULL ELSE COALESCE($9, auth_provider_id) END
        WHERE tenant_id = $4 AND id = $5 AND deleted_at IS NULL
        RETURNING id, tenant_id, domain, is_primary, is_active, mfa_policy, passkey_policy, authentication_policy, auth_provider_id
        "#,
    )
    .bind(req.domain)
    .bind(req.is_primary)
    .bind(req.is_active)
    .bind(tenant_id)
    .bind(domain_id)
    .bind(req.mfa_policy)
    .bind(req.passkey_policy)
    .bind(req.authentication_policy)
    .bind(req.auth_provider_id)
    .fetch_optional(&mut *tx)
    .await;

    let domain = match result {
        Ok(Some(domain)) => domain,
        Ok(None) => {
            let _ = tx.rollback().await;
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    error_description: "Tenant domain not found".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            let _ = tx.rollback().await;
            tracing::error!("Failed to update tenant domain: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to update tenant domain: {}", e),
                }),
            )
                .into_response();
        }
    };

    if let Err(e) = tx.commit().await {
        tracing::error!("Failed to commit transaction: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to update tenant domain".to_string(),
            }),
        )
            .into_response();
    }

    (StatusCode::OK, Json(domain)).into_response()
}

pub async fn delete_tenant_domain(
    State(db_pool): State<DbPool>,
    Path((tenant_id, domain_id)): Path<(Uuid, Uuid)>,
) -> impl IntoResponse {
    let result = sqlx::query("UPDATE tenant_domains SET is_active = false, deleted_at = NOW() WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL")
    .bind(tenant_id)
    .bind(domain_id)
    .execute(&db_pool)
    .await;

    match result {
        Ok(result) => {
            if result.rows_affected() == 0 {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        error_description: "Tenant domain not found".to_string(),
                    }),
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "Tenant domain soft-deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
            tracing::error!("Failed to delete tenant domain: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to delete tenant domain: {}", e),
                }),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Federated Identity Providers
// ============================================================================

pub async fn create_identity_provider(
    State(db_pool): State<DbPool>,
    Json(req): Json<CreateIdentityProviderRequest>,
) -> impl IntoResponse {
    let tenant_id = req.tenant_id.unwrap_or_else(default_tenant_id);
    let scopes = req.scopes.filter(|v| !v.is_empty()).unwrap_or_else(|| {
        vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ]
    });
    let encrypted_secret = match encrypt_secret(req.client_secret.trim()) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to encrypt identity provider secret: {}", e),
                }),
            )
                .into_response();
        }
    };

    let result = sqlx::query_as::<_, IdentityProviderResponse>(
        r#"
        INSERT INTO identity_providers (
            tenant_id, slug, provider_type, issuer, client_id, client_secret_encrypted,
            auth_url, token_url, jwks_url, scopes, hd_domain, is_active
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING
            id, tenant_id, slug, provider_type, issuer, client_id,
            auth_url, token_url, jwks_url, scopes, hd_domain, is_active
        "#,
    )
    .bind(tenant_id)
    .bind(req.slug.trim())
    .bind(req.provider_type.trim())
    .bind(req.issuer.trim())
    .bind(req.client_id.trim())
    .bind(encrypted_secret)
    .bind(
        req.auth_url
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
    )
    .bind(
        req.token_url
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
    )
    .bind(
        req.jwks_url
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
    )
    .bind(scopes)
    .bind(
        req.hd_domain
            .map(|v| v.trim().to_lowercase())
            .filter(|v| !v.is_empty()),
    )
    .bind(req.is_active.unwrap_or(true))
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(provider) => (StatusCode::CREATED, Json(provider)).into_response(),
        Err(e) => {
            tracing::error!("Failed to create identity provider: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to create identity provider: {}", e),
                }),
            )
                .into_response()
        }
    }
}

pub async fn list_identity_providers(
    State(db_pool): State<DbPool>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let tenant_id = default_tenant_id();
    let (limit, offset) = match pagination_limit_offset(&pagination) {
        Ok(v) => v,
        Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
    };

    let result = sqlx::query_as::<_, IdentityProviderResponse>(
        r#"
        SELECT
            id, tenant_id, slug, provider_type, issuer, client_id,
            auth_url, token_url, jwks_url, scopes, hd_domain, is_active
        FROM identity_providers
        WHERE tenant_id = $1 AND deleted_at IS NULL
        ORDER BY slug
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&db_pool)
    .await;

    match result {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list identity providers: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to list identity providers".to_string(),
                }),
            )
                .into_response()
        }
    }
}

pub async fn update_identity_provider(
    State(db_pool): State<DbPool>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateIdentityProviderRequest>,
) -> impl IntoResponse {
    let encrypted_secret_update = match req
        .client_secret
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(secret) => match encrypt_secret(secret) {
            Ok(v) => Some(v),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "bad_request".to_string(),
                        error_description: format!(
                            "Failed to encrypt identity provider secret: {}",
                            e
                        ),
                    }),
                )
                    .into_response();
            }
        },
        None => None,
    };

    let result = sqlx::query_as::<_, IdentityProviderResponse>(
        r#"
        UPDATE identity_providers
        SET
            slug = COALESCE($2, slug),
            provider_type = COALESCE($3, provider_type),
            issuer = COALESCE($4, issuer),
            client_id = COALESCE($5, client_id),
            client_secret_encrypted = COALESCE($6, client_secret_encrypted),
            auth_url = COALESCE($7, auth_url),
            token_url = COALESCE($8, token_url),
            jwks_url = COALESCE($9, jwks_url),
            scopes = COALESCE($10, scopes),
            hd_domain = COALESCE($11, hd_domain),
            is_active = COALESCE($12, is_active),
            updated_at = NOW()
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING
            id, tenant_id, slug, provider_type, issuer, client_id,
            auth_url, token_url, jwks_url, scopes, hd_domain, is_active
        "#,
    )
    .bind(id)
    .bind(
        req.slug
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
    )
    .bind(
        req.provider_type
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
    )
    .bind(
        req.issuer
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
    )
    .bind(
        req.client_id
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
    )
    .bind(encrypted_secret_update)
    .bind(
        req.auth_url
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
    )
    .bind(
        req.token_url
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
    )
    .bind(
        req.jwks_url
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
    )
    .bind(req.scopes.filter(|v| !v.is_empty()))
    .bind(
        req.hd_domain
            .map(|v| v.trim().to_lowercase())
            .filter(|v| !v.is_empty()),
    )
    .bind(req.is_active)
    .fetch_optional(&db_pool)
    .await;

    match result {
        Ok(Some(provider)) => (StatusCode::OK, Json(provider)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                error_description: "Identity provider not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to update identity provider: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to update identity provider: {}", e),
                }),
            )
                .into_response()
        }
    }
}

pub async fn delete_identity_provider(
    State(db_pool): State<DbPool>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query(
        "UPDATE identity_providers SET is_active = false, deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .execute(&db_pool)
    .await;

    match result {
        Ok(result) if result.rows_affected() > 0 => (
            StatusCode::OK,
            Json(SuccessResponse {
                message: "Identity provider soft-deleted successfully".to_string(),
            }),
        )
            .into_response(),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                error_description: "Identity provider not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to delete identity provider: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Failed to delete identity provider: {}", e),
                }),
            )
                .into_response()
        }
    }
}
