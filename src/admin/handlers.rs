use crate::auth::password::hash_password;
use crate::password_reset::{create_reset_token_for_user, PasswordResetTokenInfo};
use crate::db::{models::OAuthClient, DbPool};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx;
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
    pub groups_claim_mode: Option<String>,
    pub include_claim_maps: Option<bool>,
    pub ignore_virtual_groups: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOAuthClientRequest {
    pub name: Option<String>,
    pub client_secret: Option<String>,
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
    pub groups_claim_mode: String,
    pub include_claim_maps: bool,
    pub ignore_virtual_groups: bool,
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
    pub group_id: Uuid,
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

// ============================================================================
// User Handlers
// ============================================================================

pub async fn create_user(
    State(db_pool): State<DbPool>,
    Json(req): Json<CreateUserRequest>,
) -> impl IntoResponse {
    let conflict = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM users WHERE email = $1 OR username = $2 LIMIT 1",
    )
    .bind(&req.username)
    .bind(&req.email)
    .fetch_optional(&db_pool)
    .await;

    if let Ok(Some(_)) = conflict {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".to_string(),
                error_description: "Username or email conflicts with an existing account".to_string(),
            }),
        )
            .into_response();
    }

    // Hash password
    let password_hash = match hash_password(&req.password) {
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
        INSERT INTO users (username, email, password_hash, is_active)
        VALUES ($1, $2, $3, $4)
        RETURNING id, username, email, is_active
        "#,
        req.username,
        req.email,
        password_hash,
        is_active
    )
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(user) => (
            StatusCode::CREATED,
            Json(UserResponse {
                id: user.id,
                username: user.username,
                email: user.email,
                is_active: user.is_active,
            }),
        )
            .into_response(),
        Err(e) => {
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
        "SELECT 1 FROM users WHERE id = $1 LIMIT 1",
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
    let (limit, offset) = match pagination_limit_offset(&pagination) {
        Ok(pagination) => pagination,
        Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
    };

    let result = sqlx::query!(
        r#"
        SELECT id, username, email, is_active
        FROM users
        ORDER BY username
        LIMIT $1 OFFSET $2
        "#,
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
    let email = req.email.clone();
    if let Some(email) = &email {
        let conflict = sqlx::query_scalar::<_, i64>(
            "SELECT 1 FROM users WHERE username = $1 AND id <> $2 LIMIT 1",
        )
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
        match hash_password(password) {
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
        WHERE id = $4
        RETURNING id, username, email, is_active
        "#,
        email,
        password_hash,
        req.is_active,
        user_id
    )
    .fetch_optional(&db_pool)
    .await;

    match result {
        Ok(Some(user)) => (
            StatusCode::OK,
            Json(UserResponse {
                id: user.id,
                username: user.username,
                email: user.email,
                is_active: user.is_active,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                error_description: "User not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
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
    let result = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
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
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "User deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
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
    let result = sqlx::query!(
        r#"
        INSERT INTO groups (name, description, is_virtual)
        VALUES ($1, $2, $3)
        RETURNING id, name, description, is_virtual
        "#,
        req.name,
        req.description,
        req.is_virtual.unwrap_or(false)
    )
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(group) => (
            StatusCode::CREATED,
            Json(GroupResponse {
                id: group.id,
                name: group.name,
                description: group.description,
                is_virtual: group.is_virtual,
            }),
        )
            .into_response(),
        Err(e) => {
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
            "SELECT 1 FROM groups WHERE name = $1 AND id <> $2 LIMIT 1",
        )
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
        WHERE id = $4
        RETURNING id, name, description, is_virtual
        "#,
        req.name,
        req.description,
        req.is_virtual,
        group_id
    )
    .fetch_optional(&db_pool)
    .await;

    match result {
        Ok(Some(group)) => (
            StatusCode::OK,
            Json(GroupResponse {
                id: group.id,
                name: group.name,
                description: group.description,
                is_virtual: group.is_virtual,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                error_description: "Group not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
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
    let (limit, offset) = match pagination_limit_offset(&pagination) {
        Ok(pagination) => pagination,
        Err(err) => return (StatusCode::BAD_REQUEST, Json(err)).into_response(),
    };

    let result = sqlx::query!(
        r#"
        SELECT id, name, description, is_virtual
        FROM groups
        ORDER BY name
        LIMIT $1 OFFSET $2
        "#,
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
        ORDER BY u.username, g.name
        LIMIT $1 OFFSET $2
        "#,
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
    let result = sqlx::query!("DELETE FROM groups WHERE id = $1", group_id)
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
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "Group deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
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
    let groups_claim_mode = match req.groups_claim_mode.as_deref() {
        None | Some("effective") => "effective",
        Some("direct") => "direct",
        Some("none") => "none",
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: "groups_claim_mode must be one of: effective, direct, none".to_string(),
                }),
            )
                .into_response();
        }
    };
    let include_claim_maps = req.include_claim_maps.unwrap_or(true);
    let ignore_virtual_groups = req.ignore_virtual_groups.unwrap_or(false);

    if let Err(resp) = validate_redirect_uris(&req.client_id, &req.redirect_uris) {
        return resp;
    }

    // Hash client secret (optional for public clients)
    let client_secret_hash = match &req.client_secret {
        Some(secret) if !secret.trim().is_empty() => {
            match hash_password(secret) {
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
        _ => None, // Public client (no secret)
    };

    let result = sqlx::query!(
        r#"
        INSERT INTO oauth_clients (
            client_id, client_secret_hash, name, redirect_uris, grant_types, scope, is_active,
            groups_claim_mode, include_claim_maps, ignore_virtual_groups
        )
        VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8, $9)
        RETURNING id, client_id, name, redirect_uris, grant_types, scope, is_active,
            groups_claim_mode, include_claim_maps, ignore_virtual_groups
        "#,
        req.client_id,
        client_secret_hash,
        req.name,
        &req.redirect_uris,
        &req.grant_types,
        req.scope,
        groups_claim_mode,
        include_claim_maps,
        ignore_virtual_groups
    )
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(client) => (
            StatusCode::CREATED,
            Json(OAuthClientResponse {
                id: client.id,
                client_id: client.client_id,
                name: client.name,
                redirect_uris: client.redirect_uris,
                grant_types: client.grant_types,
                scope: client.scope,
                is_active: client.is_active,
                groups_claim_mode: client.groups_claim_mode,
                include_claim_maps: client.include_claim_maps,
                ignore_virtual_groups: client.ignore_virtual_groups,
            }),
        )
            .into_response(),
        Err(e) => {
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
        "SELECT * FROM oauth_clients ORDER BY name LIMIT $1 OFFSET $2",
    )
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
    let result = sqlx::query!("DELETE FROM oauth_clients WHERE id = $1", client_id)
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
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "OAuth client deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
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

    let secret_hash = if let Some(secret) = &req.client_secret {
        match hash_password(secret) {
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
    } else {
        None
    };

    let redirect_uris = req.redirect_uris.as_deref();
    let grant_types = req.grant_types.as_deref();

    if let Some(uris) = redirect_uris {
        let client = sqlx::query_scalar::<_, String>(
            "SELECT client_id FROM oauth_clients WHERE id = $1"
        )
        .bind(client_id)
        .fetch_optional(&db_pool)
        .await;

        match client {
            Ok(Some(client_id_str)) => {
                if let Err(resp) = validate_redirect_uris(&client_id_str, uris) {
                    return resp;
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
    let result = sqlx::query!(
        r#"
        UPDATE oauth_clients
        SET
            name = COALESCE($1, name),
            client_secret_hash = COALESCE($2, client_secret_hash),
            redirect_uris = COALESCE($3, redirect_uris),
            grant_types = COALESCE($4, grant_types),
            scope = COALESCE($5, scope),
            is_active = COALESCE($6, is_active),
            groups_claim_mode = COALESCE($7, groups_claim_mode),
            include_claim_maps = COALESCE($8, include_claim_maps),
            ignore_virtual_groups = COALESCE($9, ignore_virtual_groups)
        WHERE id = $10
        RETURNING id, client_id, name, redirect_uris, grant_types, scope, is_active,
            groups_claim_mode, include_claim_maps, ignore_virtual_groups
        "#,
        req.name,
        secret_hash,
        redirect_uris,
        grant_types,
        req.scope,
        req.is_active,
        groups_claim_mode,
        req.include_claim_maps,
        req.ignore_virtual_groups,
        client_id
    )
    .fetch_optional(&db_pool)
    .await;

    match result {
        Ok(Some(client)) => (
            StatusCode::OK,
            Json(OAuthClientResponse {
                id: client.id,
                client_id: client.client_id,
                name: client.name,
                redirect_uris: client.redirect_uris,
                grant_types: client.grant_types,
                scope: client.scope,
                is_active: client.is_active,
                groups_claim_mode: client.groups_claim_mode,
                include_claim_maps: client.include_claim_maps,
                ignore_virtual_groups: client.ignore_virtual_groups,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                error_description: "OAuth client not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
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
) -> Result<(), axum::response::Response> {
    for uri in redirect_uris {
        if uri.contains('*') {
            // Parse URL with wildcard replaced temporarily for validation
            let test_uri = uri.replace('*', "8080");
            let url = Url::parse(&test_uri).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "bad_request".to_string(),
                        error_description: format!("Invalid redirect_uri format: {}", uri),
                    }),
                )
                    .into_response()
            })?;

            // Check if host is loopback (localhost, 127.0.0.1, ::1)
            let host = url.host_str().unwrap_or("");
            let is_loopback = host == "localhost"
                || host == "127.0.0.1"
                || host == "[::1]"
                || host == "::1";

            if !is_loopback {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "bad_request".to_string(),
                        error_description: format!(
                            "Wildcard '*' in redirect_uri is only allowed for loopback addresses (localhost, 127.0.0.1, ::1), got: {}",
                            host
                        ),
                    }),
                )
                    .into_response());
            }

            // Ensure wildcard is only in port position
            if !uri.contains(":*/") && !uri.ends_with(":*") {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "bad_request".to_string(),
                        error_description: "Wildcard '*' must be used for port only (e.g., http://localhost:*/callback)".to_string(),
                    }),
                )
                    .into_response());
            }

            continue;
        }

        let url = Url::parse(uri).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!("Invalid redirect_uri: {}", uri),
                }),
            )
                .into_response()
        })?;

        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "bad_request".to_string(),
                    error_description: format!(
                        "redirect_uris must be http or https: {}",
                        uri
                    ),
                }),
            )
                .into_response());
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
    // Determine kind and values based on input
    let (kind, claim_value_str, claim_value_json) = match &req.claim_value {
        serde_json::Value::String(s) => {
            // Single string value
            ("single", Some(s.clone()), None)
        }
        serde_json::Value::Array(arr) => {
            // Array of strings
            let strings: Vec<String> = arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();

            if strings.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "bad_request".to_string(),
                        error_description: "claim_value array must contain at least one string".to_string(),
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
                    error_description: "claim_value must be a string or array of strings".to_string(),
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
            // Build response value based on kind
            let response_value = if claim_map.claim_value_kind == "array" {
                claim_map.claim_value_json.as_ref()
                    .and_then(|json| serde_json::from_str(json).ok())
            } else {
                claim_map.claim_value.as_ref().map(|s| serde_json::Value::String(s.clone()))
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
        SELECT id, client_id, group_id, claim_name, claim_value, claim_value_kind, claim_value_json, updated_at
        FROM claim_maps
        ORDER BY claim_name
        LIMIT $1 OFFSET $2
        "#,
    )
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
                        cm.claim_value_json.as_ref()
                            .and_then(|json| serde_json::from_str(json).ok())
                    } else {
                        cm.claim_value.as_ref().map(|s| serde_json::Value::String(s.clone()))
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
    let result = sqlx::query!("DELETE FROM claim_maps WHERE id = $1", claim_map_id)
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
                (
                    StatusCode::OK,
                    Json(SuccessResponse {
                        message: "Claim map deleted successfully".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
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
            "SELECT child_group_id FROM group_groups WHERE parent_group_id = $1"
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
            "SELECT child_group_id FROM group_groups WHERE parent_group_id = $1"
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
        "SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1)"
    )
    .bind(parent_id)
    .fetch_one(&db_pool)
    .await;

    let child_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1)"
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
                    error_description: "Adding this relationship would create a cycle in the group hierarchy".to_string(),
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
                "SELECT id, name, description FROM groups WHERE id = $1",
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
        Err(sqlx::Error::Database(ref db_err)) if db_err.constraint() == Some("group_groups_pkey") => {
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
    let result = sqlx::query(
        "DELETE FROM group_groups WHERE parent_group_id = $1 AND child_group_id = $2"
    )
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
            "SELECT id, name, description, is_virtual FROM groups WHERE id = ANY($1) ORDER BY name"
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
            "#
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
