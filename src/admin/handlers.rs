use crate::auth::password::hash_password;
use crate::password_reset::{create_reset_token_for_user, PasswordResetTokenInfo};
use crate::db::{models::OAuthClient, DbPool};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx;
use std::env;
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
}

#[derive(Debug, Serialize)]
pub struct GroupResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
}

// User-Group assignment
#[derive(Debug, Deserialize)]
pub struct AssignGroupRequest {
    pub group_id: Uuid,
}

// OAuth Client types
#[derive(Debug, Deserialize)]
pub struct CreateOAuthClientRequest {
    pub client_id: String,
    pub client_secret: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scope: String,
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
}

// Claim Map types
#[derive(Debug, Deserialize)]
pub struct CreateClaimMapRequest {
    pub client_id: Uuid,
    pub group_id: Uuid,
    pub claim_name: String,
    pub claim_value: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ClaimMapResponse {
    pub id: Uuid,
    pub client_id: Uuid,
    pub group_id: Uuid,
    pub claim_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_value: Option<String>,
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

pub async fn list_users(State(db_pool): State<DbPool>) -> impl IntoResponse {
    let result = sqlx::query!(
        r#"
        SELECT id, username, email, is_active
        FROM users
        ORDER BY username
        "#
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
    // Build dynamic update query
    let mut query_parts = vec![];
    let mut params: Vec<String> = vec![];
    let mut param_idx = 1;

    if let Some(email) = &req.email {
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

        query_parts.push(format!("email = ${}", param_idx));
        params.push(email.clone());
        param_idx += 1;
    }

    if let Some(password) = &req.password {
        let password_hash = match hash_password(password) {
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
        query_parts.push(format!("password_hash = ${}", param_idx));
        params.push(password_hash);
        param_idx += 1;
    }

    if let Some(is_active) = req.is_active {
        query_parts.push(format!("is_active = ${}", param_idx));
        params.push(is_active.to_string());
        param_idx += 1;
    }

    if query_parts.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bad_request".to_string(),
                error_description: "No fields to update".to_string(),
            }),
        )
            .into_response();
    }

    // Update timestamp
    query_parts.push("updated_at = NOW()".to_string());

    let query = format!(
        "UPDATE users SET {} WHERE id = ${} RETURNING id, username, email, is_active",
        query_parts.join(", "),
        param_idx
    );

    // Build query with sqlx
    let mut query_builder = sqlx::query_as::<_, (Uuid, String, String, bool)>(&query);
    for param in params {
        query_builder = query_builder.bind(param);
    }
    query_builder = query_builder.bind(user_id);

    match query_builder.fetch_one(&db_pool).await {
        Ok((id, username, email, is_active)) => (
            StatusCode::OK,
            Json(UserResponse {
                id,
                username,
                email,
                is_active,
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to update user: {:?}", e);
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    error_description: "User not found".to_string(),
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
        INSERT INTO groups (name, description)
        VALUES ($1, $2)
        RETURNING id, name, description
        "#,
        req.name,
        req.description
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

pub async fn list_groups(State(db_pool): State<DbPool>) -> impl IntoResponse {
    let result = sqlx::query!(
        r#"
        SELECT id, name, description
        FROM groups
        ORDER BY name
        "#
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
    // Hash client secret
    let client_secret_hash = match hash_password(&req.client_secret) {
        Ok(hash) => hash,
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
    };

    let result = sqlx::query!(
        r#"
        INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, grant_types, scope, is_active)
        VALUES ($1, $2, $3, $4, $5, $6, true)
        RETURNING id, client_id, name, redirect_uris, grant_types, scope, is_active
        "#,
        req.client_id,
        client_secret_hash,
        req.name,
        &req.redirect_uris,
        &req.grant_types,
        req.scope
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

pub async fn list_oauth_clients(State(db_pool): State<DbPool>) -> impl IntoResponse {
    let result = sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients ORDER BY name"
    )
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

// ============================================================================
// Claim Map Handlers
// ============================================================================

pub async fn create_claim_map(
    State(db_pool): State<DbPool>,
    Json(req): Json<CreateClaimMapRequest>,
) -> impl IntoResponse {
    let result = sqlx::query_as::<_, crate::db::models::ClaimMap>(
        r#"
        INSERT INTO claim_maps (client_id, group_id, claim_name, claim_value)
        VALUES ($1, $2, $3, $4)
        RETURNING id, client_id, group_id, claim_name, claim_value
        "#,
    )
    .bind(req.client_id)
    .bind(req.group_id)
    .bind(req.claim_name)
    .bind(req.claim_value)
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(claim_map) => (
            StatusCode::CREATED,
            Json(ClaimMapResponse {
                id: claim_map.id,
                client_id: claim_map.client_id,
                group_id: claim_map.group_id,
                claim_name: claim_map.claim_name,
                claim_value: claim_map.claim_value,
            }),
        )
            .into_response(),
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

pub async fn list_claim_maps(State(db_pool): State<DbPool>) -> impl IntoResponse {
    let result = sqlx::query_as::<_, crate::db::models::ClaimMap>(
        r#"
        SELECT id, client_id, group_id, claim_name, claim_value
        FROM claim_maps
        ORDER BY claim_name
        "#,
    )
    .fetch_all(&db_pool)
    .await;

    match result {
        Ok(claim_maps) => {
            let claim_maps: Vec<ClaimMapResponse> = claim_maps
                .into_iter()
                .map(|cm| ClaimMapResponse {
                    id: cm.id,
                    client_id: cm.client_id,
                    group_id: cm.group_id,
                    claim_name: cm.claim_name,
                    claim_value: cm.claim_value,
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
