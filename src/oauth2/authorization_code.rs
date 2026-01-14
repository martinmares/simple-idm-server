use crate::auth::{build_custom_claims, get_user_group_names, get_user_groups, verify_password, JwtService};
use crate::db::{models::{AuthorizationCode, OAuthClient, RefreshToken, User}, DbPool};
use axum::{extract::State, response::{IntoResponse, Response}, Json};
use chrono::{Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx;
use std::sync::Arc;
use uuid::Uuid;

use super::client_credentials::{ErrorResponse, OAuth2State, TokenResponse};

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub authorization_url: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub code: String,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponseWithRefresh {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Endpoint pro inicializaci authorization code flow
/// V praxi by toto bylo HTML stránka s login formulářem
pub async fn handle_authorize(
    State(state): State<Arc<OAuth2State>>,
    Json(req): Json<AuthorizeRequest>,
) -> impl IntoResponse {
    if req.response_type != "code" {
        return Json(ErrorResponse {
            error: "unsupported_response_type".to_string(),
            error_description: "Only 'code' response type is supported".to_string(),
        })
        .into_response();
    }

    // Ověř, že klient existuje
    let client = match sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients WHERE client_id = $1 AND is_active = true",
    )
    .bind(&req.client_id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return Json(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client not found".to_string(),
            })
            .into_response()
        }
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Database error".to_string(),
            })
            .into_response()
        }
    };

    // Ověř redirect_uri
    if !client.redirect_uris.contains(&req.redirect_uri) {
        return Json(ErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "Invalid redirect_uri".to_string(),
        })
        .into_response();
    }

    // V produkci by zde byl redirect na login stránku
    Json(AuthorizeResponse {
        authorization_url: format!("/login?client_id={}&redirect_uri={}", req.client_id, req.redirect_uri),
    })
    .into_response()
}

/// Endpoint pro login a vygenerování authorization code
pub async fn handle_login(
    State(state): State<Arc<OAuth2State>>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    // Ověř uživatele
    let user = match sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE username = $1 AND is_active = true",
    )
    .bind(&req.username)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Invalid credentials".to_string(),
            })
            .into_response()
        }
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Database error".to_string(),
            })
            .into_response()
        }
    };

    // Ověř heslo
    if !verify_password(&req.password, &user.password_hash).unwrap_or(false) {
        return Json(ErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Invalid credentials".to_string(),
        })
        .into_response();
    }

    // Ověř klienta
    let client = match sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients WHERE client_id = $1 AND is_active = true",
    )
    .bind(&req.client_id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return Json(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client not found".to_string(),
            })
            .into_response()
        }
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Database error".to_string(),
            })
            .into_response()
        }
    };

    // Vygeneruj authorization code
    let code: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let expires_at = Utc::now() + Duration::minutes(10);
    let scope = req.scope.unwrap_or_else(|| client.scope.clone());

    // Ulož code do DB
    if let Err(_) = sqlx::query(
        r#"
        INSERT INTO authorization_codes
        (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(&code)
    .bind(client.id)
    .bind(user.id)
    .bind(&req.redirect_uri)
    .bind(&scope)
    .bind(&req.code_challenge)
    .bind(&req.code_challenge_method)
    .bind(expires_at)
    .execute(&state.db_pool)
    .await
    {
        return Json(ErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to create authorization code".to_string(),
        })
        .into_response();
    }

    Json(LoginResponse {
        code,
        state: req.state,
    })
    .into_response()
}

/// Endpoint pro výměnu authorization code za access token
pub async fn handle_token(
    State(state): State<Arc<OAuth2State>>,
    Json(req): Json<TokenRequest>,
) -> Response {
    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_token(state, req).await,
        "refresh_token" => handle_refresh_token(state, req).await,
        _ => Json(ErrorResponse {
            error: "unsupported_grant_type".to_string(),
            error_description: "Unsupported grant type".to_string(),
        })
        .into_response(),
    }
}

async fn handle_authorization_code_token(
    state: Arc<OAuth2State>,
    req: TokenRequest,
) -> Response {
    let code = match req.code {
        Some(c) => c,
        None => {
            return Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Missing code parameter".to_string(),
            })
            .into_response()
        }
    };

    // Načti authorization code
    let auth_code = match sqlx::query_as::<_, AuthorizationCode>(
        "SELECT * FROM authorization_codes WHERE code = $1",
    )
    .bind(&code)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(ac)) => ac,
        Ok(None) => {
            return Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Invalid authorization code".to_string(),
            })
            .into_response()
        }
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Database error".to_string(),
            })
            .into_response()
        }
    };

    // Zkontroluj expiraci
    if auth_code.expires_at < Utc::now() {
        let _ = sqlx::query("DELETE FROM authorization_codes WHERE code = $1")
            .bind(&code)
            .execute(&state.db_pool)
            .await;

        return Json(ErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Authorization code expired".to_string(),
        })
        .into_response();
    }

    // Ověř klienta
    let client = match sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients WHERE id = $1 AND is_active = true",
    )
    .bind(auth_code.client_id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return Json(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client not found".to_string(),
            })
            .into_response()
        }
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Database error".to_string(),
            })
            .into_response()
        }
    };

    // Ověř client secret
    if !verify_password(&req.client_secret, &client.client_secret_hash).unwrap_or(false) {
        return Json(ErrorResponse {
            error: "invalid_client".to_string(),
            error_description: "Invalid client credentials".to_string(),
        })
        .into_response();
    }

    // PKCE validace
    if let Some(challenge) = &auth_code.code_challenge {
        match req.code_verifier {
            Some(ref verifier) => {
                // Zjednodušená PKCE validace (S256 nebo plain)
                let valid = match auth_code.code_challenge_method.as_deref() {
                    Some("plain") => challenge == verifier,
                    Some("S256") => {
                        use sha2::{Sha256, Digest};
                        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
                        let hash = Sha256::digest(verifier.as_bytes());
                        let encoded = URL_SAFE_NO_PAD.encode(hash);
                        challenge == &encoded
                    }
                    _ => false,
                };

                if !valid {
                    return Json(ErrorResponse {
                        error: "invalid_grant".to_string(),
                        error_description: "Invalid code verifier".to_string(),
                    })
                    .into_response();
                }
            }
            None => {
                return Json(ErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: "Missing code_verifier".to_string(),
                })
                .into_response()
            }
        }
    }

    // Načti uživatele
    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(auth_code.user_id)
        .fetch_optional(&state.db_pool)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "User not found".to_string(),
            })
            .into_response()
        }
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Database error".to_string(),
            })
            .into_response()
        }
    };

    // Načti skupiny uživatele
    let user_group_ids = match get_user_groups(&state.db_pool, user.id).await {
        Ok(ids) => ids,
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to fetch user groups".to_string(),
            })
            .into_response()
        }
    };

    let user_group_names = match get_user_group_names(&state.db_pool, user.id).await {
        Ok(names) => names,
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to fetch user group names".to_string(),
            })
            .into_response()
        }
    };

    // Vytvoř custom claims pomocí claim maps
    let custom_claims = match build_custom_claims(&state.db_pool, client.id, &user_group_ids).await
    {
        Ok(claims) => claims,
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to build custom claims".to_string(),
            })
            .into_response()
        }
    };

    // Vytvoř access token
    let access_token = match state.jwt_service.create_access_token(
        user.id,
        client.client_id.clone(),
        Some(user.email.clone()),
        user_group_names,
        custom_claims,
        state.access_token_expiry,
    ) {
        Ok(token) => token,
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to create access token".to_string(),
            })
            .into_response()
        }
    };

    // Vytvoř refresh token
    let refresh_token: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let refresh_expires_at = Utc::now() + Duration::seconds(2592000); // 30 days

    if let Err(_) = sqlx::query(
        r#"
        INSERT INTO refresh_tokens (token, client_id, user_id, scope, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(&refresh_token)
    .bind(client.id)
    .bind(user.id)
    .bind(&auth_code.scope)
    .bind(refresh_expires_at)
    .execute(&state.db_pool)
    .await
    {
        return Json(ErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to create refresh token".to_string(),
        })
        .into_response();
    }

    // Smaž použitý authorization code
    let _ = sqlx::query("DELETE FROM authorization_codes WHERE code = $1")
        .bind(&code)
        .execute(&state.db_pool)
        .await;

    Json(TokenResponseWithRefresh {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.access_token_expiry,
        refresh_token: Some(refresh_token),
        scope: Some(auth_code.scope),
    })
    .into_response()
}

async fn handle_refresh_token(state: Arc<OAuth2State>, req: TokenRequest) -> Response {
    let refresh_token_str = match req.refresh_token {
        Some(rt) => rt,
        None => {
            return Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Missing refresh_token parameter".to_string(),
            })
            .into_response()
        }
    };

    // Načti refresh token
    let refresh_token = match sqlx::query_as::<_, RefreshToken>(
        "SELECT * FROM refresh_tokens WHERE token = $1",
    )
    .bind(&refresh_token_str)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(rt)) => rt,
        Ok(None) => {
            return Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Invalid refresh token".to_string(),
            })
            .into_response()
        }
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Database error".to_string(),
            })
            .into_response()
        }
    };

    // Zkontroluj expiraci
    if refresh_token.expires_at < Utc::now() {
        let _ = sqlx::query("DELETE FROM refresh_tokens WHERE token = $1")
            .bind(&refresh_token_str)
            .execute(&state.db_pool)
            .await;

        return Json(ErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Refresh token expired".to_string(),
        })
        .into_response();
    }

    // Ověř klienta
    let client = match sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients WHERE id = $1 AND is_active = true",
    )
    .bind(refresh_token.client_id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return Json(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client not found".to_string(),
            })
            .into_response()
        }
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Database error".to_string(),
            })
            .into_response()
        }
    };

    if !verify_password(&req.client_secret, &client.client_secret_hash).unwrap_or(false) {
        return Json(ErrorResponse {
            error: "invalid_client".to_string(),
            error_description: "Invalid client credentials".to_string(),
        })
        .into_response();
    }

    // Načti uživatele
    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(refresh_token.user_id)
        .fetch_optional(&state.db_pool)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "User not found".to_string(),
            })
            .into_response()
        }
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Database error".to_string(),
            })
            .into_response()
        }
    };

    // Načti skupiny
    let user_group_ids = match get_user_groups(&state.db_pool, user.id).await {
        Ok(ids) => ids,
        Err(_) => vec![],
    };

    let user_group_names = match get_user_group_names(&state.db_pool, user.id).await {
        Ok(names) => names,
        Err(_) => vec![],
    };

    let custom_claims = match build_custom_claims(&state.db_pool, client.id, &user_group_ids).await
    {
        Ok(claims) => claims,
        Err(_) => std::collections::HashMap::new(),
    };

    // Vytvoř nový access token
    let access_token = match state.jwt_service.create_access_token(
        user.id,
        client.client_id.clone(),
        Some(user.email.clone()),
        user_group_names,
        custom_claims,
        state.access_token_expiry,
    ) {
        Ok(token) => token,
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to create access token".to_string(),
            })
            .into_response()
        }
    };

    Json(TokenResponseWithRefresh {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.access_token_expiry,
        refresh_token: Some(refresh_token_str), // vrátíme stejný refresh token
        scope: Some(refresh_token.scope),
    })
    .into_response()
}
