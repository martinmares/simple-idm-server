use crate::auth::{
    build_custom_claims, get_direct_user_group_names, get_effective_user_groups,
    get_user_group_names, verify_password, JwtService,
};
use crate::db::models::{AuthenticationSession, AuthorizationCode, OAuthClient, RefreshToken, UsedRefreshToken, User};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use axum::http::header::SET_COOKIE;
use chrono::{Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

const EMPTY_CLIENT_SECRET_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$cmFuZG9tc2FsdDEyMzQ1Njc4$XuNHV8S+FPZGCjrD8bqRHT5rCREu9xqhvWqmCFKaRRA";

use super::client_credentials::{ErrorResponse, OAuth2State, TokenResponse};
use super::cleanup::cleanup_refresh_tokens;
use super::templates;
use super::utils::apply_client_auth;

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
    pub nonce: Option<String>,
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
    pub nonce: Option<String>,
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
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
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
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Helper: Get valid auth session from cookie
async fn get_auth_session_from_cookie(
    db_pool: &sqlx::PgPool,
    headers: &HeaderMap,
) -> Option<AuthenticationSession> {
    // Extract session token from cookie
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;

    let session_token = cookie_header
        .split(';')
        .find_map(|cookie| {
            let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
            if parts.len() == 2 && parts[0] == "auth_session" {
                Some(parts[1].to_string())
            } else {
                None
            }
        })?;

    // Load session from database
    let session = sqlx::query_as::<_, AuthenticationSession>(
        r#"
        SELECT * FROM authentication_sessions
        WHERE session_token = $1 AND expires_at > NOW()
        "#,
    )
    .bind(&session_token)
    .fetch_optional(db_pool)
    .await
    .ok()??;

    Some(session)
}

/// Endpoint pro inicializaci authorization code flow
/// Zobrazí HTML login formulář nebo automaticky autorizuje (SSO)
pub async fn handle_authorize(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // Získej response_type
    let response_type = params.get("response_type").map(|s| s.as_str()).unwrap_or("");
    if response_type != "code" {
        let html = templates::error_page(
            "unsupported_response_type",
            "Only 'code' response type is supported",
        );
        return Html(html).into_response();
    }

    // Získej client_id
    let client_id = match params.get("client_id") {
        Some(id) => id,
        None => {
            let html = templates::error_page(
                "invalid_request",
                "Missing required parameter: client_id",
            );
            return Html(html).into_response();
        }
    };

    // Získej redirect_uri
    let redirect_uri = match params.get("redirect_uri") {
        Some(uri) => uri,
        None => {
            let html = templates::error_page(
                "invalid_request",
                "Missing required parameter: redirect_uri",
            );
            return Html(html).into_response();
        }
    };

    // Ověř, že klient existuje
    let client = match sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients WHERE client_id = $1 AND is_active = true",
    )
    .bind(client_id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            let html = templates::error_page(
                "invalid_client",
                "OAuth client not found or inactive",
            );
            return Html(html).into_response();
        }
        Err(_) => {
            let html = templates::error_page(
                "server_error",
                "Database error while validating client",
            );
            return Html(html).into_response();
        }
    };

    // Ověř redirect_uri
    if !is_redirect_uri_allowed(&client, redirect_uri) {
        let html = templates::error_page(
            "invalid_request",
            "Invalid redirect_uri for this client",
        );
        return Html(html).into_response();
    }

    // SSO: Check for existing authentication session
    if let Some(auth_session) = get_auth_session_from_cookie(&state.db_pool, &headers).await {
        // User is already authenticated - auto-generate authorization code
        tracing::debug!(
            "SSO: Found valid session for user {}, auto-authorizing",
            auth_session.user_id
        );

        // Generate authorization code
        let code: String = rand::rng()
            .sample_iter(rand::distr::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let expires_at = Utc::now() + Duration::minutes(10);
    let scope = params
        .get("scope")
        .map(|s| s.as_str())
        .unwrap_or(&client.scope);
    let nonce = params.get("nonce").map(|s| s.as_str()).and_then(non_empty);

        // Normalize PKCE fields
        let code_challenge = params.get("code_challenge").map(|s| s.as_str()).and_then(non_empty);
        let code_challenge_method = params.get("code_challenge_method").map(|s| s.as_str()).and_then(non_empty);

        // Store authorization code
        if let Err(e) = sqlx::query(
            r#"
            INSERT INTO authorization_codes
            (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(&code)
        .bind(client.id)
        .bind(auth_session.user_id)
        .bind(redirect_uri)
        .bind(scope)
        .bind(code_challenge)
        .bind(code_challenge_method)
        .bind(nonce)
        .bind(expires_at)
        .execute(&state.db_pool)
        .await
        {
            tracing::error!("Failed to store authorization code for SSO: {:?}", e);
            let html = templates::error_page(
                "server_error",
                "Failed to create authorization code",
            );
            return Html(html).into_response();
        }

        // Redirect with authorization code (SSO successful)
        let mut redirect_url = redirect_uri.clone();
        redirect_url.push_str(&format!("?code={}", code));
        if let Some(state) = params.get("state") {
            redirect_url.push_str(&format!("&state={}", state));
        }

        return Redirect::to(&redirect_url).into_response();
    }

    // No valid session - show login form
    let html = templates::login_page(&params, None);
    Html(html).into_response()
}

fn is_redirect_uri_allowed(client: &OAuthClient, redirect_uri: &str) -> bool {
    if client
        .redirect_uris
        .iter()
        .any(|uri| uri == redirect_uri)
    {
        return true;
    }

    if client.client_id != "cli-tools" {
        return false;
    }

    client.redirect_uris.iter().any(|uri| {
        matches_localhost_wildcard(uri, "localhost", redirect_uri)
            || matches_localhost_wildcard(uri, "127.0.0.1", redirect_uri)
    })
}

fn matches_localhost_wildcard(pattern: &str, host: &str, redirect_uri: &str) -> bool {
    if pattern != format!("http://{}:*/callback", host) {
        return false;
    }

    let Ok(url) = Url::parse(redirect_uri) else {
        return false;
    };

    url.scheme() == "http"
        && url.host_str() == Some(host)
        && url.path() == "/callback"
        && url.port().is_some()
}

/// Helper: Create authentication session for SSO
async fn create_auth_session(
    db_pool: &sqlx::PgPool,
    user_id: Uuid,
    client_id: Option<Uuid>,
    session_expiry_seconds: i64,
) -> Result<String, sqlx::Error> {
    // Generate random session token
    let session_token: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let expires_at = Utc::now() + Duration::seconds(session_expiry_seconds);

    // Store session in database
    sqlx::query(
        r#"
        INSERT INTO authentication_sessions
        (session_token, user_id, client_id, expires_at)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(&session_token)
    .bind(user_id)
    .bind(client_id)
    .bind(expires_at)
    .execute(db_pool)
    .await?;

    Ok(session_token)
}

/// Endpoint pro login a vygenerování authorization code
/// Přijímá HTML form data a redirectuje zpět na aplikaci
pub async fn handle_login(
    State(state): State<Arc<OAuth2State>>,
    Form(req): Form<LoginRequest>,
) -> impl IntoResponse {
    // Ověř uživatele
    let user = match sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE (username = $1 OR email = $1) AND is_active = true",
    )
    .bind(&req.username)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            // Zobraz login formulář s chybou
            let mut params = HashMap::new();
            params.insert("client_id".to_string(), req.client_id.clone());
            params.insert("redirect_uri".to_string(), req.redirect_uri.clone());
            if let Some(state) = &req.state {
                params.insert("state".to_string(), state.clone());
            }
            if let Some(nonce) = &req.nonce {
                params.insert("nonce".to_string(), nonce.clone());
            }
            if let Some(scope) = &req.scope {
                params.insert("scope".to_string(), scope.clone());
            }
            if let Some(challenge) = &req.code_challenge {
                params.insert("code_challenge".to_string(), challenge.clone());
            }
            if let Some(method) = &req.code_challenge_method {
                params.insert("code_challenge_method".to_string(), method.clone());
            }

            let html = templates::login_page(&params, Some("Invalid username or password"));
            return Html(html).into_response();
        }
        Err(_) => {
            let html = templates::error_page(
                "server_error",
                "Database error while validating user",
            );
            return Html(html).into_response();
        }
    };

    // Ověř heslo
    if !verify_password(&req.password, &user.password_hash).unwrap_or(false) {
        // Zobraz login formulář s chybou
        let mut params = HashMap::new();
        params.insert("client_id".to_string(), req.client_id.clone());
        params.insert("redirect_uri".to_string(), req.redirect_uri.clone());
        if let Some(state) = &req.state {
            params.insert("state".to_string(), state.clone());
        }
        if let Some(nonce) = &req.nonce {
            params.insert("nonce".to_string(), nonce.clone());
        }
        if let Some(scope) = &req.scope {
            params.insert("scope".to_string(), scope.clone());
        }
        if let Some(challenge) = &req.code_challenge {
            params.insert("code_challenge".to_string(), challenge.clone());
        }
        if let Some(method) = &req.code_challenge_method {
            params.insert("code_challenge_method".to_string(), method.clone());
        }

        let html = templates::login_page(&params, Some("Invalid username or password"));
        return Html(html).into_response();
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
            let html = templates::error_page(
                "invalid_client",
                "OAuth client not found",
            );
            return Html(html).into_response();
        }
        Err(_) => {
            let html = templates::error_page(
                "server_error",
                "Database error while validating client",
            );
            return Html(html).into_response();
        }
    };

    // Normalize empty PKCE fields (Grafana can submit empty values)
    let code_challenge = req.code_challenge.as_deref().and_then(non_empty);
    let code_challenge_method = req.code_challenge_method.as_deref().and_then(non_empty);
    let nonce = req.nonce.as_deref().and_then(non_empty);

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
        (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(&code)
    .bind(client.id)
    .bind(user.id)
    .bind(&req.redirect_uri)
    .bind(&scope)
    .bind(code_challenge)
    .bind(code_challenge_method)
    .bind(nonce)
    .bind(expires_at)
    .execute(&state.db_pool)
    .await
    {
        let html = templates::error_page(
            "server_error",
            "Failed to create authorization code",
        );
        return Html(html).into_response();
    }

    // Create authentication session for SSO
    let session_token = match create_auth_session(
        &state.db_pool,
        user.id,
        Some(client.id),
        state.auth_session_expiry,
    )
    .await
    {
        Ok(token) => token,
        Err(_) => {
            tracing::warn!("Failed to create auth session for user {}", user.id);
            // Continue without session - not critical for this flow
            String::new()
        }
    };

    // Redirect zpět na aplikaci s authorization code
    let mut redirect_url = req.redirect_uri.clone();
    redirect_url.push_str(&format!("?code={}", code));
    if let Some(state) = req.state {
        redirect_url.push_str(&format!("&state={}", state));
    }

    // Set session cookie if session was created
    if !session_token.is_empty() {
        let cookie = format!(
            "auth_session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
            session_token, state.auth_session_expiry
        );

        let mut response = Redirect::to(&redirect_url).into_response();
        response.headers_mut().insert(
            SET_COOKIE,
            cookie.parse().unwrap(),
        );
        return response;
    }

    Redirect::to(&redirect_url).into_response()
}

/// Endpoint pro výměnu authorization code za access token
pub async fn handle_token(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let req = match parse_token_request(&headers, &body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };

    let mut req = req;
    apply_client_auth(&mut req.client_id, &mut req.client_secret, &headers);

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

fn parse_token_request(headers: &HeaderMap, body: &[u8]) -> Result<TokenRequest, Response> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    let parse_json = || serde_json::from_slice::<TokenRequest>(body).map_err(|_| ());
    let parse_form = || serde_urlencoded::from_bytes::<TokenRequest>(body).map_err(|_| ());

    let parsed: Result<TokenRequest, ()> = if content_type.starts_with("application/json") {
        parse_json()
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        parse_form()
    } else if content_type.is_empty() {
        parse_json().or_else(|_| parse_form())
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
                error_description: "Failed to parse token request".to_string(),
            }),
        )
            .into_response()
    })
}

fn generate_refresh_token() -> String {
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

async fn handle_authorization_code_token(
    state: Arc<OAuth2State>,
    req: TokenRequest,
) -> Response {
    cleanup_refresh_tokens(&state.db_pool).await;

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

    let req_client_id = match req.client_id {
        Some(id) => id,
        None => {
            return Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Missing client_id".to_string(),
            })
            .into_response()
        }
    };

    if req_client_id != client.client_id {
        return Json(ErrorResponse {
            error: "invalid_client".to_string(),
            error_description: "Client ID mismatch".to_string(),
        })
        .into_response();
    }

    let req_redirect_uri = match req.redirect_uri {
        Some(uri) => uri,
        None => {
            return Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Missing redirect_uri".to_string(),
            })
            .into_response()
        }
    };

    if req_redirect_uri != auth_code.redirect_uri {
        return Json(ErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Redirect URI mismatch".to_string(),
        })
        .into_response();
    }

    // Validace client credentials
    // Pro PKCE public clients (code_verifier present) přeskočíme client_secret validaci
    let has_pkce = req.code_verifier.is_some();

    if !has_pkce {
        // Confidential client - vyžaduje client_secret
        let client_secret = match req.client_secret {
            Some(secret) if !secret.is_empty() => secret,
            _ => {
                return Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Missing client_secret".to_string(),
                })
                .into_response()
            }
        };

        // Verify client secret for confidential clients
        if !client.is_public {
            if let Some(ref hash) = client.client_secret_hash {
                if !verify_password(&client_secret, hash).unwrap_or(false) {
                    return Json(ErrorResponse {
                        error: "invalid_client".to_string(),
                        error_description: "Invalid client credentials".to_string(),
                    })
                    .into_response();
                }
            } else {
                return Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Client secret required for confidential client".to_string(),
                })
                .into_response();
            }
        }
    }

    // PKCE validace
    if let Some(challenge) = auth_code.code_challenge.as_deref().and_then(non_empty) {
        match req.code_verifier {
            Some(ref verifier) => {
                // Zjednodušená PKCE validace (S256 nebo plain)
                let valid = match auth_code
                    .code_challenge_method
                    .as_deref()
                    .and_then(non_empty)
                {
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

    let user_group_names = match client.groups_claim_mode.as_str() {
        "none" => vec![],
        "direct" => match get_direct_user_group_names(&state.db_pool, user.id, client.ignore_virtual_groups).await {
            Ok(names) => names,
            Err(_) => {
                return Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to fetch direct user group names".to_string(),
                })
                .into_response()
            }
        },
        _ => match get_user_group_names(&state.db_pool, user.id, client.ignore_virtual_groups).await {
            Ok(names) => names,
            Err(_) => {
                return Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to fetch user group names".to_string(),
                })
                .into_response()
            }
        },
    };

    // Vytvoř custom claims pomocí claim maps (pokud povoleno)
    let custom_claims = if client.include_claim_maps {
        let user_group_ids = match get_effective_user_groups(&state.db_pool, user.id).await {
            Ok(ids) => ids,
            Err(_) => {
                return Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to fetch user groups".to_string(),
                })
                .into_response()
            }
        };
        match build_custom_claims(&state.db_pool, client.id, &user_group_ids).await {
            Ok(claims) => claims,
            Err(_) => {
                return Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to build custom claims".to_string(),
                })
                .into_response()
            }
        }
    } else {
        std::collections::HashMap::new()
    };

    // Log JWT claims and groups for debugging
    tracing::debug!(
        user_id = %user.id,
        username = %user.username,
        client_id = %client.client_id,
        groups = ?user_group_names,
        custom_claims = ?custom_claims,
        "Issuing JWT token"
    );

    // Vytvoř access token
    let access_token = match state.jwt_service.create_access_token(
        user.id,
        client.client_id.clone(),
        Some(user.email.clone()),
        Some(user.username.clone()),
        Some(auth_code.scope.clone()),
        user_group_names.clone(),
        custom_claims.clone(),
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

    let id_token = match state.jwt_service.create_id_token(
        user.id,
        client.client_id.clone(),
        Some(user.email.clone()),
        Some(user.username.clone()),
        user_group_names,
        custom_claims,
        auth_code.nonce.clone(),
        state.access_token_expiry,
    ) {
        Ok(token) => token,
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to create ID token".to_string(),
            })
            .into_response()
        }
    };

    // Vytvoř refresh token
    let refresh_token = generate_refresh_token();
    let refresh_expires_at = Utc::now() + Duration::seconds(state.refresh_token_expiry);

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

    cleanup_refresh_tokens(&state.db_pool).await;

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
        id_token: Some(id_token),
        scope: Some(auth_code.scope),
    })
    .into_response()
}

fn non_empty(value: &str) -> Option<&str> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

async fn handle_refresh_token(state: Arc<OAuth2State>, req: TokenRequest) -> Response {
    cleanup_refresh_tokens(&state.db_pool).await;

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
            let used = sqlx::query_as::<_, UsedRefreshToken>(
                "SELECT * FROM used_refresh_tokens WHERE token = $1",
            )
            .bind(&refresh_token_str)
            .fetch_optional(&state.db_pool)
            .await;

            if let Ok(Some(used)) = used {
                let _ = sqlx::query(
                    "DELETE FROM refresh_tokens WHERE client_id = $1 AND user_id = $2",
                )
                .bind(used.client_id)
                .bind(used.user_id)
                .execute(&state.db_pool)
                .await;
            }

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

    let client_secret = req.client_secret.unwrap_or_default();

    // Verify client credentials (only for confidential clients)
    if !client.is_public {
        if client_secret.is_empty() {
            return Json(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Missing client_secret for confidential client".to_string(),
            })
            .into_response();
        }

        if let Some(ref hash) = client.client_secret_hash {
            if !verify_password(&client_secret, hash).unwrap_or(false) {
                return Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Invalid client credentials".to_string(),
                })
                .into_response();
            }
        } else {
            return Json(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client secret required for confidential client".to_string(),
            })
            .into_response();
        }
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

    let user_group_names = match client.groups_claim_mode.as_str() {
        "none" => vec![],
        "direct" => get_direct_user_group_names(&state.db_pool, user.id, client.ignore_virtual_groups)
            .await
            .unwrap_or_default(),
        _ => get_user_group_names(&state.db_pool, user.id, client.ignore_virtual_groups).await.unwrap_or_default(),
    };

    let custom_claims = if client.include_claim_maps {
        let user_group_ids = get_effective_user_groups(&state.db_pool, user.id)
            .await
            .unwrap_or_default();
        build_custom_claims(&state.db_pool, client.id, &user_group_ids)
            .await
            .unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };

    // Log JWT claims and groups for debugging
    tracing::debug!(
        user_id = %user.id,
        username = %user.username,
        client_id = %client.client_id,
        groups = ?user_group_names,
        custom_claims = ?custom_claims,
        "Issuing JWT token (refresh)"
    );

    // Vytvoř nový access token
    let access_token = match state.jwt_service.create_access_token(
        user.id,
        client.client_id.clone(),
        Some(user.email.clone()),
        Some(user.username.clone()),
        Some(refresh_token.scope.clone()),
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

    // Rotate refresh token
    let new_refresh_token = generate_refresh_token();
    let new_refresh_expires_at = Utc::now() + Duration::seconds(state.refresh_token_expiry);

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to start transaction".to_string(),
            })
            .into_response()
        }
    };

    if sqlx::query(
        r#"
        INSERT INTO refresh_tokens (token, client_id, user_id, scope, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(&new_refresh_token)
    .bind(refresh_token.client_id)
    .bind(refresh_token.user_id)
    .bind(&refresh_token.scope)
    .bind(new_refresh_expires_at)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        return Json(ErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to create refresh token".to_string(),
        })
        .into_response();
    }

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
        return Json(ErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to mark refresh token as used".to_string(),
        })
        .into_response();
    }

    if sqlx::query("DELETE FROM refresh_tokens WHERE token = $1")
        .bind(&refresh_token_str)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        let _ = tx.rollback().await;
        return Json(ErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to rotate refresh token".to_string(),
        })
        .into_response();
    }

    if tx.commit().await.is_err() {
        return Json(ErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to commit refresh token rotation".to_string(),
        })
        .into_response();
    }

    Json(TokenResponseWithRefresh {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.access_token_expiry,
        refresh_token: Some(new_refresh_token),
        id_token: None,
        scope: Some(refresh_token.scope),
    })
    .into_response()
}

/// Logout endpoint - invalidates authentication session
pub async fn handle_logout(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Extract session token from cookie
    if let Some(cookie_header) = headers.get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            if let Some(session_token) = cookie_str.split(';').find_map(|cookie| {
                let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
                if parts.len() == 2 && parts[0] == "auth_session" {
                    Some(parts[1].to_string())
                } else {
                    None
                }
            }) {
                // Delete session from database
                let _ = sqlx::query("DELETE FROM authentication_sessions WHERE session_token = $1")
                    .bind(&session_token)
                    .execute(&state.db_pool)
                    .await;

                tracing::debug!("Logout: Deleted session {}", session_token);
            }
        }
    }

    // Clear cookie by setting Max-Age=0
    let cookie = "auth_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";

    let mut response = Html("<html><body><h1>Logged out</h1><p>You have been successfully logged out.</p></body></html>")
        .into_response();

    response.headers_mut().insert(
        SET_COOKIE,
        cookie.parse().unwrap(),
    );

    response
}
