use crate::auth::{
    build_custom_claims, get_direct_user_group_names, get_effective_user_groups,
    get_user_group_names, verify_password,
};
use crate::audit;
use crate::client_group_filters::apply_client_group_filters;
use crate::db::models::{AuthenticationSession, AuthorizationCode, OAuthClient, OAuthClientGroupPattern, RefreshToken, UsedRefreshToken, User};
use crate::secret_crypto::decrypt_secret;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use axum::http::header::SET_COOKIE;
use chrono::{Duration, Utc};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sqlx;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

#[allow(dead_code)]
const EMPTY_CLIENT_SECRET_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$cmFuZG9tc2FsdDEyMzQ1Njc4$XuNHV8S+FPZGCjrD8bqRHT5rCREu9xqhvWqmCFKaRRA";

use super::client_credentials::{ErrorResponse, OAuth2State};
use super::cleanup::cleanup_refresh_tokens;
use super::ldap_role_sync::sync_ldap_roles_if_stale;
use super::throttle;
use super::templates;
use super::utils::{apply_client_auth, resolve_oauth_client, ClientLookupError};
use simple_idm_ad_auth::verify_ldap_password;

#[derive(Debug, Deserialize, Serialize)]
struct FederatedStatePayload {
    csrf: String,
    client_id: String,
    redirect_uri: String,
    tenant: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct IdentityProviderRow {
    id: Uuid,
    tenant_id: Uuid,
    slug: String,
    issuer: String,
    client_id: String,
    client_secret_encrypted: String,
    auth_url: Option<String>,
    token_url: Option<String>,
    scopes: Vec<String>,
    hd_domain: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryResponse {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct OidcUserInfoResponse {
    sub: String,
}

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
#[allow(dead_code)]
pub struct AuthorizeResponse {
    pub authorization_url: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub client_id: String,
    pub tenant: Option<String>,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub csrf_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
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
    pub device_code: Option<String>, // For device flow
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
    let tenant_hint = params.get("tenant").map(|s| s.as_str());
    let client = match resolve_oauth_client(&state.db_pool, client_id, tenant_hint).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            let html = templates::error_page(
                "invalid_client",
                "OAuth client not found or inactive",
            );
            return Html(html).into_response();
        }
        Err(ClientLookupError::AmbiguousClientId) => {
            let html = templates::error_page(
                "invalid_request",
                "Ambiguous client_id. Provide tenant hint.",
            );
            return Html(html).into_response();
        }
        Err(ClientLookupError::InvalidTenantHint) => {
            let html = templates::error_page(
                "invalid_request",
                "Invalid tenant hint",
            );
            return Html(html).into_response();
        }
        Err(ClientLookupError::Database) => {
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
    let csrf_token: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let mut params = params;
    params.insert("csrf_token".to_string(), csrf_token.clone());
    let html = templates::login_page(&params, None);

    let secure =
        state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
    let csrf_cookie = build_csrf_cookie(&csrf_token, secure);
    let mut response = Html(html).into_response();
    response
        .headers_mut()
        .insert(SET_COOKIE, csrf_cookie.parse().unwrap());
    response
}

fn is_redirect_uri_allowed(client: &OAuthClient, redirect_uri: &str) -> bool {
    // Exact match
    if client
        .redirect_uris
        .iter()
        .any(|uri| uri == redirect_uri)
    {
        return true;
    }

    // Check for loopback wildcard patterns (for all clients)
    client.redirect_uris.iter().any(|pattern| {
        matches_loopback_wildcard(pattern, redirect_uri)
    })
}

fn matches_loopback_wildcard(pattern: &str, redirect_uri: &str) -> bool {
    // Check if pattern contains wildcard
    if !pattern.contains("*") {
        return false;
    }

    // Parse both pattern (with * replaced) and actual redirect_uri
    let test_pattern = pattern.replace('*', "8080");
    let Ok(pattern_url) = Url::parse(&test_pattern) else {
        return false;
    };
    let Ok(redirect_url) = Url::parse(redirect_uri) else {
        return false;
    };

    // Check if pattern is for loopback address
    let pattern_host = pattern_url.host_str().unwrap_or("");
    let is_loopback = pattern_host == "localhost"
        || pattern_host == "127.0.0.1"
        || pattern_host == "::1"
        || pattern_host == "[::1]";

    if !is_loopback {
        return false;
    }

    // Match: scheme, host, and path must be identical; port can vary
    pattern_url.scheme() == redirect_url.scheme()
        && pattern_url.host_str() == redirect_url.host_str()
        && pattern_url.path() == redirect_url.path()
        && redirect_url.port().is_some()
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

async fn resolve_identity_provider_for_client(
    db_pool: &sqlx::PgPool,
    slug: &str,
    oauth_client_id: Uuid,
) -> Result<Option<IdentityProviderRow>, sqlx::Error> {
    sqlx::query_as::<_, IdentityProviderRow>(
        r#"
        SELECT ip.id, ip.tenant_id, ip.slug, ip.issuer, ip.client_id, ip.client_secret_encrypted,
               ip.auth_url, ip.token_url, ip.scopes, ip.hd_domain
        FROM identity_providers ip
        JOIN oauth_clients oc ON oc.tenant_id = ip.tenant_id
        WHERE oc.id = $1
          AND ip.slug = $2
          AND ip.is_active = true
          AND ip.deleted_at IS NULL
        LIMIT 1
        "#,
    )
    .bind(oauth_client_id)
    .bind(slug)
    .fetch_optional(db_pool)
    .await
}

async fn resolve_discovery(idp: &IdentityProviderRow) -> Result<OidcDiscoveryResponse, String> {
    if let (Some(auth), Some(token)) = (&idp.auth_url, &idp.token_url) {
        return Ok(OidcDiscoveryResponse {
            authorization_endpoint: auth.clone(),
            token_endpoint: token.clone(),
            userinfo_endpoint: None,
        });
    }
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        idp.issuer.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .get(discovery_url)
        .send()
        .await
        .map_err(|e| format!("OIDC discovery request failed: {e}"))?;
    let resp = resp
        .error_for_status()
        .map_err(|e| format!("OIDC discovery non-success response: {e}"))?;
    resp.json::<OidcDiscoveryResponse>()
        .await
        .map_err(|e| format!("OIDC discovery parse failed: {e}"))
}

fn build_federated_csrf_cookie(token: Option<&str>, secure: bool) -> String {
    let value = token.unwrap_or("");
    let mut cookie = format!(
        "federated_csrf={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        value,
        if token.is_some() { 600 } else { 0 }
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub async fn handle_federated_start(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let client_id = match params.get("client_id") {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            return Html(templates::error_page(
                "invalid_request",
                "Missing required parameter: client_id",
            ))
            .into_response();
        }
    };
    let redirect_uri = match params.get("redirect_uri") {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            return Html(templates::error_page(
                "invalid_request",
                "Missing required parameter: redirect_uri",
            ))
            .into_response();
        }
    };

    let client = match resolve_oauth_client(
        &state.db_pool,
        client_id,
        params.get("tenant").map(|s| s.as_str()),
    )
    .await
    {
        Ok(Some(c)) => c,
        _ => return Html(templates::error_page("invalid_client", "OAuth client not found")).into_response(),
    };
    if !is_redirect_uri_allowed(&client, redirect_uri) {
        return Html(templates::error_page("invalid_request", "Invalid redirect_uri for this client")).into_response();
    }

    let idp =
        match resolve_identity_provider_for_client(&state.db_pool, provider.trim(), client.id).await
        {
            Ok(Some(v)) => v,
            Ok(None) => {
                return Html(templates::error_page(
                    "invalid_request",
                    "Identity provider not found for this client tenant",
                ))
                .into_response();
            }
            Err(_) => {
                return Html(templates::error_page(
                    "server_error",
                    "Database error while loading identity provider",
                ))
                .into_response();
            }
        };

    let discovery = match resolve_discovery(&idp).await {
        Ok(v) => v,
        Err(e) => return Html(templates::error_page("server_error", &e)).into_response(),
    };

    let csrf: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let payload = FederatedStatePayload {
        csrf: csrf.clone(),
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        tenant: params.get("tenant").cloned().filter(|v| !v.trim().is_empty()),
        scope: params.get("scope").cloned().filter(|v| !v.trim().is_empty()),
        state: params.get("state").cloned().filter(|v| !v.trim().is_empty()),
        code_challenge: params.get("code_challenge").cloned().filter(|v| !v.trim().is_empty()),
        code_challenge_method: params
            .get("code_challenge_method")
            .cloned()
            .filter(|v| !v.trim().is_empty()),
        nonce: params.get("nonce").cloned().filter(|v| !v.trim().is_empty()),
    };
    let state_token = match serde_json::to_vec(&payload) {
        Ok(v) => URL_SAFE_NO_PAD.encode(v),
        Err(_) => {
            return Html(templates::error_page("server_error", "Failed to prepare federated state"))
                .into_response()
        }
    };

    let issuer = std::env::var("JWT_ISSUER").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let callback = format!(
        "{}/oauth2/federated/{}/callback",
        issuer.trim_end_matches('/'),
        provider.trim()
    );
    let mut auth_url = match Url::parse(&discovery.authorization_endpoint) {
        Ok(v) => v,
        Err(_) => {
            return Html(templates::error_page(
                "server_error",
                "Invalid upstream authorization endpoint",
            ))
            .into_response()
        }
    };
    let scope = if idp.scopes.is_empty() {
        "openid profile email".to_string()
    } else {
        idp.scopes.join(" ")
    };
    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &idp.client_id)
        .append_pair("redirect_uri", &callback)
        .append_pair("scope", &scope)
        .append_pair("state", &state_token);
    if let Some(domain) = &idp.hd_domain {
        auth_url.query_pairs_mut().append_pair("hd", domain);
    }

    let secure = state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
    let cookie = build_federated_csrf_cookie(Some(&csrf), secure);
    ([(SET_COOKIE, cookie)], Redirect::to(auth_url.as_ref())).into_response()
}

pub async fn handle_federated_callback(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let code = match params.get("code") {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => return Html(templates::error_page("invalid_request", "Missing code parameter")).into_response(),
    };
    let state_token = match params.get("state") {
        Some(v) if !v.trim().is_empty() => v.trim(),
        _ => return Html(templates::error_page("invalid_request", "Missing state parameter")).into_response(),
    };

    let payload: FederatedStatePayload = match URL_SAFE_NO_PAD
        .decode(state_token)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(v) => v,
        None => return Html(templates::error_page("invalid_request", "Invalid state parameter")).into_response(),
    };

    let cookie_csrf = cookie_value(&headers, "federated_csrf").unwrap_or_default();
    if cookie_csrf.is_empty() || cookie_csrf != payload.csrf {
        return Html(templates::error_page("invalid_request", "CSRF verification failed")).into_response();
    }

    let local_client = match resolve_oauth_client(&state.db_pool, &payload.client_id, payload.tenant.as_deref()).await {
        Ok(Some(c)) => c,
        _ => return Html(templates::error_page("invalid_client", "OAuth client not found")).into_response(),
    };
    if !is_redirect_uri_allowed(&local_client, &payload.redirect_uri) {
        return Html(templates::error_page("invalid_request", "Invalid redirect_uri")).into_response();
    }

    let idp = match resolve_identity_provider_for_client(&state.db_pool, provider.trim(), local_client.id).await {
        Ok(Some(v)) => v,
        _ => return Html(templates::error_page("invalid_request", "Identity provider not found")).into_response(),
    };
    let discovery = match resolve_discovery(&idp).await {
        Ok(v) => v,
        Err(e) => return Html(templates::error_page("server_error", &e)).into_response(),
    };

    let issuer = std::env::var("JWT_ISSUER").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let callback = format!(
        "{}/oauth2/federated/{}/callback",
        issuer.trim_end_matches('/'),
        provider.trim()
    );

    let client_secret = match decrypt_secret(&idp.client_secret_encrypted) {
        Ok(v) => v,
        Err(_) => {
            return Html(templates::error_page(
                "server_error",
                "Failed to decrypt upstream client secret",
            ))
            .into_response()
        }
    };

    let token_resp = {
        let resp = match reqwest::Client::new()
            .post(&discovery.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", callback.as_str()),
                ("client_id", idp.client_id.as_str()),
                ("client_secret", client_secret.as_str()),
            ])
            .send()
            .await
        {
            Ok(v) => v,
            Err(_) => return Html(templates::error_page("server_error", "Failed to exchange code with upstream IdP")).into_response(),
        };
        let resp = match resp.error_for_status() {
            Ok(v) => v,
            Err(_) => return Html(templates::error_page("server_error", "Upstream IdP rejected token request")).into_response(),
        };
        match resp.json::<OidcTokenResponse>().await {
            Ok(v) => v,
            Err(_) => return Html(templates::error_page("server_error", "Failed to parse token response from upstream IdP")).into_response(),
        }
    };

    let userinfo_endpoint = match discovery.userinfo_endpoint {
        Some(v) => v,
        None => return Html(templates::error_page("server_error", "Upstream IdP userinfo endpoint is missing")).into_response(),
    };
    let userinfo = {
        let resp = match reqwest::Client::new()
            .get(&userinfo_endpoint)
            .bearer_auth(&token_resp.access_token)
            .send()
            .await
        {
            Ok(v) => v,
            Err(_) => return Html(templates::error_page("server_error", "Failed to load userinfo from upstream IdP")).into_response(),
        };
        let resp = match resp.error_for_status() {
            Ok(v) => v,
            Err(_) => return Html(templates::error_page("server_error", "Upstream IdP rejected userinfo request")).into_response(),
        };
        match resp.json::<OidcUserInfoResponse>().await {
            Ok(v) => v,
            Err(_) => return Html(templates::error_page("server_error", "Failed to parse userinfo from upstream IdP")).into_response(),
        }
    };

    let user = match sqlx::query_as::<_, User>(
        r#"
        SELECT u.*
        FROM user_identities ui
        JOIN users u ON u.id = ui.user_id
        WHERE ui.tenant_id = $1
          AND ui.idp_id = $2
          AND ui.subject = $3
          AND COALESCE(ui.approval_status, 'approved') = 'approved'
          AND ui.deleted_at IS NULL
          AND u.deleted_at IS NULL
          AND u.is_active = true
        LIMIT 1
        "#,
    )
    .bind(idp.tenant_id)
    .bind(idp.id)
    .bind(&userinfo.sub)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return Html(templates::error_page(
                "access_denied",
                "Federated identity is not linked or approved in Simple IDM",
            ))
            .into_response();
        }
        Err(_) => return Html(templates::error_page("server_error", "Database error while resolving federated identity")).into_response(),
    };

    let _ = sqlx::query(
        r#"
        UPDATE user_identities
        SET last_login_at = NOW(), updated_at = NOW()
        WHERE tenant_id = $1 AND idp_id = $2 AND subject = $3 AND deleted_at IS NULL
        "#,
    )
    .bind(idp.tenant_id)
    .bind(idp.id)
    .bind(&userinfo.sub)
    .execute(&state.db_pool)
    .await;

    let code_out: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let expires_at = Utc::now() + Duration::minutes(10);
    let scope = payload.scope.unwrap_or_else(|| local_client.scope.clone());
    let nonce = payload.nonce.as_deref().and_then(non_empty);
    let code_challenge = payload.code_challenge.as_deref().and_then(non_empty);
    let code_challenge_method = payload.code_challenge_method.as_deref().and_then(non_empty);

    if sqlx::query(
        r#"
        INSERT INTO authorization_codes
        (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(&code_out)
    .bind(local_client.id)
    .bind(user.id)
    .bind(&payload.redirect_uri)
    .bind(&scope)
    .bind(code_challenge)
    .bind(code_challenge_method)
    .bind(nonce)
    .bind(expires_at)
    .execute(&state.db_pool)
    .await
    .is_err()
    {
        return Html(templates::error_page("server_error", "Failed to store authorization code")).into_response();
    }

    let secure = state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
    let session_token = create_auth_session(
        &state.db_pool,
        user.id,
        Some(local_client.id),
        state.auth_session_expiry,
    )
    .await
    .ok();
    let auth_cookie = build_auth_session_cookie(session_token.as_deref(), state.auth_session_expiry, secure);
    let federated_cookie = build_federated_csrf_cookie(None, secure);

    let mut redirect = match Url::parse(&payload.redirect_uri) {
        Ok(v) => v,
        Err(_) => return Html(templates::error_page("invalid_request", "Invalid redirect URI")).into_response(),
    };
    redirect.query_pairs_mut().append_pair("code", &code_out);
    if let Some(state_param) = payload.state {
        redirect.query_pairs_mut().append_pair("state", &state_param);
    }

    audit::emit_event(
        &state.db_pool,
        "auth.login.federated",
        "session",
        Some(user.id),
        "success",
        Some(serde_json::json!({
            "provider": idp.slug,
            "issuer": idp.issuer,
            "subject": userinfo.sub,
            "client_id": payload.client_id
        })),
    )
    .await;

    ([(SET_COOKIE, auth_cookie), (SET_COOKIE, federated_cookie)], Redirect::to(redirect.as_ref())).into_response()
}

/// Endpoint pro login a vygenerování authorization code
/// Přijímá HTML form data a redirectuje zpět na aplikaci
pub async fn handle_login(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Form(req): Form<LoginRequest>,
) -> impl IntoResponse {
    let login_throttle_keys = build_login_throttle_keys(
        &req.username,
        throttle::extract_client_ip(&headers, state.trust_proxy_headers),
    );
    if state.auth_protection.enabled
        && is_any_identity_locked(&state.db_pool, "oauth2_login", &login_throttle_keys)
            .await
            .unwrap_or(false)
    {
        return rate_limited_login_response(&req);
    }

    let req_csrf = req.csrf_token.clone().unwrap_or_default();
    let cookie_csrf = cookie_value(&headers, "csrf_token").unwrap_or_default();
    if req_csrf.is_empty() || cookie_csrf.is_empty() || req_csrf != cookie_csrf {
        register_failures(
            &state.db_pool,
            "oauth2_login",
            &login_throttle_keys,
            &state.auth_protection,
        )
        .await;
        audit::emit_event(
            &state.db_pool,
            "auth.login",
            "session",
            None,
            "failure",
            Some(serde_json::json!({
                "reason": "csrf_mismatch",
                "username": req.username,
                "client_id": req.client_id
            })),
        ).await;
        return invalid_login_response(&req);
    }

    let tenant_id = if req.username.contains('@') {
        resolve_tenant_for_email(&state.db_pool, &req.username)
            .await
            .unwrap_or_else(default_tenant_id)
    } else {
        default_tenant_id()
    };

    if !state.allow_username_login && !req.username.contains('@') {
        register_failures(
            &state.db_pool,
            "oauth2_login",
            &login_throttle_keys,
            &state.auth_protection,
        )
        .await;
        audit::emit_event(
            &state.db_pool,
            "auth.login",
            "session",
            None,
            "failure",
            Some(serde_json::json!({
                "reason": "username_login_disabled",
                "username": req.username,
                "client_id": req.client_id
            })),
        ).await;
        return invalid_login_response(&req);
    }

    // Ověř uživatele
    let user = match if state.allow_username_login {
        sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE tenant_id = $1 AND (username = $2 OR email = $2) AND is_active = true AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .bind(&req.username)
        .fetch_optional(&state.db_pool)
        .await
    } else {
        sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE tenant_id = $1 AND email = $2 AND is_active = true AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .bind(&req.username)
        .fetch_optional(&state.db_pool)
        .await
    } {
        Ok(Some(user)) => user,
        Ok(None) => {
            register_failures(
                &state.db_pool,
                "oauth2_login",
                &login_throttle_keys,
                &state.auth_protection,
            )
            .await;
            audit::emit_event(
                &state.db_pool,
                "auth.login",
                "session",
                None,
                "failure",
                Some(serde_json::json!({
                    "reason": "user_not_found",
                    "username": req.username,
                    "client_id": req.client_id
                })),
            ).await;
            return invalid_login_response(&req);
        }
        Err(_) => {
            let html = templates::error_page(
                "server_error",
                "Database error while validating user",
            );
            return Html(html).into_response();
        }
    };

    if !is_email_domain_allowed(&user.email, &state.allowed_email_domains) {
        register_failures(
            &state.db_pool,
            "oauth2_login",
            &login_throttle_keys,
            &state.auth_protection,
        )
        .await;
        audit::emit_event(
            &state.db_pool,
            "auth.login",
            "session",
            Some(user.id),
            "failure",
            Some(serde_json::json!({
                "reason": "email_domain_not_allowed",
                "email": user.email,
                "client_id": req.client_id
            })),
        ).await;
        return invalid_login_response(&req);
    }

    // Ověř heslo (lokálně nebo delegovaně přes AD/LDAP)
    if !verify_user_password(state.as_ref(), &user, &req.password).await {
        register_failures(
            &state.db_pool,
            "oauth2_login",
            &login_throttle_keys,
            &state.auth_protection,
        )
        .await;
        audit::emit_event(
            &state.db_pool,
            "auth.login",
            "session",
            Some(user.id),
            "failure",
            Some(serde_json::json!({
                "reason": "invalid_password",
                "email": user.email,
                "client_id": req.client_id
            })),
        ).await;
        return invalid_login_response(&req);
    }

    // Ověř klienta
    let client = match resolve_oauth_client(
        &state.db_pool,
        &req.client_id,
        req.tenant.as_deref(),
    )
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
        Err(ClientLookupError::AmbiguousClientId) => {
            let html = templates::error_page(
                "invalid_request",
                "Ambiguous client_id. Provide tenant hint.",
            );
            return Html(html).into_response();
        }
        Err(ClientLookupError::InvalidTenantHint) => {
            let html = templates::error_page("invalid_request", "Invalid tenant hint");
            return Html(html).into_response();
        }
        Err(ClientLookupError::Database) => {
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
    if sqlx::query(
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
    .is_err()
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

    audit::emit_event(
        &state.db_pool,
        "auth.login",
        "session",
        Some(user.id),
        "success",
        Some(serde_json::json!({
            "client_id": client.client_id,
            "scope": scope
        })),
    ).await;
    clear_failures(&state.db_pool, "oauth2_login", &login_throttle_keys).await;

    // Redirect zpět na aplikaci s authorization code
    let mut redirect_url = req.redirect_uri.clone();
    redirect_url.push_str(&format!("?code={}", code));
    if let Some(state) = req.state {
        redirect_url.push_str(&format!("&state={}", state));
    }

    // Set session cookie if session was created
    if !session_token.is_empty() {
        let secure =
            state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
        let cookie =
            build_auth_session_cookie(Some(&session_token), state.auth_session_expiry, secure);

        let mut response = Redirect::to(&redirect_url).into_response();
        response.headers_mut().insert(
            SET_COOKIE,
            cookie.parse().unwrap(),
        );
        return response;
    }

    Redirect::to(&redirect_url).into_response()
}

fn invalid_login_response(req: &LoginRequest) -> Response {
    let mut params = HashMap::new();
    params.insert("client_id".to_string(), req.client_id.clone());
    if let Some(tenant) = &req.tenant {
        params.insert("tenant".to_string(), tenant.clone());
    }
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
    let html = templates::login_page(&params, Some("Invalid email or password"));
    Html(html).into_response()
}

fn rate_limited_login_response(req: &LoginRequest) -> Response {
    let mut params = HashMap::new();
    params.insert("client_id".to_string(), req.client_id.clone());
    if let Some(tenant) = &req.tenant {
        params.insert("tenant".to_string(), tenant.clone());
    }
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
    let html = templates::login_page(
        &params,
        Some("Too many failed attempts. Please wait and try again."),
    );
    (StatusCode::TOO_MANY_REQUESTS, Html(html)).into_response()
}

fn build_login_throttle_keys(username: &str, ip: Option<String>) -> Vec<String> {
    let mut keys = vec![format!("login:{}", username.trim().to_lowercase())];
    if let Some(ip) = ip {
        keys.push(format!("ip:{}", ip));
    }
    keys
}

fn build_token_throttle_keys(client_id: Option<&str>, ip: Option<String>) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(client_id) = client_id {
        keys.push(format!("client:{}", client_id.trim().to_lowercase()));
    }
    if let Some(ip) = ip {
        keys.push(format!("ip:{}", ip));
    }
    keys
}

async fn is_any_identity_locked(
    db_pool: &sqlx::PgPool,
    endpoint: &str,
    keys: &[String],
) -> Result<bool, sqlx::Error> {
    for key in keys {
        if throttle::is_locked(db_pool, endpoint, key).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn register_failures(
    db_pool: &sqlx::PgPool,
    endpoint: &str,
    keys: &[String],
    cfg: &crate::config::AuthProtectionConfig,
) {
    for key in keys {
        let _ = throttle::register_failure(db_pool, endpoint, key, cfg).await;
    }
}

async fn clear_failures(
    db_pool: &sqlx::PgPool,
    endpoint: &str,
    keys: &[String],
) {
    for key in keys {
        let _ = throttle::clear_failures(db_pool, endpoint, key).await;
    }
}

fn is_email_domain_allowed(email: &str, allowed_domains: &[String]) -> bool {
    if allowed_domains.is_empty() {
        return true;
    }
    let domain = match email.rsplit_once('@') {
        Some((_, d)) => d.trim().to_lowercase(),
        None => return false,
    };
    allowed_domains.iter().any(|d| d == &domain)
}

fn request_is_https(headers: &HeaderMap, trust_proxy_headers: bool) -> bool {
    if !trust_proxy_headers {
        return false;
    }
    headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

fn build_auth_session_cookie(token: Option<&str>, max_age: i64, secure: bool) -> String {
    let value = token.unwrap_or("");
    let mut cookie = format!(
        "auth_session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        value, max_age
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn build_csrf_cookie(token: &str, secure: bool) -> String {
    let mut cookie = format!(
        "csrf_token={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1200",
        token
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie_header.split(';').find_map(|cookie| {
        let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
        if parts.len() == 2 && parts[0] == name {
            Some(parts[1].to_string())
        } else {
            None
        }
    })
}

fn should_use_ldap_for_email(state: &OAuth2State, email: &str) -> bool {
    if state.ldap_auth.is_none() {
        return false;
    }
    if state.ldap_auth_domains.is_empty() {
        return true;
    }
    let domain = match email.rsplit_once('@') {
        Some((_, d)) => d.trim().to_lowercase(),
        None => return false,
    };
    state
        .ldap_auth_domains
        .iter()
        .any(|d| d.eq_ignore_ascii_case(&domain))
}

async fn verify_user_password(
    state: &OAuth2State,
    user: &User,
    password: &str,
) -> bool {
    if user.password_disabled || user.auth_mode.eq_ignore_ascii_case("federated") {
        return false;
    }

    if should_use_ldap_for_email(state, &user.email) {
        if let Some(cfg) = &state.ldap_auth {
            match verify_ldap_password(cfg, &user.email, password).await {
                Ok(()) => {
                    if let Err(err) = sync_ldap_roles_if_stale(state, user, &user.email).await {
                        tracing::warn!(
                            user_id = %user.id,
                            username = %user.username,
                            "LDAP role sync warning: {}",
                            err
                        );
                    }
                    return true;
                }
                Err(err) => {
                    tracing::warn!(
                        user_id = %user.id,
                        username = %user.username,
                        "LDAP auth failed: {}",
                        err
                    );
                    return false;
                }
            }
        }
    }
    match user.password_hash.as_deref() {
        Some(hash) => verify_password(password, hash).unwrap_or(false),
        None => false,
    }
}

fn default_tenant_id() -> Uuid {
    Uuid::parse_str("11111111-1111-1111-1111-111111111111").expect("valid default tenant uuid")
}

async fn resolve_tenant_for_email(db_pool: &sqlx::PgPool, email: &str) -> Option<Uuid> {
    let domain = email.rsplit_once('@')?.1.trim().to_lowercase();
    sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT td.tenant_id
        FROM tenant_domains td
        JOIN tenants t ON t.id = td.tenant_id
        WHERE lower(td.domain) = $1
          AND td.is_active = true
          AND t.is_active = true
        LIMIT 1
        "#,
    )
    .bind(domain)
    .fetch_optional(db_pool)
    .await
    .ok()
    .flatten()
}

/// Wrapper pro device code token exchange - deleguje na device_flow modul
async fn handle_device_code_token(state: Arc<OAuth2State>, req: TokenRequest) -> Response {
    use crate::oauth2::device_flow::{handle_device_token_internal, DeviceTokenRequest};

    let device_req = DeviceTokenRequest {
        grant_type: req.grant_type,
        device_code: match req.device_code {
            Some(code) => code,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_request".to_string(),
                        error_description: "Missing device_code parameter".to_string(),
                    }),
                )
                    .into_response()
            }
        },
        client_id: req.client_id.unwrap_or_default(),
    };

    handle_device_token_internal(state, device_req).await
}

/// Endpoint pro výměnu authorization code za access token
pub async fn handle_token(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let req = match parse_token_request(&headers, &body) {
        Ok(req) => req,
        Err(resp) => return *resp,
    };

    let mut req = req;
    apply_client_auth(&mut req.client_id, &mut req.client_secret, &headers);
    let token_throttle_keys = build_token_throttle_keys(
        req.client_id.as_deref(),
        throttle::extract_client_ip(&headers, state.trust_proxy_headers),
    );
    if state.auth_protection.enabled
        && is_any_identity_locked(&state.db_pool, "oauth2_token", &token_throttle_keys)
            .await
            .unwrap_or(false)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate_limited".to_string(),
                error_description: "Too many failed attempts. Please wait and try again.".to_string(),
            }),
        )
            .into_response();
    }

    let response = match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_token(state.clone(), req).await,
        "refresh_token" => handle_refresh_token(state.clone(), req).await,
        "urn:ietf:params:oauth:grant-type:device_code" => {
            handle_device_code_token(state.clone(), req).await
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "unsupported_grant_type".to_string(),
                error_description: "Unsupported grant type".to_string(),
                }),
            )
                .into_response(),
    };

    if response.status().is_success() {
        clear_failures(&state.db_pool, "oauth2_token", &token_throttle_keys).await;
    } else if matches!(
        response.status(),
        StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED
    ) {
        register_failures(
            &state.db_pool,
            "oauth2_token",
            &token_throttle_keys,
            &state.auth_protection,
        )
        .await;
    }

    response
}

fn parse_token_request(headers: &HeaderMap, body: &[u8]) -> Result<TokenRequest, Box<Response>> {
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
        return Err(Box::new(
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(ErrorResponse {
                    error: "unsupported_media_type".to_string(),
                    error_description: "Expected Content-Type application/json or application/x-www-form-urlencoded".to_string(),
                }),
            )
                .into_response(),
        ));
    };

    parsed.map_err(|_| {
        Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: "Failed to parse token request".to_string(),
                }),
            )
                .into_response(),
        )
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
        "SELECT * FROM oauth_clients WHERE id = $1 AND is_active = true AND deleted_at IS NULL",
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

    // Validate redirect_uri (REQUIRED by OAuth2 RFC 6749 section 4.1.3)
    // "REQUIRED if the redirect_uri parameter was included in the authorization request"
    let req_redirect_uri = match req.redirect_uri {
        Some(uri) => uri,
        None => {
            return Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Missing redirect_uri parameter (required by OAuth2 spec)".to_string(),
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
                        challenge == encoded
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
    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL")
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

    // Apply client group filtering patterns (if any)
    let filtered_group_names = match sqlx::query_as!(
        OAuthClientGroupPattern,
        r#"
        SELECT id, client_id, pattern, is_include, priority, created_at
        FROM oauth_client_group_patterns
        WHERE client_id = $1
          AND deleted_at IS NULL
        ORDER BY priority ASC
        "#,
        client.id
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(patterns) => {
            if patterns.is_empty() {
                user_group_names
            } else {
                apply_client_group_filters(&user_group_names, &patterns)
            }
        }
        Err(e) => {
            tracing::error!("Failed to fetch client group patterns: {:?}", e);
            // Fallback to unfiltered groups on error
            user_group_names
        }
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
        match build_custom_claims(&state.db_pool, client.id, &user_group_ids, &filtered_group_names).await {
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
        groups = ?filtered_group_names,
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
        filtered_group_names.clone(),
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
        filtered_group_names,
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

    if sqlx::query(
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
    .is_err()
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

    let response = TokenResponseWithRefresh {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.access_token_expiry,
        refresh_token: Some(refresh_token),
        id_token: Some(id_token),
        scope: Some(auth_code.scope),
    };

    audit::emit_event(
        &state.db_pool,
        "oauth.token.issue",
        "token",
        Some(user.id),
        "success",
        Some(serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": client.client_id
        })),
    ).await;

    tracing::debug!("Token response: {:?}", response);

    Json(response).into_response()
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
        "SELECT * FROM oauth_clients WHERE id = $1 AND is_active = true AND deleted_at IS NULL",
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
    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL")
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

    // Apply client group filtering patterns (if any)
    let filtered_group_names = match sqlx::query_as!(
        OAuthClientGroupPattern,
        r#"
        SELECT id, client_id, pattern, is_include, priority, created_at
        FROM oauth_client_group_patterns
        WHERE client_id = $1
          AND deleted_at IS NULL
        ORDER BY priority ASC
        "#,
        client.id
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(patterns) => {
            if patterns.is_empty() {
                user_group_names
            } else {
                apply_client_group_filters(&user_group_names, &patterns)
            }
        }
        Err(e) => {
            tracing::error!("Failed to fetch client group patterns: {:?}", e);
            user_group_names
        }
    };

    let custom_claims = if client.include_claim_maps {
        let user_group_ids = get_effective_user_groups(&state.db_pool, user.id)
            .await
            .unwrap_or_default();
        build_custom_claims(&state.db_pool, client.id, &user_group_ids, &filtered_group_names)
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
        groups = ?filtered_group_names,
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
        filtered_group_names,
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

    let response = TokenResponseWithRefresh {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.access_token_expiry,
        refresh_token: Some(new_refresh_token),
        id_token: None,
        scope: Some(refresh_token.scope),
    };

    audit::emit_event(
        &state.db_pool,
        "oauth.token.refresh",
        "token",
        Some(user.id),
        "success",
        Some(serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": client.client_id
        })),
    ).await;

    Json(response).into_response()
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
    let secure =
        state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
    let cookie = build_auth_session_cookie(None, 0, secure);

    let mut response = Html("<html><body><h1>Logged out</h1><p>You have been successfully logged out.</p></body></html>")
        .into_response();

    response.headers_mut().insert(
        SET_COOKIE,
        cookie.parse().unwrap(),
    );

    response
}
