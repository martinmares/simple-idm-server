use crate::audit;
use crate::auth::{claims::user_authorization_claims, verify_password_async};
use crate::db::models::{
    AuthenticationSession, AuthorizationCode, OAuthClient, RefreshToken, UsedRefreshToken, User,
};
use crate::mfa::{self, MfaPolicy, NewMfaTransaction};
use crate::secret_crypto::{decrypt_secret, encrypt_secret};
use axum::http::header::SET_COOKIE;
use axum::{
    Form, Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use qrcode::{QrCode, render::svg};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use simple_idm_common::tabler_standalone_page;
use sqlx;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

#[allow(dead_code)]
const EMPTY_CLIENT_SECRET_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$cmFuZG9tc2FsdDEyMzQ1Njc4$XuNHV8S+FPZGCjrD8bqRHT5rCREu9xqhvWqmCFKaRRA";

use super::cleanup::cleanup_refresh_tokens;
use super::client_credentials::{ErrorResponse, OAuth2State};
use super::ldap_role_sync::{load_ad_ldap_provider_for_user, sync_ldap_roles_if_stale};
use super::templates;
use super::throttle;
use super::utils::{ClientLookupError, apply_client_auth, resolve_oauth_client};
use simple_idm_ad_auth::verify_ldap_password;

#[derive(Debug, Deserialize, Serialize)]
struct FederatedStatePayload {
    csrf: String,
    upstream_nonce: String,
    upstream_verifier: String,
    issued_at: i64,
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

#[derive(Debug)]
struct OidcDiscoveryResponse {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
    metadata: openidconnect::core::CoreProviderMetadata,
}

#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    access_token: String,
    id_token: String,
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
pub struct MfaCodeRequest {
    pub code: String,
}

#[derive(Debug, Clone)]
pub(super) struct PendingAuthorization {
    pub credential_version: i64,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

pub(super) struct AuthorizationCompletion {
    pub redirect_url: String,
    pub session_token: Option<String>,
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
pub(crate) async fn get_auth_session_from_cookie(
    db_pool: &sqlx::PgPool,
    headers: &HeaderMap,
) -> Option<AuthenticationSession> {
    // Extract session token from cookie
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;

    let session_token = cookie_header.split(';').find_map(|cookie| {
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

    // Re-evaluate tenant/domain policy after settings or the user's email change.
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1 AND is_active AND deleted_at IS NULL",
    )
    .bind(session.user_id)
    .fetch_optional(db_pool)
    .await
    .ok()??;
    if user.credential_version != session.credential_version {
        return None;
    }
    let auth_mode = user.auth_mode;
    let policy = crate::auth_policy::for_user(db_pool, session.user_id)
        .await
        .ok()?;
    if auth_mode.eq_ignore_ascii_case("local") && !policy.accepts_session(&session.amr) {
        return None;
    }

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
    let response_type = params
        .get("response_type")
        .map(|s| s.as_str())
        .unwrap_or("");
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
            let html =
                templates::error_page("invalid_request", "Missing required parameter: client_id");
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
            let html =
                templates::error_page("invalid_client", "OAuth client not found or inactive");
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
            let html =
                templates::error_page("server_error", "Database error while validating client");
            return Html(html).into_response();
        }
    };

    // Ověř redirect_uri
    if !is_login_destination_allowed(&state.db_pool, &client, redirect_uri).await {
        let html = templates::error_page("invalid_request", "Invalid redirect_uri for this client");
        return Html(html).into_response();
    }

    if !super::account_routes::is_account_destination(&client, redirect_uri)
        && super::device_flow::device_login_code(redirect_uri).is_none()
        && !super::utils::authorization_allowed(
            &client,
            params
                .get("scope")
                .map(String::as_str)
                .unwrap_or(&client.scope),
            params.get("code_challenge").map(String::as_str),
            params.get("code_challenge_method").map(String::as_str),
        )
    {
        return Html(templates::error_page(
            "invalid_request",
            "Scope, grant or S256 PKCE configuration is not allowed",
        ))
        .into_response();
    }
    // SSO: Check for existing authentication session
    if let Some(auth_session) = get_auth_session_from_cookie(&state.db_pool, &headers).await {
        if !super::utils::user_client_allowed(&state.db_pool, client.id, auth_session.user_id)
            .await
            .unwrap_or(false)
        {
            return Html(templates::error_page(
                "access_denied",
                "Account is not authorized for this client",
            ))
            .into_response();
        }
        if let Some(code) = super::device_flow::device_login_code(redirect_uri) {
            return Redirect::to(&super::device_flow::device_confirmation_url(code))
                .into_response();
        }
        let completion = complete_user_authorization(
            &state,
            PendingAuthorization {
                credential_version: auth_session.credential_version,
                user_id: auth_session.user_id,
                client_id: client.id,
                redirect_uri: redirect_uri.clone(),
                scope: params
                    .get("scope")
                    .cloned()
                    .unwrap_or_else(|| client.scope.clone()),
                state: params.get("state").cloned(),
                code_challenge: params.get("code_challenge").cloned(),
                code_challenge_method: params.get("code_challenge_method").cloned(),
                nonce: params.get("nonce").cloned(),
            },
            auth_session.amr,
            auth_session.acr,
        )
        .await;
        return match completion {
            Ok(completion) => authorization_completion_response(&state, &headers, completion),
            Err(_) => Html(templates::error_page(
                "access_denied",
                "Authentication changed; sign in again",
            ))
            .into_response(),
        };
    }

    // A hint selects a provider only; the callback must still verify the linked identity.
    if let Some(hint) = params
        .get("login_hint")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        let provider = sqlx::query_scalar::<_, String>(
            r#"
            SELECT ip.slug FROM users u
            JOIN oauth_clients oc ON oc.tenant_id = u.tenant_id
            JOIN identity_providers ip ON ip.id = u.auth_provider_id AND ip.tenant_id = u.tenant_id
            WHERE oc.id = $1 AND u.is_active = true AND u.deleted_at IS NULL
              AND u.auth_mode = 'federated'
              AND (LOWER(u.email) = LOWER($2) OR ($3 AND u.username = $2))
              AND ip.provider_type IN ('google', 'oidc') AND ip.is_active = true AND ip.deleted_at IS NULL
              AND EXISTS (
                  SELECT 1 FROM user_identities ui WHERE ui.user_id = u.id
                    AND ui.tenant_id = u.tenant_id AND ui.idp_id = ip.id AND ui.issuer = ip.issuer
                    AND ui.approval_status = 'approved' AND ui.deleted_at IS NULL
              )
            LIMIT 1
            "#,
        ).bind(client.id).bind(hint).bind(state.allow_username_login)
            .fetch_optional(&state.db_pool).await;
        match provider {
            Ok(Some(slug)) => {
                return Redirect::to(&templates::federated_login_url(&params, &slug))
                    .into_response();
            }
            Ok(None) => {}
            Err(err) => {
                tracing::error!("Failed to resolve sign-in hint: {err}");
                return Html(templates::error_page(
                    "server_error",
                    "Failed to prepare sign-in. Please try again.",
                ))
                .into_response();
            }
        }
    }

    // No valid session or linked provider - show login form.
    let csrf_token: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let mut params = params;
    params.insert("csrf_token".to_string(), csrf_token.clone());
    if state.passkeys.is_some() {
        params.insert("passkeys_enabled".to_string(), "true".to_string());
    }
    let html = render_login_page(state.as_ref(), &params, None).await;

    let secure =
        state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
    let csrf_cookie = build_csrf_cookie(&csrf_token, secure);
    let mut response = Html(html).into_response();
    response
        .headers_mut()
        .insert(SET_COOKIE, csrf_cookie.parse().unwrap());
    response
}

/// Device sign-in uses a reserved internal destination, never an OAuth callback.
/// Revalidate the pending code against its client at every authentication step.
pub(crate) async fn is_login_destination_allowed(
    pool: &sqlx::PgPool,
    client: &OAuthClient,
    destination: &str,
) -> bool {
    if client.client_id == super::account_routes::CLIENT_ID {
        return super::account_routes::is_account_destination(client, destination);
    }
    if destination.starts_with(super::device_flow::DEVICE_LOGIN_PREFIX) {
        let Some(code) = super::device_flow::device_login_code(destination) else {
            return false;
        };
        return super::device_flow::pending_device_client(pool, code)
            .await
            .is_ok_and(|pending| pending.id == client.id);
    }
    is_redirect_uri_allowed(client, destination)
}

pub(crate) fn is_redirect_uri_allowed(client: &OAuthClient, redirect_uri: &str) -> bool {
    // Exact match
    if client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
        return true;
    }

    // Check for loopback wildcard patterns (for all clients)
    client
        .redirect_uris
        .iter()
        .any(|pattern| matches_loopback_wildcard(pattern, redirect_uri))
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
pub(super) async fn complete_user_authorization(
    state: &OAuth2State,
    pending: PendingAuthorization,
    amr: Vec<String>,
    acr: Option<String>,
) -> Result<AuthorizationCompletion, String> {
    let device = super::device_flow::device_login_code(&pending.redirect_uri);
    let client = sqlx::query_as::<_, OAuthClient>("SELECT * FROM oauth_clients WHERE id = $1")
        .bind(pending.client_id)
        .fetch_one(&state.db_pool)
        .await
        .map_err(|_| "Cannot validate client")?;
    if !super::utils::user_client_allowed(&state.db_pool, client.id, pending.user_id)
        .await
        .map_err(|_| "Cannot validate account")?
    {
        return Err("Account is not authorized for this client".into());
    }
    if let Some(device_code) = device {
        if super::device_flow::pending_device_client(&state.db_pool, device_code)
            .await?
            .id
            != client.id
        {
            return Err("Device client mismatch".into());
        }
    } else if client.client_id == super::account_routes::CLIENT_ID {
        if !super::account_routes::is_account_destination(&client, &pending.redirect_uri)
            || !pending.scope.is_empty()
        {
            return Err("Invalid account sign-in destination".into());
        }
    } else if !super::utils::authorization_allowed(
        &client,
        &pending.scope,
        pending.code_challenge.as_deref(),
        pending.code_challenge_method.as_deref(),
    ) {
        return Err("Authorization request is not allowed".into());
    }
    let mut tx = state
        .db_pool
        .begin()
        .await
        .map_err(|_| "Cannot start authorization")?;
    let version = sqlx::query_scalar::<_, i64>("SELECT credential_version FROM users WHERE id = $1 AND is_active AND deleted_at IS NULL FOR UPDATE")
        .bind(pending.user_id).fetch_optional(&mut *tx).await.map_err(|_| "Cannot validate credentials")?;
    if version != Some(pending.credential_version) {
        return Err("Credentials changed; sign in again".into());
    }
    let session = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO authentication_sessions (session_token,user_id,client_id,expires_at,amr,acr,credential_version) VALUES ($1,$2,$3,$4,$5,$6,$7)")
        .bind(&session).bind(pending.user_id).bind(client.id).bind(Utc::now()+Duration::seconds(state.auth_session_expiry)).bind(&amr).bind(&acr).bind(pending.credential_version)
        .execute(&mut *tx).await.map_err(|_| "Cannot create session")?;
    let redirect_url = if super::account_routes::is_account_destination(
        &client,
        &pending.redirect_uri,
    ) {
        pending.redirect_uri.clone()
    } else if let Some(device_code) = device {
        super::device_flow::device_confirmation_url(device_code)
    } else {
        let code = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO authorization_codes (code,client_id,user_id,redirect_uri,scope,code_challenge,code_challenge_method,nonce,amr,acr,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind(&code).bind(client.id).bind(pending.user_id).bind(&pending.redirect_uri).bind(&pending.scope).bind(&pending.code_challenge).bind(&pending.code_challenge_method).bind(&pending.nonce).bind(&amr).bind(&acr).bind(Utc::now()+Duration::minutes(10))
            .execute(&mut *tx).await.map_err(|_| "Cannot create authorization code")?;
        let mut redirect = Url::parse(&pending.redirect_uri).map_err(|_| "Invalid redirect URI")?;
        redirect.query_pairs_mut().append_pair("code", &code);
        if let Some(value) = &pending.state {
            redirect.query_pairs_mut().append_pair("state", value);
        }
        redirect.to_string()
    };
    tx.commit()
        .await
        .map_err(|_| "Cannot commit authorization")?;
    Ok(AuthorizationCompletion {
        redirect_url,
        session_token: Some(session),
    })
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
          AND ip.provider_type IN ('google', 'oidc')
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

fn identity_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|error| error.to_string())
}

async fn resolve_discovery(idp: &IdentityProviderRow) -> Result<OidcDiscoveryResponse, String> {
    use openidconnect::{IssuerUrl, core::CoreProviderMetadata};
    simple_idm_common::validate_identity_url(&idp.issuer)?;
    let http = openidconnect::reqwest::Client::builder()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|error| error.to_string())?;
    let metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(idp.issuer.clone()).map_err(|error| error.to_string())?,
        &http,
    )
    .await
    .map_err(|error| error.to_string())?;
    let authorization_endpoint = idp
        .auth_url
        .clone()
        .unwrap_or_else(|| metadata.authorization_endpoint().as_str().to_owned());
    let token_endpoint = idp
        .token_url
        .clone()
        .or_else(|| metadata.token_endpoint().map(|url| url.as_str().to_owned()))
        .ok_or("Missing token endpoint")?;
    let userinfo_endpoint = metadata
        .userinfo_endpoint()
        .map(|url| url.as_str().to_owned());
    for url in [
        &authorization_endpoint,
        &token_endpoint,
        metadata.jwks_uri().as_str(),
    ] {
        simple_idm_common::validate_identity_url(url)?;
    }
    if let Some(url) = &userinfo_endpoint {
        simple_idm_common::validate_identity_url(url)?;
    }
    Ok(OidcDiscoveryResponse {
        authorization_endpoint,
        token_endpoint,
        userinfo_endpoint,
        metadata,
    })
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
        _ => {
            return Html(templates::error_page(
                "invalid_client",
                "OAuth client not found",
            ))
            .into_response();
        }
    };
    if !is_login_destination_allowed(&state.db_pool, &client, redirect_uri).await {
        return Html(templates::error_page(
            "invalid_request",
            "Invalid redirect_uri for this client",
        ))
        .into_response();
    }

    let idp = match resolve_identity_provider_for_client(&state.db_pool, provider.trim(), client.id)
        .await
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

    let (upstream_challenge, upstream_verifier) =
        openidconnect::PkceCodeChallenge::new_random_sha256();
    let upstream_nonce = openidconnect::Nonce::new_random();
    let payload = FederatedStatePayload {
        upstream_nonce: upstream_nonce.secret().to_owned(),
        upstream_verifier: upstream_verifier.secret().to_owned(),
        issued_at: Utc::now().timestamp(),
        csrf: csrf.clone(),
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        tenant: params
            .get("tenant")
            .cloned()
            .filter(|v| !v.trim().is_empty()),
        scope: params
            .get("scope")
            .cloned()
            .filter(|v| !v.trim().is_empty()),
        state: params
            .get("state")
            .cloned()
            .filter(|v| !v.trim().is_empty()),
        code_challenge: params
            .get("code_challenge")
            .cloned()
            .filter(|v| !v.trim().is_empty()),
        code_challenge_method: params
            .get("code_challenge_method")
            .cloned()
            .filter(|v| !v.trim().is_empty()),
        nonce: params
            .get("nonce")
            .cloned()
            .filter(|v| !v.trim().is_empty()),
    };
    let state_token = match serde_json::to_string(&payload)
        .ok()
        .and_then(|json| encrypt_secret(&json).ok())
    {
        Some(v) => v,
        None => {
            return Html(templates::error_page(
                "server_error",
                "Failed to prepare federated state",
            ))
            .into_response();
        }
    };

    let issuer =
        std::env::var("JWT_ISSUER").unwrap_or_else(|_| "http://localhost:8080".to_string());
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
            .into_response();
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
        .append_pair("state", &state_token)
        .append_pair("nonce", upstream_nonce.secret())
        .append_pair("code_challenge", upstream_challenge.as_str())
        .append_pair("code_challenge_method", "S256");
    if let Some(hint) = params
        .get("login_hint")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        auth_url.query_pairs_mut().append_pair("login_hint", hint);
    }
    if let Some(domain) = &idp.hd_domain {
        auth_url.query_pairs_mut().append_pair("hd", domain);
    }

    let secure =
        state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
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
        _ => {
            return Html(templates::error_page(
                "invalid_request",
                "Missing code parameter",
            ))
            .into_response();
        }
    };
    let state_token = match params.get("state") {
        Some(v) if !v.trim().is_empty() => v.trim(),
        _ => {
            return Html(templates::error_page(
                "invalid_request",
                "Missing state parameter",
            ))
            .into_response();
        }
    };

    let payload: FederatedStatePayload = match decrypt_secret(state_token)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
    {
        Some(v) => v,
        None => {
            return Html(templates::error_page(
                "invalid_request",
                "Invalid state parameter",
            ))
            .into_response();
        }
    };

    let cookie_csrf = cookie_value(&headers, "federated_csrf").unwrap_or_default();
    if cookie_csrf.is_empty()
        || cookie_csrf != payload.csrf
        || Utc::now().timestamp() - payload.issued_at > 600
        || payload.issued_at > Utc::now().timestamp()
    {
        return Html(templates::error_page(
            "invalid_request",
            "CSRF verification failed",
        ))
        .into_response();
    }

    let local_client = match resolve_oauth_client(
        &state.db_pool,
        &payload.client_id,
        payload.tenant.as_deref(),
    )
    .await
    {
        Ok(Some(c)) => c,
        _ => {
            return Html(templates::error_page(
                "invalid_client",
                "OAuth client not found",
            ))
            .into_response();
        }
    };
    if !is_login_destination_allowed(&state.db_pool, &local_client, &payload.redirect_uri).await {
        return Html(templates::error_page(
            "invalid_request",
            "Invalid redirect_uri",
        ))
        .into_response();
    }

    let idp = match resolve_identity_provider_for_client(
        &state.db_pool,
        provider.trim(),
        local_client.id,
    )
    .await
    {
        Ok(Some(v)) => v,
        _ => {
            return Html(templates::error_page(
                "invalid_request",
                "Identity provider not found",
            ))
            .into_response();
        }
    };
    let discovery = match resolve_discovery(&idp).await {
        Ok(v) => v,
        Err(e) => return Html(templates::error_page("server_error", &e)).into_response(),
    };

    let issuer =
        std::env::var("JWT_ISSUER").unwrap_or_else(|_| "http://localhost:8080".to_string());
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
            .into_response();
        }
    };

    let http_client = match identity_http_client() {
        Ok(client) => client,
        Err(_) => {
            return Html(templates::error_page(
                "server_error",
                "Cannot initialize upstream HTTP client",
            ))
            .into_response();
        }
    };
    let token_resp = {
        let resp = match http_client
            .post(&discovery.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", callback.as_str()),
                ("client_id", idp.client_id.as_str()),
                ("client_secret", client_secret.as_str()),
                ("code_verifier", payload.upstream_verifier.as_str()),
            ])
            .send()
            .await
        {
            Ok(v) => v,
            Err(_) => {
                return Html(templates::error_page(
                    "server_error",
                    "Failed to exchange code with upstream IdP",
                ))
                .into_response();
            }
        };
        let resp = match resp.error_for_status() {
            Ok(v) => v,
            Err(_) => {
                return Html(templates::error_page(
                    "server_error",
                    "Upstream IdP rejected token request",
                ))
                .into_response();
            }
        };
        match resp.json::<OidcTokenResponse>().await {
            Ok(v) => v,
            Err(_) => {
                return Html(templates::error_page(
                    "server_error",
                    "Failed to parse token response from upstream IdP",
                ))
                .into_response();
            }
        }
    };

    let oidc_client = openidconnect::core::CoreClient::from_provider_metadata(
        discovery.metadata.clone(),
        openidconnect::ClientId::new(idp.client_id.clone()),
        None,
    );
    let verified_subject = token_resp
        .id_token
        .parse::<openidconnect::core::CoreIdToken>()
        .ok()
        .and_then(|token| {
            token
                .claims(
                    &oidc_client.id_token_verifier(),
                    &openidconnect::Nonce::new(payload.upstream_nonce.clone()),
                )
                .ok()
                .map(|claims| claims.subject().as_str().to_owned())
        });
    let Some(verified_subject) = verified_subject else {
        return Html(templates::error_page(
            "access_denied",
            "Upstream ID token verification failed",
        ))
        .into_response();
    };
    let userinfo_endpoint = match discovery.userinfo_endpoint {
        Some(v) => v,
        None => {
            return Html(templates::error_page(
                "server_error",
                "Upstream IdP userinfo endpoint is missing",
            ))
            .into_response();
        }
    };
    let userinfo = {
        let resp = match http_client
            .get(&userinfo_endpoint)
            .bearer_auth(&token_resp.access_token)
            .send()
            .await
        {
            Ok(v) => v,
            Err(_) => {
                return Html(templates::error_page(
                    "server_error",
                    "Failed to load userinfo from upstream IdP",
                ))
                .into_response();
            }
        };
        let resp = match resp.error_for_status() {
            Ok(v) => v,
            Err(_) => {
                return Html(templates::error_page(
                    "server_error",
                    "Upstream IdP rejected userinfo request",
                ))
                .into_response();
            }
        };
        match resp.json::<OidcUserInfoResponse>().await {
            Ok(v) => v,
            Err(_) => {
                return Html(templates::error_page(
                    "server_error",
                    "Failed to parse userinfo from upstream IdP",
                ))
                .into_response();
            }
        }
    };

    if userinfo.sub != verified_subject {
        return Html(templates::error_page(
            "access_denied",
            "Upstream subject mismatch",
        ))
        .into_response();
    }
    let user = match sqlx::query_as::<_, User>(
        r#"
        SELECT u.*
        FROM user_identities ui
        JOIN users u ON u.id = ui.user_id
        JOIN effective_user_auth_policies policy ON policy.user_id = u.id
        WHERE ui.tenant_id = $1
          AND u.auth_mode = 'federated'
          AND u.auth_provider_id = ui.idp_id
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
        Err(_) => {
            return Html(templates::error_page(
                "server_error",
                "Database error while resolving federated identity",
            ))
            .into_response();
        }
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

    let completion = match complete_user_authorization(
        state.as_ref(),
        PendingAuthorization {
            credential_version: user.credential_version,
            user_id: user.id,
            client_id: local_client.id,
            redirect_uri: payload.redirect_uri,
            scope: payload.scope.unwrap_or_else(|| local_client.scope.clone()),
            state: payload.state,
            code_challenge: payload
                .code_challenge
                .and_then(|v| non_empty(&v).map(str::to_string)),
            code_challenge_method: payload
                .code_challenge_method
                .and_then(|v| non_empty(&v).map(str::to_string)),
            nonce: payload
                .nonce
                .and_then(|v| non_empty(&v).map(str::to_string)),
        },
        vec!["federated".into()],
        Some("urn:simple-idm:acr:federated".into()),
    )
    .await
    {
        Ok(completion) => completion,
        Err(err) => return Html(templates::error_page("server_error", &err)).into_response(),
    };
    let secure =
        state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
    let auth_cookie = build_auth_session_cookie(
        completion.session_token.as_deref(),
        state.auth_session_expiry,
        secure,
    );
    let federated_cookie = build_federated_csrf_cookie(None, secure);

    audit::emit_event_as(
        &state.db_pool,
        &audit::Actor {
            subject: Some(user.id.to_string()),
            client_id: Some(payload.client_id.clone()),
            root_token: false,
        },
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

    (
        [(SET_COOKIE, auth_cookie), (SET_COOKIE, federated_cookie)],
        Redirect::to(&completion.redirect_url),
    )
        .into_response()
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
        return rate_limited_login_response(state.as_ref(), &req).await;
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
        )
        .await;
        return invalid_login_response(state.as_ref(), &req).await;
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
        )
        .await;
        return invalid_login_response(state.as_ref(), &req).await;
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
            )
            .await;
            return invalid_login_response(state.as_ref(), &req).await;
        }
        Err(_) => {
            let html =
                templates::error_page("server_error", "Database error while validating user");
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
        )
        .await;
        return invalid_login_response(state.as_ref(), &req).await;
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
        )
        .await;
        return invalid_login_response(state.as_ref(), &req).await;
    }

    // Ověř klienta
    let client =
        match resolve_oauth_client(&state.db_pool, &req.client_id, req.tenant.as_deref()).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                let html = templates::error_page("invalid_client", "OAuth client not found");
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
                let html =
                    templates::error_page("server_error", "Database error while validating client");
                return Html(html).into_response();
            }
        };

    if !is_login_destination_allowed(&state.db_pool, &client, &req.redirect_uri).await {
        let html = templates::error_page("invalid_request", "Invalid redirect_uri for this client");
        return Html(html).into_response();
    }

    // Normalize empty PKCE fields (Grafana can submit empty values)
    let pending = PendingAuthorization {
        credential_version: user.credential_version,
        user_id: user.id,
        client_id: client.id,
        redirect_uri: req.redirect_uri.clone(),
        scope: req.scope.clone().unwrap_or_else(|| client.scope.clone()),
        state: req.state.clone(),
        code_challenge: req
            .code_challenge
            .as_deref()
            .and_then(non_empty)
            .map(str::to_string),
        code_challenge_method: req
            .code_challenge_method
            .as_deref()
            .and_then(non_empty)
            .map(str::to_string),
        nonce: req.nonce.as_deref().and_then(non_empty).map(str::to_string),
    };

    // MFA is enforced only for identities managed locally by Simple IDM.
    // AD and federated identities delegate authentication policy upstream.
    if user.auth_mode.eq_ignore_ascii_case("local") {
        let policy = match mfa::user_mfa_policy(&state.db_pool, user.id).await {
            Ok(policy) => policy,
            Err(err) => {
                tracing::error!(user_id = %user.id, "Failed to load tenant MFA policy: {err}");
                return Html(templates::error_page(
                    "server_error",
                    "Failed to evaluate MFA policy",
                ))
                .into_response();
            }
        };
        let authenticator = match mfa::active_totp_authenticator(&state.db_pool, user.id).await {
            Ok(value) => value,
            Err(err) => {
                tracing::error!(user_id = %user.id, "Failed to load MFA authenticator: {err}");
                return Html(templates::error_page(
                    "server_error",
                    "Failed to evaluate MFA state",
                ))
                .into_response();
            }
        };
        let stage = match (policy, authenticator.is_some()) {
            (MfaPolicy::Required, false) => Some("enroll"),
            (MfaPolicy::Required, true) | (MfaPolicy::Optional, true) => Some("challenge"),
            _ => None,
        };

        if let Some(stage) = stage {
            let transaction = NewMfaTransaction {
                credential_version: user.credential_version,
                tenant_id: user.tenant_id,
                user_id: user.id,
                client_id: client.id,
                redirect_uri: &pending.redirect_uri,
                scope: &pending.scope,
                state: pending.state.as_deref(),
                code_challenge: pending.code_challenge.as_deref(),
                code_challenge_method: pending.code_challenge_method.as_deref(),
                nonce: pending.nonce.as_deref(),
                stage,
            };
            let token = match mfa::create_login_transaction(&state.db_pool, transaction).await {
                Ok(token) => token,
                Err(err) => {
                    tracing::error!(user_id = %user.id, "Failed to create MFA transaction: {err}");
                    return Html(templates::error_page(
                        "server_error",
                        "Failed to start MFA verification",
                    ))
                    .into_response();
                }
            };
            audit::emit_event(
                &state.db_pool,
                "auth.mfa.required",
                "user",
                Some(user.id),
                "success",
                Some(serde_json::json!({"stage": stage, "client_id": client.client_id})),
            )
            .await;
            clear_failures(&state.db_pool, "oauth2_login", &login_throttle_keys).await;
            let secure =
                state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
            let mut response = Redirect::to("/oauth2/mfa").into_response();
            response.headers_mut().insert(
                SET_COOKIE,
                build_mfa_transaction_cookie(Some(&token), secure)
                    .parse()
                    .expect("valid MFA cookie"),
            );
            return response;
        }
    }

    let (amr, acr) = if user.auth_mode.eq_ignore_ascii_case("federated") {
        (
            vec!["federated".to_string()],
            Some("urn:simple-idm:acr:federated".to_string()),
        )
    } else {
        (
            vec!["pwd".to_string()],
            Some("urn:simple-idm:acr:password".to_string()),
        )
    };
    let scope_for_audit = pending.scope.clone();
    let completion =
        match complete_user_authorization(state.as_ref(), pending, amr.clone(), acr).await {
            Ok(value) => value,
            Err(err) => {
                tracing::error!(user_id = %user.id, "{err}");
                return Html(templates::error_page(
                    "server_error",
                    "Failed to complete sign-in",
                ))
                .into_response();
            }
        };
    audit::emit_event_as(
        &state.db_pool,
        &audit::Actor { subject: Some(user.id.to_string()), client_id: Some(client.client_id.clone()), root_token: false },
        "auth.login",
        "session",
        Some(user.id),
        "success",
        Some(serde_json::json!({"client_id": client.client_id, "scope": scope_for_audit, "amr": amr})),
    )
    .await;
    clear_failures(&state.db_pool, "oauth2_login", &login_throttle_keys).await;
    authorization_completion_response(state.as_ref(), &headers, completion)
}

pub async fn show_mfa_form(State(state): State<Arc<OAuth2State>>, headers: HeaderMap) -> Response {
    let Some(token) = cookie_value(&headers, "mfa_transaction") else {
        return Html(templates::error_page(
            "invalid_request",
            "The MFA sign-in transaction is missing. Start sign-in again.",
        ))
        .into_response();
    };
    let transaction = match mfa::load_login_transaction(&state.db_pool, &token).await {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!("Cannot load MFA transaction: {err}");
            return Html(templates::error_page(
                "invalid_request",
                "The MFA sign-in transaction is invalid or expired. Start sign-in again.",
            ))
            .into_response();
        }
    };
    if transaction.stage == "enroll"
        && let Err(err) = crate::secret_crypto::validate_master_key()
    {
        tracing::warn!("Cannot prepare MFA enrollment: {err}");
        return Html(templates::error_page(
            "server_error",
            "Authenticator setup is unavailable because the server encryption key is missing or invalid. Ask your administrator to configure IDP_SECRETS_MASTER_KEY.",
        ))
        .into_response();
    }
    match render_mfa_transaction_page(state.as_ref(), &transaction, None).await {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            tracing::warn!("Cannot prepare MFA enrollment: {err}");
            Html(templates::error_page(
                "server_error",
                "Could not prepare authenticator setup. Contact your administrator to check the server configuration.",
            ))
            .into_response()
        }
    }
}

pub async fn handle_mfa(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Form(req): Form<MfaCodeRequest>,
) -> Response {
    let Some(token) = cookie_value(&headers, "mfa_transaction") else {
        return Html(templates::error_page(
            "invalid_request",
            "The MFA sign-in transaction is missing. Start sign-in again.",
        ))
        .into_response();
    };
    let transaction = match mfa::load_login_transaction(&state.db_pool, &token).await {
        Ok(value) => value,
        Err(_) => {
            return Html(templates::error_page(
                "invalid_request",
                "The MFA sign-in transaction is invalid or expired. Start sign-in again.",
            ))
            .into_response();
        }
    };

    let user = match sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1 AND tenant_id = $2 AND is_active = true AND deleted_at IS NULL",
    )
    .bind(transaction.user_id)
    .bind(transaction.tenant_id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(user)) if user.auth_mode.eq_ignore_ascii_case("local") => user,
        _ => {
            return Html(templates::error_page(
                "access_denied",
                "This MFA transaction no longer belongs to an active locally managed account.",
            ))
            .into_response();
        }
    };

    let submitted = req.code.trim();
    let (verified, amr, recovery_codes) = if transaction.stage == "enroll" {
        let enrollment = match mfa::ensure_pending_totp(
            &state.db_pool,
            user.tenant_id,
            user.id,
            &user.email,
            "Simple IDM",
        )
        .await
        {
            Ok(value) => value,
            Err(err) => {
                tracing::error!(user_id = %user.id, "Failed to load TOTP enrollment: {err}");
                return Html(templates::error_page(
                    "server_error",
                    "Failed to load MFA enrollment",
                ))
                .into_response();
            }
        };
        let authenticator = match mfa::pending_totp_authenticator(&state.db_pool, user.id).await {
            Ok(Some(value)) if value.id == enrollment.authenticator_id => value,
            _ => {
                return Html(templates::error_page(
                    "server_error",
                    "MFA enrollment state is invalid",
                ))
                .into_response();
            }
        };
        match mfa::verify_totp(&state.db_pool, &authenticator, submitted).await {
            Ok(true) => {
                match mfa::activate_totp_and_generate_recovery_codes(
                    &state.db_pool,
                    &authenticator,
                    transaction.credential_version,
                )
                .await
                {
                    Ok(codes) => (
                        true,
                        vec!["pwd".to_string(), "otp".to_string()],
                        Some(codes),
                    ),
                    Err(err) => {
                        tracing::error!(user_id = %user.id, "Failed to activate TOTP: {err}");
                        return Html(templates::error_page(
                            "server_error",
                            "Failed to activate MFA",
                        ))
                        .into_response();
                    }
                }
            }
            Ok(false) => (false, Vec::new(), None),
            Err(err) => {
                tracing::warn!(user_id = %user.id, "TOTP verification failed: {err}");
                (false, Vec::new(), None)
            }
        }
    } else {
        let authenticator = match mfa::active_totp_authenticator(&state.db_pool, user.id).await {
            Ok(Some(value)) => value,
            _ => {
                return Html(templates::error_page(
                    "access_denied",
                    "No active authenticator is available for this account.",
                ))
                .into_response();
            }
        };
        let looks_like_totp = submitted.len() == 6 && submitted.bytes().all(|b| b.is_ascii_digit());
        if looks_like_totp {
            match mfa::verify_totp(&state.db_pool, &authenticator, submitted).await {
                Ok(true) => (true, vec!["pwd".to_string(), "otp".to_string()], None),
                _ => (false, Vec::new(), None),
            }
        } else {
            match mfa::consume_recovery_code(&state.db_pool, user.id, submitted).await {
                Ok(true) => (true, vec!["pwd".to_string(), "recovery".to_string()], None),
                _ => (false, Vec::new(), None),
            }
        }
    };

    if !verified {
        mfa::register_failed_attempt(&state.db_pool, &token).await;
        audit::emit_event(
            &state.db_pool,
            "auth.mfa.verify",
            "user",
            Some(user.id),
            "failure",
            Some(serde_json::json!({"stage": transaction.stage})),
        )
        .await;
        let transaction = mfa::load_login_transaction(&state.db_pool, &token).await;
        return match transaction {
            Ok(transaction) => match render_mfa_transaction_page(
                state.as_ref(),
                &transaction,
                Some("The verification code is invalid or has already been used."),
            )
            .await
            {
                Ok(html) => Html(html).into_response(),
                Err(err) => {
                    tracing::warn!("Cannot render MFA enrollment after invalid code: {err}");
                    Html(templates::error_page(
                        "server_error",
                        "Could not prepare authenticator setup. Contact your administrator.",
                    ))
                    .into_response()
                }
            },
            Err(_) => Html(templates::error_page(
                "access_denied",
                "Too many invalid attempts or the MFA transaction expired. Start sign-in again.",
            ))
            .into_response(),
        };
    }

    let transaction = match mfa::consume_login_transaction(&state.db_pool, &token).await {
        Ok(value) => value,
        Err(_) => {
            return Html(templates::error_page(
                "invalid_request",
                "The MFA sign-in transaction expired. Start sign-in again.",
            ))
            .into_response();
        }
    };
    let audit_client_id =
        sqlx::query_scalar::<_, String>("SELECT client_id FROM oauth_clients WHERE id=$1")
            .bind(transaction.client_id)
            .fetch_optional(&state.db_pool)
            .await
            .unwrap_or(None);
    let pending = pending_from_mfa_transaction(transaction);
    let completion = match complete_user_authorization(
        state.as_ref(),
        pending,
        amr.clone(),
        Some("urn:simple-idm:acr:mfa".to_string()),
    )
    .await
    {
        Ok(value) => value,
        Err(err) => {
            tracing::error!(user_id = %user.id, "{err}");
            return Html(templates::error_page(
                "server_error",
                "Failed to complete sign-in",
            ))
            .into_response();
        }
    };
    audit::emit_event_as(
        &state.db_pool,
        &audit::Actor {
            subject: Some(user.id.to_string()),
            client_id: audit_client_id,
            root_token: false,
        },
        if recovery_codes.is_some() {
            "auth.mfa.enroll"
        } else {
            "auth.mfa.verify"
        },
        "user",
        Some(user.id),
        "success",
        Some(serde_json::json!({"amr": amr})),
    )
    .await;

    let secure =
        state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
    if let Some(codes) = recovery_codes {
        let html = templates::recovery_codes_page(&codes, &completion.redirect_url);
        let mut response = Html(html).into_response();
        append_completion_cookies(state.as_ref(), &mut response, &completion, secure, true);
        response
    } else {
        let mut response = Redirect::to(&completion.redirect_url).into_response();
        append_completion_cookies(state.as_ref(), &mut response, &completion, secure, true);
        response
    }
}

async fn render_mfa_transaction_page(
    state: &OAuth2State,
    transaction: &mfa::MfaLoginTransaction,
    error: Option<&str>,
) -> Result<String, String> {
    if transaction.stage != "enroll" {
        return Ok(templates::mfa_challenge_page(error));
    }
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1 AND tenant_id = $2 AND is_active = true AND deleted_at IS NULL",
    )
    .bind(transaction.user_id)
    .bind(transaction.tenant_id)
    .fetch_one(&state.db_pool)
    .await
    .map_err(|err| err.to_string())?;
    let enrollment = mfa::ensure_pending_totp(
        &state.db_pool,
        user.tenant_id,
        user.id,
        &user.email,
        "Simple IDM",
    )
    .await
    .map_err(|err| err.to_string())?;
    let code = QrCode::new(enrollment.otpauth_url.as_bytes()).map_err(|err| err.to_string())?;
    let qr_svg = code.render::<svg::Color>().min_dimensions(220, 220).build();
    Ok(templates::mfa_enrollment_page(
        &enrollment.base32_secret,
        &qr_svg,
        error,
    ))
}

fn pending_from_mfa_transaction(transaction: mfa::MfaLoginTransaction) -> PendingAuthorization {
    PendingAuthorization {
        credential_version: transaction.credential_version,
        user_id: transaction.user_id,
        client_id: transaction.client_id,
        redirect_uri: transaction.redirect_uri,
        scope: transaction.scope,
        state: transaction.state,
        code_challenge: transaction.code_challenge,
        code_challenge_method: transaction.code_challenge_method,
        nonce: transaction.nonce,
    }
}

pub(super) fn authorization_completion_response(
    state: &OAuth2State,
    headers: &HeaderMap,
    completion: AuthorizationCompletion,
) -> Response {
    let secure = state.force_secure_cookies || request_is_https(headers, state.trust_proxy_headers);
    let mut response = Redirect::to(&completion.redirect_url).into_response();
    append_completion_cookies(state, &mut response, &completion, secure, false);
    response
}

fn append_completion_cookies(
    state: &OAuth2State,
    response: &mut Response,
    completion: &AuthorizationCompletion,
    secure: bool,
    clear_mfa: bool,
) {
    if let Some(session_token) = completion.session_token.as_deref() {
        if let Ok(cookie) =
            build_auth_session_cookie(Some(session_token), state.auth_session_expiry, secure)
                .parse()
        {
            response.headers_mut().append(SET_COOKIE, cookie);
        }
    }
    if clear_mfa {
        if let Ok(cookie) = build_mfa_transaction_cookie(None, secure).parse() {
            response.headers_mut().append(SET_COOKIE, cookie);
        }
    }
}

fn build_mfa_transaction_cookie(token: Option<&str>, secure: bool) -> String {
    let (value, max_age) = token
        .map(|value| (value, mfa::MFA_TRANSACTION_TTL_SECONDS))
        .unwrap_or(("", 0));
    let mut cookie = format!(
        "mfa_transaction={value}; Path=/oauth2/mfa; HttpOnly; SameSite=Strict; Max-Age={max_age}"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

async fn render_login_page(
    state: &OAuth2State,
    params: &HashMap<String, String>,
    error: Option<&str>,
) -> String {
    let providers = async {
        let Some(client_id) = params.get("client_id") else {
            return Ok::<Vec<(String, String)>, String>(Vec::new());
        };
        let client = resolve_oauth_client(
            &state.db_pool,
            client_id,
            params.get("tenant").map(String::as_str),
        )
        .await
        .map_err(|err| format!("{err:?}"))?;
        let Some(client) = client else {
            return Ok(Vec::new());
        };
        sqlx::query_as::<_, (String, String)>(
            "SELECT ip.slug, ip.provider_type FROM identity_providers ip \
             JOIN oauth_clients oc ON oc.tenant_id = ip.tenant_id WHERE oc.id = $1 \
             AND ip.provider_type IN ('google', 'oidc') AND ip.is_active = true \
             AND ip.deleted_at IS NULL ORDER BY ip.slug",
        )
        .bind(client.id)
        .fetch_all(&state.db_pool)
        .await
        .map_err(|err| err.to_string())
    }
    .await;
    match providers {
        Ok(providers) => templates::login_page_with_providers(params, error, &providers),
        Err(err) => {
            tracing::error!("Failed to load sign-in identity providers: {err}");
            templates::error_page(
                "server_error",
                "Failed to load sign-in providers. Please try again.",
            )
        }
    }
}

async fn invalid_login_response(state: &OAuth2State, req: &LoginRequest) -> Response {
    let passkeys_enabled = state.passkeys.is_some();
    let mut params = HashMap::new();
    params.insert("login_hint".to_string(), req.username.clone());
    if let Some(csrf_token) = &req.csrf_token {
        params.insert("csrf_token".to_string(), csrf_token.clone());
    }
    if passkeys_enabled {
        params.insert("passkeys_enabled".to_string(), "true".to_string());
    }
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
    let html = render_login_page(state, &params, Some("Invalid email or password")).await;
    Html(html).into_response()
}

async fn rate_limited_login_response(state: &OAuth2State, req: &LoginRequest) -> Response {
    let passkeys_enabled = state.passkeys.is_some();
    let mut params = HashMap::new();
    params.insert("login_hint".to_string(), req.username.clone());
    if let Some(csrf_token) = &req.csrf_token {
        params.insert("csrf_token".to_string(), csrf_token.clone());
    }
    if passkeys_enabled {
        params.insert("passkeys_enabled".to_string(), "true".to_string());
    }
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
    let html = render_login_page(
        state,
        &params,
        Some("Too many failed attempts. Please wait and try again."),
    )
    .await;
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

async fn clear_failures(db_pool: &sqlx::PgPool, endpoint: &str, keys: &[String]) {
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

pub(super) fn request_is_https(headers: &HeaderMap, trust_proxy_headers: bool) -> bool {
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

pub(super) fn build_auth_session_cookie(token: Option<&str>, max_age: i64, secure: bool) -> String {
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

pub(super) fn build_csrf_cookie(token: &str, secure: bool) -> String {
    let mut cookie = format!(
        "csrf_token={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1200",
        token
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub(super) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
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

async fn verify_user_password(state: &OAuth2State, user: &User, password: &str) -> bool {
    if crate::auth_policy::for_user(&state.db_pool, user.id)
        .await
        .is_err()
    {
        return false;
    }
    if user.password_disabled || user.auth_mode.eq_ignore_ascii_case("federated") {
        return false;
    }

    if user.auth_mode.eq_ignore_ascii_case("ad") {
        let provider = match load_ad_ldap_provider_for_user(state, user).await {
            Ok(Some(v)) => v,
            Ok(None) => return false,
            Err(err) => {
                tracing::warn!(user_id = %user.id, username = %user.username, "LDAP provider load failed: {}", err);
                return false;
            }
        };
        match verify_ldap_password(&provider.config, &user.email, password).await {
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
    match user.password_hash.as_deref() {
        Some(hash) => verify_password_async(password, hash).await.unwrap_or(false),
        None => false,
    }
}

pub(super) fn default_tenant_id() -> Uuid {
    Uuid::parse_str("11111111-1111-1111-1111-111111111111").expect("valid default tenant uuid")
}

pub(super) async fn resolve_tenant_for_email(db_pool: &sqlx::PgPool, email: &str) -> Option<Uuid> {
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
    use crate::oauth2::device_flow::{DeviceTokenRequest, handle_device_token_internal};

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
                    .into_response();
            }
        },
        client_id: req.client_id.unwrap_or_default(),
        client_secret: req.client_secret,
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
                error_description: "Too many failed attempts. Please wait and try again."
                    .to_string(),
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

fn oauth_token_error(error: ErrorResponse) -> Response {
    let status = match error.error.as_str() {
        "invalid_client" => StatusCode::UNAUTHORIZED,
        "server_error" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    let mut response = (status, Json(error)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::PRAGMA, "no-cache".parse().unwrap());
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"oauth2/token\"".parse().unwrap(),
        );
    }
    response
}

async fn handle_authorization_code_token(state: Arc<OAuth2State>, req: TokenRequest) -> Response {
    cleanup_refresh_tokens(&state.db_pool).await;

    let code = match req.code {
        Some(c) => c,
        None => {
            return oauth_token_error(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Missing code parameter".to_string(),
            });
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
            return oauth_token_error(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Invalid authorization code".to_string(),
            });
        }
        Err(_) => {
            return oauth_token_error(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Database error".to_string(),
            });
        }
    };

    // Zkontroluj expiraci
    if auth_code.expires_at < Utc::now() {
        let _ = sqlx::query("DELETE FROM authorization_codes WHERE code = $1")
            .bind(&code)
            .execute(&state.db_pool)
            .await;

        return oauth_token_error(ErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Authorization code expired".to_string(),
        });
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
            return oauth_token_error(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client not found".to_string(),
            });
        }
        Err(_) => {
            return oauth_token_error(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Database error".to_string(),
            });
        }
    };

    let req_client_id = match req.client_id {
        Some(id) => id,
        None => {
            return oauth_token_error(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Missing client_id".to_string(),
            });
        }
    };

    if req_client_id != client.client_id {
        return oauth_token_error(ErrorResponse {
            error: "invalid_client".to_string(),
            error_description: "Client ID mismatch".to_string(),
        });
    }

    // Validate redirect_uri (REQUIRED by OAuth2 RFC 6749 section 4.1.3)
    // "REQUIRED if the redirect_uri parameter was included in the authorization request"
    let req_redirect_uri = match req.redirect_uri {
        Some(uri) => uri,
        None => {
            return oauth_token_error(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Missing redirect_uri parameter (required by OAuth2 spec)"
                    .to_string(),
            });
        }
    };

    if req_redirect_uri != auth_code.redirect_uri {
        return oauth_token_error(ErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Redirect URI mismatch".to_string(),
        });
    }

    // Confidential-client authentication and PKCE are independent checks.
    let credentials_valid = match (
        req.client_secret.as_deref(),
        client.client_secret_hash.as_deref(),
    ) {
        (Some(secret), Some(hash)) => verify_password_async(secret, hash).await.unwrap_or(false),
        _ => false,
    };
    if !client.is_public && !credentials_valid {
        return oauth_token_error(ErrorResponse {
            error: "invalid_client".into(),
            error_description: "Invalid client credentials".into(),
        });
    }
    if !super::utils::authorization_allowed(
        &client,
        &auth_code.scope,
        auth_code.code_challenge.as_deref(),
        auth_code.code_challenge_method.as_deref(),
    ) {
        return oauth_token_error(ErrorResponse {
            error: "invalid_grant".into(),
            error_description: "Authorization no longer allowed".into(),
        });
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
                    Some("plain") => false,
                    Some("S256") => {
                        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
                        use sha2::{Digest, Sha256};
                        if !(43..=128).contains(&verifier.len())
                            || !verifier
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
                        {
                            return oauth_token_error(ErrorResponse {
                                error: "invalid_grant".into(),
                                error_description: "Invalid code verifier".into(),
                            });
                        }
                        let hash = Sha256::digest(verifier.as_bytes());
                        let encoded = URL_SAFE_NO_PAD.encode(hash);
                        challenge == encoded
                    }
                    _ => false,
                };

                if !valid {
                    return oauth_token_error(ErrorResponse {
                        error: "invalid_grant".to_string(),
                        error_description: "Invalid code verifier".to_string(),
                    });
                }
            }
            None => {
                return oauth_token_error(ErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: "Missing code_verifier".to_string(),
                });
            }
        }
    }

    if !super::utils::user_client_allowed(&state.db_pool, client.id, auth_code.user_id)
        .await
        .unwrap_or(false)
    {
        return oauth_token_error(ErrorResponse {
            error: "invalid_grant".into(),
            error_description: "Account is not authorized for this client".into(),
        });
    }
    // Načti uživatele
    let user =
        match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL")
            .bind(auth_code.user_id)
            .fetch_optional(&state.db_pool)
            .await
        {
            Ok(Some(user)) => user,
            Ok(None) => {
                return oauth_token_error(ErrorResponse {
                    error: "invalid_grant".to_string(),
                    error_description: "User not found".to_string(),
                });
            }
            Err(_) => {
                return oauth_token_error(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Database error".to_string(),
                });
            }
        };

    if !crate::auth_policy::accepts_authentication(&state.db_pool, &user, &auth_code.amr)
        .await
        .unwrap_or(false)
    {
        return (
            StatusCode::BAD_REQUEST,
            oauth_token_error(ErrorResponse {
                error: "invalid_grant".into(),
                error_description: "Account or authentication policy changed; sign in again".into(),
            }),
        )
            .into_response();
    }

    let (filtered_group_names, mut custom_claims) =
        match user_authorization_claims(&state.db_pool, user.id, &client).await {
            Ok(data) => data,
            Err(error) => {
                tracing::error!(%error, "Failed to load authorization data");
                return oauth_token_error(ErrorResponse {
                    error: "server_error".into(),
                    error_description: "Failed to load authorization data".into(),
                });
            }
        };

    // Tenant is authoritative server metadata, never a group claim-map override.
    custom_claims.insert("tenant_id".into(), serde_json::json!(user.tenant_id));
    custom_claims.insert(
        "credential_version".into(),
        serde_json::json!(user.credential_version),
    );

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
        auth_code.amr.clone(),
        auth_code.acr.clone(),
        state.access_token_expiry,
    ) {
        Ok(token) => token,
        Err(_) => {
            return oauth_token_error(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to create access token".to_string(),
            });
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
        auth_code.amr.clone(),
        auth_code.acr.clone(),
        state.access_token_expiry,
    ) {
        Ok(token) => token,
        Err(_) => {
            return oauth_token_error(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to create ID token".to_string(),
            });
        }
    };

    // Vytvoř refresh token
    let refresh_token = generate_refresh_token();
    let refresh_expires_at = Utc::now() + Duration::seconds(state.refresh_token_expiry);

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return oauth_token_error(ErrorResponse {
                error: "server_error".into(),
                error_description: "Failed to begin code exchange".into(),
            });
        }
    };
    if sqlx::query(
        "SELECT id FROM users WHERE id = $1 AND is_active AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(user.id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .is_none()
    {
        return oauth_token_error(ErrorResponse {
            error: "invalid_grant".into(),
            error_description: "Account is no longer active".into(),
        });
    }
    // Consume exactly once and persist the replacement in the same transaction.
    match sqlx::query("DELETE FROM authorization_codes WHERE code = $1 AND expires_at > NOW()")
        .bind(&code)
        .execute(&mut *tx)
        .await
    {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            return oauth_token_error(ErrorResponse {
                error: "invalid_grant".into(),
                error_description: "Authorization code is no longer valid".into(),
            });
        }
        Err(_) => {
            return oauth_token_error(ErrorResponse {
                error: "server_error".into(),
                error_description: "Failed to consume authorization code".into(),
            });
        }
    }
    if sqlx::query(
        r#"
        INSERT INTO refresh_tokens (token, client_id, user_id, scope, amr, acr, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(&refresh_token)
    .bind(client.id)
    .bind(user.id)
    .bind(&auth_code.scope)
    .bind(&auth_code.amr)
    .bind(auth_code.acr.as_deref())
    .bind(refresh_expires_at)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        return oauth_token_error(ErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to create refresh token".to_string(),
        });
    }

    if tx.commit().await.is_err() {
        return oauth_token_error(ErrorResponse {
            error: "server_error".into(),
            error_description: "Failed to commit code exchange".into(),
        });
    }
    cleanup_refresh_tokens(&state.db_pool).await;

    let response = TokenResponseWithRefresh {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.access_token_expiry,
        refresh_token: Some(refresh_token),
        id_token: Some(id_token),
        scope: Some(auth_code.scope),
    };

    audit::emit_event_as(
        &state.db_pool,
        &audit::Actor {
            subject: Some(user.id.to_string()),
            client_id: Some(client.client_id.clone()),
            root_token: false,
        },
        "oauth.token.issue",
        "token",
        Some(user.id),
        "success",
        Some(serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": client.client_id
        })),
    )
    .await;

    tracing::debug!("Authorization code exchanged successfully");

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
            return oauth_token_error(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Missing refresh_token parameter".to_string(),
            });
        }
    };

    // Načti refresh token
    let refresh_token =
        match sqlx::query_as::<_, RefreshToken>("SELECT * FROM refresh_tokens WHERE token = $1")
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

                return oauth_token_error(ErrorResponse {
                    error: "invalid_grant".to_string(),
                    error_description: "Invalid refresh token".to_string(),
                });
            }
            Err(_) => {
                return oauth_token_error(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Database error".to_string(),
                });
            }
        };

    // Zkontroluj expiraci
    if refresh_token.expires_at < Utc::now() {
        let _ = sqlx::query("DELETE FROM refresh_tokens WHERE token = $1")
            .bind(&refresh_token_str)
            .execute(&state.db_pool)
            .await;

        return oauth_token_error(ErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Refresh token expired".to_string(),
        });
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
            return oauth_token_error(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client not found".to_string(),
            });
        }
        Err(_) => {
            return oauth_token_error(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Database error".to_string(),
            });
        }
    };

    let client_secret = req.client_secret.unwrap_or_default();

    // Verify client credentials (only for confidential clients)
    if !client.is_public {
        if client_secret.is_empty() {
            return oauth_token_error(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Missing client_secret for confidential client".to_string(),
            });
        }

        if let Some(ref hash) = client.client_secret_hash {
            if !verify_password_async(&client_secret, hash)
                .await
                .unwrap_or(false)
            {
                return oauth_token_error(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Invalid client credentials".to_string(),
                });
            }
        } else {
            return oauth_token_error(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client secret required for confidential client".to_string(),
            });
        }
    }

    if !super::utils::user_client_allowed(&state.db_pool, client.id, refresh_token.user_id)
        .await
        .unwrap_or(false)
    {
        return oauth_token_error(ErrorResponse {
            error: "invalid_grant".into(),
            error_description: "Account is not authorized for this client".into(),
        });
    }
    if req.client_id.as_deref() != Some(client.client_id.as_str())
        || !client
            .grant_types
            .iter()
            .any(|grant| grant == "refresh_token")
        || !super::utils::scope_allowed(&client.scope, &refresh_token.scope)
    {
        return oauth_token_error(ErrorResponse {
            error: "invalid_grant".into(),
            error_description: "Refresh authorization no longer allowed".into(),
        });
    }
    // Načti uživatele
    let user =
        match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL")
            .bind(refresh_token.user_id)
            .fetch_optional(&state.db_pool)
            .await
        {
            Ok(Some(user)) => user,
            Ok(None) => {
                return oauth_token_error(ErrorResponse {
                    error: "invalid_grant".to_string(),
                    error_description: "User not found".to_string(),
                });
            }
            Err(_) => {
                return oauth_token_error(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Database error".to_string(),
                });
            }
        };

    let policy = match crate::auth_policy::for_user(&state.db_pool, user.id).await {
        Ok(policy) => policy,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                oauth_token_error(ErrorResponse {
                    error: "invalid_grant".into(),
                    error_description: "Account is unavailable; sign in again".into(),
                }),
            )
                .into_response();
        }
    };
    if user.auth_mode.eq_ignore_ascii_case("local") && !policy.accepts_session(&refresh_token.amr) {
        return (
            StatusCode::BAD_REQUEST,
            oauth_token_error(ErrorResponse {
                error: "invalid_grant".into(),
                error_description: "Authentication policy changed; sign in again".into(),
            }),
        )
            .into_response();
    }

    let (filtered_group_names, mut custom_claims) =
        match user_authorization_claims(&state.db_pool, user.id, &client).await {
            Ok(data) => data,
            Err(error) => {
                tracing::error!(%error, "Failed to load authorization data");
                return oauth_token_error(ErrorResponse {
                    error: "server_error".into(),
                    error_description: "Failed to load authorization data".into(),
                });
            }
        };

    // Tenant is authoritative server metadata, never a group claim-map override.
    custom_claims.insert("tenant_id".into(), serde_json::json!(user.tenant_id));
    custom_claims.insert(
        "credential_version".into(),
        serde_json::json!(user.credential_version),
    );

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
        refresh_token.amr.clone(),
        refresh_token.acr.clone(),
        state.access_token_expiry,
    ) {
        Ok(token) => token,
        Err(_) => {
            return oauth_token_error(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to create access token".to_string(),
            });
        }
    };

    // Rotate refresh token
    let new_refresh_token = generate_refresh_token();
    let new_refresh_expires_at = Utc::now() + Duration::seconds(state.refresh_token_expiry);

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return oauth_token_error(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to start transaction".to_string(),
            });
        }
    };

    if sqlx::query(
        "SELECT id FROM users WHERE id = $1 AND is_active AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(user.id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .is_none()
    {
        return oauth_token_error(ErrorResponse {
            error: "invalid_grant".into(),
            error_description: "Account is no longer active".into(),
        });
    }
    match sqlx::query("DELETE FROM refresh_tokens WHERE token = $1 AND expires_at > NOW()")
        .bind(&refresh_token_str)
        .execute(&mut *tx)
        .await
    {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            return oauth_token_error(ErrorResponse {
                error: "invalid_grant".into(),
                error_description: "Refresh token is no longer valid".into(),
            });
        }
        Err(_) => {
            return oauth_token_error(ErrorResponse {
                error: "server_error".into(),
                error_description: "Failed to consume refresh token".into(),
            });
        }
    }
    if sqlx::query(
        r#"
        INSERT INTO refresh_tokens (token, client_id, user_id, scope, amr, acr, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(&new_refresh_token)
    .bind(refresh_token.client_id)
    .bind(refresh_token.user_id)
    .bind(&refresh_token.scope)
    .bind(&refresh_token.amr)
    .bind(refresh_token.acr.as_deref())
    .bind(new_refresh_expires_at)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        return oauth_token_error(ErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to create refresh token".to_string(),
        });
    }

    if sqlx::query(
        r#"
        INSERT INTO used_refresh_tokens (token, client_id, user_id, scope, amr, acr, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(&refresh_token.token)
    .bind(refresh_token.client_id)
    .bind(refresh_token.user_id)
    .bind(&refresh_token.scope)
    .bind(&refresh_token.amr)
    .bind(refresh_token.acr.as_deref())
    .bind(refresh_token.expires_at)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        return oauth_token_error(ErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to mark refresh token as used".to_string(),
        });
    }

    if sqlx::query("DELETE FROM refresh_tokens WHERE token = $1")
        .bind(&refresh_token_str)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        let _ = tx.rollback().await;
        return oauth_token_error(ErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to rotate refresh token".to_string(),
        });
    }

    if tx.commit().await.is_err() {
        return oauth_token_error(ErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to commit refresh token rotation".to_string(),
        });
    }

    let response = TokenResponseWithRefresh {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.access_token_expiry,
        refresh_token: Some(new_refresh_token),
        id_token: None,
        scope: Some(refresh_token.scope),
    };

    audit::emit_event_as(
        &state.db_pool,
        &audit::Actor {
            subject: Some(user.id.to_string()),
            client_id: Some(client.client_id.clone()),
            root_token: false,
        },
        "oauth.token.refresh",
        "token",
        Some(user.id),
        "success",
        Some(serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": client.client_id
        })),
    )
    .await;

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

                tracing::debug!("Logout: authentication session removed");
            }
        }
    }

    // Clear cookie by setting Max-Age=0
    let secure =
        state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
    let cookie = build_auth_session_cookie(None, 0, secure);

    let body = r#"<div class="alert alert-info mb-0" role="alert">
  You have been signed out from Simple IDM.
</div>"#;
    let html = tabler_standalone_page(
        "Signed out - Simple IDM",
        "Simple IDM",
        "Signed out",
        "Your SSO session has been closed.",
        body,
        "Protected by Simple IDM",
        "",
    );
    let mut response = Html(html).into_response();

    response
        .headers_mut()
        .insert(SET_COOKIE, cookie.parse().unwrap());

    response
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use rsa::{
        RsaPrivateKey, RsaPublicKey,
        pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
        rand_core::OsRng,
    };

    #[tokio::test]
    async fn oauth_errors_use_failure_status_and_safe_json() {
        for (error, status) in [
            ("invalid_client", StatusCode::UNAUTHORIZED),
            ("invalid_grant", StatusCode::BAD_REQUEST),
            ("server_error", StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let response = oauth_token_error(ErrorResponse {
                error: error.into(),
                error_description: "Test error".into(),
            });
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            if status == StatusCode::UNAUTHORIZED {
                assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
            }
            assert_eq!(body(response).await["error"], error);
        }
    }

    fn request(client: &str, code: &str, secret: Option<&str>) -> TokenRequest {
        TokenRequest {
            grant_type: "authorization_code".into(),
            code: Some(code.into()),
            redirect_uri: Some("https://app.test/callback".into()),
            client_id: Some(client.into()),
            client_secret: secret.map(str::to_owned),
            code_verifier: Some("A".repeat(43)),
            refresh_token: None,
            device_code: None,
        }
    }
    async fn body(response: Response) -> serde_json::Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65_536)
                .await
                .unwrap(),
        )
        .unwrap()
    }
    async fn code(pool: &sqlx::PgPool, client: Uuid, user: Uuid) -> String {
        let code = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO authorization_codes (code,client_id,user_id,redirect_uri,scope,amr,expires_at) VALUES ($1,$2,$3,'https://app.test/callback','openid',ARRAY['pwd'],NOW()+INTERVAL '10 minutes')")
            .bind(&code).bind(client).bind(user).execute(pool).await.unwrap();
        code
    }
    #[tokio::test]
    #[ignore = "requires disposable DATABASE_URL; run scripts/test-postgres.sh"]
    async fn postgres_confidential_auth_code_consumption_and_revocation() {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let private = dir.path().join("private.pem");
        let public = dir.path().join("public.pem");
        std::fs::write(
            &private,
            key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::write(
            &public,
            RsaPublicKey::from(&key)
                .to_public_key_pem(LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let jwt = crate::auth::JwtService::new(
            private.to_str().unwrap(),
            public.to_str().unwrap(),
            "https://idm.test".into(),
            "test".into(),
            vec![],
        )
        .unwrap();
        let state = Arc::new(OAuth2State {
            db_pool: pool.clone(),
            jwt_service: Arc::new(jwt),
            access_token_expiry: 3600,
            refresh_token_expiry: 3600,
            auth_session_expiry: 3600,
            allow_username_login: true,
            allowed_email_domains: vec![],
            trust_proxy_headers: false,
            force_secure_cookies: false,
            passkeys: None,
            device_flow_config: crate::config::DeviceFlowConfig {
                expiry_seconds: 600,
                polling_interval_seconds: 1,
                user_code_length: 8,
                user_code_format: "XXXX-XXXX".into(),
                cleanup_interval_seconds: 60,
                max_verification_attempts: 5,
            },
            auth_protection: crate::config::AuthProtectionConfig {
                enabled: false,
                failure_window_seconds: 60,
                max_failures: 5,
                lockout_seconds: 60,
                clear_on_start: false,
            },
        });
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let client = Uuid::new_v4();
        let name = client.to_string();
        sqlx::query("INSERT INTO tenants (id,slug,name) VALUES ($1,$2,'Security tests')")
            .bind(tenant)
            .bind(tenant.to_string())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (id,tenant_id,username,email,password_hash) VALUES ($1,$2,$3,$4,'unused')")
            .bind(user).bind(tenant).bind(user.to_string()).bind(format!("{user}@example.test")).execute(&pool).await.unwrap();
        let secret = "confidential+test/secret:% space";
        let hash = crate::auth::hash_password_async(secret).await.unwrap();
        sqlx::query("INSERT INTO oauth_clients (id,tenant_id,client_id,name,redirect_uris,grant_types,is_public,client_secret_hash,scope) VALUES ($1,$2,$3,'Security test',ARRAY['https://app.test/callback'],ARRAY['authorization_code','refresh_token'],false,$4,'openid')")
            .bind(client).bind(tenant).bind(&name).bind(hash).execute(&pool).await.unwrap();
        let first = code(&pool, client, user).await;
        let rejected =
            handle_authorization_code_token(state.clone(), request(&name, &first, None)).await;
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
        let rejected = body(rejected).await;
        assert_eq!(rejected["error"], "invalid_client");
        let valid = body(
            handle_authorization_code_token(state.clone(), request(&name, &first, Some(secret)))
                .await,
        )
        .await;
        assert!(valid["access_token"].is_string());
        assert!(valid["refresh_token"].is_string());
        // Exercise the endpoint as an OIDC client does: encoded Basic secret plus S256.
        {
            use base64::Engine;
            use sha2::Digest;
            let basic_code = code(&pool, client, user).await;
            let verifier = "A".repeat(43);
            let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(verifier.as_bytes()));
            sqlx::query("UPDATE authorization_codes SET code_challenge=$1, code_challenge_method='S256' WHERE code=$2")
                .bind(challenge).bind(&basic_code).execute(&pool).await.unwrap();
            let encoded_id: String =
                url::form_urlencoded::byte_serialize(name.as_bytes()).collect();
            let encoded_secret: String =
                url::form_urlencoded::byte_serialize(secret.as_bytes()).collect();
            let basic = base64::engine::general_purpose::STANDARD
                .encode(format!("{encoded_id}:{encoded_secret}"));
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                format!("Basic {basic}").parse().unwrap(),
            );
            headers.insert(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded".parse().unwrap(),
            );
            let form = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "authorization_code")
                .append_pair("code", &basic_code)
                .append_pair("redirect_uri", "https://app.test/callback")
                .append_pair("code_verifier", &verifier)
                .finish();
            let response = handle_token(State(state.clone()), headers, Bytes::from(form)).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(body(response).await["access_token"].is_string());
        }

        let replay = body(
            handle_authorization_code_token(state.clone(), request(&name, &first, Some(secret)))
                .await,
        )
        .await;
        assert_eq!(replay["error"], "invalid_grant");
        let second = code(&pool, client, user).await;
        let (left, right) = tokio::join!(
            handle_authorization_code_token(state.clone(), request(&name, &second, Some(secret))),
            handle_authorization_code_token(state.clone(), request(&name, &second, Some(secret)))
        );
        let left = body(left).await;
        let right = body(right).await;
        assert_ne!(
            left["access_token"].is_string(),
            right["access_token"].is_string()
        );
        let third = code(&pool, client, user).await;
        sqlx::query("INSERT INTO authentication_sessions (session_token,user_id,expires_at) VALUES ($1,$2,NOW()+INTERVAL '1 hour')").bind(Uuid::new_v4().to_string()).bind(user).execute(&pool).await.unwrap();
        sqlx::query("UPDATE users SET password_hash = 'changed' WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        for query in [
            "SELECT count(*) FROM authorization_codes WHERE user_id = $1",
            "SELECT count(*) FROM refresh_tokens WHERE user_id = $1",
            "SELECT count(*) FROM authentication_sessions WHERE user_id = $1",
        ] {
            let count: i64 = sqlx::query_scalar(query)
                .bind(user)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(count, 0, "All grants must be revoked");
        }
        let revoked = body(
            handle_authorization_code_token(state.clone(), request(&name, &third, Some(secret)))
                .await,
        )
        .await;
        assert_eq!(revoked["error"], "invalid_grant");
        assert!(
            complete_user_authorization(
                &state,
                PendingAuthorization {
                    credential_version: 0,
                    user_id: user,
                    client_id: client,
                    redirect_uri: "https://app.test/callback".into(),
                    scope: "openid".into(),
                    state: None,
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None
                },
                vec!["pwd".into()],
                None
            )
            .await
            .is_err()
        );
        let fourth = code(&pool, client, user).await;
        let authenticator = Uuid::new_v4();
        sqlx::query("INSERT INTO user_authenticators (id,tenant_id,user_id,kind,secret_encrypted,status) VALUES ($1,$2,$3,'totp','unused','active')").bind(authenticator).bind(tenant).bind(user).execute(&pool).await.unwrap();
        sqlx::query("UPDATE user_authenticators SET status = 'revoked' WHERE id = $1")
            .bind(authenticator)
            .execute(&pool)
            .await
            .unwrap();
        let revoked = body(
            handle_authorization_code_token(state.clone(), request(&name, &fourth, Some(secret)))
                .await,
        )
        .await;
        assert_eq!(revoked["error"], "invalid_grant");
        // A stale enrollment must not activate a new factor after credential revocation.
        let pending_authenticator = sqlx::query_as::<_, crate::db::models::UserAuthenticator>(
            "INSERT INTO user_authenticators (tenant_id,user_id,kind,secret_encrypted,status) VALUES ($1,$2,'totp','unused','pending') RETURNING *",
        ).bind(tenant).bind(user).fetch_one(&pool).await.unwrap();
        assert!(
            mfa::activate_totp_and_generate_recovery_codes(&pool, &pending_authenticator, 0)
                .await
                .is_err()
        );
        let status: String =
            sqlx::query_scalar("SELECT status FROM user_authenticators WHERE id = $1")
                .bind(pending_authenticator.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(status, "pending");
        // Admin access depends on the designated default-tenant client and current DB role.
        let admin_user = Uuid::new_v4();
        let admin_client = Uuid::new_v4();
        let admin_name = admin_client.to_string();
        sqlx::query(
            "INSERT INTO users (id,username,email,password_hash) VALUES ($1,$2,$3,'unused')",
        )
        .bind(admin_user)
        .bind(admin_user.to_string())
        .bind(format!("{admin_user}@example.test"))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO oauth_clients (id,client_id,name,redirect_uris,grant_types,is_public,scope) VALUES ($1,$2,'Admin test','{}',ARRAY['authorization_code'],true,'openid admin:*')")
            .bind(admin_client).bind(&admin_name).execute(&pool).await.unwrap();
        let admin = crate::admin::middleware::AdminAuth {
            admin_root_token: None,
            allow_legacy_admin_group: false,
            allow_admin_substring_claim: true,
            oauth_client_ids: vec![admin_name.clone()],
            jwt_service: state.jwt_service.clone(),
            db_pool: pool.clone(),
        };
        let mut claims = std::collections::HashMap::new();
        claims.insert("credential_version".into(), serde_json::json!(0));
        claims.insert("admin_fake".into(), serde_json::json!(true));
        let admin_token = state
            .jwt_service
            .create_access_token(
                admin_user,
                admin_name.clone(),
                None,
                None,
                Some("admin:*".into()),
                vec!["simple-idm:role:admin".into()],
                claims.clone(),
                vec!["pwd".into()],
                None,
                3600,
            )
            .unwrap();
        assert!(!admin.validate_token(&admin_token).await);
        let foreign_group = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO groups (id,tenant_id,name) VALUES ($1,$2,'simple-idm:role:admin')",
        )
        .bind(foreign_group)
        .bind(tenant)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO user_groups (user_id,group_id) VALUES ($1,$2)")
            .bind(admin_user)
            .bind(foreign_group)
            .execute(&pool)
            .await
            .unwrap();
        assert!(!admin.validate_token(&admin_token).await);
        let actual_group: Uuid = sqlx::query_scalar("SELECT id FROM groups WHERE tenant_id = '11111111-1111-1111-1111-111111111111' AND name = 'simple-idm:role:admin' AND deleted_at IS NULL").fetch_one(&pool).await.unwrap();
        sqlx::query("INSERT INTO user_groups (user_id,group_id) VALUES ($1,$2)")
            .bind(admin_user)
            .bind(actual_group)
            .execute(&pool)
            .await
            .unwrap();
        assert!(admin.validate_token(&admin_token).await);
        let wrong_audience = state
            .jwt_service
            .create_access_token(
                admin_user,
                "unregistered-admin-audience".into(),
                None,
                None,
                Some("admin:*".into()),
                vec!["simple-idm:role:admin".into()],
                claims,
                vec!["pwd".into()],
                None,
                3600,
            )
            .unwrap();
        assert!(!admin.validate_token(&wrong_audience).await);
        sqlx::query("UPDATE users SET password_hash = 'changed' WHERE id = $1")
            .bind(admin_user)
            .execute(&pool)
            .await
            .unwrap();
        assert!(!admin.validate_token(&admin_token).await);
    }
}
