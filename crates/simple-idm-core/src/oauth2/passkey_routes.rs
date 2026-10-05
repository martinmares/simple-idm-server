use super::authorization_code::{
    PendingAuthorization as OidcPending, build_auth_session_cookie, build_csrf_cookie,
    complete_user_authorization, cookie_value, default_tenant_id, get_auth_session_from_cookie,
    request_is_https, resolve_tenant_for_email,
};
use super::client_credentials::OAuth2State;
use super::throttle;
use super::utils::resolve_oauth_client;
use crate::audit;
use crate::db::models::{AuthenticationSession, User};
use crate::mfa::{self, MfaPolicy};
use crate::passkeys::{PasskeyService, PendingAuthorization as PasskeyPending};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use chrono::{Duration, Utc};
use rand::RngExt;
use serde::Deserialize;
use serde_json::json;
use simple_idm_common::{escape_html, tabler_standalone_page};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

const FRESH_SESSION_MINUTES: i64 = 5;

#[derive(Deserialize)]
pub struct PasskeyLoginStart {
    username: String,
    client_id: String,
    tenant: Option<String>,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct PasskeyLoginFinish {
    token: String,
    credential: PublicKeyCredential,
}

#[derive(Deserialize)]
pub struct PasskeyRegisterFinish {
    token: String,
    label: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
pub struct PasskeyRename {
    id: Uuid,
    label: String,
}

#[derive(Deserialize)]
pub struct PasskeyRevoke {
    id: Uuid,
}

fn error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({"error": message}))).into_response()
}

fn service(state: &OAuth2State) -> Result<&PasskeyService, Response> {
    state
        .passkeys
        .as_deref()
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "Passkeys are not enabled"))
}

fn same_origin(service: &PasskeyService, headers: &HeaderMap) -> bool {
    headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| service.allows_origin(origin))
}

fn csrf_matches(headers: &HeaderMap) -> bool {
    let cookie = cookie_value(headers, "csrf_token");
    let supplied = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok());
    matches!((cookie, supplied), (Some(cookie), Some(supplied)) if !cookie.is_empty() && cookie == supplied)
}

fn require_post_security(service: &PasskeyService, headers: &HeaderMap) -> Result<(), Response> {
    if !same_origin(service, headers) || !csrf_matches(headers) {
        return Err(error(
            StatusCode::FORBIDDEN,
            "Invalid request origin or CSRF token",
        ));
    }
    Ok(())
}

async fn local_session(
    state: &OAuth2State,
    headers: &HeaderMap,
    fresh: bool,
) -> Result<(AuthenticationSession, User), Response> {
    let session = get_auth_session_from_cookie(&state.db_pool, headers)
        .await
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "Sign in to manage passkeys"))?;
    if fresh && Utc::now() - session.created_at > Duration::minutes(FRESH_SESSION_MINUTES) {
        return Err(error(
            StatusCode::FORBIDDEN,
            "Sign out and sign in again to change passkeys",
        ));
    }
    let user = sqlx::query_as::<_, User>(
        "SELECT u.* FROM users u JOIN tenants t ON t.id = u.tenant_id JOIN effective_user_auth_policies p ON p.user_id = u.id WHERE u.id = $1 AND u.is_active = true AND u.deleted_at IS NULL AND u.auth_mode = 'local' AND t.is_active = true AND p.passkey_policy = 'allowed'",
    )
    .bind(session.user_id).fetch_optional(&state.db_pool).await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Could not load account"))?
    .ok_or_else(|| error(StatusCode::FORBIDDEN, "Passkeys are not available for this account"))?;
    Ok((session, user))
}

pub async fn login_start(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Json(req): Json<PasskeyLoginStart>,
) -> Response {
    let Ok(passkeys) = service(&state) else {
        return error(StatusCode::NOT_FOUND, "Passkeys are not enabled");
    };
    if let Err(response) = require_post_security(passkeys, &headers) {
        return response;
    }
    if cookie_value(&headers, "csrf_token").as_deref() != Some(req.csrf_token.as_str()) {
        return error(StatusCode::FORBIDDEN, "Invalid CSRF token");
    }
    let username = req.username.trim();
    if username.is_empty() || username.len() > 254 || req.client_id.len() > 255 {
        return error(StatusCode::BAD_REQUEST, "Passkey sign-in is unavailable");
    }
    let keys = [
        format!("login:{}", username.to_lowercase()),
        format!(
            "ip:{}",
            throttle::extract_client_ip(&headers, state.trust_proxy_headers).unwrap_or_default()
        ),
    ];
    if state.auth_protection.enabled {
        for key in &keys {
            if throttle::is_locked(&state.db_pool, "oauth2_passkey", key)
                .await
                .unwrap_or(true)
            {
                return error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many attempts; try again later",
                );
            }
        }
    }
    let tenant_id = if username.contains('@') {
        resolve_tenant_for_email(&state.db_pool, username)
            .await
            .unwrap_or_else(default_tenant_id)
    } else {
        default_tenant_id()
    };
    let user = if state.allow_username_login {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE tenant_id = $1 AND (username = $2 OR email = $2) AND is_active = true AND deleted_at IS NULL")
            .bind(tenant_id).bind(username).fetch_optional(&state.db_pool).await
    } else if username.contains('@') {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE tenant_id = $1 AND email = $2 AND is_active = true AND deleted_at IS NULL")
            .bind(tenant_id).bind(username).fetch_optional(&state.db_pool).await
    } else {
        Ok(None)
    };
    let client = resolve_oauth_client(&state.db_pool, &req.client_id, req.tenant.as_deref()).await;
    let pending = match (user, client) {
        (Ok(Some(user)), Ok(Some(client)))
            if user.auth_mode == "local"
                && (state.allowed_email_domains.is_empty()
                    || user.email.rsplit_once('@').is_some_and(|(_, domain)| {
                        state
                            .allowed_email_domains
                            .iter()
                            .any(|d| d == &domain.to_lowercase())
                    })) =>
        {
            PasskeyPending {
                credential_version: user.credential_version,
                tenant_id: user.tenant_id,
                user_id: user.id,
                client_id: client.id,
                redirect_uri: req.redirect_uri,
                scope: req.scope.unwrap_or(client.scope),
                state: req.state,
                code_challenge: req.code_challenge.filter(|v| !v.is_empty()),
                code_challenge_method: req.code_challenge_method.filter(|v| !v.is_empty()),
                nonce: req.nonce.filter(|v| !v.is_empty()),
            }
        }
        _ => {
            for key in &keys {
                let _ = throttle::register_failure(
                    &state.db_pool,
                    "oauth2_passkey",
                    key,
                    &state.auth_protection,
                )
                .await;
            }
            return error(StatusCode::BAD_REQUEST, "Passkey sign-in is unavailable");
        }
    };
    match passkeys
        .start_authentication(&state.db_pool, &pending)
        .await
    {
        Ok((token, options)) => Json(json!({"token": token, "options": options})).into_response(),
        Err(err) => {
            tracing::warn!("Passkey start rejected: {err}");
            for key in &keys {
                let _ = throttle::register_failure(
                    &state.db_pool,
                    "oauth2_passkey",
                    key,
                    &state.auth_protection,
                )
                .await;
            }
            error(StatusCode::BAD_REQUEST, "Passkey sign-in is unavailable")
        }
    }
}

pub async fn login_finish(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Json(req): Json<PasskeyLoginFinish>,
) -> Response {
    let Ok(passkeys) = service(&state) else {
        return error(StatusCode::NOT_FOUND, "Passkeys are not enabled");
    };
    if let Err(response) = require_post_security(passkeys, &headers) {
        return response;
    }
    if req.token.len() > 128 {
        return error(StatusCode::BAD_REQUEST, "Invalid passkey transaction");
    }
    let pending = match passkeys
        .finish_authentication(&state.db_pool, &req.token, &req.credential)
        .await
    {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!("Passkey assertion rejected: {err}");
            audit::emit_event(
                &state.db_pool,
                "auth.passkey.login",
                "user",
                None,
                "failure",
                None,
            )
            .await;
            return error(
                StatusCode::BAD_REQUEST,
                "Passkey verification failed; try again",
            );
        }
    };
    let user_id = pending.user_id;
    let oidc = OidcPending {
        credential_version: pending.credential_version,
        user_id,
        client_id: pending.client_id,
        redirect_uri: pending.redirect_uri,
        scope: pending.scope,
        state: pending.state,
        code_challenge: pending.code_challenge,
        code_challenge_method: pending.code_challenge_method,
        nonce: pending.nonce,
    };
    let completion = match complete_user_authorization(
        &state,
        oidc,
        vec!["webauthn".into()],
        Some("urn:simple-idm:acr:phishing-resistant".into()),
    )
    .await
    {
        Ok(value) => value,
        Err(err) => {
            tracing::error!(user_id = %user_id, "Could not complete passkey sign-in: {err}");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not complete sign-in",
            );
        }
    };
    audit::emit_event(
        &state.db_pool,
        "auth.passkey.login",
        "user",
        Some(user_id),
        "success",
        None,
    )
    .await;
    let mut response = Json(json!({"redirect_url": completion.redirect_url})).into_response();
    if let Some(token) = completion.session_token {
        let secure =
            state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
        if let Ok(cookie) =
            build_auth_session_cookie(Some(&token), state.auth_session_expiry, secure).parse()
        {
            response.headers_mut().append(header::SET_COOKIE, cookie);
        }
    }
    response
}

pub async fn security_page(State(state): State<Arc<OAuth2State>>, headers: HeaderMap) -> Response {
    if service(&state).is_err() {
        return error(StatusCode::NOT_FOUND, "Passkeys are not enabled");
    }
    let (session, user) = match local_session(&state, &headers, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let fresh = Utc::now() - session.created_at <= Duration::minutes(FRESH_SESSION_MINUTES);
    let mfa_link = match mfa::user_mfa_policy(&state.db_pool, user.id).await {
        Ok(MfaPolicy::Optional | MfaPolicy::Required) => {
            "<a href=\"/account/mfa\" class=\"btn btn-outline-primary w-100 mb-2\">Manage authenticator app (2FA)</a>"
        }
        _ => "",
    };
    let csrf: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(48)
        .map(char::from)
        .collect();
    let body = format!(
        r#"<div id="passkey-account" data-csrf="{csrf}" data-fresh="{fresh}">
  <div class="mb-3">Signed in as <strong>{email}</strong>.</div>
  {fresh_notice}
  <div id="passkey-list" class="mb-3"></div>
  <label class="form-label" for="passkey-label">Name this passkey</label>
  <input class="form-control mb-2" id="passkey-label" maxlength="100" value="My passkey">
  <button class="btn btn-primary w-100" type="button" id="passkey-add" {disabled}>Add passkey</button>
  <div id="passkey-message" class="form-hint mt-2" role="status" aria-live="polite"></div>
  <p class="text-secondary small mt-3">Add a second passkey as a backup. Your password and authenticator app remain available.</p>
  {mfa_link}
  <a href="/oauth2/logout" class="btn btn-outline-secondary w-100">Sign out</a>
</div>
<script>{script}</script>"#,
        csrf = escape_html(&csrf),
        fresh = fresh,
        email = escape_html(&user.email),
        fresh_notice = if fresh {
            ""
        } else {
            "<div class=\"alert alert-warning\">Sign out and sign in again to change passkeys. Your current session is older than five minutes.</div>"
        },
        disabled = if fresh { "" } else { "disabled" },
        mfa_link = mfa_link,
        script = include_str!("passkey_ui.js"),
    );
    let html = tabler_standalone_page(
        "Passkeys - Simple IDM",
        "Simple IDM",
        "Your passkeys",
        "Manage passkeys for your local account.",
        &body,
        "Protected by Simple IDM",
        "",
    );
    let secure =
        state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
    let mut response = Html(html).into_response();
    if let Ok(cookie) = build_csrf_cookie(&csrf, secure).parse() {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

pub async fn list(State(state): State<Arc<OAuth2State>>, headers: HeaderMap) -> Response {
    let Ok(passkeys) = service(&state) else {
        return error(StatusCode::NOT_FOUND, "Passkeys are not enabled");
    };
    let (_, user) = match local_session(&state, &headers, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match passkeys.list(&state.db_pool, user.tenant_id, user.id).await {
        Ok(items) => Json(json!({"passkeys": items})).into_response(),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "Could not load passkeys"),
    }
}

pub async fn registration_start(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
) -> Response {
    let Ok(passkeys) = service(&state) else {
        return error(StatusCode::NOT_FOUND, "Passkeys are not enabled");
    };
    if let Err(response) = require_post_security(passkeys, &headers) {
        return response;
    }
    let (_, user) = match local_session(&state, &headers, true).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let display_name = format!(
        "{} {}",
        user.first_name.as_deref().unwrap_or(""),
        user.last_name.as_deref().unwrap_or("")
    )
    .trim()
    .to_string();
    match passkeys
        .start_registration(
            &state.db_pool,
            user.tenant_id,
            user.id,
            &user.email,
            if display_name.is_empty() {
                &user.email
            } else {
                &display_name
            },
        )
        .await
    {
        Ok((token, options)) => Json(json!({"token": token, "options": options})).into_response(),
        Err(err) => {
            tracing::warn!(user_id = %user.id, "Passkey registration start failed: {err}");
            error(
                StatusCode::BAD_REQUEST,
                "Could not start passkey registration",
            )
        }
    }
}

pub async fn registration_finish(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Json(req): Json<PasskeyRegisterFinish>,
) -> Response {
    let Ok(passkeys) = service(&state) else {
        return error(StatusCode::NOT_FOUND, "Passkeys are not enabled");
    };
    if let Err(response) = require_post_security(passkeys, &headers) {
        return response;
    }
    let (_, user) = match local_session(&state, &headers, true).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if req.token.len() > 128 {
        return error(StatusCode::BAD_REQUEST, "Invalid passkey transaction");
    }
    match passkeys
        .finish_registration(
            &state.db_pool,
            &req.token,
            user.tenant_id,
            user.id,
            &req.label,
            &req.credential,
        )
        .await
    {
        Ok(id) => {
            audit::emit_event(
                &state.db_pool,
                "auth.passkey.register",
                "user",
                Some(user.id),
                "success",
                Some(json!({"passkey_id": id})),
            )
            .await;
            Json(json!({"id": id})).into_response()
        }
        Err(err) => {
            tracing::warn!(user_id = %user.id, "Passkey registration failed: {err}");
            audit::emit_event(
                &state.db_pool,
                "auth.passkey.register",
                "user",
                Some(user.id),
                "failure",
                None,
            )
            .await;
            error(StatusCode::BAD_REQUEST, "Passkey registration failed")
        }
    }
}

pub async fn rename(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Json(req): Json<PasskeyRename>,
) -> Response {
    let Ok(passkeys) = service(&state) else {
        return error(StatusCode::NOT_FOUND, "Passkeys are not enabled");
    };
    if let Err(response) = require_post_security(passkeys, &headers) {
        return response;
    }
    let (_, user) = match local_session(&state, &headers, true).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match passkeys
        .rename(&state.db_pool, user.tenant_id, user.id, req.id, &req.label)
        .await
    {
        Ok(true) => {
            audit::emit_event(
                &state.db_pool,
                "auth.passkey.rename",
                "user",
                Some(user.id),
                "success",
                Some(json!({"passkey_id": req.id})),
            )
            .await;
            Json(json!({"ok": true})).into_response()
        }
        Ok(false) => error(StatusCode::NOT_FOUND, "Passkey not found"),
        Err(_) => error(StatusCode::BAD_REQUEST, "Could not rename passkey"),
    }
}

pub async fn revoke(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Json(req): Json<PasskeyRevoke>,
) -> Response {
    let Ok(passkeys) = service(&state) else {
        return error(StatusCode::NOT_FOUND, "Passkeys are not enabled");
    };
    if let Err(response) = require_post_security(passkeys, &headers) {
        return response;
    }
    let (_, user) = match local_session(&state, &headers, true).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match passkeys
        .revoke(&state.db_pool, user.tenant_id, user.id, req.id)
        .await
    {
        Ok(true) => {
            audit::emit_event(
                &state.db_pool,
                "auth.passkey.revoke",
                "user",
                Some(user.id),
                "success",
                Some(json!({"passkey_id": req.id})),
            )
            .await;
            Json(json!({"ok": true})).into_response()
        }
        Ok(false) => error(StatusCode::NOT_FOUND, "Passkey not found"),
        Err(err) if err.to_string().contains("last sign-in method") => error(
            StatusCode::CONFLICT,
            "Cannot remove your last sign-in method",
        ),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not remove passkey",
        ),
    }
}
