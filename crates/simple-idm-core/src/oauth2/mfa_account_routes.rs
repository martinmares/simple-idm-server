//! Self-service TOTP enrollment for locally managed accounts.
use super::authorization_code::{
    build_csrf_cookie, cookie_value, get_auth_session_from_cookie, request_is_https,
};
use super::client_credentials::OAuth2State;
use crate::audit;
use crate::db::models::{AuthenticationSession, User};
use crate::mfa;
use crate::secret_crypto;
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use chrono::{Duration, Utc};
use qrcode::{QrCode, render::svg};
use rand::RngExt;
use serde::Deserialize;
use serde_json::json;
use simple_idm_common::{escape_html, tabler_standalone_page};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

const FRESH_SESSION_MINUTES: i64 = 5;

#[derive(Deserialize)]
pub struct EnrollmentForm {
    csrf_token: String,
    code: Option<String>,
}

fn page(title: &str, body: &str) -> Response {
    let html = tabler_standalone_page(
        title,
        "Simple IDM",
        title,
        "Manage two-factor authentication for your local account.",
        body,
        "Protected by Simple IDM",
        "",
    );
    no_store(Html(html).into_response())
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn failure(status: StatusCode, message: &str) -> Response {
    let body = format!(
        "<div class=\"alert alert-danger\" role=\"alert\">{}</div><a class=\"btn btn-outline-secondary w-100\" href=\"/account/mfa\">Back to two-factor settings</a>",
        escape_html(message)
    );
    let mut response = page("Two-factor authentication", &body);
    *response.status_mut() = status;
    response
}

async fn local_session(
    state: &OAuth2State,
    headers: &HeaderMap,
    fresh: bool,
) -> Result<(AuthenticationSession, User), Box<Response>> {
    let session = get_auth_session_from_cookie(&state.db_pool, headers)
        .await
        .ok_or_else(|| {
            Box::new(failure(
                StatusCode::UNAUTHORIZED,
                "Sign in to manage two-factor authentication.",
            ))
        })?;
    if fresh && Utc::now() - session.created_at > Duration::minutes(FRESH_SESSION_MINUTES) {
        return Err(Box::new(failure(
            StatusCode::FORBIDDEN,
            "Your sign-in is older than five minutes. Sign out and sign in again to change two-factor authentication.",
        )));
    }
    let user = sqlx::query_as::<_, User>(
        "SELECT u.* FROM users u JOIN tenants t ON t.id = u.tenant_id JOIN effective_user_auth_policies p ON p.user_id = u.id WHERE u.id = $1 AND u.is_active = true AND u.deleted_at IS NULL AND u.auth_mode = 'local' AND t.is_active = true AND p.mfa_policy IN ('optional', 'required')",
    )
    .bind(session.user_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|_| Box::new(failure(StatusCode::INTERNAL_SERVER_ERROR, "Could not load your account.")))?
    .ok_or_else(|| Box::new(failure(StatusCode::FORBIDDEN, "Two-factor setup is not available for this account.")))?;
    Ok((session, user))
}

fn valid_post(state: &OAuth2State, headers: &HeaderMap, csrf: &str) -> bool {
    let Some(cookie) = cookie_value(headers, "csrf_token") else {
        return false;
    };
    if cookie.is_empty() || cookie != csrf {
        return false;
    }
    let secure = state.force_secure_cookies || request_is_https(headers, state.trust_proxy_headers);
    same_origin(headers, secure)
}

fn same_origin(headers: &HeaderMap, secure: bool) -> bool {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let scheme = if secure { "https" } else { "http" };
    matches!((Url::parse(origin), Url::parse(&format!("{scheme}://{host}"))),
        (Ok(origin), Ok(expected)) if origin.origin() == expected.origin())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_enrollment_requires_exact_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("sso.example.com"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://sso.example.com"),
        );
        assert!(same_origin(&headers, true));
        assert!(!same_origin(&headers, false));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://other.example.com"),
        );
        assert!(!same_origin(&headers, true));
    }
}

pub async fn settings(State(state): State<Arc<OAuth2State>>, headers: HeaderMap) -> Response {
    let (session, user) = match local_session(&state, &headers, false).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let active = match mfa::active_totp_authenticator(&state.db_pool, user.id).await {
        Ok(value) => value.is_some(),
        Err(_) => {
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not load authenticator status.",
            );
        }
    };
    let fresh = Utc::now() - session.created_at <= Duration::minutes(FRESH_SESSION_MINUTES);
    let csrf: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(48)
        .map(char::from)
        .collect();
    let controls = if active {
        "<div class=\"alert alert-success\">Authenticator app is active. Password sign-in requires a current code or a recovery code.</div>".to_string()
    } else if !fresh {
        "<div class=\"alert alert-warning\">Sign out and sign in again to set up an authenticator app. Your current session is older than five minutes.</div>".to_string()
    } else if secret_crypto::validate_master_key().is_err() {
        "<div class=\"alert alert-danger\">Authenticator setup is unavailable because the server encryption key is missing or invalid. Ask your administrator to configure IDP_SECRETS_MASTER_KEY.</div>".to_string()
    } else {
        format!(
            "<p>Set up an authenticator app for your account. This does not change the policy for other users.</p><form method=\"post\" action=\"/account/mfa/start\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button class=\"btn btn-primary w-100\" type=\"submit\">Set up authenticator app</button></form>",
            escape_html(&csrf)
        )
    };
    let passkeys_allowed = state.passkeys.is_some()
        && crate::auth_policy::for_user(&state.db_pool, user.id)
            .await
            .is_ok_and(|policy| policy.passkey_policy == "allowed");
    let back_link = if passkeys_allowed {
        "<a class=\"btn btn-outline-secondary w-100 mt-3\" href=\"/account/security\">Back to account security</a>"
    } else {
        "<a class=\"btn btn-outline-secondary w-100 mt-3\" href=\"/oauth2/logout\">Sign out</a>"
    };
    let body = format!(
        "<p>Signed in as <strong>{}</strong>.</p>{controls}{back_link}",
        escape_html(&user.email)
    );
    let mut response = page("Two-factor authentication", &body);
    let secure =
        state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
    if let Ok(cookie) = build_csrf_cookie(&csrf, secure).parse() {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

async fn setup_page(
    state: &OAuth2State,
    session: &AuthenticationSession,
    user: &User,
    csrf: &str,
    error: Option<&str>,
) -> Result<Response, anyhow::Error> {
    let enrollment = mfa::ensure_pending_totp(
        &state.db_pool,
        user.tenant_id,
        user.id,
        &user.email,
        "Simple IDM",
    )
    .await?;
    sqlx::query("DELETE FROM mfa_self_enrollments WHERE expires_at <= NOW()")
        .execute(&state.db_pool)
        .await?;
    let expires_at = session.created_at + Duration::minutes(FRESH_SESSION_MINUTES);
    sqlx::query(
        "INSERT INTO mfa_self_enrollments (session_id, authenticator_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT (session_id) DO NOTHING",
    )
    .bind(session.id)
    .bind(enrollment.authenticator_id)
    .bind(expires_at)
    .execute(&state.db_pool)
    .await?;
    let saved = sqlx::query_as::<_, (Uuid, i32)>(
        "SELECT authenticator_id, attempts FROM mfa_self_enrollments WHERE session_id = $1 AND expires_at > NOW()",
    )
    .bind(session.id)
    .fetch_one(&state.db_pool)
    .await?;
    if saved.0 != enrollment.authenticator_id || saved.1 >= mfa::MAX_MFA_ATTEMPTS {
        anyhow::bail!("TOTP self-enrollment is no longer available");
    }
    let qr = QrCode::new(enrollment.otpauth_url.as_bytes())?
        .render::<svg::Color>()
        .min_dimensions(220, 220)
        .build();
    let error = error.map_or_else(String::new, |message| {
        format!(
            "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
            escape_html(message)
        )
    });
    let body = format!(
        r#"{error}<p>Scan this code with your authenticator app, then enter its current six-digit code.</p>
<div class="text-center bg-white rounded p-3 mb-3">{qr}</div>
<p class="small text-secondary">If scanning is unavailable, enter this setup key manually: <code>{secret}</code></p>
<form method="post" action="/account/mfa/confirm">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <label class="form-label" for="code">Verification code</label>
  <input class="form-control mb-3" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{6}}" maxlength="6" required>
  <button class="btn btn-primary w-100" type="submit">Enable two-factor authentication</button>
</form>"#,
        secret = escape_html(&enrollment.base32_secret),
        csrf = escape_html(csrf),
    );
    Ok(page("Set up authenticator app", &body))
}

pub async fn start(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Form(form): Form<EnrollmentForm>,
) -> Response {
    if !valid_post(&state, &headers, &form.csrf_token) {
        return failure(
            StatusCode::FORBIDDEN,
            "Invalid request origin or CSRF token.",
        );
    }
    let (session, user) = match local_session(&state, &headers, true).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    match mfa::active_totp_authenticator(&state.db_pool, user.id).await {
        Ok(None) => {}
        Ok(Some(_)) => {
            return failure(
                StatusCode::CONFLICT,
                "An authenticator app is already active.",
            );
        }
        Err(_) => {
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not check authenticator status.",
            );
        }
    }
    match setup_page(&state, &session, &user, &form.csrf_token, None).await {
        Ok(response) => response,
        Err(err) => {
            tracing::warn!(user_id = %user.id, "Could not start TOTP self-enrollment: {err}");
            failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not start authenticator setup. Contact your administrator if this persists.",
            )
        }
    }
}

pub async fn confirm(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Form(form): Form<EnrollmentForm>,
) -> Response {
    if !valid_post(&state, &headers, &form.csrf_token) {
        return failure(
            StatusCode::FORBIDDEN,
            "Invalid request origin or CSRF token.",
        );
    }
    let (session, user) = match local_session(&state, &headers, true).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let code = form.code.as_deref().unwrap_or("").trim();
    let row = sqlx::query_as::<_, (Uuid, i32)>(
        "UPDATE mfa_self_enrollments SET attempts = attempts + 1 WHERE session_id = $1 AND expires_at > NOW() AND attempts < $2 RETURNING authenticator_id, attempts",
    )
    .bind(session.id)
    .bind(mfa::MAX_MFA_ATTEMPTS)
    .fetch_optional(&state.db_pool)
    .await;
    let (authenticator_id, attempts) = match row {
        Ok(Some(value)) => value,
        Ok(None) => {
            return failure(
                StatusCode::BAD_REQUEST,
                "This setup has expired or too many codes were entered. Sign in again.",
            );
        }
        Err(_) => {
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not verify the setup code.",
            );
        }
    };
    let authenticator = match mfa::pending_totp_authenticator(&state.db_pool, user.id).await {
        Ok(Some(value)) if value.id == authenticator_id => value,
        _ => {
            return failure(
                StatusCode::BAD_REQUEST,
                "Authenticator setup is no longer pending.",
            );
        }
    };
    let valid = if code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()) {
        mfa::verify_totp(&state.db_pool, &authenticator, code).await
    } else {
        Ok(false)
    };
    match valid {
        Ok(false) => {
            if attempts >= mfa::MAX_MFA_ATTEMPTS {
                return failure(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many invalid codes. Sign out and sign in again before retrying setup.",
                );
            }
            return match setup_page(
                &state,
                &session,
                &user,
                &form.csrf_token,
                Some("Invalid code. Try the current code from your authenticator app."),
            )
            .await
            {
                Ok(response) => response,
                Err(_) => failure(
                    StatusCode::BAD_REQUEST,
                    "Invalid code. Return to two-factor settings to try again.",
                ),
            };
        }
        Err(err) => {
            tracing::warn!(user_id = %user.id, "TOTP self-enrollment verification failed: {err}");
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not verify the setup code.",
            );
        }
        Ok(true) => {}
    }
    let codes = match mfa::activate_totp_and_generate_recovery_codes(&state.db_pool, &authenticator)
        .await
    {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(user_id = %user.id, "Could not activate TOTP self-enrollment: {err}");
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not enable two-factor authentication.",
            );
        }
    };
    let _ = sqlx::query("DELETE FROM mfa_self_enrollments WHERE session_id = $1")
        .bind(session.id)
        .execute(&state.db_pool)
        .await;
    audit::emit_event(
        &state.db_pool,
        "auth.mfa.enroll",
        "user",
        Some(user.id),
        "success",
        Some(json!({"method": "self_service"})),
    )
    .await;
    let codes = codes
        .iter()
        .map(|code| format!("<li><code>{}</code></li>", escape_html(code)))
        .collect::<String>();
    let body = format!(
        "<div class=\"alert alert-success\">Two-factor authentication is enabled.</div><p>Save these one-time recovery codes now. They will not be shown again.</p><ul class=\"list-unstyled font-monospace\">{codes}</ul><a class=\"btn btn-primary w-100\" href=\"/account/mfa\">Done</a>"
    );
    page("Save your recovery codes", &body)
}
