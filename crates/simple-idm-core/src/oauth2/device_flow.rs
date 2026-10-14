use crate::auth::claims::user_authorization_claims;
use crate::db::models::{DeviceCode, OAuthClient, User};
use axum::{
    Form, Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use chrono::{Duration, Utc};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sqlx;
use std::sync::Arc;
use uuid::Uuid;

use super::client_credentials::{ErrorResponse, OAuth2State};
use super::templates;
use super::utils::{ClientLookupError, resolve_oauth_client};

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationRequest {
    pub client_id: String,
    pub tenant: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: i64,
    pub interval: i64, // doporučený polling interval v sekundách
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DeviceTokenRequest {
    pub client_secret: Option<String>,
    pub grant_type: String,
    pub device_code: String,
    pub client_id: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceVerifyRequest {
    pub user_code: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct DevicePageQuery {
    pub user_code: Option<String>,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct DeviceVerifyResponse {
    pub success: bool,
    pub message: String,
}

/// Generuje náhodný user code podle konfigurace
fn generate_user_code(length: usize, format: &str) -> String {
    let chars: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .filter(|c: &u8| c.is_ascii_uppercase() || c.is_ascii_digit())
        .take(length)
        .map(char::from)
        .collect();

    // Formátuj podle pattern (např. "XXXX-XXXX" -> "ABCD-1234")
    if format.contains('-') && length == 8 {
        format!("{}-{}", &chars[..4], &chars[4..])
    } else {
        chars
    }
}

pub(crate) const DEVICE_LOGIN_PREFIX: &str = "urn:simple-idm:device:";

pub(crate) fn device_login_code(destination: &str) -> Option<&str> {
    destination
        .strip_prefix(DEVICE_LOGIN_PREFIX)
        .filter(|code| {
            !code.is_empty()
                && code.len() <= 64
                && code
                    .bytes()
                    .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == b'-')
        })
}

pub(crate) fn device_confirmation_url(code: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("user_code", code)
        .finish();
    format!("/device?{query}")
}

pub(crate) async fn pending_device_client(
    pool: &sqlx::PgPool,
    code: &str,
) -> Result<OAuthClient, String> {
    sqlx::query_as::<_, OAuthClient>(
        "SELECT oc.* FROM device_codes dc JOIN oauth_clients oc ON oc.id = dc.client_id          JOIN tenants t ON t.id = oc.tenant_id          WHERE dc.user_code = $1 AND dc.expires_at > NOW() AND NOT dc.is_authorized          AND oc.is_active AND oc.deleted_at IS NULL AND t.is_active AND t.deleted_at IS NULL          AND 'urn:ietf:params:oauth:grant-type:device_code' = ANY(oc.grant_types)",
    ).bind(code).fetch_optional(pool).await
        .map_err(|err| { tracing::error!("Could not load device request: {err}"); "Could not load device request".to_string() })?
        .ok_or_else(|| "Device code is invalid, expired or already used".into())
}

pub(crate) async fn device_user_allowed(
    state: &OAuth2State,
    client_id: Uuid,
    user_id: Uuid,
) -> Result<bool, String> {
    let email = sqlx::query_scalar::<_, String>(
        "SELECT u.email FROM users u JOIN oauth_clients oc ON oc.tenant_id = u.tenant_id          WHERE u.id = $1 AND oc.id = $2 AND u.is_active AND u.deleted_at IS NULL",
    ).bind(user_id).bind(client_id).fetch_optional(&state.db_pool).await
        .map_err(|err| format!("Could not validate device account: {err}"))?;
    Ok(email.is_some_and(|email| {
        state.allowed_email_domains.is_empty()
            || email.rsplit_once('@').is_some_and(|(_, domain)| {
                state
                    .allowed_email_domains
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(domain))
            })
    }))
}

/// Device approval shares the normal browser login, including SSO, Passkeys and MFA.
/// GET never grants access: an authenticated user must explicitly approve by POST.
pub async fn show_device_form(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Query(query): Query<DevicePageQuery>,
) -> Response {
    use super::authorization_code::{
        build_csrf_cookie, get_auth_session_from_cookie, request_is_https,
    };
    let Some(code) = query.user_code.filter(|code| !code.trim().is_empty()) else {
        return Html(templates::device_code_page()).into_response();
    };
    let code = code.trim().to_ascii_uppercase();
    let client = match pending_device_client(&state.db_pool, &code).await {
        Ok(client) => client,
        Err(err) => return device_error(StatusCode::BAD_REQUEST, &err),
    };
    let Some(session) = get_auth_session_from_cookie(&state.db_pool, &headers).await else {
        let tenant = match sqlx::query_scalar::<_, String>(
            "SELECT t.slug FROM tenants t JOIN oauth_clients oc ON oc.tenant_id = t.id WHERE oc.id = $1",
        ).bind(client.id).fetch_one(&state.db_pool).await {
            Ok(tenant) => tenant,
            Err(_) => return device_error(StatusCode::INTERNAL_SERVER_ERROR, "Could not prepare sign-in"),
        };
        let params = std::collections::HashMap::from([
            ("response_type".into(), "code".into()),
            ("client_id".into(), client.client_id),
            ("tenant".into(), tenant),
            (
                "redirect_uri".into(),
                format!("{DEVICE_LOGIN_PREFIX}{code}"),
            ),
        ]);
        return super::authorization_code::handle_authorize(State(state), headers, Query(params))
            .await
            .into_response();
    };
    match device_user_allowed(&state, client.id, session.user_id).await {
        Ok(true) => {}
        Ok(false) => {
            return device_error(
                StatusCode::FORBIDDEN,
                "This account cannot authorize this device application. Sign out and use an account in the application's tenant.",
            );
        }
        Err(err) => return device_error(StatusCode::INTERNAL_SERVER_ERROR, &err),
    }
    let username = match sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE id = $1")
        .bind(session.user_id)
        .fetch_one(&state.db_pool)
        .await
    {
        Ok(name) => name,
        Err(_) => {
            return device_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not load signed-in account",
            );
        }
    };
    let csrf: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let secure =
        state.force_secure_cookies || request_is_https(&headers, state.trust_proxy_headers);
    let mut response = Html(templates::device_approval_page(
        &code,
        &client.name,
        &username,
        &csrf,
    ))
    .into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        build_csrf_cookie(&csrf, secure).parse().unwrap(),
    );
    response
}

fn device_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Html(templates::error_page("device_authorization", message)),
    )
        .into_response()
}

/// Endpoint pro iniciaci device flow
/// Klient (TV) volá tento endpoint a dostane device_code a user_code
pub async fn handle_device_authorization(
    State(state): State<Arc<OAuth2State>>,
    Form(req): Form<DeviceAuthorizationRequest>,
) -> impl IntoResponse {
    // Ověř klienta
    let client =
        match resolve_oauth_client(&state.db_pool, &req.client_id, req.tenant.as_deref()).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                return Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Client not found or inactive".to_string(),
                })
                .into_response();
            }
            Err(ClientLookupError::AmbiguousClientId) => {
                return Json(ErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: "Ambiguous client_id. Provide tenant hint.".to_string(),
                })
                .into_response();
            }
            Err(ClientLookupError::InvalidTenantHint) => {
                return Json(ErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: "Invalid tenant hint".to_string(),
                })
                .into_response();
            }
            Err(ClientLookupError::Database) => {
                return Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Database error".to_string(),
                })
                .into_response();
            }
        };

    // Zkontroluj, že klient podporuje device_code flow
    if !client
        .grant_types
        .contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string())
    {
        return Json(ErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized for device flow".to_string(),
        })
        .into_response();
    }

    // Vygeneruj device_code a user_code
    let device_code: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let user_code = generate_user_code(
        state.device_flow_config.user_code_length,
        &state.device_flow_config.user_code_format,
    );
    let expires_at = Utc::now() + Duration::seconds(state.device_flow_config.expiry_seconds);
    let scope = req.scope.unwrap_or_else(|| client.scope.clone());
    if !super::utils::scope_allowed(&client.scope, &scope) {
        return Json(ErrorResponse {
            error: "invalid_scope".into(),
            error_description: "Requested scope is not registered for this client".into(),
        })
        .into_response();
    }

    // Ulož do databáze
    if sqlx::query(
        r#"
        INSERT INTO device_codes
        (device_code, user_code, client_id, scope, expires_at, is_authorized)
        VALUES ($1, $2, $3, $4, $5, false)
        "#,
    )
    .bind(&device_code)
    .bind(&user_code)
    .bind(client.id)
    .bind(&scope)
    .bind(expires_at)
    .execute(&state.db_pool)
    .await
    .is_err()
    {
        return Json(ErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to create device code".to_string(),
        })
        .into_response();
    }

    // V produkci by issuer byl z konfigurace
    let verification_uri = format!("{}/device", state.jwt_service.issuer);
    let verification_uri_complete = format!("{}?user_code={}", verification_uri, user_code);

    Json(DeviceAuthorizationResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete: Some(verification_uri_complete),
        expires_in: state.device_flow_config.expiry_seconds,
        interval: state.device_flow_config.polling_interval_seconds,
    })
    .into_response()
}

/// Approve only with a policy-valid browser session and CSRF token.
pub async fn handle_device_verify(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Form(req): Form<DeviceVerifyRequest>,
) -> Response {
    use super::authorization_code::{cookie_value, get_auth_session_from_cookie};
    if req.csrf_token.is_empty()
        || cookie_value(&headers, "csrf_token").as_deref() != Some(&req.csrf_token)
    {
        return device_error(
            StatusCode::FORBIDDEN,
            "Invalid approval request. Reload the device page and try again.",
        );
    }
    let Some(session) = get_auth_session_from_cookie(&state.db_pool, &headers).await else {
        return device_error(
            StatusCode::UNAUTHORIZED,
            "Your sign-in has expired. Reopen the device link to sign in again.",
        );
    };
    let code = req.user_code.trim().to_ascii_uppercase();
    let client = match pending_device_client(&state.db_pool, &code).await {
        Ok(client) => client,
        Err(err) => return device_error(StatusCode::BAD_REQUEST, &err),
    };
    match device_user_allowed(&state, client.id, session.user_id).await {
        Ok(true) => {}
        Ok(false) => {
            return device_error(
                StatusCode::FORBIDDEN,
                "This account cannot authorize this device application",
            );
        }
        Err(err) => return device_error(StatusCode::INTERNAL_SERVER_ERROR, &err),
    }
    let result = sqlx::query(
        "UPDATE device_codes SET is_authorized = true, user_id = $1, amr = $3, acr = $4          WHERE user_code = $2 AND expires_at > NOW() AND NOT is_authorized",
    ).bind(session.user_id).bind(&code).bind(&session.amr).bind(&session.acr)
        .execute(&state.db_pool).await;
    match result {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            return device_error(
                StatusCode::BAD_REQUEST,
                "Device code is expired or already used",
            );
        }
        Err(err) => {
            tracing::error!("Device approval failed: {err}");
            return device_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not authorize device",
            );
        }
    }
    crate::audit::emit_event_as(
        &state.db_pool,
        &crate::audit::Actor {
            subject: Some(session.user_id.to_string()),
            client_id: Some(client.client_id.clone()),
            root_token: false,
        },
        "auth.device.approve",
        "oauth_client",
        Some(client.id),
        "success",
        Some(serde_json::json!({"user_id":session.user_id, "amr":session.amr})),
    )
    .await;
    Html(templates::device_verify_page(
        None,
        None,
        Some("Device authorized successfully! You can now return to your device."),
    ))
    .into_response()
}

/// Interní implementace device token exchange - volaná z handle_token routeru
pub async fn handle_device_token_internal(
    state: Arc<OAuth2State>,
    req: DeviceTokenRequest,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    if req.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
        tracing::warn!("Unsupported grant_type: {}", req.grant_type);
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "unsupported_grant_type".to_string(),
                error_description: "Only device_code grant type is supported".to_string(),
            }),
        )
            .into_response();
    }

    // Načti device code
    let device_code =
        match sqlx::query_as::<_, DeviceCode>("SELECT * FROM device_codes WHERE device_code = $1")
            .bind(&req.device_code)
            .fetch_optional(&state.db_pool)
            .await
        {
            Ok(Some(dc)) => dc,
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_grant".to_string(),
                        error_description: "Invalid device code".to_string(),
                    }),
                )
                    .into_response();
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        error_description: "Database error".to_string(),
                    }),
                )
                    .into_response();
            }
        };

    // Zkontroluj expiraci
    if device_code.expires_at < Utc::now() {
        let _ = sqlx::query("DELETE FROM device_codes WHERE device_code = $1")
            .bind(&req.device_code)
            .execute(&state.db_pool)
            .await;

        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "expired_token".to_string(),
                error_description: "Device code expired".to_string(),
            }),
        )
            .into_response();
    }

    // Zkontroluj, jestli je autorizovaný
    if !device_code.is_authorized {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "authorization_pending".to_string(),
                error_description: "User has not authorized the device yet".to_string(),
            }),
        )
            .into_response();
    }

    tracing::info!(
        "Device code authorized, exchanging for tokens: user_id={:?}",
        device_code.user_id
    );

    // Musí existovat user_id, pokud je autorizovaný
    let user_id = match device_code.user_id {
        Some(id) => id,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Device authorized but no user_id".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Načti klienta
    let client = match sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients WHERE id = $1 AND is_active = true AND deleted_at IS NULL",
    )
    .bind(device_code.client_id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Client not found".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Database error".to_string(),
                }),
            )
                .into_response();
        }
    };

    let credentials_valid = match (
        req.client_secret.as_deref(),
        client.client_secret_hash.as_deref(),
    ) {
        (Some(secret), Some(hash)) => crate::auth::verify_password_async(secret, hash)
            .await
            .unwrap_or(false),
        _ => false,
    };
    if req.client_id != client.client_id || (!client.is_public && !credentials_valid) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_client".into(),
                error_description: "Invalid device client credentials".into(),
            }),
        )
            .into_response();
    }
    if !client
        .grant_types
        .iter()
        .any(|grant| grant == "urn:ietf:params:oauth:grant-type:device_code")
        || !super::utils::scope_allowed(&client.scope, &device_code.scope)
        || !super::utils::user_client_allowed(&state.db_pool, client.id, user_id)
            .await
            .unwrap_or(false)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_grant".into(),
                error_description: "Device authorization no longer allowed".into(),
            }),
        )
            .into_response();
    }
    // Načti uživatele
    let user =
        match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL")
            .bind(user_id)
            .fetch_optional(&state.db_pool)
            .await
        {
            Ok(Some(user)) => user,
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_grant".to_string(),
                        error_description: "User not found".to_string(),
                    }),
                )
                    .into_response();
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        error_description: "Database error".to_string(),
                    }),
                )
                    .into_response();
            }
        };

    if !crate::auth_policy::accepts_authentication(&state.db_pool, &user, &device_code.amr)
        .await
        .unwrap_or(false)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_grant".into(),
                error_description: "Account or authentication policy changed; sign in again".into(),
            }),
        )
            .into_response();
    }

    macro_rules! authorization_data {
        ($value:expr) => {
            match $value {
                Ok(value) => value,
                Err(_) => {
                    return Json(ErrorResponse {
                        error: "server_error".into(),
                        error_description: "Failed to load authorization data".into(),
                    })
                    .into_response()
                }
            }
        };
    }
    let (filtered_group_names, mut custom_claims) =
        authorization_data!(user_authorization_claims(&state.db_pool, user.id, &client).await);

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
        "Issuing JWT token (device flow)"
    );

    // Vytvoř access token
    let access_token = match state.jwt_service.create_access_token(
        user.id,
        client.client_id.clone(),
        Some(user.email.clone()),
        Some(user.username.clone()),
        Some(device_code.scope.clone()),
        filtered_group_names.clone(),
        custom_claims.clone(),
        device_code.amr.clone(),
        device_code.acr.clone(),
        state.access_token_expiry,
    ) {
        Ok(token) => token,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to create access token".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Vytvoř ID token (pokud scope obsahuje "openid")
    let id_token = if device_code
        .scope
        .split_whitespace()
        .any(|scope| scope == "openid")
    {
        match state.jwt_service.create_id_token(
            user.id,
            client.client_id.clone(),
            Some(user.email.clone()),
            Some(user.username.clone()),
            filtered_group_names,
            custom_claims,
            None, // device flow nemá nonce
            device_code.amr.clone(),
            device_code.acr.clone(),
            state.access_token_expiry,
        ) {
            Ok(token) => Some(token),
            Err(e) => {
                tracing::error!("Failed to create ID token for device flow: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        error_description: "Failed to create ID token".to_string(),
                    }),
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_grant".into(),
                error_description: "Account no longer active".into(),
            }),
        )
            .into_response();
    }
    match sqlx::query(
        "DELETE FROM device_codes WHERE device_code = $1 AND expires_at > NOW() AND is_authorized",
    )
    .bind(&req.device_code)
    .execute(&mut *tx)
    .await
    {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_grant".into(),
                    error_description: "Device code is no longer valid".into(),
                }),
            )
                .into_response();
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    if tx.commit().await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    Json(DeviceTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.access_token_expiry,
        id_token,
        scope: Some(device_code.scope),
    })
    .into_response()
}

/// Axum endpoint wrapper pro device token (pro přímé volání /oauth2/device/token)
/// DEPRECATED: Mělo by se volat přes /oauth2/token s grant_type=urn:ietf:params:oauth:grant-type:device_code
pub async fn handle_device_token(
    State(state): State<Arc<OAuth2State>>,
    Form(req): Form<DeviceTokenRequest>,
) -> axum::response::Response {
    handle_device_token_internal(state, req).await
}

#[cfg(test)]
mod browser_tests {
    use super::super::authorization_code::{
        LoginRequest, PendingAuthorization, complete_user_authorization, handle_login,
        is_login_destination_allowed,
    };
    use super::*;
    use axum::http::header::{COOKIE, SET_COOKIE};

    #[test]
    fn internal_destination_and_pages() {
        assert_eq!(
            device_login_code("urn:simple-idm:device:ABCD-1234"),
            Some("ABCD-1234")
        );
        for bad in [
            "urn:simple-idm:device:",
            "urn:simple-idm:device:abcd",
            "urn:simple-idm:device:ABCD?evil",
            "https://evil.test/device",
        ] {
            assert!(device_login_code(bad).is_none());
        }
        assert!(!templates::device_code_page().contains("name=\"password\""));
        let page =
            templates::device_approval_page("ABCD-1234", "<script>app</script>", "<user>", "csrf");
        assert!(page.contains("&lt;script&gt;app&lt;/script&gt;"));
        assert!(page.contains("&lt;user&gt;"));
        assert!(page.contains("name=\"csrf_token\""));
        assert!(!page.contains("name=\"password\""));
        let success = templates::device_verify_page(None, None, Some("Authorized"));
        assert!(!success.contains("<form"));
    }

    async fn body(response: Response) -> String {
        String::from_utf8(
            axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }
    fn cookies(session: &str, csrf: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("auth_session={session}; csrf_token={csrf}")
                .parse()
                .unwrap(),
        );
        headers
    }
    fn pending(user: Uuid, client: Uuid, code: &str) -> PendingAuthorization {
        PendingAuthorization {
            credential_version: 0,
            user_id: user,
            client_id: client,
            redirect_uri: format!("{DEVICE_LOGIN_PREFIX}{code}"),
            scope: "openid".into(),
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
        }
    }

    #[tokio::test]
    #[ignore = "requires disposable DEVICE_SSO_TEST_DATABASE_URL"]
    async fn postgres_browser_device_approval() {
        use rsa::{
            RsaPrivateKey, RsaPublicKey,
            pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
            rand_core::OsRng,
        };
        let pool = sqlx::PgPool::connect(&std::env::var("DEVICE_SSO_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let migrations = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        sqlx::migrate::Migrator::new(migrations)
            .await
            .unwrap()
            .run(&pool)
            .await
            .unwrap();
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
                .unwrap(),
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
            passkeys: Some(Arc::new(
                crate::passkeys::PasskeyService::new(&crate::config::WebauthnConfig {
                    rp_id: "idm.test".into(),
                    rp_name: "Test".into(),
                    origins: vec!["https://idm.test".into()],
                })
                .unwrap(),
            )),
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
        let user = Uuid::new_v4();
        let client = Uuid::new_v4();
        let suffix = user.simple().to_string();
        let username = format!("device-{suffix}");
        let client_name = format!("app-{suffix}");
        let password = crate::auth::hash_password("device-test-password").unwrap();
        sqlx::query("INSERT INTO users (id, username, email, password_hash) VALUES ($1,$2,$3,$4)")
            .bind(user)
            .bind(&username)
            .bind(format!("{suffix}@example.test"))
            .bind(password)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO oauth_clients (id,client_id,name,redirect_uris,grant_types,is_public) VALUES ($1,$2,'Device test','{}',ARRAY['urn:ietf:params:oauth:grant-type:device_code'],true)")
            .bind(client).bind(&client_name).execute(&pool).await.unwrap();
        sqlx::query("UPDATE tenants SET mfa_policy='disabled', passkey_policy='allowed' WHERE slug='default'").execute(&pool).await.unwrap();
        let unique_code = format!("{}-1234", suffix[..4].to_ascii_uppercase());
        let code = unique_code.as_str();
        sqlx::query("INSERT INTO device_codes (device_code,user_code,client_id,scope,expires_at,is_authorized) VALUES ($1,$2,$3,'openid',NOW()+INTERVAL '10 minutes',false)")
            .bind(&suffix).bind(code).bind(client).execute(&pool).await.unwrap();
        let oauth_client = pending_device_client(&pool, code).await.unwrap();
        assert!(
            is_login_destination_allowed(
                &pool,
                &oauth_client,
                &format!("{DEVICE_LOGIN_PREFIX}{code}")
            )
            .await
        );
        assert!(!is_login_destination_allowed(&pool, &oauth_client, "https://evil.test").await);
        let mut other_client = oauth_client.clone();
        other_client.id = Uuid::new_v4();
        assert!(
            !is_login_destination_allowed(
                &pool,
                &other_client,
                &format!("{DEVICE_LOGIN_PREFIX}{code}")
            )
            .await
        );
        sqlx::query("UPDATE oauth_clients SET is_active=false WHERE id=$1")
            .bind(client)
            .execute(&pool)
            .await
            .unwrap();
        assert!(pending_device_client(&pool, code).await.is_err());
        sqlx::query("UPDATE oauth_clients SET is_active=true WHERE id=$1")
            .bind(client)
            .execute(&pool)
            .await
            .unwrap();

        let response = show_device_form(
            State(state.clone()),
            HeaderMap::new(),
            Query(DevicePageQuery {
                user_code: Some(code.into()),
            }),
        )
        .await;
        let csrf_cookie = response.headers()[SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let csrf = csrf_cookie.strip_prefix("csrf_token=").unwrap().to_string();
        let page = body(response).await;
        assert!(page.contains("/oauth2/login"));
        assert!(page.contains("passkey"));
        assert!(page.contains(&format!("{DEVICE_LOGIN_PREFIX}{code}")));
        // No session and wrong CSRF must never approve.
        let response = handle_device_verify(
            State(state.clone()),
            cookies("invalid", &csrf),
            Form(DeviceVerifyRequest {
                user_code: code.into(),
                csrf_token: csrf.clone(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // Normal password login now completes into a browser session, not an OAuth code.
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, csrf_cookie.parse().unwrap());
        let response = handle_login(
            State(state.clone()),
            headers,
            Form(LoginRequest {
                username: username.clone(),
                password: "device-test-password".into(),
                client_id: client_name.clone(),
                tenant: Some("default".into()),
                redirect_uri: format!("{DEVICE_LOGIN_PREFIX}{code}"),
                scope: None,
                state: None,
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
                csrf_token: Some(csrf.clone()),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[axum::http::header::LOCATION],
            device_confirmation_url(code)
        );
        let session: String = sqlx::query_scalar("SELECT session_token FROM authentication_sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1").bind(user).fetch_one(&pool).await.unwrap();
        let unapproved: bool =
            sqlx::query_scalar("SELECT NOT is_authorized FROM device_codes WHERE user_code=$1")
                .bind(code)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(unapproved);
        let response = show_device_form(
            State(state.clone()),
            cookies(&session, &csrf),
            Query(DevicePageQuery {
                user_code: Some(code.into()),
            }),
        )
        .await;
        let approval_csrf = response.headers()[SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("csrf_token=")
            .unwrap()
            .to_string();
        let page = body(response).await;
        assert!(page.contains(&username));
        assert!(page.contains("Authorize device"));
        assert!(!page.contains("name=\"password\""));
        assert_eq!(
            handle_device_verify(
                State(state.clone()),
                cookies(&session, &approval_csrf),
                Form(DeviceVerifyRequest {
                    user_code: code.into(),
                    csrf_token: "wrong".into()
                })
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        // A newly required MFA policy invalidates password-only SSO for device approval.
        sqlx::query("UPDATE tenants SET mfa_policy='required' WHERE slug='default'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            handle_device_verify(
                State(state.clone()),
                cookies(&session, &approval_csrf),
                Form(DeviceVerifyRequest {
                    user_code: code.into(),
                    csrf_token: approval_csrf.clone()
                })
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        // The same password login now enters the normal MFA challenge, not device approval.
        sqlx::query("INSERT INTO user_authenticators (tenant_id,user_id,kind,secret_encrypted,status) VALUES ('11111111-1111-1111-1111-111111111111',$1,'totp','not-used-by-this-challenge-test','active')")
            .bind(user).execute(&pool).await.unwrap();
        let response = handle_login(
            State(state.clone()),
            cookies("invalid", &csrf),
            Form(LoginRequest {
                username: username.clone(),
                password: "device-test-password".into(),
                client_id: client_name,
                tenant: Some("default".into()),
                redirect_uri: format!("{DEVICE_LOGIN_PREFIX}{code}"),
                scope: None,
                state: None,
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
                csrf_token: Some(csrf),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[axum::http::header::LOCATION],
            "/oauth2/mfa"
        );
        let challenge_destination: String = sqlx::query_scalar("SELECT redirect_uri FROM mfa_login_transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1")
            .bind(user).fetch_one(&pool).await.unwrap();
        assert_eq!(
            challenge_destination,
            format!("{DEVICE_LOGIN_PREFIX}{code}")
        );
        // Passkey completion uses the same destination and preserves WebAuthn AMR/ACR.
        let completion = complete_user_authorization(
            &state,
            pending(user, client, code),
            vec!["webauthn".into()],
            Some("urn:simple-idm:acr:phishing-resistant".into()),
        )
        .await
        .unwrap();
        let passkey_session = completion.session_token.unwrap();
        let authorization_codes: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM authorization_codes WHERE client_id=$1")
                .bind(client)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            authorization_codes, 0,
            "Device sign-in must not issue OAuth callback codes"
        );

        assert_eq!(completion.redirect_url, device_confirmation_url(code));
        assert_eq!(
            handle_device_verify(
                State(state.clone()),
                cookies(&passkey_session, &approval_csrf),
                Form(DeviceVerifyRequest {
                    user_code: code.into(),
                    csrf_token: approval_csrf.clone()
                })
            )
            .await
            .status(),
            StatusCode::OK
        );
        let amr: Vec<String> =
            sqlx::query_scalar("SELECT amr FROM device_codes WHERE user_code=$1")
                .bind(code)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(amr, vec!["webauthn"]);
        assert!(pending_device_client(&pool, code).await.is_err());
        assert_eq!(
            handle_device_verify(
                State(state.clone()),
                cookies(&passkey_session, &approval_csrf),
                Form(DeviceVerifyRequest {
                    user_code: code.into(),
                    csrf_token: approval_csrf
                })
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        sqlx::query("UPDATE device_codes SET is_authorized=false,expires_at=NOW()-INTERVAL '1 minute' WHERE user_code=$1").bind(code).execute(&pool).await.unwrap();
        assert!(
            complete_user_authorization(
                &state,
                pending(user, client, code),
                vec!["otp".into()],
                None
            )
            .await
            .is_err()
        );
        // An account from another tenant cannot complete a device login.
        sqlx::query(
            "UPDATE device_codes SET expires_at=NOW()+INTERVAL '1 minute' WHERE user_code=$1",
        )
        .bind(code)
        .execute(&pool)
        .await
        .unwrap();
        let foreign = Uuid::new_v4();
        sqlx::query("INSERT INTO tenants (id,slug,name) VALUES ($1,$2,'Foreign')")
            .bind(foreign)
            .bind(foreign.to_string())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE users SET tenant_id=$1 WHERE id=$2")
            .bind(foreign)
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            complete_user_authorization(
                &state,
                pending(user, client, code),
                vec!["otp".into()],
                None
            )
            .await
            .is_err()
        );
    }
}
