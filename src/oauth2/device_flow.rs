use crate::auth::{
    build_custom_claims, get_direct_user_group_names, get_effective_user_groups,
    get_user_group_names,
};
use crate::db::models::{DeviceCode, OAuthClient, User};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
    Form, Json,
};
use chrono::{Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx;
use std::sync::Arc;

use super::client_credentials::{ErrorResponse, OAuth2State};
use super::templates;

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationRequest {
    pub client_id: String,
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
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceVerifyRequest {
    pub user_code: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct DevicePageQuery {
    pub user_code: Option<String>,
}

#[derive(Debug, Serialize)]
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

/// Endpoint pro zobrazení HTML formuláře pro device verification
/// GET /device?user_code=XXXX-XXXX
pub async fn show_device_form(
    Query(query): Query<DevicePageQuery>,
) -> impl IntoResponse {
    Html(templates::device_verify_page(
        query.user_code.as_deref(),
        None,
        None,
    ))
}

/// Endpoint pro iniciaci device flow
/// Klient (TV) volá tento endpoint a dostane device_code a user_code
pub async fn handle_device_authorization(
    State(state): State<Arc<OAuth2State>>,
    Form(req): Form<DeviceAuthorizationRequest>,
) -> impl IntoResponse {
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
                error_description: "Client not found or inactive".to_string(),
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

    // Zkontroluj, že klient podporuje device_code flow
    if !client.grant_types.contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string()) {
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

    // Ulož do databáze
    if let Err(_) = sqlx::query(
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

/// Endpoint pro ověření user_code uživatelem
/// Uživatel zadá user_code a svoje credentials
/// Podporuje JSON i HTML formuláře
pub async fn handle_device_verify(
    State(state): State<Arc<OAuth2State>>,
    axum::extract::Form(req): axum::extract::Form<DeviceVerifyRequest>,
) -> impl IntoResponse {
    // Načti device code podle user_code
    let device_code = match sqlx::query_as::<_, DeviceCode>(
        "SELECT * FROM device_codes WHERE user_code = $1",
    )
    .bind(&req.user_code)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(dc)) => dc,
        Ok(None) => {
            return Html(templates::device_verify_page(
                Some(&req.user_code),
                Some("Invalid user code"),
                None,
            ))
            .into_response()
        }
        Err(_) => {
            return Html(templates::device_verify_page(
                Some(&req.user_code),
                Some("Database error"),
                None,
            ))
            .into_response()
        }
    };

    // Brute force protection: Zkontroluj počet failed attempts
    let failed_attempts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_verification_attempts WHERE user_code = $1"
    )
    .bind(&req.user_code)
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);

    if failed_attempts >= state.device_flow_config.max_verification_attempts as i64 {
        // Smaž device code po překročení limitu
        let _ = sqlx::query("DELETE FROM device_codes WHERE user_code = $1")
            .bind(&req.user_code)
            .execute(&state.db_pool)
            .await;

        return Html(templates::device_verify_page(
            Some(&req.user_code),
            Some("Too many failed attempts. This device code has been invalidated."),
            None,
        ))
        .into_response();
    }

    // Zkontroluj expiraci
    if device_code.expires_at < Utc::now() {
        let _ = sqlx::query("DELETE FROM device_codes WHERE user_code = $1")
            .bind(&req.user_code)
            .execute(&state.db_pool)
            .await;

        return Html(templates::device_verify_page(
            Some(&req.user_code),
            Some("User code expired"),
            None,
        ))
        .into_response();
    }

    // Zkontroluj, jestli už není autorizovaný
    if device_code.is_authorized {
        return Html(templates::device_verify_page(
            Some(&req.user_code),
            Some("Device already authorized"),
            None,
        ))
        .into_response();
    }

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
            // Log failed attempt
            let _ = sqlx::query(
                "INSERT INTO device_verification_attempts (user_code, ip_address) VALUES ($1, $2)"
            )
            .bind(&req.user_code)
            .bind("unknown") // TODO: extract real IP from request
            .execute(&state.db_pool)
            .await;

            return Html(templates::device_verify_page(
                Some(&req.user_code),
                Some("Invalid credentials"),
                None,
            ))
            .into_response()
        }
        Err(_) => {
            return Html(templates::device_verify_page(
                Some(&req.user_code),
                Some("Database error"),
                None,
            ))
            .into_response()
        }
    };

    // Ověř heslo
    if !crate::auth::verify_password(&req.password, &user.password_hash).unwrap_or(false) {
        // Log failed attempt
        let _ = sqlx::query(
            "INSERT INTO device_verification_attempts (user_code, ip_address) VALUES ($1, $2)"
        )
        .bind(&req.user_code)
        .bind("unknown") // TODO: extract real IP from request
        .execute(&state.db_pool)
        .await;

        return Html(templates::device_verify_page(
            Some(&req.user_code),
            Some("Invalid credentials"),
            None,
        ))
        .into_response();
    }

    // Označ device code jako autorizovaný
    if let Err(_) = sqlx::query(
        "UPDATE device_codes SET is_authorized = true, user_id = $1 WHERE user_code = $2",
    )
    .bind(user.id)
    .bind(&req.user_code)
    .execute(&state.db_pool)
    .await
    {
        return Html(templates::device_verify_page(
            Some(&req.user_code),
            Some("Failed to authorize device"),
            None,
        ))
        .into_response();
    }

    Html(templates::device_verify_page(
        None,
        None,
        Some("Device authorized successfully! You can now return to your device."),
    ))
    .into_response()
}

/// Endpoint pro polling - klient (TV) volá opakovaně, dokud nedostane token
pub async fn handle_device_token(
    State(state): State<Arc<OAuth2State>>,
    Form(req): Form<DeviceTokenRequest>,
) -> impl IntoResponse {
    if req.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
        return Json(ErrorResponse {
            error: "unsupported_grant_type".to_string(),
            error_description: "Only device_code grant type is supported".to_string(),
        })
        .into_response();
    }

    // Načti device code
    let device_code = match sqlx::query_as::<_, DeviceCode>(
        "SELECT * FROM device_codes WHERE device_code = $1",
    )
    .bind(&req.device_code)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(dc)) => dc,
        Ok(None) => {
            return Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Invalid device code".to_string(),
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
    if device_code.expires_at < Utc::now() {
        let _ = sqlx::query("DELETE FROM device_codes WHERE device_code = $1")
            .bind(&req.device_code)
            .execute(&state.db_pool)
            .await;

        return Json(ErrorResponse {
            error: "expired_token".to_string(),
            error_description: "Device code expired".to_string(),
        })
        .into_response();
    }

    // Zkontroluj, jestli je autorizovaný
    if !device_code.is_authorized {
        return Json(ErrorResponse {
            error: "authorization_pending".to_string(),
            error_description: "User has not authorized the device yet".to_string(),
        })
        .into_response();
    }

    // Musí existovat user_id, pokud je autorizovaný
    let user_id = match device_code.user_id {
        Some(id) => id,
        None => {
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: "Device authorized but no user_id".to_string(),
            })
            .into_response()
        }
    };

    // Načti klienta
    let client = match sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients WHERE id = $1 AND is_active = true",
    )
    .bind(device_code.client_id)
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

    // Načti uživatele
    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
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

    // Vytvoř custom claims
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
        "Issuing JWT token (device flow)"
    );

    // Vytvoř access token
    let access_token = match state.jwt_service.create_access_token(
        user.id,
        client.client_id.clone(),
        Some(user.email.clone()),
        Some(user.username.clone()),
        Some(device_code.scope.clone()),
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

    // Smaž použitý device code
    let _ = sqlx::query("DELETE FROM device_codes WHERE device_code = $1")
        .bind(&req.device_code)
        .execute(&state.db_pool)
        .await;

    Json(DeviceTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.access_token_expiry,
        scope: Some(device_code.scope),
    })
    .into_response()
}
