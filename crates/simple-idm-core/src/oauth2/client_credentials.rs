use super::throttle;
use super::utils::{ClientLookupError, resolve_oauth_client};
use crate::auth::{JwtService, verify_password};
use crate::config::AuthProtectionConfig;
use crate::config::DeviceFlowConfig;
use crate::db::DbPool;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct ClientCredentialsRequest {
    pub grant_type: String,
    pub client_id: String,
    pub tenant: Option<String>,
    pub client_secret: String,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

pub struct OAuth2State {
    pub db_pool: DbPool,
    pub jwt_service: Arc<JwtService>,
    pub access_token_expiry: i64,
    pub refresh_token_expiry: i64,
    pub auth_session_expiry: i64,
    pub device_flow_config: DeviceFlowConfig,
    pub allow_username_login: bool,
    pub allowed_email_domains: Vec<String>,
    pub trust_proxy_headers: bool,
    pub force_secure_cookies: bool,
    pub auth_protection: AuthProtectionConfig,
}

pub async fn handle_client_credentials(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Json(req): Json<ClientCredentialsRequest>,
) -> impl IntoResponse {
    let mut throttle_keys = vec![format!("client:{}", req.client_id.trim().to_lowercase())];
    if let Some(ip) = throttle::extract_client_ip(&headers, state.trust_proxy_headers) {
        throttle_keys.push(format!("ip:{}", ip));
    }
    if state.auth_protection.enabled {
        for key in &throttle_keys {
            if throttle::is_locked(&state.db_pool, "oauth2_client_credentials", key)
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
        }
    }

    if req.grant_type != "client_credentials" {
        if state.auth_protection.enabled {
            for key in &throttle_keys {
                let _ = throttle::register_failure(
                    &state.db_pool,
                    "oauth2_client_credentials",
                    key,
                    &state.auth_protection,
                )
                .await;
            }
        }
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "unsupported_grant_type".to_string(),
                error_description: "Only client_credentials grant type is supported".to_string(),
            }),
        )
            .into_response();
    }

    // Načti OAuth klienta z databáze
    let client =
        match resolve_oauth_client(&state.db_pool, &req.client_id, req.tenant.as_deref()).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                if state.auth_protection.enabled {
                    for key in &throttle_keys {
                        let _ = throttle::register_failure(
                            &state.db_pool,
                            "oauth2_client_credentials",
                            key,
                            &state.auth_protection,
                        )
                        .await;
                    }
                }
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "invalid_client".to_string(),
                        error_description: "Client not found or inactive".to_string(),
                    }),
                )
                    .into_response();
            }
            Err(ClientLookupError::AmbiguousClientId) => {
                if state.auth_protection.enabled {
                    for key in &throttle_keys {
                        let _ = throttle::register_failure(
                            &state.db_pool,
                            "oauth2_client_credentials",
                            key,
                            &state.auth_protection,
                        )
                        .await;
                    }
                }
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_request".to_string(),
                        error_description: "Ambiguous client_id. Provide tenant hint.".to_string(),
                    }),
                )
                    .into_response();
            }
            Err(ClientLookupError::InvalidTenantHint) => {
                if state.auth_protection.enabled {
                    for key in &throttle_keys {
                        let _ = throttle::register_failure(
                            &state.db_pool,
                            "oauth2_client_credentials",
                            key,
                            &state.auth_protection,
                        )
                        .await;
                    }
                }
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_request".to_string(),
                        error_description: "Invalid tenant hint".to_string(),
                    }),
                )
                    .into_response();
            }
            Err(ClientLookupError::Database) => {
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

    // Ověř client secret (client_credentials flow vyžaduje vždy secret)
    match &client.client_secret_hash {
        Some(hash) if verify_password(&req.client_secret, hash).unwrap_or(false) => {
            // OK
        }
        _ => {
            if state.auth_protection.enabled {
                for key in &throttle_keys {
                    let _ = throttle::register_failure(
                        &state.db_pool,
                        "oauth2_client_credentials",
                        key,
                        &state.auth_protection,
                    )
                    .await;
                }
            }
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Invalid client credentials".to_string(),
                }),
            )
                .into_response();
        }
    }

    // Zkontroluj, že klient podporuje client_credentials flow
    if !client
        .grant_types
        .contains(&"client_credentials".to_string())
    {
        if state.auth_protection.enabled {
            for key in &throttle_keys {
                let _ = throttle::register_failure(
                    &state.db_pool,
                    "oauth2_client_credentials",
                    key,
                    &state.auth_protection,
                )
                .await;
            }
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized_client".to_string(),
                error_description: "Client is not authorized for this grant type".to_string(),
            }),
        )
            .into_response();
    }

    // Pro M2M flow nemáme uživatele, takže použijeme client_id jako subject
    let scope = req.scope.unwrap_or_else(|| client.scope.clone());

    // Log JWT token issuance for M2M
    tracing::debug!(
        client_id = %client.client_id,
        scope = %scope,
        "Issuing JWT token (M2M)"
    );

    // Vytvoř access token (bez custom claims pro M2M)
    let access_token = match state.jwt_service.create_access_token(
        client.id,
        client.client_id.clone(),
        None, // žádný email
        None, // žádné preferred_username
        Some(scope.clone()),
        vec![],         // žádné skupiny
        HashMap::new(), // žádné custom claims
        vec!["client_credentials".to_string()],
        Some("urn:simple-idm:acr:service".to_string()),
        state.access_token_expiry,
    ) {
        Ok(token) => token,
        Err(e) => {
            if state.auth_protection.enabled {
                for key in &throttle_keys {
                    let _ = throttle::register_failure(
                        &state.db_pool,
                        "oauth2_client_credentials",
                        key,
                        &state.auth_protection,
                    )
                    .await;
                }
            }
            tracing::error!("Failed to create JWT token: {:?}", e);
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

    if state.auth_protection.enabled {
        for key in &throttle_keys {
            let _ =
                throttle::clear_failures(&state.db_pool, "oauth2_client_credentials", key).await;
        }
    }

    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: state.access_token_expiry,
            scope: Some(scope),
        }),
    )
        .into_response()
}
