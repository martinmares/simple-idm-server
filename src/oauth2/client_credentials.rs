use crate::auth::{verify_password, JwtService};
use crate::db::{models::OAuthClient, DbPool};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use sqlx;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct ClientCredentialsRequest {
    pub grant_type: String,
    pub client_id: String,
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
}

pub async fn handle_client_credentials(
    State(state): State<Arc<OAuth2State>>,
    Json(req): Json<ClientCredentialsRequest>,
) -> impl IntoResponse {
    if req.grant_type != "client_credentials" {
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
    let client = match sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients WHERE client_id = $1 AND is_active = true",
    )
    .bind(&req.client_id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Client not found or inactive".to_string(),
                }),
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Database error".to_string(),
                }),
            )
                .into_response()
        }
    };

    // Ověř client secret
    if !verify_password(&req.client_secret, &client.client_secret_hash).unwrap_or(false) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Invalid client credentials".to_string(),
            }),
        )
            .into_response();
    }

    // Zkontroluj, že klient podporuje client_credentials flow
    if !client.grant_types.contains(&"client_credentials".to_string()) {
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

    // Vytvoř access token (bez custom claims pro M2M)
    let access_token = match state.jwt_service.create_access_token(
        client.id,
        client.client_id.clone(),
        None, // žádný email
        None, // žádné preferred_username
        vec![], // žádné skupiny
        HashMap::new(), // žádné custom claims
        state.access_token_expiry,
    ) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Failed to create JWT token: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to create access token".to_string(),
                }),
            )
                .into_response()
        }
    };

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
