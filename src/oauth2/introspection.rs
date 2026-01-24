use crate::db::models::{OAuthClient, RefreshToken, User};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx;
use std::sync::Arc;

use super::client_credentials::OAuth2State;
use super::utils::apply_client_auth;

#[derive(Debug, Deserialize)]
pub struct IntrospectionRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

pub async fn handle_introspect(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let mut req = match parse_introspection_request(&headers, &body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };

    apply_client_auth(&mut req.client_id, &mut req.client_secret, &headers);

    let client_id = match req.client_id {
        Some(id) => id,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Missing client_id".to_string(),
                }),
            )
                .into_response()
        }
    };

    let client_secret = match req.client_secret {
        Some(secret) => secret,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Missing client_secret".to_string(),
                }),
            )
                .into_response()
        }
    };

    let client = match sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients WHERE client_id = $1 AND is_active = true",
    )
    .bind(&client_id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(client)) => client,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Invalid client credentials".to_string(),
                }),
            )
                .into_response()
        }
    };

    // Verify client secret
    match &client.client_secret_hash {
        Some(hash) if crate::auth::verify_password(&client_secret, hash).unwrap_or(false) => {
            // OK
        }
        _ => {
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

    if req
        .token_type_hint
        .as_deref()
        .map(|hint| hint == "refresh_token")
        .unwrap_or(false)
    {
        return introspect_refresh_token(&state.db_pool, &req.token, &client).await;
    }

    if let Ok(claims) = state.jwt_service.verify_token(&req.token) {
        let response = IntrospectionResponse {
            active: true,
            scope: None,
            client_id: claims.aud.get(0).cloned(),
            username: claims.preferred_username.clone(),
            sub: Some(claims.sub),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            iss: Some(claims.iss),
            aud: Some(claims.aud),
            email: claims.email,
            preferred_username: claims.preferred_username,
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    introspect_refresh_token(&state.db_pool, &req.token, &client).await
}

async fn introspect_refresh_token(
    pool: &crate::db::DbPool,
    token: &str,
    client: &OAuthClient,
) -> axum::response::Response {
    let refresh_token = match sqlx::query_as::<_, RefreshToken>(
        "SELECT * FROM refresh_tokens WHERE token = $1",
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(rt)) => rt,
        _ => {
            return (
                StatusCode::OK,
                Json(IntrospectionResponse {
                    active: false,
                    scope: None,
                    client_id: None,
                    username: None,
                    sub: None,
                    exp: None,
                    iat: None,
                    iss: None,
                    aud: None,
                    email: None,
                    preferred_username: None,
                }),
            )
                .into_response()
        }
    };

    if refresh_token.client_id != client.id || refresh_token.expires_at < Utc::now() {
        return (
            StatusCode::OK,
            Json(IntrospectionResponse {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                sub: None,
                exp: None,
                iat: None,
                iss: None,
                aud: None,
                email: None,
                preferred_username: None,
            }),
        )
            .into_response();
    }

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(refresh_token.user_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();

    (
        StatusCode::OK,
        Json(IntrospectionResponse {
            active: true,
            scope: Some(refresh_token.scope),
            client_id: Some(client.client_id.clone()),
            username: user.as_ref().map(|u| u.username.clone()),
            sub: Some(refresh_token.user_id.to_string()),
            exp: Some(refresh_token.expires_at.timestamp()),
            iat: None,
            iss: None,
            aud: None,
            email: user.as_ref().map(|u| u.email.clone()),
            preferred_username: user.as_ref().map(|u| u.username.clone()),
        }),
    )
        .into_response()
}

fn parse_introspection_request(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<IntrospectionRequest, axum::response::Response> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    let parsed: Result<IntrospectionRequest, ()> = if content_type.starts_with("application/json") {
        serde_json::from_slice::<IntrospectionRequest>(body).map_err(|_| ())
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        serde_urlencoded::from_bytes::<IntrospectionRequest>(body).map_err(|_| ())
    } else if content_type.is_empty() {
        serde_json::from_slice::<IntrospectionRequest>(body)
            .map_err(|_| ())
            .or_else(|_| serde_urlencoded::from_bytes::<IntrospectionRequest>(body).map_err(|_| ()))
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
                error_description: "Failed to parse introspection request".to_string(),
            }),
        )
            .into_response()
    })
}
