use crate::auth::JwtService;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub struct UserinfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    #[serde(flatten)]
    pub custom_claims: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

/// Userinfo endpoint per OpenID Connect Core 1.0
///
/// Returns claims about the authenticated user
pub async fn handle_userinfo(
    State(jwt_service): State<Arc<JwtService>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Get Authorization header
    let auth_header = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        Some(h) => h,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: "Missing Authorization header".to_string(),
                }),
            )
                .into_response()
        }
    };

    // Check Bearer token
    if !auth_header.starts_with("Bearer ") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Invalid Authorization header format".to_string(),
            }),
        )
            .into_response();
    }

    let token = &auth_header[7..]; // Skip "Bearer "

    // Verify and decode token
    match jwt_service.verify_token(token) {
        Ok(claims) => {
            let userinfo = UserinfoResponse {
                sub: claims.sub,
                email: claims.email,
                preferred_username: claims.preferred_username,
                groups: Some(claims.groups),
                custom_claims: claims.custom_claims,
            };

            (StatusCode::OK, Json(userinfo)).into_response()
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "Invalid or expired token".to_string(),
            }),
        )
            .into_response(),
    }
}
