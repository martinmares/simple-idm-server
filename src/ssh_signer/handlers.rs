use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::cert_signer::{CertSigner, SignRequest};
use super::jwt_validator::JwtValidator;
use super::principal_mapper::PrincipalMapper;

pub struct AppState {
    pub jwt_validator: Arc<JwtValidator>,
    pub principal_mapper: Arc<PrincipalMapper>,
    pub cert_signer: Arc<CertSigner>,
}

#[derive(Debug, Deserialize)]
pub struct SignRequestBody {
    pub public_key: String,
    #[serde(default)]
    pub requested_principals: Vec<String>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub certificate: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub principals: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    error_description: String,
}

pub async fn handle_sign(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SignRequestBody>,
) -> impl IntoResponse {
    // Extract Bearer token
    let token = match extract_bearer_token(&headers) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_token".to_string(),
                    error_description: e,
                }),
            )
                .into_response();
        }
    };

    // Validate JWT
    let claims = match state.jwt_validator.validate_token(&token).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("JWT validation failed: {}", e);
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_token".to_string(),
                    error_description: e,
                }),
            )
                .into_response();
        }
    };

    // Map principals from groups
    let principals = match state.principal_mapper.map_principals(&claims) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Principal mapping failed for sub {}: {}", claims.sub, e);
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "forbidden".to_string(),
                    error_description: format!("No valid principals: {}", e),
                }),
            )
                .into_response();
        }
    };

    if principals.is_empty() {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".to_string(),
                error_description: "No principals available".to_string(),
            }),
        )
            .into_response();
    }

    // Sign certificate
    let sign_req = SignRequest {
        public_key: req.public_key,
        principals: principals.clone(),
        ttl_seconds: req.ttl_seconds,
    };

    let signed_cert = match state.cert_signer.sign_certificate(sign_req) {
        Ok(cert) => cert,
        Err(e) => {
            tracing::error!("Certificate signing failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: format!("Failed to sign certificate: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Audit log
    tracing::info!(
        "Certificate signed: sub={}, principals={:?}, ttl={}s",
        claims.sub,
        signed_cert.principals,
        signed_cert.valid_before - signed_cert.valid_after
    );

    (
        StatusCode::OK,
        Json(SignResponse {
            certificate: signed_cert.certificate,
            valid_after: signed_cert.valid_after,
            valid_before: signed_cert.valid_before,
            principals: signed_cert.principals,
        }),
    )
        .into_response()
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<String, String> {
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| "Missing Authorization header".to_string())?;

    let auth_str = auth_header
        .to_str()
        .map_err(|_| "Invalid Authorization header".to_string())?;

    if !auth_str.starts_with("Bearer ") {
        return Err("Authorization header must be 'Bearer <token>'".to_string());
    }

    let token = auth_str.trim_start_matches("Bearer ").trim();
    if token.is_empty() {
        return Err("Token is empty".to_string());
    }

    Ok(token.to_string())
}
