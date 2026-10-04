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
    pub bastion: Option<BastionSigningState>,
}

pub struct BastionSigningState {
    pub jwt_validator: Arc<JwtValidator>,
    pub service_key: String,
    pub required_scope: String,
    pub tenant_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BastionSignRequest {
    pub public_key: String,
    #[serde(default)]
    pub requested_principals: Vec<String>,
    pub ttl_seconds: Option<u64>,
    pub session_id: String,
}

fn matches_service_key(expected: &str, supplied: &str) -> bool {
    use sha2::{Digest, Sha256};
    let expected = Sha256::digest(expected.as_bytes());
    let supplied = Sha256::digest(supplied.as_bytes());
    expected
        .iter()
        .zip(supplied.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn narrow_principals(
    allowed: Vec<String>,
    requested: Vec<String>,
) -> Result<Vec<String>, &'static str> {
    if requested.is_empty() {
        return Ok(allowed);
    }
    if requested.iter().any(|p| !allowed.contains(p)) {
        return Err("Requested principal is not authorized");
    }
    let mut result = requested;
    result.sort();
    result.dedup();
    Ok(result)
}

/// Separate audience and service authentication keep direct OIDC login compatible.
pub async fn handle_bastion_sign(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BastionSignRequest>,
) -> impl IntoResponse {
    let fail = |status, message: &str| {
        (status, Json(serde_json::json!({"error":message}))).into_response()
    };
    let Some(bastion) = &state.bastion else {
        return fail(StatusCode::NOT_FOUND, "Bastion signing disabled");
    };
    let key = headers
        .get("x-bastion-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !matches_service_key(&bastion.service_key, key) {
        return fail(StatusCode::UNAUTHORIZED, "Invalid bastion credentials");
    }
    let token = match extract_bearer_token(&headers) {
        Ok(t) => t,
        Err(_) => return fail(StatusCode::UNAUTHORIZED, "Missing user access token"),
    };
    let claims = match bastion.jwt_validator.validate_token(&token).await {
        Ok(c) => c,
        Err(_) => return fail(StatusCode::UNAUTHORIZED, "Invalid user access token"),
    };
    if claims
        .require_access_scope(&bastion.required_scope)
        .is_err()
        || claims.tenant_id.as_deref() != Some(&bastion.tenant_id)
    {
        return fail(
            StatusCode::FORBIDDEN,
            "User scope or tenant is not authorized",
        );
    }
    if uuid::Uuid::parse_str(&req.session_id).is_err() {
        return fail(StatusCode::BAD_REQUEST, "Invalid session ID");
    }
    let allowed = match state.principal_mapper.map_principals(&claims) {
        Ok(p) => p,
        Err(_) => return fail(StatusCode::FORBIDDEN, "No authorized SSH principals"),
    };
    let principals = match narrow_principals(allowed, req.requested_principals) {
        Ok(p) => p,
        Err(e) => return fail(StatusCode::FORBIDDEN, e),
    };
    let signer = state.cert_signer.clone();
    let session_id = req.session_id;
    let identity = session_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        signer.sign_bastion_certificate(
            SignRequest {
                public_key: req.public_key,
                principals,
                ttl_seconds: req.ttl_seconds,
            },
            &identity,
        )
    })
    .await;
    let signed = match result {
        Ok(Ok(s)) => s,
        _ => return fail(StatusCode::BAD_REQUEST, "Certificate signing failed"),
    };
    tracing::info!(
        session_id,
        subject = claims.sub,
        "Bastion certificate signed"
    );
    (
        StatusCode::OK,
        Json(SignResponse {
            certificate: signed.certificate,
            valid_after: signed.valid_after,
            valid_before: signed.valid_before,
            principals: signed.principals,
        }),
    )
        .into_response()
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delegated_principals_cannot_expand_user_permissions() {
        assert_eq!(
            narrow_principals(
                vec!["alice".into(), "role:ops".into()],
                vec!["alice".into()]
            )
            .unwrap(),
            vec!["alice"]
        );
        assert!(narrow_principals(vec!["alice".into()], vec!["root".into()]).is_err());
        assert_eq!(
            narrow_principals(vec!["alice".into()], vec![]).unwrap(),
            vec!["alice"]
        );
    }
    #[test]
    fn service_key_requires_exact_match() {
        assert!(matches_service_key("a-secret", "a-secret"));
        assert!(!matches_service_key("a-secret", ""));
        assert!(!matches_service_key("a-secret", "a-secreT"));
    }
}
