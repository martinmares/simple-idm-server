use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;
use std::sync::Arc;

use crate::auth::JwtService;

/// JSON Web Key (JWK) representation for RSA public key
#[derive(Debug, Serialize)]
pub struct JsonWebKey {
    /// Key type (always "RSA" for our use case)
    pub kty: String,

    /// Public key use (always "sig" for signature verification)
    #[serde(rename = "use")]
    pub key_use: String,

    /// Key ID (optional, but useful for key rotation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// RSA modulus (n) - base64url encoded
    pub n: String,

    /// RSA public exponent (e) - base64url encoded (usually "AQAB" = 65537)
    pub e: String,

    /// Algorithm (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

/// JSON Web Key Set (JWKS) - container for multiple keys
#[derive(Debug, Serialize)]
pub struct JsonWebKeySet {
    pub keys: Vec<JsonWebKey>,
}

/// Error response for JWKS endpoint
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

/// Handler for /.well-known/jwks.json endpoint
///
/// Returns the public key(s) in JWK format for JWT token verification
pub async fn jwks_handler(
    State(jwt_service): State<Arc<JwtService>>,
) -> impl IntoResponse {
    match jwt_service.get_jwks() {
        Ok(jwks) => (StatusCode::OK, Json(jwks)).into_response(),
        Err(e) => {
            tracing::error!("Failed to generate JWKS: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: format!("Failed to generate JWKS: {}", e),
                }),
            )
                .into_response()
        }
    }
}

/// Convert RSA public key components to JWK
///
/// Takes the RSA modulus (n) and exponent (e) as big-endian bytes
/// and encodes them as base64url strings per RFC 7517
pub fn rsa_components_to_jwk(
    modulus: &[u8],
    exponent: &[u8],
    kid: Option<String>,
) -> JsonWebKey {
    // Encode as base64url (no padding)
    let n = URL_SAFE_NO_PAD.encode(modulus);
    let e = URL_SAFE_NO_PAD.encode(exponent);

    JsonWebKey {
        kty: "RSA".to_string(),
        key_use: "sig".to_string(),
        kid,
        n,
        e,
        alg: Some("RS256".to_string()),
    }
}
