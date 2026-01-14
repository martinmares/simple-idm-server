use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use std::sync::Arc;

use crate::config::Config;

/// OIDC Discovery metadata per OpenID Connect Discovery 1.0
/// https://openid.net/specs/openid-connect-discovery-1_0.html
#[derive(Debug, Serialize)]
pub struct OidcDiscovery {
    /// REQUIRED. URL using the https scheme with no query or fragment component
    pub issuer: String,

    /// REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,

    /// REQUIRED. URL of the OP's OAuth 2.0 Token Endpoint
    pub token_endpoint: String,

    /// RECOMMENDED. URL of the OP's JWK Set document
    pub jwks_uri: String,

    /// RECOMMENDED. JSON array containing a list of the OAuth 2.0 [RFC6749] scope values
    pub scopes_supported: Vec<String>,

    /// REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values
    pub response_types_supported: Vec<String>,

    /// OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values
    pub grant_types_supported: Vec<String>,

    /// OPTIONAL. JSON array containing a list of the Subject Identifier types
    pub subject_types_supported: Vec<String>,

    /// REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values)
    pub id_token_signing_alg_values_supported: Vec<String>,

    /// OPTIONAL. JSON array containing a list of Client Authentication methods
    pub token_endpoint_auth_methods_supported: Vec<String>,

    /// OPTIONAL. JSON array containing a list of the Claim Names
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,

    /// OPTIONAL. URL of the OP's UserInfo Endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,

    /// OPTIONAL. JSON array containing a list of PKCE code challenge methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// Error response for discovery endpoint
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

/// State for OIDC discovery endpoint
#[derive(Clone)]
pub struct OidcState {
    pub issuer: String,
}

impl OidcState {
    pub fn new(config: &Config) -> Self {
        Self {
            issuer: config.jwt.issuer.clone(),
        }
    }

    pub fn get_discovery(&self) -> OidcDiscovery {
        OidcDiscovery {
            issuer: self.issuer.clone(),
            authorization_endpoint: Some(format!("{}/oauth2/authorize", self.issuer)),
            token_endpoint: format!("{}/oauth2/token", self.issuer),
            jwks_uri: format!("{}/.well-known/jwks.json", self.issuer),
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            response_types_supported: vec![
                "code".to_string(), // Authorization Code flow
            ],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
                "refresh_token".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["RS256".to_string()],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_post".to_string(),
                "client_secret_basic".to_string(),
            ],
            claims_supported: Some(vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "email".to_string(),
                "groups".to_string(),
            ]),
            userinfo_endpoint: None, // Not implemented yet
            code_challenge_methods_supported: Some(vec![
                "S256".to_string(), // PKCE with SHA-256
                "plain".to_string(),
            ]),
        }
    }
}

/// Handler for /.well-known/openid-configuration endpoint
///
/// Returns OpenID Connect Discovery metadata
pub async fn discovery_handler(State(oidc_state): State<Arc<OidcState>>) -> impl IntoResponse {
    let discovery = oidc_state.get_discovery();
    (StatusCode::OK, Json(discovery)).into_response()
}
