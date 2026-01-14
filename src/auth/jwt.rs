use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("Failed to encode JWT: {0}")]
    EncodeError(String),
    #[error("Failed to decode JWT: {0}")]
    DecodeError(String),
    #[error("Failed to read key file: {0}")]
    KeyFileError(String),
    #[error("Invalid token")]
    InvalidToken,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,           // Subject (user ID)
    pub iss: String,           // Issuer
    pub aud: Vec<String>,      // Audience (client IDs)
    pub exp: i64,              // Expiration time
    pub iat: i64,              // Issued at
    pub email: Option<String>, // User email
    pub groups: Vec<String>,   // User groups
    #[serde(flatten)]
    pub custom_claims: HashMap<String, serde_json::Value>, // Custom claim maps
}

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    pub issuer: String,
}

impl JwtService {
    pub fn new(
        private_key_path: &str,
        public_key_path: &str,
        issuer: String,
    ) -> Result<Self, JwtError> {
        let private_key = fs::read(private_key_path)
            .map_err(|e| JwtError::KeyFileError(format!("Private key: {}", e)))?;
        let public_key = fs::read(public_key_path)
            .map_err(|e| JwtError::KeyFileError(format!("Public key: {}", e)))?;

        let encoding_key = EncodingKey::from_rsa_pem(&private_key)
            .map_err(|e| JwtError::KeyFileError(format!("Invalid private key: {}", e)))?;
        let decoding_key = DecodingKey::from_rsa_pem(&public_key)
            .map_err(|e| JwtError::KeyFileError(format!("Invalid public key: {}", e)))?;

        Ok(Self {
            encoding_key,
            decoding_key,
            issuer,
        })
    }

    pub fn create_access_token(
        &self,
        user_id: Uuid,
        client_id: String,
        email: Option<String>,
        groups: Vec<String>,
        custom_claims: HashMap<String, serde_json::Value>,
        expiry_seconds: i64,
    ) -> Result<String, JwtError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(expiry_seconds);

        let claims = Claims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            aud: vec![client_id],
            exp: exp.timestamp(),
            iat: now.timestamp(),
            email,
            groups,
            custom_claims,
        };

        let header = Header::new(Algorithm::RS256);
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| JwtError::EncodeError(e.to_string()))
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.issuer]);

        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| JwtError::DecodeError(e.to_string()))
    }
}
