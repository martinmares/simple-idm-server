use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum JwtError {
    #[error("Failed to encode JWT: {0}")]
    EncodeError(String),
    #[error("Failed to decode JWT: {0}")]
    DecodeError(String),
    #[error("Failed to read key file: {0}")]
    KeyFileError(String),
    #[error("Invalid token")]
    InvalidToken,
    #[error("Invalid token audience")]
    InvalidAudience,
    #[error("Insufficient scope")]
    InsufficientScope,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,      // Subject (user ID)
    pub iss: String,      // Issuer
    pub aud: Vec<String>, // Audience (client IDs)
    pub exp: i64,         // Expiration time
    pub iat: i64,         // Issued at
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>, // OIDC nonce (ID token only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub email: Option<String>, // User email
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    pub groups: Vec<String>, // User groups
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub amr: Vec<String>, // Authentication Methods References (OIDC)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>, // Authentication Context Class Reference (OIDC)
    #[serde(flatten)]
    pub custom_claims: HashMap<String, serde_json::Value>, // Custom claim maps
}

pub struct JwtService {
    encoding_key: EncodingKey,
    active_decoding_key: DecodingKey,
    pub issuer: String,
    public_key_paths: Vec<(String, String)>, // (kid, path)
    decoding_keys: HashMap<String, DecodingKey>,
    key_id: String,
}

impl JwtService {
    pub fn new(
        private_key_path: &str,
        public_key_path: &str,
        issuer: String,
        key_id: String,
        additional_public_keys: Vec<(String, String)>,
    ) -> Result<Self, JwtError> {
        let private_key = fs::read(private_key_path)
            .map_err(|e| JwtError::KeyFileError(format!("Private key: {}", e)))?;
        let public_key = fs::read(public_key_path)
            .map_err(|e| JwtError::KeyFileError(format!("Public key: {}", e)))?;

        let encoding_key = EncodingKey::from_rsa_pem(&private_key)
            .map_err(|e| JwtError::KeyFileError(format!("Invalid private key: {}", e)))?;
        let active_decoding_key = DecodingKey::from_rsa_pem(&public_key)
            .map_err(|e| JwtError::KeyFileError(format!("Invalid public key: {}", e)))?;

        let mut decoding_keys = HashMap::new();
        decoding_keys.insert(key_id.clone(), active_decoding_key.clone());

        let mut public_key_paths = vec![(key_id.clone(), public_key_path.to_string())];
        for (kid, path) in additional_public_keys {
            if kid == key_id {
                continue;
            }
            let additional_pem = fs::read(&path)
                .map_err(|e| JwtError::KeyFileError(format!("Public key ({}): {}", path, e)))?;
            let additional_decoding_key =
                DecodingKey::from_rsa_pem(&additional_pem).map_err(|e| {
                    JwtError::KeyFileError(format!(
                        "Invalid additional public key ({}): {}",
                        path, e
                    ))
                })?;
            decoding_keys.insert(kid.clone(), additional_decoding_key);
            public_key_paths.push((kid, path));
        }

        Ok(Self {
            encoding_key,
            active_decoding_key,
            issuer,
            public_key_paths,
            decoding_keys,
            key_id,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_access_token(
        &self,
        user_id: Uuid,
        client_id: String,
        email: Option<String>,
        preferred_username: Option<String>,
        scope: Option<String>,
        groups: Vec<String>,
        custom_claims: HashMap<String, serde_json::Value>,
        amr: Vec<String>,
        acr: Option<String>,
        expiry_seconds: i64,
    ) -> Result<String, JwtError> {
        if custom_claims.keys().any(|name| {
            !matches!(name.as_str(), "tenant_id" | "credential_version")
                && super::claims::is_reserved_claim(name)
        }) {
            return Err(JwtError::EncodeError("Reserved JWT claim name".into()));
        }
        let now = Utc::now();
        let exp = now + Duration::seconds(expiry_seconds);

        let claims = Claims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            aud: vec![client_id],
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nonce: None,
            scope,
            email,
            preferred_username,
            groups,
            amr,
            acr,
            custom_claims,
        };

        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some(self.key_id.clone());
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| JwtError::EncodeError(e.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_id_token(
        &self,
        user_id: Uuid,
        client_id: String,
        email: Option<String>,
        preferred_username: Option<String>,
        groups: Vec<String>,
        custom_claims: HashMap<String, serde_json::Value>,
        nonce: Option<String>,
        amr: Vec<String>,
        acr: Option<String>,
        expiry_seconds: i64,
    ) -> Result<String, JwtError> {
        if custom_claims.keys().any(|name| {
            !matches!(name.as_str(), "tenant_id" | "credential_version")
                && super::claims::is_reserved_claim(name)
        }) {
            return Err(JwtError::EncodeError("Reserved JWT claim name".into()));
        }
        let now = Utc::now();
        let exp = now + Duration::seconds(expiry_seconds);

        let claims = Claims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            aud: vec![client_id],
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nonce,
            scope: None,
            email,
            preferred_username,
            groups,
            amr,
            acr,
            custom_claims,
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.clone());
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| JwtError::EncodeError(e.to_string()))
    }

    fn decode_token_without_audience_validation(&self, token: &str) -> Result<Claims, JwtError> {
        let header = decode_header(token)
            .map_err(|e| JwtError::DecodeError(format!("Invalid token header: {}", e)))?;

        let decoding_key = if let Some(kid) = header.kid {
            self.decoding_keys
                .get(&kid)
                .ok_or_else(|| JwtError::DecodeError(format!("Unknown key id (kid): {}", kid)))?
        } else {
            &self.active_decoding_key
        };

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.validate_aud = false;

        decode::<Claims>(token, decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                tracing::error!("JWT verification failed: {}", e);
                JwtError::DecodeError(e.to_string())
            })
    }

    #[deprecated(
        note = "Use verify_access_token(token, expected_audiences, required_scopes) for access-token protected endpoints"
    )]
    pub fn verify_token(&self, token: &str) -> Result<Claims, JwtError> {
        self.decode_token_without_audience_validation(token)
    }

    pub fn verify_access_token(
        &self,
        token: &str,
        expected_audiences: &[String],
        required_scopes: &[&str],
    ) -> Result<Claims, JwtError> {
        if decode_header(token)
            .map_err(|_| JwtError::InvalidToken)?
            .typ
            .as_deref()
            != Some("at+jwt")
        {
            return Err(JwtError::InvalidToken);
        }
        let claims = self.decode_token_without_audience_validation(token)?;

        if claims.aud.is_empty()
            || !claims
                .aud
                .iter()
                .any(|aud| expected_audiences.iter().any(|expected| expected == aud))
        {
            return Err(JwtError::InvalidAudience);
        }

        if !required_scopes.is_empty() {
            let token_scopes = claims.scope.as_deref().unwrap_or("");
            let has_all_scopes = required_scopes.iter().all(|required| {
                token_scopes
                    .split_whitespace()
                    .any(|value| value == *required)
            });
            if !has_all_scopes {
                return Err(JwtError::InsufficientScope);
            }
        }

        Ok(claims)
    }

    pub fn verify_token_for_audience(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> Result<Claims, JwtError> {
        self.verify_access_token(token, &[expected_audience.to_string()], &[])
    }

    /// Get JWKS (JSON Web Key Set) for public key distribution
    ///
    /// Reads the public key from PEM file and converts it to JWK format
    pub fn get_jwks(&self) -> Result<crate::jwks::JsonWebKeySet, JwtError> {
        let mut keys = Vec::new();
        for (kid, path) in &self.public_key_paths {
            let pem_data = fs::read_to_string(path).map_err(|e| {
                JwtError::KeyFileError(format!("Failed to read public key ({}): {}", path, e))
            })?;
            let public_key = RsaPublicKey::from_public_key_pem(&pem_data).map_err(|e| {
                JwtError::KeyFileError(format!("Failed to parse public key ({}): {}", path, e))
            })?;
            let n = public_key.n().to_bytes_be();
            let e = public_key.e().to_bytes_be();
            keys.push(crate::jwks::rsa_components_to_jwk(
                &n,
                &e,
                Some(kid.clone()),
            ));
        }

        Ok(crate::jwks::JsonWebKeySet { keys })
    }
}

#[cfg(test)]
mod tests {
    use super::JwtService;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use tempfile::tempdir;

    #[test]
    fn verifies_rs256_token_from_jsonwebtoken_10() {
        // Signed with jsonwebtoken 10.4.0 and a disposable test key.
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/jwt-10-rs256.json")).unwrap();
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(
            fixture["public_key"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
        let token = fixture["token"].as_str().unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&["https://legacy.example.test"]);
        validation.set_audience(&["legacy-client"]);
        let decoded = jsonwebtoken::decode::<super::Claims>(token, &key, &validation).unwrap();
        assert_eq!(decoded.claims.sub, "legacy-user");
        assert_eq!(decoded.header.kid.as_deref(), Some("legacy-key"));
        validation.set_audience(&["wrong-client"]);
        assert!(jsonwebtoken::decode::<super::Claims>(token, &key, &validation).is_err());
        validation.set_audience(&["legacy-client"]);
        validation.set_issuer(&["https://wrong.example.test"]);
        assert!(jsonwebtoken::decode::<super::Claims>(token, &key, &validation).is_err());
    }

    #[test]
    fn jwks_contains_active_and_additional_keys() {
        let dir = tempdir().expect("temp dir");
        let private_key_path = dir.path().join("private.pem");
        let public_key_path = dir.path().join("public.pem");

        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa private key");
        let public_key = RsaPublicKey::from(&private_key);
        std::fs::write(
            &private_key_path,
            private_key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("private key pem")
                .as_bytes(),
        )
        .expect("write private key");
        std::fs::write(
            &public_key_path,
            public_key
                .to_public_key_pem(LineEnding::LF)
                .expect("public key pem"),
        )
        .expect("write public key");

        let private_key = private_key_path.to_string_lossy().to_string();
        let public_key = public_key_path.to_string_lossy().to_string();

        let service = JwtService::new(
            &private_key,
            &public_key,
            "http://localhost:8080".to_string(),
            "active-key".to_string(),
            vec![("old-key".to_string(), public_key.clone())],
        )
        .expect("jwt service should initialize");

        let user_id = uuid::Uuid::new_v4();
        let token = service
            .create_access_token(
                user_id,
                "test-client".into(),
                Some("user@example.test".into()),
                Some("user".into()),
                Some("openid profile".into()),
                vec!["test-group".into()],
                std::collections::HashMap::new(),
                vec!["pwd".into()],
                None,
                3600,
            )
            .expect("sign RS256 token");
        let claims = service
            .verify_token_for_audience(&token, "test-client")
            .expect("verify RS256 token");
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.amr, vec!["pwd"]);
        assert!(
            service
                .verify_token_for_audience(&token, "wrong-client")
                .is_err()
        );

        let id_token = service
            .create_id_token(
                user_id,
                "test-client".into(),
                None,
                None,
                vec![],
                std::collections::HashMap::new(),
                None,
                vec!["pwd".into()],
                None,
                3600,
            )
            .unwrap();
        assert!(
            service
                .verify_access_token(&id_token, &["test-client".into()], &[])
                .is_err()
        );
        let jwks = service.get_jwks().expect("jwks should generate");
        assert_eq!(jwks.keys.len(), 2);
        let kids: Vec<String> = jwks.keys.into_iter().filter_map(|k| k.kid).collect();
        assert!(kids.iter().any(|k| k == "active-key"));
        assert!(kids.iter().any(|k| k == "old-key"));
    }
}
