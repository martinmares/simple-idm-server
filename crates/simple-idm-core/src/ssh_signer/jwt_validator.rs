use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: i64,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

impl TokenClaims {
    /// API access tokens have scopes; OIDC ID tokens are not API credentials.
    pub fn require_access_scope(&self, required: &str) -> Result<(), String> {
        if self.nonce.is_some()
            || !self
                .scope
                .as_deref()
                .unwrap_or_default()
                .split_whitespace()
                .any(|s| s == required)
        {
            return Err(format!("Access token with scope {required} is required"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwks {
    keys: Vec<JwksKey>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct JwksKey {
    kid: String,
    kty: String,
    #[serde(rename = "use")]
    key_use: Option<String>,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
    attempted_at: Option<Instant>,
}

pub struct JwtValidator {
    oidc_issuer: String,
    expected_audience: String,
    allowed_algs: Vec<Algorithm>,
    jwks_cache: Arc<Mutex<KeyCache>>,
    jwks_uri: String,
    http_client: reqwest::Client,
}

impl JwtValidator {
    pub async fn new(
        oidc_issuer: String,
        expected_audience: String,
        allowed_algs: Vec<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        simple_idm_common::validate_identity_url(&oidc_issuer)?;
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        // Fetch OIDC discovery
        let discovery_url = format!("{}/.well-known/openid-configuration", oidc_issuer);
        tracing::debug!("Fetching OIDC discovery from {}", discovery_url);

        let discovery: OidcDiscovery = http_client.get(&discovery_url).send().await?.json().await?;

        simple_idm_common::validate_identity_url(&discovery.jwks_uri)?;
        tracing::info!("OIDC JWKS URI: {}", discovery.jwks_uri);

        // Parse allowed algorithms
        let allowed_algs: Vec<Algorithm> = allowed_algs
            .iter()
            .filter_map(|alg| match alg.as_str() {
                "RS256" => Some(Algorithm::RS256),
                "RS384" => Some(Algorithm::RS384),
                "RS512" => Some(Algorithm::RS512),
                "ES256" => Some(Algorithm::ES256),
                "ES384" => Some(Algorithm::ES384),
                _ => {
                    tracing::warn!("Unsupported algorithm: {}", alg);
                    None
                }
            })
            .collect();

        if allowed_algs.is_empty() {
            return Err("No valid signing algorithms configured".into());
        }

        Ok(Self {
            oidc_issuer,
            expected_audience,
            allowed_algs,
            jwks_cache: Arc::new(Mutex::new(KeyCache::default())),
            jwks_uri: discovery.jwks_uri,
            http_client,
        })
    }

    pub async fn validate_token(&self, token: &str) -> Result<TokenClaims, String> {
        // Decode header to get kid
        let header = decode_header(token).map_err(|e| format!("Invalid token header: {}", e))?;

        let kid = header
            .kid
            .ok_or_else(|| "Token missing kid in header".to_string())?;

        // Get decoding key (from cache or fetch)
        let decoding_key = self
            .get_decoding_key(&kid)
            .await
            .map_err(|e| format!("Failed to get decoding key for kid {}: {}", kid, e))?;

        // Validate token
        let mut validation = Validation::new(
            self.allowed_algs
                .first()
                .copied()
                .unwrap_or(Algorithm::RS256),
        );
        validation.set_issuer(&[&self.oidc_issuer]);
        validation.set_audience(&[&self.expected_audience]);
        validation.algorithms = self.allowed_algs.clone();
        validation.leeway = 0;

        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)
            .map_err(|e| format!("Token validation failed: {}", e))?;

        tracing::debug!(
            "Token validated successfully for sub: {}",
            token_data.claims.sub
        );

        Ok(token_data.claims)
    }

    async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey, Box<dyn std::error::Error>> {
        // The lock provides single-flight refresh, including misses for unknown kids.
        let mut cache = self.jwks_cache.lock().await;
        let fresh = cache
            .fetched_at
            .is_some_and(|at| at.elapsed() < Duration::from_secs(300));
        if fresh {
            if let Some(key) = cache.keys.get(kid) {
                return Ok(key.clone());
            }
        }
        if cache
            .attempted_at
            .is_some_and(|at| at.elapsed() < Duration::from_secs(30))
        {
            return Err("Signing key unavailable; refresh is rate limited".into());
        }
        cache.attempted_at = Some(Instant::now());
        let response = self
            .http_client
            .get(&self.jwks_uri)
            .send()
            .await?
            .error_for_status()?;
        if response
            .content_length()
            .is_some_and(|length| length > 1_048_576)
        {
            return Err("JWKS too large".into());
        }
        let bytes = response.bytes().await?;
        if bytes.len() > 1_048_576 {
            return Err("JWKS too large".into());
        }
        let jwks: Jwks = serde_json::from_slice(&bytes)?;
        let mut keys = HashMap::new();
        for key in jwks.keys {
            if key.kty != "RSA"
                || key.key_use.as_deref().is_some_and(|usage| usage != "sig")
                || key
                    .alg
                    .as_deref()
                    .is_some_and(|alg| !matches!(alg, "RS256" | "RS384" | "RS512"))
            {
                continue;
            }
            let decoding_key = DecodingKey::from_rsa_components(
                key.n.as_deref().ok_or("Missing RSA modulus")?,
                key.e.as_deref().ok_or("Missing RSA exponent")?,
            )?;
            if keys.insert(key.kid, decoding_key).is_some() {
                return Err("Duplicate signing key ID".into());
            }
        }
        // Replace the entire set so removed keys cannot remain trusted indefinitely.
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        cache
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| "Signing key not found".into())
    }

    pub async fn refresh_jwks(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut cache = self.jwks_cache.lock().await;
        cache.keys.clear();
        cache.fetched_at = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::get};
    use rsa::{
        RsaPrivateKey, RsaPublicKey,
        pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
        rand_core::OsRng,
    };

    #[tokio::test]
    async fn api_token_verifies_signature_audience_expiry_scope_and_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public = RsaPublicKey::from(&private);
        let private_path = dir.path().join("private.pem");
        let public_path = dir.path().join("public.pem");
        std::fs::write(
            &private_path,
            private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::write(
            &public_path,
            public.to_public_key_pem(LineEnding::LF).unwrap(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let jwt = crate::auth::jwt::JwtService::new(
            private_path.to_str().unwrap(),
            public_path.to_str().unwrap(),
            issuer.clone(),
            "test".into(),
            vec![],
        )
        .unwrap();
        let jwks = serde_json::to_value(jwt.get_jwks().unwrap()).unwrap();
        let uri = format!("{issuer}/jwks");
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move { Json(serde_json::json!({"jwks_uri":uri})) }),
            )
            .route("/jwks", get(move || async move { Json(jwks) }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let validator = JwtValidator::new(issuer, "bastion".into(), vec!["RS256".into()])
            .await
            .unwrap();
        let make_token = |aud: &str, scope: &str, ttl: i64| {
            jwt.create_access_token(
                uuid::Uuid::new_v4(),
                aud.into(),
                None,
                Some("alice".into()),
                Some(scope.into()),
                vec!["infra".into()],
                HashMap::from([("tenant_id".into(), serde_json::json!("tenant-a"))]),
                vec![],
                None,
                ttl,
            )
            .unwrap()
        };
        let token = make_token("bastion", "openid bastion:connect", 3600);
        let claims = validator.validate_token(&token).await.unwrap();
        assert_eq!(claims.tenant_id.as_deref(), Some("tenant-a"));
        assert!(claims.require_access_scope("bastion:connect").is_ok());
        assert!(claims.require_access_scope("bastion:admin").is_err());
        assert!(
            validator
                .validate_token(&make_token("another-client", "bastion:connect", 3600))
                .await
                .is_err()
        );
        assert!(
            validator
                .validate_token(&make_token("bastion", "bastion:connect", -10))
                .await
                .is_err()
        );
        let mut id_claims = claims;
        id_claims.nonce = Some("oidc-nonce".into());
        assert!(id_claims.require_access_scope("bastion:connect").is_err());
        server.abort();
    }
}
