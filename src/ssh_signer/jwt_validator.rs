use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

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

pub struct JwtValidator {
    oidc_issuer: String,
    expected_audience: String,
    allowed_algs: Vec<Algorithm>,
    jwks_cache: Arc<RwLock<HashMap<String, DecodingKey>>>,
    jwks_uri: String,
    http_client: reqwest::Client,
}

impl JwtValidator {
    pub async fn new(
        oidc_issuer: String,
        expected_audience: String,
        allowed_algs: Vec<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let http_client = reqwest::Client::new();

        // Fetch OIDC discovery
        let discovery_url = format!("{}/.well-known/openid-configuration", oidc_issuer);
        tracing::debug!("Fetching OIDC discovery from {}", discovery_url);

        let discovery: OidcDiscovery = http_client
            .get(&discovery_url)
            .send()
            .await?
            .json()
            .await?;

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
            jwks_cache: Arc::new(RwLock::new(HashMap::new())),
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
        let decoding_key = self.get_decoding_key(&kid).await.map_err(|e| {
            format!("Failed to get decoding key for kid {}: {}", kid, e)
        })?;

        // Validate token
        let mut validation = Validation::new(
            self.allowed_algs
                .get(0)
                .copied()
                .unwrap_or(Algorithm::RS256),
        );
        validation.set_issuer(&[&self.oidc_issuer]);
        validation.set_audience(&[&self.expected_audience]);
        validation.algorithms = self.allowed_algs.clone();

        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)
            .map_err(|e| format!("Token validation failed: {}", e))?;

        tracing::debug!(
            "Token validated successfully for sub: {}",
            token_data.claims.sub
        );

        Ok(token_data.claims)
    }

    async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey, Box<dyn std::error::Error>> {
        // Check cache first
        {
            let cache = self.jwks_cache.read().await;
            if let Some(key) = cache.get(kid) {
                return Ok(key.clone());
            }
        }

        // Fetch JWKS
        tracing::debug!("Fetching JWKS from {}", self.jwks_uri);
        let jwks: Jwks = self
            .http_client
            .get(&self.jwks_uri)
            .send()
            .await?
            .json()
            .await?;

        // Find key with matching kid
        let jwks_key = jwks
            .keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| format!("Key with kid {} not found in JWKS", kid))?;

        // Convert to DecodingKey
        let decoding_key = match jwks_key.kty.as_str() {
            "RSA" => {
                let n = jwks_key
                    .n
                    .as_ref()
                    .ok_or("Missing n in RSA key")?;
                let e = jwks_key
                    .e
                    .as_ref()
                    .ok_or("Missing e in RSA key")?;

                DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| format!("Failed to create RSA key: {}", e))?
            }
            kty => return Err(format!("Unsupported key type: {}", kty).into()),
        };

        // Cache the key
        {
            let mut cache = self.jwks_cache.write().await;
            cache.insert(kid.to_string(), decoding_key.clone());
        }

        tracing::info!("Cached decoding key for kid: {}", kid);

        Ok(decoding_key)
    }

    pub async fn refresh_jwks(&self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Refreshing JWKS cache");
        let mut cache = self.jwks_cache.write().await;
        cache.clear();
        Ok(())
    }
}
