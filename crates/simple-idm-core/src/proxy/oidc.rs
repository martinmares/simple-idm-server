use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use openidconnect::OAuth2TokenResponse;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenResponse as OidcTokenResponse,
    core::{CoreAuthenticationFlow, CoreIdToken, CoreIdTokenClaims, CoreProviderMetadata},
    reqwest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use super::config::Config;
use super::session::FlowState;

pub struct OidcClient {
    provider_metadata: CoreProviderMetadata,
    http_client: reqwest::Client,
    config: Config,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub subject: String,
    pub username: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RefreshResult {
    pub subject: String,
    pub username: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub refresh_token: Option<String>,
}

impl OidcClient {
    pub async fn new(config: &Config) -> Result<Self> {
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .context("Failed to build OIDC HTTP client")?;

        // Discover OIDC provider metadata
        let issuer_url =
            IssuerUrl::new(config.oidc_issuer.clone()).context("Invalid issuer URL")?;

        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
            .await
            .context("Failed to discover OIDC provider metadata")?;

        for endpoint in [
            Some(provider_metadata.authorization_endpoint().as_str()),
            provider_metadata.token_endpoint().map(|url| url.as_str()),
            Some(provider_metadata.jwks_uri().as_str()),
            provider_metadata
                .userinfo_endpoint()
                .map(|url| url.as_str()),
        ]
        .into_iter()
        .flatten()
        {
            simple_idm_common::validate_identity_url(endpoint).map_err(anyhow::Error::msg)?;
        }
        tracing::debug!("OIDC client created for issuer: {}", config.oidc_issuer);

        Ok(Self {
            provider_metadata,
            http_client,
            config: config.clone(),
        })
    }

    pub async fn start_flow(&self, redirect_url: &str) -> Result<(String, FlowState)> {
        let callback_redirect_url = format!(
            "{}{}",
            self.config.public_base_url, self.config.redirect_path
        );
        let callback_redirect_url =
            RedirectUrl::new(callback_redirect_url).context("Invalid redirect URL")?;
        let client = openidconnect::core::CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
        )
        .set_redirect_uri(callback_redirect_url);

        // Generate PKCE challenge
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate nonce
        let nonce = Nonce::new_random();

        // Generate state
        let state = CsrfToken::new_random();

        // Clone for closures
        let state_clone = state.clone();
        let nonce_clone = nonce.clone();

        // Build authorization URL
        let mut auth_request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                move || state_clone.clone(),
                move || nonce_clone.clone(),
            )
            .set_pkce_challenge(pkce_challenge);

        // Add scopes
        for scope in &self.config.scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        let (auth_url, _csrf_token, _nonce) = auth_request.url();

        let flow_state = FlowState {
            state: state.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
            redirect_url: redirect_url.to_string(),
            created_at: Utc::now(),
        };

        Ok((auth_url.to_string(), flow_state))
    }

    pub async fn exchange_code(&self, code: &str, flow_state: &FlowState) -> Result<TokenResponse> {
        let redirect_url = format!(
            "{}{}",
            self.config.public_base_url, self.config.redirect_path
        );
        let redirect_url = RedirectUrl::new(redirect_url).context("Invalid redirect URL")?;
        let client = openidconnect::core::CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
        )
        .set_redirect_uri(redirect_url);

        // Exchange code for tokens
        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .context("Failed to build token exchange request")?
            .set_pkce_verifier(PkceCodeVerifier::new(flow_state.pkce_verifier.clone()))
            .request_async(&self.http_client)
            .await
            .context("Failed to exchange authorization code for tokens")?;

        // Extract ID token
        let id_token = token_response
            .id_token()
            .context("No ID token in response")?;

        // Verify ID token
        let (standard_claims, raw_claims) =
            self.verify_id_token(id_token, &client.id_token_verifier(), &flow_state.nonce)?;

        // Extract claims
        let subject = standard_claims.subject().to_string();

        // Extract username (try preferred_username, then sub)
        let username = self.extract_username(&standard_claims, &raw_claims)?;

        // Extract email
        let email = standard_claims.email().map(|e| e.as_str()).and_then(|e| {
            if e.is_empty() {
                None
            } else {
                Some(e.to_string())
            }
        });

        // Extract groups
        let groups = self.extract_groups(&raw_claims)?;

        tracing::debug!(
            "Token exchange successful for user: {}, groups: {:?}",
            username,
            groups
        );

        Ok(TokenResponse {
            subject,
            username,
            email,
            groups,
            issued_at: Utc::now(),
            refresh_token: token_response
                .refresh_token()
                .map(|token| token.secret().to_string()),
        })
    }

    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        expected_subject: &str,
    ) -> Result<RefreshResult> {
        let redirect_url = format!(
            "{}{}",
            self.config.public_base_url, self.config.redirect_path
        );
        let redirect_url = RedirectUrl::new(redirect_url).context("Invalid redirect URL")?;
        let client = openidconnect::core::CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
        )
        .set_redirect_uri(redirect_url);

        let token_response = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .context("Failed to build refresh token request")?
            .request_async(&self.http_client)
            .await
            .context("Failed to refresh token")?;

        let endpoint = self
            .provider_metadata
            .userinfo_endpoint()
            .context("UserInfo is required to renew authorization claims")?;
        simple_idm_common::validate_identity_url(endpoint.as_str()).map_err(anyhow::Error::msg)?;
        let response = self
            .http_client
            .get(endpoint.url().clone())
            .bearer_auth(token_response.access_token().secret())
            .send()
            .await?
            .error_for_status()?;
        let claims: HashMap<String, Value> = serde_json::from_slice(&response.bytes().await?)
            .context("Invalid UserInfo response")?;
        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .context("Missing UserInfo subject")?;
        if subject != expected_subject {
            anyhow::bail!("UserInfo subject changed during refresh");
        }
        let username = self
            .config
            .username_claims
            .iter()
            .find_map(|key| {
                claims
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
            })
            .unwrap_or(subject)
            .to_owned();
        let email = claims
            .get(&self.config.email_claim)
            .and_then(Value::as_str)
            .map(str::to_owned);
        let groups = self.extract_groups(&claims)?;
        Ok(RefreshResult {
            subject: subject.to_owned(),
            username,
            email,
            groups,
            refresh_token: token_response
                .refresh_token()
                .map(|token| token.secret().to_string()),
        })
    }

    fn verify_id_token(
        &self,
        id_token: &CoreIdToken,
        id_token_verifier: &openidconnect::core::CoreIdTokenVerifier,
        expected_nonce: &str,
    ) -> Result<(CoreIdTokenClaims, HashMap<String, Value>)> {
        let claims = id_token
            .claims(id_token_verifier, &Nonce::new(expected_nonce.to_string()))
            .context("Failed to verify ID token")?;

        // Parse raw claims to get additional fields
        let raw_claims = self.parse_raw_claims(id_token)?;

        Ok((claims.clone(), raw_claims))
    }

    fn parse_raw_claims(&self, id_token: &CoreIdToken) -> Result<HashMap<String, Value>> {
        // Decode JWT without verification (already verified above)
        let token_str = id_token.to_string();
        let parts: Vec<&str> = token_str.split('.').collect();

        if parts.len() != 3 {
            anyhow::bail!("Invalid JWT format");
        }

        // Decode payload (base64url)
        let payload =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
                .context("Failed to decode JWT payload")?;

        let claims: HashMap<String, Value> =
            serde_json::from_slice(&payload).context("Failed to parse JWT claims")?;

        Ok(claims)
    }

    fn extract_username(
        &self,
        standard_claims: &CoreIdTokenClaims,
        raw_claims: &HashMap<String, Value>,
    ) -> Result<String> {
        // Try username_claims in order
        for claim_name in &self.config.username_claims {
            if claim_name == "sub" {
                return Ok(standard_claims.subject().to_string());
            }

            if let Some(value) = raw_claims.get(claim_name) {
                if let Some(username) = value.as_str() {
                    if !username.is_empty() {
                        return Ok(username.to_string());
                    }
                }
            }
        }

        // Fallback to sub
        Ok(standard_claims.subject().to_string())
    }

    fn extract_groups(&self, raw_claims: &HashMap<String, Value>) -> Result<Vec<String>> {
        if let Some(groups_value) = raw_claims.get(&self.config.groups_claim) {
            return self.parse_groups_claim(groups_value);
        }

        // No groups found
        Ok(Vec::new())
    }

    fn parse_groups_claim(&self, value: &Value) -> Result<Vec<String>> {
        match value {
            Value::Array(arr) => {
                let groups: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                Ok(groups)
            }
            Value::String(s) => {
                // Single group as string
                Ok(vec![s.clone()])
            }
            _ => {
                tracing::warn!("Unexpected groups claim type: {:?}", value);
                Ok(Vec::new())
            }
        }
    }
}
