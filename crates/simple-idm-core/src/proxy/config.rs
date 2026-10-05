use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(skip)]
    pub config_file: PathBuf,

    // Server settings
    #[serde(default)]
    pub mode: ProxyMode,
    pub listen_addr: String,
    pub public_base_url: String,
    #[serde(default)]
    pub upstream_url: Option<String>,
    #[serde(default = "default_protected_prefixes")]
    pub protected_prefixes: Vec<String>,
    #[serde(default)]
    pub public_prefixes: Vec<String>,
    #[serde(default = "default_upstream_timeout_secs")]
    pub upstream_timeout_secs: u64,

    // Cookie settings
    pub cookie_name: String,
    pub cookie_secret: String,
    pub cookie_samesite: String,
    pub session_max_age: i64,

    // Session backend
    pub session_backend: SessionBackend,
    pub session_sqlite_path: Option<PathBuf>,

    // OIDC provider
    pub oidc_issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_path: String,
    pub scopes: Vec<String>,

    // Claim mapping
    pub groups_claim: String,
    pub username_claims: Vec<String>,
    pub email_claim: String,

    // Header behavior
    pub pass_token_header: bool,
    pub groups_header_name: String,
    pub groups_header_format: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    AuthRequest,
    ReverseProxy,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionBackend {
    Memory,
    Sqlite,
}

fn default_protected_prefixes() -> Vec<String> {
    vec!["/".into()]
}

fn default_upstream_timeout_secs() -> u64 {
    300
}

impl Config {
    pub fn load() -> Result<Self> {
        // Try to find config file
        let config_file = Self::find_config_file()?;

        // Read config file
        let config_content = std::fs::read_to_string(&config_file)
            .with_context(|| format!("Failed to read config file: {}", config_file.display()))?;

        let mut config: Config = toml::from_str(&config_content)
            .with_context(|| format!("Failed to parse config file: {}", config_file.display()))?;

        config.config_file = config_file;

        // Override with environment variables
        Self::apply_env_overrides(&mut config);

        // Validate
        config.validate()?;

        Ok(config)
    }

    fn find_config_file() -> Result<PathBuf> {
        // Check environment variable
        if let Ok(path) = std::env::var("OAUTH2_PROXY_CONFIG") {
            return Ok(PathBuf::from(path));
        }

        // Check common locations
        let candidates = vec![
            PathBuf::from("./config.toml"),
            PathBuf::from("./oauth2-proxy.toml"),
            PathBuf::from("/etc/simple-idm-oauth2-proxy/config.toml"),
        ];

        for candidate in candidates {
            if candidate.exists() {
                return Ok(candidate);
            }
        }

        anyhow::bail!("Config file not found. Set OAUTH2_PROXY_CONFIG or create config.toml");
    }

    fn apply_env_overrides(config: &mut Config) {
        if let Ok(val) = std::env::var("LISTEN_ADDR") {
            config.listen_addr = val;
        }
        if let Ok(val) = std::env::var("OAUTH2_PROXY_MODE") {
            config.mode = match val.as_str() {
                "auth_request" => ProxyMode::AuthRequest,
                "reverse_proxy" => ProxyMode::ReverseProxy,
                other => {
                    tracing::warn!("Ignoring unsupported OAUTH2_PROXY_MODE={}", other);
                    config.mode.clone()
                }
            };
        }
        if let Ok(val) = std::env::var("PUBLIC_BASE_URL") {
            config.public_base_url = val;
        }
        if let Ok(val) = std::env::var("UPSTREAM_URL") {
            config.upstream_url = Some(val);
        }
        if let Ok(val) = std::env::var("OIDC_ISSUER") {
            config.oidc_issuer = val;
        }
        if let Ok(val) = std::env::var("CLIENT_ID") {
            config.client_id = val;
        }
        if let Ok(val) = std::env::var("CLIENT_SECRET") {
            config.client_secret = val;
        }
        if let Ok(val) = std::env::var("COOKIE_SECRET") {
            config.cookie_secret = val;
        }
    }

    fn validate(&self) -> Result<()> {
        // Validate cookie_secret length
        if self.cookie_secret.len() < 32 {
            anyhow::bail!("cookie_secret must be at least 32 characters");
        }

        simple_idm_common::validate_identity_url(&self.public_base_url)
            .map_err(anyhow::Error::msg)?;
        simple_idm_common::validate_identity_url(&self.oidc_issuer).map_err(anyhow::Error::msg)?;

        // Validate URLs
        if !self.public_base_url.starts_with("http://")
            && !self.public_base_url.starts_with("https://")
        {
            anyhow::bail!("public_base_url must start with http:// or https://");
        }

        if !self.oidc_issuer.starts_with("http://") && !self.oidc_issuer.starts_with("https://") {
            anyhow::bail!("oidc_issuer must start with http:// or https://");
        }

        // Validate session backend
        if self.session_backend == SessionBackend::Sqlite && self.session_sqlite_path.is_none() {
            anyhow::bail!("session_sqlite_path is required when session_backend is sqlite");
        }

        if self.session_max_age <= 0 {
            anyhow::bail!("session_max_age must be positive");
        }
        if self.protected_prefixes.is_empty() {
            anyhow::bail!(
                "protected_prefixes must not be empty; use explicit public_prefixes for public paths"
            );
        }
        for prefix in self.protected_prefixes.iter().chain(&self.public_prefixes) {
            if !prefix.starts_with('/')
                || prefix.contains(['%', '?', '#', '\\'])
                || prefix.contains("//")
                || prefix.split('/').any(|part| part == "." || part == "..")
            {
                anyhow::bail!("Path prefixes must be canonical absolute paths");
            }
        }
        if self.public_prefixes.iter().any(|prefix| prefix == "/") {
            anyhow::bail!("public_prefixes must not expose the entire proxy");
        }
        if self.mode == ProxyMode::ReverseProxy {
            let Some(upstream_url) = self.upstream_url.as_ref() else {
                anyhow::bail!("upstream_url is required when mode is reverse_proxy");
            };
            if !upstream_url.starts_with("http://") && !upstream_url.starts_with("https://") {
                anyhow::bail!("upstream_url must start with http:// or https://");
            }
        }

        Ok(())
    }
}

impl Default for ProxyMode {
    fn default() -> Self {
        Self::AuthRequest
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_file: PathBuf::from("config.toml"),
            mode: ProxyMode::AuthRequest,
            listen_addr: "127.0.0.1:4180".to_string(),
            public_base_url: "https://legacy-app.example.com".to_string(),
            upstream_url: None,
            protected_prefixes: vec!["/".to_string()],
            public_prefixes: vec!["/healthz".to_string()],
            upstream_timeout_secs: default_upstream_timeout_secs(),
            cookie_name: "__Host_simple_idm_sso".to_string(),
            cookie_secret: "CHANGE_ME_TO_RANDOM_32_PLUS_CHARS".to_string(),
            cookie_samesite: "Lax".to_string(),
            session_max_age: 3600,
            session_backend: SessionBackend::Memory,
            session_sqlite_path: None,
            oidc_issuer: "https://sso.example.com".to_string(),
            client_id: "legacy-app-edge".to_string(),
            client_secret: "CHANGE_ME".to_string(),
            redirect_path: "/callback".to_string(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "groups".to_string(),
            ],
            groups_claim: "groups".to_string(),
            username_claims: vec!["preferred_username".to_string(), "sub".to_string()],
            email_claim: "email".to_string(),
            pass_token_header: false,
            groups_header_name: "X-Auth-Groups".to_string(),
            groups_header_format: "csv".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_request_mode_does_not_require_upstream_url() {
        let mut config = Config::default();
        config.mode = ProxyMode::AuthRequest;
        config.upstream_url = None;

        config.validate().unwrap();
    }

    #[test]
    fn reverse_proxy_mode_requires_upstream_url() {
        let mut config = Config::default();
        config.mode = ProxyMode::ReverseProxy;
        config.upstream_url = None;

        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("upstream_url is required"));
    }

    #[test]
    fn reverse_proxy_mode_accepts_http_upstream_url() {
        let mut config = Config::default();
        config.mode = ProxyMode::ReverseProxy;
        config.upstream_url = Some("http://127.0.0.1:3000".to_string());

        config.validate().unwrap();
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    #[test]
    fn omitted_protection_keeps_secure_default_and_empty_is_rejected() {
        let mut serialized = toml::Value::try_from(Config::default()).unwrap();
        serialized
            .as_table_mut()
            .unwrap()
            .remove("protected_prefixes");
        let config: Config = serialized.try_into().unwrap();
        assert_eq!(config.protected_prefixes, vec!["/"]);
        let config = Config {
            protected_prefixes: vec![],
            ..config
        };
        assert!(config.validate().is_err());
    }
}
