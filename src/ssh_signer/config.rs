use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct SshSignerConfig {
    /// Listen address (e.g. "127.0.0.1:9222")
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// OIDC issuer URL
    pub oidc_issuer: String,

    /// Expected audience (client_id)
    pub expected_audience: String,

    /// Allowed signing algorithms
    #[serde(default = "default_allowed_algs")]
    pub allowed_algs: Vec<String>,

    /// CA private key path
    pub ca_private_key_path: PathBuf,

    /// CA public key path (optional, can be derived from private)
    pub ca_public_key_path: Option<PathBuf>,

    /// Default certificate TTL in seconds
    #[serde(default = "default_ttl")]
    pub default_ttl_seconds: u64,

    /// Maximum certificate TTL in seconds
    #[serde(default = "default_max_ttl")]
    pub max_ttl_seconds: u64,

    /// Clock skew tolerance in seconds
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,

    /// Maximum number of principals per certificate
    #[serde(default = "default_max_principals")]
    pub max_principals: usize,

    /// Maximum principal name length
    #[serde(default = "default_principal_max_len")]
    pub principal_max_len: usize,

    /// SSH certificate extensions
    #[serde(default)]
    pub permit_port_forwarding: bool,

    #[serde(default)]
    pub permit_agent_forwarding: bool,

    #[serde(default)]
    pub permit_x11_forwarding: bool,

    #[serde(default)]
    pub permit_user_rc: bool,
}

fn default_listen_addr() -> String {
    "127.0.0.1:9222".to_string()
}

fn default_allowed_algs() -> Vec<String> {
    vec!["RS256".to_string()]
}

fn default_ttl() -> u64 {
    3600 // 1 hour
}

fn default_max_ttl() -> u64 {
    28800 // 8 hours
}

fn default_clock_skew() -> u64 {
    30
}

fn default_max_principals() -> usize {
    32
}

fn default_principal_max_len() -> usize {
    64
}

impl SshSignerConfig {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        // Load from env var CONFIG_PATH or default location
        let config_path = std::env::var("SSH_SIGNER_CONFIG")
            .unwrap_or_else(|_| "/etc/simple-idm-ssh-signer/config.toml".to_string());

        let config_str = std::fs::read_to_string(&config_path)
            .map_err(|e| format!("Failed to read config from {}: {}", config_path, e))?;

        let mut config: SshSignerConfig = toml::from_str(&config_str)
            .map_err(|e| format!("Failed to parse config: {}", e))?;

        // Env overrides
        if let Ok(addr) = std::env::var("LISTEN_ADDR") {
            config.listen_addr = addr;
        }
        if let Ok(issuer) = std::env::var("OIDC_ISSUER") {
            config.oidc_issuer = issuer;
        }
        if let Ok(aud) = std::env::var("EXPECTED_AUDIENCE") {
            config.expected_audience = aud;
        }

        Ok(config)
    }

    pub fn config_source(&self) -> String {
        std::env::var("SSH_SIGNER_CONFIG")
            .unwrap_or_else(|_| "/etc/simple-idm-ssh-signer/config.toml".to_string())
    }
}
