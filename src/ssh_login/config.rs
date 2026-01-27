use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshLoginConfig {
    pub oidc_issuer: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub signer_url: String,
    pub ttl_seconds: u64,
}

impl SshLoginConfig {
    pub fn load() -> Result<Self, String> {
        // Try loading from config file first
        if let Ok(config) = Self::load_from_file() {
            return Ok(config);
        }

        // Fallback to defaults with env overrides
        Ok(Self::default_with_env())
    }

    fn load_from_file() -> Result<Self, String> {
        let config_path = dirs::config_dir()
            .ok_or("Cannot determine config directory")?
            .join("simple-idm-ssh-login")
            .join("config.toml");

        if !config_path.exists() {
            return Err("Config file not found".to_string());
        }

        let content = std::fs::read_to_string(&config_path)
            .map_err(|e| format!("Failed to read config: {}", e))?;

        let config: Self = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config: {}", e))?;

        Ok(Self::apply_env_overrides(config))
    }

    fn default_with_env() -> Self {
        let config = Self {
            oidc_issuer: "http://localhost:8080".to_string(),
            client_id: "simple-idm-ssh-login".to_string(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "groups".to_string(),
            ],
            signer_url: "http://localhost:9222".to_string(),
            ttl_seconds: 3600,
        };

        Self::apply_env_overrides(config)
    }

    fn apply_env_overrides(mut config: Self) -> Self {
        if let Ok(issuer) = std::env::var("OIDC_ISSUER") {
            config.oidc_issuer = issuer;
        }
        if let Ok(client_id) = std::env::var("CLIENT_ID") {
            config.client_id = client_id;
        }
        if let Ok(signer_url) = std::env::var("SIGNER_URL") {
            config.signer_url = signer_url;
        }
        if let Ok(ttl) = std::env::var("TTL_SECONDS") {
            if let Ok(ttl_num) = ttl.parse() {
                config.ttl_seconds = ttl_num;
            }
        }

        config
    }

    pub fn ssh_key_path(&self) -> PathBuf {
        let base_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("simple-idm-ssh-login")
            .join("keys");
        base_dir.join("id_simpleidm")
    }

    pub fn cert_path(&self) -> PathBuf {
        let mut path = self.ssh_key_path();
        let filename = path.file_name().unwrap().to_str().unwrap();
        path.set_file_name(format!("{}-cert.pub", filename));
        path
    }

    pub fn public_key_path(&self) -> PathBuf {
        let mut path = self.ssh_key_path();
        let filename = path.file_name().unwrap().to_str().unwrap();
        path.set_file_name(format!("{}.pub", filename));
        path
    }
}
