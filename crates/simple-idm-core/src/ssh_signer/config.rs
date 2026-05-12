use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct SshSignerConfig {
    /// Listen address (e.g. "127.0.0.1:9222")
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// OIDC issuer URL
    #[serde(default)]
    pub oidc_issuer: String,

    /// Expected audience (client_id)
    #[serde(default)]
    pub expected_audience: String,

    /// Allowed signing algorithms
    #[serde(default = "default_allowed_algs")]
    pub allowed_algs: Vec<String>,

    /// CA private key path
    #[serde(default)]
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

    /// Require explicit SSH principal/role in groups (disable username/email fallback)
    #[serde(default)]
    pub require_explicit_ssh_principal: bool,

    /// Allow mapping ssh:role:<role> -> role:<role> principal
    #[serde(default = "default_allow_ssh_role_principals")]
    pub allow_ssh_role_principals: bool,

    /// SSH certificate key ID (`ssh-keygen -I`)
    #[serde(default = "default_cert_key_id")]
    pub cert_key_id: String,

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

fn default_allow_ssh_role_principals() -> bool {
    true
}

fn default_cert_key_id() -> String {
    "simple-idm-cert".to_string()
}

impl Default for SshSignerConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            oidc_issuer: String::new(),
            expected_audience: String::new(),
            allowed_algs: default_allowed_algs(),
            ca_private_key_path: PathBuf::new(),
            ca_public_key_path: None,
            default_ttl_seconds: default_ttl(),
            max_ttl_seconds: default_max_ttl(),
            clock_skew_seconds: default_clock_skew(),
            max_principals: default_max_principals(),
            principal_max_len: default_principal_max_len(),
            require_explicit_ssh_principal: false,
            allow_ssh_role_principals: default_allow_ssh_role_principals(),
            cert_key_id: default_cert_key_id(),
            permit_port_forwarding: false,
            permit_agent_forwarding: false,
            permit_x11_forwarding: false,
            permit_user_rc: false,
        }
    }
}

impl SshSignerConfig {
    /// Load config from optional file path, env vars, or defaults
    /// Priority: env vars > config file > defaults
    pub fn load(config_path: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = if let Some(path) = config_path {
            // Explicit config path provided
            tracing::info!("Loading config from: {}", path);
            let config_str = std::fs::read_to_string(path)
                .map_err(|e| format!("Failed to read config from {}: {}", path, e))?;

            toml::from_str(&config_str).map_err(|e| format!("Failed to parse config: {}", e))?
        } else {
            // Try default locations
            let default_paths = vec![
                "/etc/simple-idm-ssh-signer/config.toml",
                "config.ssh-signer.toml",
                "./config.example.ssh-signer.toml",
            ];

            let mut loaded_config = None;
            for path in &default_paths {
                if std::path::Path::new(path).exists() {
                    tracing::info!("Loading config from default location: {}", path);
                    let config_str = std::fs::read_to_string(path).ok();
                    if let Some(content) = config_str {
                        if let Ok(cfg) = toml::from_str(&content) {
                            loaded_config = Some(cfg);
                            break;
                        }
                    }
                }
            }

            loaded_config.unwrap_or_else(|| {
                tracing::warn!("No config file found, using defaults + env vars");
                Self::default()
            })
        };

        // Env overrides (highest priority after CLI args)
        if let Ok(addr) = std::env::var("LISTEN_ADDR") {
            config.listen_addr = addr;
        }
        if let Ok(issuer) = std::env::var("OIDC_ISSUER") {
            config.oidc_issuer = issuer;
        }
        if let Ok(aud) = std::env::var("EXPECTED_AUDIENCE") {
            config.expected_audience = aud;
        }
        if let Ok(key_path) = std::env::var("CA_PRIVATE_KEY_PATH") {
            config.ca_private_key_path = PathBuf::from(key_path);
        }
        if let Ok(ca_public_key_path) = std::env::var("CA_PUBLIC_KEY_PATH") {
            config.ca_public_key_path = Some(PathBuf::from(ca_public_key_path));
        }
        if let Ok(algs) = std::env::var("ALLOWED_ALGS") {
            let parsed: Vec<String> = algs
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !parsed.is_empty() {
                config.allowed_algs = parsed;
            }
        }
        if let Ok(default_ttl_seconds) = std::env::var("DEFAULT_TTL_SECONDS") {
            if let Ok(v) = default_ttl_seconds.parse::<u64>() {
                config.default_ttl_seconds = v;
            }
        }
        if let Ok(max_ttl_seconds) = std::env::var("MAX_TTL_SECONDS") {
            if let Ok(v) = max_ttl_seconds.parse::<u64>() {
                config.max_ttl_seconds = v;
            }
        }
        if let Ok(clock_skew_seconds) = std::env::var("CLOCK_SKEW_SECONDS") {
            if let Ok(v) = clock_skew_seconds.parse::<u64>() {
                config.clock_skew_seconds = v;
            }
        }
        if let Ok(max_principals) = std::env::var("MAX_PRINCIPALS") {
            if let Ok(v) = max_principals.parse::<usize>() {
                config.max_principals = v;
            }
        }
        if let Ok(principal_max_len) = std::env::var("PRINCIPAL_MAX_LEN") {
            if let Ok(v) = principal_max_len.parse::<usize>() {
                config.principal_max_len = v;
            }
        }
        if let Ok(require_explicit) = std::env::var("REQUIRE_EXPLICIT_SSH_PRINCIPAL") {
            if let Ok(v) = require_explicit.parse::<bool>() {
                config.require_explicit_ssh_principal = v;
            }
        }
        if let Ok(allow_roles) = std::env::var("ALLOW_SSH_ROLE_PRINCIPALS") {
            if let Ok(v) = allow_roles.parse::<bool>() {
                config.allow_ssh_role_principals = v;
            }
        }
        if let Ok(cert_key_id) = std::env::var("CERT_KEY_ID") {
            config.cert_key_id = cert_key_id;
        }
        if let Ok(permit_port_forwarding) = std::env::var("PERMIT_PORT_FORWARDING") {
            if let Ok(v) = permit_port_forwarding.parse::<bool>() {
                config.permit_port_forwarding = v;
            }
        }
        if let Ok(permit_agent_forwarding) = std::env::var("PERMIT_AGENT_FORWARDING") {
            if let Ok(v) = permit_agent_forwarding.parse::<bool>() {
                config.permit_agent_forwarding = v;
            }
        }
        if let Ok(permit_x11_forwarding) = std::env::var("PERMIT_X11_FORWARDING") {
            if let Ok(v) = permit_x11_forwarding.parse::<bool>() {
                config.permit_x11_forwarding = v;
            }
        }
        if let Ok(permit_user_rc) = std::env::var("PERMIT_USER_RC") {
            if let Ok(v) = permit_user_rc.parse::<bool>() {
                config.permit_user_rc = v;
            }
        }

        // Validate required fields
        if config.oidc_issuer.is_empty() {
            return Err(
                "OIDC issuer is required (set via config file, env OIDC_ISSUER, or --oidc-issuer)"
                    .into(),
            );
        }
        if config.expected_audience.is_empty() {
            return Err("Expected audience is required (set via config file, env EXPECTED_AUDIENCE, or --expected-audience)".into());
        }
        if config.ca_private_key_path.as_os_str().is_empty() {
            return Err("CA private key path is required (set via config file, env CA_PRIVATE_KEY_PATH, or --ca-private-key-path)".into());
        }
        if config.cert_key_id.trim().is_empty() {
            return Err("Certificate key ID is required (set via config file cert_key_id or env CERT_KEY_ID)".into());
        }

        Ok(config)
    }
}
