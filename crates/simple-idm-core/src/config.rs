use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub rate_limit: RateLimitConfig,
    pub admin: AdminConfig,
    pub device_flow: DeviceFlowConfig,
    pub group_patterns: GroupPatternsConfig,
    pub soft_delete_purge: SoftDeletePurgeConfig,
    pub ui: UiConfig,
    pub identity: IdentityConfig,
    pub onboarding: OnboardingConfig,
    pub security: SecurityConfig,
    pub auth_protection: AuthProtectionConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub issuer: String,
    pub access_token_expiry_seconds: i64,
    pub refresh_token_expiry_seconds: i64,
    pub refresh_token_cleanup_interval_seconds: u64,
    pub auth_session_expiry_seconds: i64, // SSO session duration
    pub private_key_path: String,
    pub public_key_path: String,
    pub key_id: String,                                // kid for JWKS
    pub additional_public_keys: Vec<(String, String)>, // (kid, public_key_path)
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub token_endpoint_requests_per_second: u32,
    pub token_endpoint_burst_size: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    pub root_token: Option<String>,
    pub allow_legacy_admin_group: bool,
    pub allow_admin_substring_claim: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceFlowConfig {
    pub expiry_seconds: i64,
    pub polling_interval_seconds: i64,
    pub user_code_length: usize,
    pub user_code_format: String,
    pub cleanup_interval_seconds: u64,
    pub max_verification_attempts: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GroupPatternsConfig {
    pub sync_interval_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SoftDeletePurgeConfig {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub retention_days: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UiConfig {
    pub brand_name: String,
    pub brand_domain: Option<String>,
    pub page_title: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    pub allow_username_login: bool,
    pub allowed_email_domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingConfig {
    pub token_ttl_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub app_env: String,
    pub trust_proxy_headers: bool,
    pub force_secure_cookies: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthProtectionConfig {
    pub enabled: bool,
    pub failure_window_seconds: i64,
    pub max_failures: i32,
    pub lockout_seconds: i64,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let server_host = env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let server_port = env::var("SERVER_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .unwrap_or(8080);

        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/simple_idm".to_string());

        let jwt_issuer =
            env::var("JWT_ISSUER").unwrap_or_else(|_| "http://localhost:8080".to_string());
        let access_token_expiry = env::var("ACCESS_TOKEN_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "3600".to_string())
            .parse()
            .unwrap_or(3600);
        let refresh_token_expiry = env::var("REFRESH_TOKEN_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "2592000".to_string()) // 30 days
            .parse()
            .unwrap_or(2592000);
        let refresh_token_cleanup_interval = env::var("REFRESH_TOKEN_CLEANUP_INTERVAL_SECONDS")
            .unwrap_or_else(|_| "0".to_string())
            .parse()
            .unwrap_or(0);
        let auth_session_expiry = env::var("AUTH_SESSION_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "3600".to_string()) // 1 hour default
            .parse()
            .unwrap_or(3600);
        let private_key_path =
            env::var("JWT_PRIVATE_KEY_PATH").unwrap_or_else(|_| "./keys/private.pem".to_string());
        let public_key_path =
            env::var("JWT_PUBLIC_KEY_PATH").unwrap_or_else(|_| "./keys/public.pem".to_string());
        let key_id = env::var("JWT_KEY_ID").unwrap_or_else(|_| "default-key-2025".to_string());
        let additional_public_keys = parse_additional_public_keys(
            &env::var("JWT_ADDITIONAL_PUBLIC_KEYS").unwrap_or_default(),
        );

        let admin_root_token = env::var("ADMIN_ROOT_TOKEN").ok();
        let admin_allow_legacy_admin_group = env::var("ALLOW_LEGACY_ADMIN_GROUP")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);
        let admin_allow_admin_substring_claim = env::var("ALLOW_ADMIN_SUBSTRING_CLAIM")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);
        let rate_limit_rps = env::var("RATE_LIMIT_REQUESTS_PER_SECOND")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .unwrap_or(5);
        let rate_limit_burst = env::var("RATE_LIMIT_BURST_SIZE")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .unwrap_or(10);
        let token_endpoint_rps = env::var("RATE_LIMIT_TOKEN_ENDPOINT_REQUESTS_PER_SECOND")
            .unwrap_or_else(|_| "2".to_string())
            .parse()
            .unwrap_or(2);
        let token_endpoint_burst = env::var("RATE_LIMIT_TOKEN_ENDPOINT_BURST_SIZE")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .unwrap_or(5);

        let device_code_expiry = env::var("DEVICE_CODE_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "600".to_string())
            .parse()
            .unwrap_or(600);
        let device_polling_interval = env::var("DEVICE_CODE_POLLING_INTERVAL_SECONDS")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .unwrap_or(5);
        let device_user_code_length = env::var("DEVICE_USER_CODE_LENGTH")
            .unwrap_or_else(|_| "8".to_string())
            .parse()
            .unwrap_or(8);
        let device_user_code_format =
            env::var("DEVICE_USER_CODE_FORMAT").unwrap_or_else(|_| "XXXX-XXXX".to_string());
        let device_cleanup_interval = env::var("DEVICE_CODE_CLEANUP_INTERVAL_SECONDS")
            .unwrap_or_else(|_| "3600".to_string())
            .parse()
            .unwrap_or(3600);
        let device_max_attempts = env::var("DEVICE_MAX_VERIFICATION_ATTEMPTS")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .unwrap_or(5);

        let group_patterns_sync_interval = env::var("GROUP_PATTERNS_SYNC_INTERVAL_SECONDS")
            .unwrap_or_else(|_| "300".to_string())
            .parse()
            .unwrap_or(300); // Default 5 minutes
        let soft_delete_purge_enabled = env::var("SOFT_DELETE_PURGE_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);
        let soft_delete_purge_interval_seconds = env::var("SOFT_DELETE_PURGE_INTERVAL_SECONDS")
            .unwrap_or_else(|_| "3600".to_string())
            .parse()
            .unwrap_or(3600);
        let soft_delete_purge_retention_days = env::var("SOFT_DELETE_RETENTION_DAYS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .unwrap_or(30);

        let ui_brand_name = env::var("UI_BRAND_NAME").unwrap_or_else(|_| "Cloud App".to_string());
        let ui_brand_domain = env::var("UI_BRAND_DOMAIN")
            .ok()
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty());
        let ui_page_title = env::var("UI_PAGE_TITLE").unwrap_or_else(|_| "Simple IDM".to_string());

        let allow_username_login = env::var("AUTH_ALLOW_USERNAME_LOGIN")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);
        let allowed_email_domains = env::var("ALLOWED_EMAIL_DOMAINS")
            .unwrap_or_default()
            .split(',')
            .map(|d| d.trim().to_lowercase())
            .filter(|d| !d.is_empty())
            .collect::<Vec<_>>();

        let onboarding_token_ttl_seconds = env::var("ONBOARDING_TOKEN_TTL_SECONDS")
            .unwrap_or_else(|_| "86400".to_string())
            .parse()
            .unwrap_or(86400);

        let app_env = env::var("APP_ENV")
            .or_else(|_| env::var("MODE"))
            .unwrap_or_else(|_| "development".to_string())
            .to_lowercase();
        let trust_proxy_headers = env::var("TRUST_PROXY_HEADERS")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);
        let force_secure_cookies = env::var("FORCE_SECURE_COOKIES")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);
        let auth_protection_enabled = env::var("AUTH_PROTECTION_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);
        let auth_failure_window_seconds = env::var("AUTH_FAILURE_WINDOW_SECONDS")
            .unwrap_or_else(|_| "900".to_string())
            .parse()
            .unwrap_or(900);
        let auth_max_failures = env::var("AUTH_MAX_FAILURES")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .unwrap_or(5);
        let auth_lockout_seconds = env::var("AUTH_LOCKOUT_SECONDS")
            .unwrap_or_else(|_| "900".to_string())
            .parse()
            .unwrap_or(900);

        validate_admin_root_token_policy(&app_env, &admin_root_token)?;

        Ok(Config {
            server: ServerConfig {
                host: server_host,
                port: server_port,
            },
            database: DatabaseConfig { url: database_url },
            jwt: JwtConfig {
                issuer: jwt_issuer,
                access_token_expiry_seconds: access_token_expiry,
                refresh_token_expiry_seconds: refresh_token_expiry,
                refresh_token_cleanup_interval_seconds: refresh_token_cleanup_interval,
                auth_session_expiry_seconds: auth_session_expiry,
                private_key_path,
                public_key_path,
                key_id,
                additional_public_keys,
            },
            rate_limit: RateLimitConfig {
                requests_per_second: rate_limit_rps,
                burst_size: rate_limit_burst,
                token_endpoint_requests_per_second: token_endpoint_rps,
                token_endpoint_burst_size: token_endpoint_burst,
            },
            admin: AdminConfig {
                root_token: admin_root_token,
                allow_legacy_admin_group: admin_allow_legacy_admin_group,
                allow_admin_substring_claim: admin_allow_admin_substring_claim,
            },
            device_flow: DeviceFlowConfig {
                expiry_seconds: device_code_expiry,
                polling_interval_seconds: device_polling_interval,
                user_code_length: device_user_code_length,
                user_code_format: device_user_code_format,
                cleanup_interval_seconds: device_cleanup_interval,
                max_verification_attempts: device_max_attempts,
            },
            group_patterns: GroupPatternsConfig {
                sync_interval_seconds: group_patterns_sync_interval,
            },
            soft_delete_purge: SoftDeletePurgeConfig {
                enabled: soft_delete_purge_enabled,
                interval_seconds: soft_delete_purge_interval_seconds,
                retention_days: soft_delete_purge_retention_days,
            },
            ui: UiConfig {
                brand_name: ui_brand_name,
                brand_domain: ui_brand_domain,
                page_title: ui_page_title,
            },
            identity: IdentityConfig {
                allow_username_login,
                allowed_email_domains,
            },
            onboarding: OnboardingConfig {
                token_ttl_seconds: onboarding_token_ttl_seconds,
            },
            security: SecurityConfig {
                app_env,
                trust_proxy_headers,
                force_secure_cookies,
            },
            auth_protection: AuthProtectionConfig {
                enabled: auth_protection_enabled,
                failure_window_seconds: auth_failure_window_seconds,
                max_failures: auth_max_failures,
                lockout_seconds: auth_lockout_seconds,
            },
        })
    }
}

fn validate_admin_root_token_policy(
    app_env: &str,
    admin_root_token: &Option<String>,
) -> Result<(), config::ConfigError> {
    if matches!(app_env, "prod" | "production") && admin_root_token.is_some() {
        return Err(config::ConfigError::Message(
            "ADMIN_ROOT_TOKEN is forbidden in production".to_string(),
        ));
    }
    Ok(())
}

fn parse_additional_public_keys(input: &str) -> Vec<(String, String)> {
    input
        .split(',')
        .filter_map(|entry| {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                return None;
            }
            let mut parts = trimmed.splitn(2, '=');
            let kid = parts.next()?.trim();
            let path = parts.next()?.trim();
            if kid.is_empty() || path.is_empty() {
                return None;
            }
            Some((kid.to_string(), path.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_additional_public_keys, validate_admin_root_token_policy};

    #[test]
    fn parse_additional_public_keys_empty() {
        assert!(parse_additional_public_keys("").is_empty());
        assert!(parse_additional_public_keys(" , ").is_empty());
    }

    #[test]
    fn parse_additional_public_keys_valid_entries() {
        let parsed = parse_additional_public_keys("old-key=./keys/old.pem,new-key=./keys/new.pem");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "old-key");
        assert_eq!(parsed[0].1, "./keys/old.pem");
        assert_eq!(parsed[1].0, "new-key");
        assert_eq!(parsed[1].1, "./keys/new.pem");
    }

    #[test]
    fn parse_additional_public_keys_skips_invalid_entries() {
        let parsed = parse_additional_public_keys("bad-entry,ok=./keys/ok.pem,also-bad=");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, "ok");
        assert_eq!(parsed[0].1, "./keys/ok.pem");
    }

    #[test]
    fn production_rejects_admin_root_token() {
        let result =
            validate_admin_root_token_policy("production", &Some("dev-root-token".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn development_allows_admin_root_token() {
        let result =
            validate_admin_root_token_policy("development", &Some("dev-root-token".to_string()));
        assert!(result.is_ok());
    }
}
