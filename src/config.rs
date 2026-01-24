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
    pub key_id: String, // kid for JWKS
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

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let server_host = env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let server_port = env::var("SERVER_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .unwrap_or(8080);

        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/simple_idm".to_string());

        let jwt_issuer = env::var("JWT_ISSUER")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());
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
        let private_key_path = env::var("JWT_PRIVATE_KEY_PATH")
            .unwrap_or_else(|_| "./keys/private.pem".to_string());
        let public_key_path = env::var("JWT_PUBLIC_KEY_PATH")
            .unwrap_or_else(|_| "./keys/public.pem".to_string());
        let key_id = env::var("JWT_KEY_ID")
            .unwrap_or_else(|_| "default-key-2025".to_string());

        let admin_root_token = env::var("ADMIN_ROOT_TOKEN").ok();
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
        let device_user_code_format = env::var("DEVICE_USER_CODE_FORMAT")
            .unwrap_or_else(|_| "XXXX-XXXX".to_string());
        let device_cleanup_interval = env::var("DEVICE_CODE_CLEANUP_INTERVAL_SECONDS")
            .unwrap_or_else(|_| "3600".to_string())
            .parse()
            .unwrap_or(3600);
        let device_max_attempts = env::var("DEVICE_MAX_VERIFICATION_ATTEMPTS")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .unwrap_or(5);

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
            },
            rate_limit: RateLimitConfig {
                requests_per_second: rate_limit_rps,
                burst_size: rate_limit_burst,
                token_endpoint_requests_per_second: token_endpoint_rps,
                token_endpoint_burst_size: token_endpoint_burst,
            },
            admin: AdminConfig {
                root_token: admin_root_token,
            },
            device_flow: DeviceFlowConfig {
                expiry_seconds: device_code_expiry,
                polling_interval_seconds: device_polling_interval,
                user_code_length: device_user_code_length,
                user_code_format: device_user_code_format,
                cleanup_interval_seconds: device_cleanup_interval,
                max_verification_attempts: device_max_attempts,
            },
        })
    }
}
