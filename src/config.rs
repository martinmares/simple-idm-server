use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub admin: AdminConfig,
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
    pub private_key_path: String,
    pub public_key_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    pub root_token: Option<String>,
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
        let private_key_path = env::var("JWT_PRIVATE_KEY_PATH")
            .unwrap_or_else(|_| "./keys/private.pem".to_string());
        let public_key_path = env::var("JWT_PUBLIC_KEY_PATH")
            .unwrap_or_else(|_| "./keys/public.pem".to_string());

        let admin_root_token = env::var("ADMIN_ROOT_TOKEN").ok();

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
                private_key_path,
                public_key_path,
            },
            admin: AdminConfig {
                root_token: admin_root_token,
            },
        })
    }
}
