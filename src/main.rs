mod auth;
mod config;
mod db;
mod oauth2;

use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Inicializace loggingu
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "simple_idm_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Načti konfiguraci
    dotenvy::dotenv().ok();
    let config = config::Config::from_env()?;

    tracing::info!("Starting simple-idm-server");
    tracing::info!("Server: {}:{}", config.server.host, config.server.port);
    tracing::info!("Database: {}", config.database.url);

    // Připoj se k databázi
    let db_pool = db::create_pool(&config.database.url).await?;
    tracing::info!("Connected to database");

    // Spusť migrace
    db::run_migrations(&db_pool).await?;
    tracing::info!("Migrations completed");

    // Inicializuj JWT service
    let jwt_service = Arc::new(auth::JwtService::new(
        &config.jwt.private_key_path,
        &config.jwt.public_key_path,
        config.jwt.issuer.clone(),
    )?);

    // Vytvoř OAuth2 state
    let oauth_state = Arc::new(oauth2::OAuth2State {
        db_pool: db_pool.clone(),
        jwt_service: jwt_service.clone(),
        access_token_expiry: config.jwt.access_token_expiry_seconds,
    });

    // Vytvoř routes
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        // OAuth2 endpoints
        .route("/oauth2/token", post(oauth2::handle_token))
        .route("/oauth2/authorize", post(oauth2::handle_authorize))
        .route("/oauth2/login", post(oauth2::handle_login))
        .route(
            "/oauth2/device/authorize",
            post(oauth2::handle_device_authorization),
        )
        .route("/oauth2/device/token", post(oauth2::handle_device_token))
        .route("/oauth2/device/verify", post(oauth2::handle_device_verify))
        // Client credentials endpoint
        .route(
            "/oauth2/client_credentials/token",
            post(oauth2::handle_client_credentials),
        )
        .with_state(oauth_state)
        .layer(TraceLayer::new_for_http());

    // Spusť server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}
