mod admin;
mod auth;
mod config;
mod db;
mod jwks;
mod oauth2;
mod oidc;

use axum::{
    middleware,
    routing::{delete, get, post, put},
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

    // Vytvoř Admin auth state
    let admin_auth = admin::AdminAuth::new(&config, jwt_service.clone());

    // Admin API routes (protected by middleware)
    let admin_routes = Router::new()
        // User management
        .route("/admin/users", post(admin::handlers::create_user))
        .route("/admin/users", get(admin::handlers::list_users))
        .route("/admin/users/{id}", put(admin::handlers::update_user))
        .route("/admin/users/{id}", delete(admin::handlers::delete_user))
        // Group management
        .route("/admin/groups", post(admin::handlers::create_group))
        .route("/admin/groups", get(admin::handlers::list_groups))
        .route("/admin/groups/{id}", delete(admin::handlers::delete_group))
        // User-Group assignments
        .route(
            "/admin/users/{id}/groups",
            post(admin::handlers::assign_user_to_group),
        )
        .route(
            "/admin/users/{user_id}/groups/{group_id}",
            delete(admin::handlers::remove_user_from_group),
        )
        // OAuth client management
        .route(
            "/admin/oauth-clients",
            post(admin::handlers::create_oauth_client),
        )
        .route(
            "/admin/oauth-clients",
            get(admin::handlers::list_oauth_clients),
        )
        .route(
            "/admin/oauth-clients/{id}",
            delete(admin::handlers::delete_oauth_client),
        )
        // Claim map management
        .route("/admin/claim-maps", post(admin::handlers::create_claim_map))
        .route("/admin/claim-maps", get(admin::handlers::list_claim_maps))
        .route(
            "/admin/claim-maps/{id}",
            delete(admin::handlers::delete_claim_map),
        )
        .layer(middleware::from_fn_with_state(
            admin_auth.clone(),
            admin::middleware::admin_auth_middleware,
        ))
        .with_state(db_pool.clone());

    // OIDC state
    let oidc_state = Arc::new(oidc::OidcState::new(&config));

    // JWKS route
    let jwks_routes = Router::new()
        .route("/.well-known/jwks.json", get(jwks::jwks_handler))
        .with_state(jwt_service.clone());

    // OIDC Discovery route
    let discovery_routes = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(oidc::discovery_handler),
        )
        .with_state(oidc_state);

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
        // Merge well-known routes
        .merge(jwks_routes)
        .merge(discovery_routes)
        // Merge admin routes
        .merge(admin_routes)
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
