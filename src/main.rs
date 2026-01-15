mod admin;
mod auth;
mod config;
mod db;
mod jwks;
mod oauth2;
mod oidc;
mod password_reset;

use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::SmartIpKeyExtractor,
    GovernorLayer,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
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
    tracing::info!(
        "Database: {}",
        redact_database_url(&config.database.url)
    );

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
        refresh_token_expiry: config.jwt.refresh_token_expiry_seconds,
    });

    let cleanup_interval = config.jwt.refresh_token_cleanup_interval_seconds;
    if cleanup_interval > 0 {
        let cleanup_pool = db_pool.clone();
        tokio::spawn(async move {
            tracing::info!(
                "Refresh token cleanup scheduler enabled (interval {}s)",
                cleanup_interval
            );
            let mut interval = tokio::time::interval(Duration::from_secs(cleanup_interval));
            loop {
                interval.tick().await;
                tracing::info!("Running refresh token cleanup");
                oauth2::cleanup::cleanup_refresh_tokens(&cleanup_pool).await;
            }
        });
    }

    let password_reset_cleanup_interval = std::env::var("PASSWORD_RESET_CLEANUP_INTERVAL_SECONDS")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap_or(0);
    if password_reset_cleanup_interval > 0 {
        let cleanup_pool = db_pool.clone();
        tokio::spawn(async move {
            tracing::info!(
                "Password reset cleanup scheduler enabled (interval {}s)",
                password_reset_cleanup_interval
            );
            let mut interval =
                tokio::time::interval(Duration::from_secs(password_reset_cleanup_interval));
            loop {
                interval.tick().await;
                tracing::info!("Running password reset cleanup");
                password_reset::cleanup_password_reset_tokens(&cleanup_pool).await;
            }
        });
    }

    // Vytvoř Admin auth state
    let admin_auth = admin::AdminAuth::new(&config, jwt_service.clone(), db_pool.clone());

    // Admin API routes (protected by middleware)
    let admin_routes = Router::new()
        // User management
        .route("/admin/users", post(admin::handlers::create_user))
        .route("/admin/users", get(admin::handlers::list_users))
        .route("/admin/users/{id}", put(admin::handlers::update_user))
        .route("/admin/users/{id}", delete(admin::handlers::delete_user))
        .route(
            "/admin/users/{id}/password-reset",
            post(admin::handlers::create_password_reset),
        )
        // Group management
        .route("/admin/groups", post(admin::handlers::create_group))
        .route("/admin/groups", get(admin::handlers::list_groups))
        .route("/admin/groups/{id}", put(admin::handlers::update_group))
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
        .route("/admin/user-groups", get(admin::handlers::list_user_groups))
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
            put(admin::handlers::update_oauth_client),
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

    tracing::info!(
        "Rate limiting enabled (rps={}, burst={})",
        config.rate_limit.requests_per_second,
        config.rate_limit.burst_size
    );
    let governor = GovernorConfigBuilder::default()
        .per_second(config.rate_limit.requests_per_second.into())
        .burst_size(config.rate_limit.burst_size)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("Failed to build rate limiter");

    // Vytvoř routes
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        // OAuth2 endpoints
        .route("/oauth2/token", post(oauth2::handle_token))
        .route("/oauth2/introspect", post(oauth2::handle_introspect))
        .route("/oauth2/revoke", post(oauth2::handle_revoke))
        .route("/oauth2/authorize", get(oauth2::handle_authorize))
        .route("/oauth2/login", post(oauth2::handle_login))
        .route(
            "/oauth2/device/authorize",
            post(oauth2::handle_device_authorization),
        )
        .route("/oauth2/device/token", post(oauth2::handle_device_token))
        .route("/oauth2/device/verify", post(oauth2::handle_device_verify))
        .route(
            "/password/reset",
            get(password_reset::show_password_reset_form),
        )
        .route(
            "/password/reset",
            post(password_reset::submit_password_reset_form),
        )
        // Client credentials endpoint
        .route(
            "/oauth2/client_credentials/token",
            post(oauth2::handle_client_credentials),
        )
        // Userinfo endpoint
        .route("/oauth2/userinfo", get(oauth2::handle_userinfo))
        .layer(GovernorLayer::new(governor))
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

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

fn redact_database_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let Some(at_pos) = url.rfind('@') else {
        return url.to_string();
    };

    let (prefix, rest) = url.split_at(scheme_end + 3);
    let credentials = &rest[..at_pos - (scheme_end + 3)];
    let suffix = &rest[at_pos - (scheme_end + 3)..];

    if let Some((user, _password)) = credentials.split_once(':') {
        format!("{prefix}{user}:***{suffix}")
    } else {
        url.to_string()
    }
}
