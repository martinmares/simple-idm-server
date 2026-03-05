
use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use clap::Parser;
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
use simple_idm_core::{
    admin, auth, config, db, group_patterns, jwks, oauth2, oidc, password_reset,
    security_headers, soft_delete_cleanup,
};
use simple_idm_ad_auth::{LdapAuthConfig, LdapTlsMode};
mod web_admin;

fn install_rustls_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

#[derive(Parser, Debug)]
#[command(name = "simple-idm-server")]
struct CliArgs {
    /// Explicit path to env file (has priority over ./.env and /app/.env)
    #[arg(long)]
    env_file: Option<String>,
    /// UI brand/company name shown on auth pages
    #[arg(long)]
    ui_brand_name: Option<String>,
    /// Optional domain/tenant hint shown on auth pages
    #[arg(long)]
    ui_brand_domain: Option<String>,
    /// UI theme preset: blue, red, white, green, gold
    #[arg(long)]
    ui_theme: Option<String>,
    /// Optional path to custom CSS file injected into auth pages
    #[arg(long)]
    ui_custom_css_path: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    install_rustls_provider();

    // Inicializace loggingu
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "simple_idm_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = CliArgs::parse();
    // Načti konfiguraci z .env (lokálně i v kontejneru/K8s mountu).
    load_env_file(cli.env_file.as_deref())?;
    let mut config = config::Config::from_env()?;
    if let Some(brand_name) = cli.ui_brand_name {
        config.ui.brand_name = brand_name;
    }
    if let Some(brand_domain) = cli.ui_brand_domain {
        let domain = brand_domain.trim().to_string();
        config.ui.brand_domain = if domain.is_empty() { None } else { Some(domain) };
    }
    if let Some(theme) = cli.ui_theme {
        config.ui.theme = theme.to_lowercase();
    }
    if let Some(path) = cli.ui_custom_css_path {
        let p = path.trim().to_string();
        config.ui.custom_css_path = if p.is_empty() { None } else { Some(p) };
    }

    let custom_css = if let Some(path) = &config.ui.custom_css_path {
        match std::fs::read_to_string(path) {
            Ok(css) => Some(css),
            Err(err) => {
                tracing::warn!("Failed to load custom UI CSS from '{}': {}", path, err);
                None
            }
        }
    } else {
        None
    };

    oauth2::templates::set_branding_from_config(
        config.ui.brand_name.clone(),
        config.ui.brand_domain.clone(),
        config.ui.theme.clone(),
        custom_css,
    );

    tracing::info!("Starting simple-idm-server");
    tracing::info!("Server: {}:{}", config.server.host, config.server.port);
    tracing::info!(
        "UI branding: name='{}' domain='{}' theme='{}'",
        config.ui.brand_name,
        config
            .ui
            .brand_domain
            .clone()
            .unwrap_or_else(|| "-".to_string()),
        config.ui.theme
    );
    if let Some(path) = &config.ui.custom_css_path {
        tracing::info!("UI custom CSS: {}", path);
    }
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
        config.jwt.key_id.clone(),
        config.jwt.additional_public_keys.clone(),
    )?);

    // Vytvoř OAuth2 state
    let ldap_auth = if config.ad_auth.enabled {
        let tls_mode = match config.ad_auth.tls_mode.as_str() {
            "ldaps" => LdapTlsMode::Ldaps,
            "starttls" => LdapTlsMode::StartTls,
            other => {
                tracing::warn!(
                    "Unknown AD_AUTH_TLS_MODE='{}', using 'ldaps'",
                    other
                );
                LdapTlsMode::Ldaps
            }
        };
        Some(LdapAuthConfig {
            host: config.ad_auth.host.clone(),
            port: config.ad_auth.port,
            base_dn: config.ad_auth.base_dn.clone(),
            bind_dn: config.ad_auth.bind_dn.clone(),
            bind_password: config.ad_auth.bind_password.clone(),
            user_filter: config.ad_auth.user_filter.clone(),
            tls_mode,
            timeout_seconds: config.ad_auth.timeout_seconds,
            allow_insecure: config.ad_auth.allow_insecure,
        })
    } else {
        None
    };

    if ldap_auth.is_some() {
        tracing::info!(
            "AD/LDAP auth enabled (domains: {})",
            if config.ad_auth.domains.is_empty() {
                "*"
            } else {
                "configured"
            }
        );
    }

    let oauth_state = Arc::new(oauth2::OAuth2State {
        db_pool: db_pool.clone(),
        jwt_service: jwt_service.clone(),
        access_token_expiry: config.jwt.access_token_expiry_seconds,
        refresh_token_expiry: config.jwt.refresh_token_expiry_seconds,
        auth_session_expiry: config.jwt.auth_session_expiry_seconds,
        device_flow_config: config.device_flow.clone(),
        allow_username_login: config.identity.allow_username_login,
        allowed_email_domains: config.identity.allowed_email_domains.clone(),
        ldap_auth,
        ldap_auth_domains: config.ad_auth.domains.clone(),
        ldap_role_sync_enabled: config.ad_auth.role_sync_enabled,
        ldap_role_sync_ttl_seconds: config.ad_auth.role_sync_ttl_seconds,
        ldap_role_sync_timeout_seconds: config.ad_auth.role_sync_timeout_seconds,
        trust_proxy_headers: config.security.trust_proxy_headers,
        force_secure_cookies: config.security.force_secure_cookies,
        auth_protection: config.auth_protection.clone(),
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

    let device_cleanup_interval = config.device_flow.cleanup_interval_seconds;
    if device_cleanup_interval > 0 {
        let cleanup_pool = db_pool.clone();
        tokio::spawn(async move {
            tracing::info!(
                "Device code cleanup scheduler enabled (interval {}s)",
                device_cleanup_interval
            );
            let mut interval = tokio::time::interval(Duration::from_secs(device_cleanup_interval));
            loop {
                interval.tick().await;
                tracing::debug!("Running device code cleanup");
                oauth2::cleanup::cleanup_device_codes(&cleanup_pool).await;
            }
        });
    }

    let group_patterns_sync_interval = config.group_patterns.sync_interval_seconds;
    if group_patterns_sync_interval > 0 {
        let sync_pool = db_pool.clone();
        tokio::spawn(async move {
            tracing::info!(
                "Group patterns sync scheduler enabled (interval {}s)",
                group_patterns_sync_interval
            );
            let mut interval =
                tokio::time::interval(Duration::from_secs(group_patterns_sync_interval));
            loop {
                interval.tick().await;
                tracing::info!("Running group patterns sync");
                group_patterns::evaluate_and_sync_patterns(&sync_pool).await;
            }
        });
    }

    if config.soft_delete_purge.enabled && config.soft_delete_purge.interval_seconds > 0 {
        let purge_pool = db_pool.clone();
        let purge_interval_seconds = config.soft_delete_purge.interval_seconds;
        let retention_days = config.soft_delete_purge.retention_days;
        tokio::spawn(async move {
            tracing::info!(
                "Soft-delete purge scheduler enabled (interval {}s, retention {}d)",
                purge_interval_seconds,
                retention_days
            );
            let mut interval =
                tokio::time::interval(Duration::from_secs(purge_interval_seconds));
            loop {
                interval.tick().await;
                tracing::info!("Running soft-delete purge");
                soft_delete_cleanup::purge_soft_deleted(&purge_pool, retention_days).await;
            }
        });
    }

    // Vytvoř Admin auth state
    let admin_auth = admin::AdminAuth::new(&config, jwt_service.clone(), db_pool.clone());
    let web_admin_state = web_admin::WebAdminState {
        db_pool: db_pool.clone(),
        oauth_state: oauth_state.clone(),
        admin_auth: admin_auth.clone(),
        secure_cookies: config.security.force_secure_cookies,
        ad_onboarding_token_ttl_seconds: config.ad_auth.onboarding_token_ttl_seconds as i64,
        admin_sessions: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
    };

    // Admin API routes (protected by middleware)
    let admin_routes = Router::new()
        // Tenant management
        .route("/admin/tenants", post(admin::handlers::create_tenant))
        .route("/admin/tenants", get(admin::handlers::list_tenants))
        .route("/admin/tenants/{id}", put(admin::handlers::update_tenant))
        .route("/admin/tenants/{id}", delete(admin::handlers::delete_tenant))
        .route(
            "/admin/tenants/{tenant_id}/domains",
            post(admin::handlers::create_tenant_domain),
        )
        .route(
            "/admin/tenants/{tenant_id}/domains",
            get(admin::handlers::list_tenant_domains),
        )
        .route(
            "/admin/tenants/{tenant_id}/domains/{domain_id}",
            put(admin::handlers::update_tenant_domain),
        )
        .route(
            "/admin/tenants/{tenant_id}/domains/{domain_id}",
            delete(admin::handlers::delete_tenant_domain),
        )
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
        .route("/admin/groups/tree", get(admin::handlers::get_groups_tree))
        .route("/admin/groups/{id}", put(admin::handlers::update_group))
        .route("/admin/groups/{id}", delete(admin::handlers::delete_group))
        // Nested groups (group-group relationships)
        .route(
            "/admin/groups/{id}/children",
            post(admin::handlers::add_child_group),
        )
        .route(
            "/admin/groups/{id}/children",
            get(admin::handlers::list_child_groups),
        )
        .route(
            "/admin/groups/{parent_id}/children/{child_id}",
            delete(admin::handlers::remove_child_group),
        )
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
        // User Group Patterns management
        .route(
            "/admin/users/{id}/group-patterns",
            post(admin::handlers::create_user_group_pattern),
        )
        .route(
            "/admin/users/{id}/group-patterns",
            get(admin::handlers::list_user_group_patterns),
        )
        .route(
            "/admin/users/{user_id}/group-patterns/{pattern_id}",
            put(admin::handlers::update_user_group_pattern),
        )
        .route(
            "/admin/users/{user_id}/group-patterns/{pattern_id}",
            delete(admin::handlers::delete_user_group_pattern),
        )
        // OAuth Client Group Patterns management
        .route(
            "/admin/oauth-clients/{id}/group-patterns",
            post(admin::handlers::create_client_group_pattern),
        )
        .route(
            "/admin/oauth-clients/{id}/group-patterns",
            get(admin::handlers::list_client_group_patterns),
        )
        .route(
            "/admin/oauth-clients/{client_id}/group-patterns/{pattern_id}",
            put(admin::handlers::update_client_group_pattern),
        )
        .route(
            "/admin/oauth-clients/{client_id}/group-patterns/{pattern_id}",
            delete(admin::handlers::delete_client_group_pattern),
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
        // Claim Map Patterns management
        .route(
            "/admin/claim-maps/{id}/patterns",
            post(admin::handlers::create_claim_map_pattern),
        )
        .route(
            "/admin/claim-maps/{id}/patterns",
            get(admin::handlers::list_claim_map_patterns),
        )
        .route(
            "/admin/claim-maps/{claim_map_id}/patterns/{pattern_id}",
            put(admin::handlers::update_claim_map_pattern),
        )
        .route(
            "/admin/claim-maps/{claim_map_id}/patterns/{pattern_id}",
            delete(admin::handlers::delete_claim_map_pattern),
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
        "Rate limiting enabled (default: rps={}, burst={}; token endpoint: rps={}, burst={})",
        config.rate_limit.requests_per_second,
        config.rate_limit.burst_size,
        config.rate_limit.token_endpoint_requests_per_second,
        config.rate_limit.token_endpoint_burst_size
    );
    tracing::info!(
        "Auth protection {} (window={}s, max_failures={}, lockout={}s)",
        if config.auth_protection.enabled {
            "enabled"
        } else {
            "disabled"
        },
        config.auth_protection.failure_window_seconds,
        config.auth_protection.max_failures,
        config.auth_protection.lockout_seconds
    );

    // Globální rate limiter
    let governor_global = GovernorConfigBuilder::default()
        .per_second(config.rate_limit.requests_per_second.into())
        .burst_size(config.rate_limit.burst_size)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("Failed to build global rate limiter");

    // Přísnější rate limiter pro token endpoint
    let governor_token = GovernorConfigBuilder::default()
        .per_second(config.rate_limit.token_endpoint_requests_per_second.into())
        .burst_size(config.rate_limit.token_endpoint_burst_size)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("Failed to build token endpoint rate limiter");

    // Token endpoint s přísnějším rate limitingem
    let token_routes = Router::new()
        .route("/oauth2/token", post(oauth2::handle_token))
        .layer(GovernorLayer::new(governor_token))
        .with_state(oauth_state.clone());

    let security_headers_state = security_headers::SecurityHeadersConfig {
        app_env: config.security.app_env.clone(),
        trust_proxy_headers: config.security.trust_proxy_headers,
    };

    // Vytvoř routes
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        // OAuth2 endpoints (mimo /oauth2/token)
        .route("/oauth2/introspect", post(oauth2::handle_introspect))
        .route("/oauth2/revoke", post(oauth2::handle_revoke))
        .route("/oauth2/authorize", get(oauth2::handle_authorize))
        .route("/oauth2/login", post(oauth2::handle_login))
        .route("/oauth2/logout", get(oauth2::handle_logout))
        .route(
            "/oauth2/device/authorize",
            post(oauth2::handle_device_authorization),
        )
        .route("/oauth2/device/token", post(oauth2::handle_device_token))
        .route("/device", get(oauth2::show_device_form))
        .route("/device", post(oauth2::handle_device_verify))
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
        .layer(GovernorLayer::new(governor_global))
        .with_state(oauth_state)
        // Merge token route s přísnějším rate limitingem
        .merge(token_routes)
        // Merge well-known routes
        .merge(jwks_routes)
        .merge(discovery_routes)
        // Merge admin routes
        .merge(admin_routes)
        // Web admin UI
        .merge(web_admin::router(web_admin_state))
        .layer(middleware::from_fn_with_state(
            security_headers_state,
            security_headers::security_headers_middleware,
        ))
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

fn load_env_file(env_file: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = env_file {
        dotenvy::from_filename(path)?;
        tracing::info!("Loaded env file from --env-file: {}", path);
        return Ok(());
    }

    // 1) Standard path from current working directory
    if let Ok(path) = dotenvy::dotenv() {
        tracing::info!("Loaded env file: {}", path.display());
        return Ok(());
    }

    // 2) Explicit container path used in Kubernetes manifests
    if dotenvy::from_filename("/app/.env").is_ok() {
        tracing::info!("Loaded env file: /app/.env");
        return Ok(());
    }

    tracing::warn!("No .env file loaded from CWD or /app/.env; using process environment only");
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
