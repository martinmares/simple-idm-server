use axum::{routing::{get, post}, Router};
use simple_idm_server::ssh_signer::{
    cert_signer::CertSigner,
    handlers::{handle_sign, AppState},
    jwt_validator::JwtValidator,
    principal_mapper::PrincipalMapper,
    SshSignerConfig,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Inicializace loggingu
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "simple_idm_ssh_signer=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting simple-idm-ssh-signer");

    // Načti konfiguraci
    let config = SshSignerConfig::load()?;
    tracing::info!("Loaded configuration from {}", config.config_source());
    tracing::info!("OIDC Issuer: {}", config.oidc_issuer);
    tracing::info!("Expected Audience: {}", config.expected_audience);
    tracing::info!("CA Private Key: {:?}", config.ca_private_key_path);

    // Validate CA key exists
    if !config.ca_private_key_path.exists() {
        return Err(format!(
            "CA private key not found at {:?}",
            config.ca_private_key_path
        )
        .into());
    }

    // Initialize JWT validator
    tracing::info!("Initializing JWT validator...");
    let jwt_validator = Arc::new(
        JwtValidator::new(
            config.oidc_issuer.clone(),
            config.expected_audience.clone(),
            config.allowed_algs.clone(),
        )
        .await?,
    );
    tracing::info!("JWT validator initialized");

    // Initialize principal mapper
    let principal_mapper = Arc::new(PrincipalMapper::new(
        config.max_principals,
        config.principal_max_len,
    ));

    // Initialize certificate signer
    let cert_signer = Arc::new(
        CertSigner::new(
            config.ca_private_key_path.clone(),
            config.default_ttl_seconds,
            config.max_ttl_seconds,
            config.clock_skew_seconds,
        )
        .map_err(|e| format!("Failed to initialize cert signer: {}", e))?,
    );
    tracing::info!("Certificate signer initialized");

    // Build app state
    let app_state = Arc::new(AppState {
        jwt_validator,
        principal_mapper,
        cert_signer,
    });

    // Build router
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/ssh/sign", post(handle_sign))
        .with_state(app_state);

    // Start server
    let addr: SocketAddr = config.listen_addr.parse()?;
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn healthz() -> &'static str {
    "OK"
}
