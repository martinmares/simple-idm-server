use axum::{
    Router,
    routing::{get, post},
};
use clap::Parser;
use simple_idm_core::ssh_signer::{
    SshSignerConfig,
    cert_signer::CertSigner,
    handlers::{AppState, BastionSigningState, handle_bastion_sign, handle_sign},
    jwt_validator::JwtValidator,
    principal_mapper::PrincipalMapper,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (git ",
    env!("SIMPLE_IDM_GIT_SHA"),
    ")"
);

#[derive(Parser)]
#[command(name = "simple-idm-ssh-signer", version = VERSION)]
#[command(about = "SSH certificate signer for Simple IDM", long_about = None)]
struct Cli {
    /// Path to config file (TOML)
    #[arg(short = 'c', long)]
    config: Option<String>,

    /// Listen address (e.g. "127.0.0.1:9222")
    #[arg(short = 'l', long)]
    listen_addr: Option<String>,

    /// OIDC issuer URL
    #[arg(long)]
    oidc_issuer: Option<String>,

    /// Expected audience (OAuth2 client ID)
    #[arg(long)]
    expected_audience: Option<String>,

    /// CA private key path
    #[arg(long)]
    ca_private_key_path: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Inicializace loggingu
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "simple_idm_ssh_signer=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    tracing::info!("Starting simple-idm-ssh-signer");

    // Load .env file (same behavior as simple-idm-server).
    dotenvy::dotenv().ok();

    // Načti konfiguraci
    let mut config = SshSignerConfig::load(cli.config.as_deref())?;

    // CLI overrides (highest priority)
    if let Some(addr) = cli.listen_addr {
        config.listen_addr = addr;
    }
    if let Some(issuer) = cli.oidc_issuer {
        config.oidc_issuer = issuer;
    }
    if let Some(aud) = cli.expected_audience {
        config.expected_audience = aud;
    }
    if let Some(key_path) = cli.ca_private_key_path {
        config.ca_private_key_path = key_path.into();
    }

    tracing::info!("Configuration loaded");
    tracing::info!("Listen address: {}", config.listen_addr);
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
        config.require_explicit_ssh_principal,
        config.allow_ssh_role_principals,
    ));

    // Initialize certificate signer
    let cert_signer = Arc::new(
        CertSigner::new(
            config.ca_private_key_path.clone(),
            config.cert_key_id.clone(),
            config.default_ttl_seconds,
            config.max_ttl_seconds,
            config.clock_skew_seconds,
        )
        .map_err(|e| format!("Failed to initialize cert signer: {}", e))?
        .with_extensions(&config),
    );
    tracing::info!("Certificate signer initialized");

    // Build app state
    let bastion = if let Some(b) = &config.bastion {
        if b.expected_audience.trim().is_empty()
            || b.tenant_id.trim().is_empty()
            || b.required_scope.trim().is_empty()
        {
            return Err("Bastion audience, tenant_id and scope must be configured".into());
        }
        let key = std::env::var(&b.service_key_env)
            .map_err(|_| "Bastion service secret environment variable is missing")?;
        if key.len() < 32 {
            return Err("Bastion service secret must contain at least 32 bytes".into());
        }
        Some(BastionSigningState {
            jwt_validator: Arc::new(
                JwtValidator::new(
                    config.oidc_issuer.clone(),
                    b.expected_audience.clone(),
                    config.allowed_algs.clone(),
                )
                .await?,
            ),
            service_key: key,
            required_scope: b.required_scope.clone(),
            tenant_id: b.tenant_id.clone(),
        })
    } else {
        None
    };
    let app_state = Arc::new(AppState {
        jwt_validator,
        principal_mapper,
        cert_signer,
        bastion,
    });

    // Build router
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/ssh/sign", post(handle_sign))
        .route("/ssh/sign/bastion", post(handle_bastion_sign))
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
