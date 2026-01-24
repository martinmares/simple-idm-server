use clap::{Parser, Subcommand};
use simple_idm_server::ssh_login::{commands, SshLoginConfig};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "simple-idm-ssh-login")]
#[command(about = "SSH certificate login via Simple IDM", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// OIDC issuer URL
    #[arg(long, global = true)]
    issuer: Option<String>,

    /// OAuth2 client ID
    #[arg(long, global = true)]
    client_id: Option<String>,

    /// SSH signer URL
    #[arg(long, global = true)]
    signer_url: Option<String>,

    /// Certificate TTL in seconds
    #[arg(long, global = true)]
    ttl_seconds: Option<u64>,
}

#[derive(Subcommand)]
enum Commands {
    /// Login and obtain SSH certificate
    Login {
        /// Force browser flow
        #[arg(long)]
        browser: bool,

        /// Force device flow
        #[arg(long)]
        device: bool,
    },

    /// Show current certificate status
    Status,

    /// Logout and remove certificate
    Logout,

    /// Print recommended SSH config
    PrintSshConfig,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "simple_idm_ssh_login=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    // Load config
    let mut config = SshLoginConfig::load()?;

    // Apply CLI overrides
    if let Some(issuer) = cli.issuer {
        config.oidc_issuer = issuer;
    }
    if let Some(client_id) = cli.client_id {
        config.client_id = client_id;
    }
    if let Some(signer_url) = cli.signer_url {
        config.signer_url = signer_url;
    }
    if let Some(ttl) = cli.ttl_seconds {
        config.ttl_seconds = ttl;
    }

    match cli.command {
        Commands::Login { browser, device } => {
            commands::login(&config, browser, device).await?;
        }
        Commands::Status => {
            commands::status(&config)?;
        }
        Commands::Logout => {
            commands::logout(&config)?;
        }
        Commands::PrintSshConfig => {
            commands::print_ssh_config(&config);
        }
    }

    Ok(())
}
