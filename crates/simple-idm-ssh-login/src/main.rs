mod bastion;
mod protocol;

use clap::{CommandFactory, Parser, Subcommand};
use simple_idm_core::ssh_login::{SshLoginConfig, commands};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (git ",
    env!("SIMPLE_IDM_GIT_SHA"),
    ")"
);

#[derive(Parser)]
#[command(name = "simple-idm-ssh-login", version = VERSION)]
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

    /// Tenant slug hint for OAuth2/OIDC requests
    #[arg(long, global = true)]
    tenant: Option<String>,

    /// SSH signer URL
    #[arg(long, global = true)]
    signer_url: Option<String>,

    /// Certificate TTL in seconds
    #[arg(long, global = true)]
    ttl_seconds: Option<u64>,

    /// OIDC scopes (comma-separated)
    #[arg(long, global = true, value_delimiter = ',')]
    scopes: Option<Vec<String>>,

    /// Config profile name (for multi-profile config.toml)
    #[arg(long, global = true)]
    profile: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Print offline usage examples and a bastions.toml sample
    Examples,

    /// Open the bastion host picker (configured in bastions.toml)
    #[command(
        after_long_help = "Both forms are supported:\n  simple-idm-ssh-login <hostname>\n  simple-idm-ssh-login bastion <hostname>\n\nProfiles are read from bastions.toml alongside config.toml in the OS configuration directory."
    )]
    Bastion { hostname: String },

    /// Bastion hostname shortcut
    #[command(external_subcommand)]
    Hostname(Vec<String>),

    /// Login and obtain SSH certificate
    Login {
        /// Force browser flow
        #[arg(long)]
        browser: bool,

        /// Force device flow
        #[arg(long)]
        device: bool,
    },

    /// SSH with automatic certificate renewal
    Ssh {
        /// Force browser flow for renewal
        #[arg(long)]
        browser: bool,

        /// Force device flow for renewal
        #[arg(long)]
        device: bool,

        /// SSH arguments (e.g., user@host, -p 2222, etc.)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        ssh_args: Vec<String>,
    },

    /// Show current certificate status
    Status,

    /// Logout and remove certificate
    Logout,

    /// Print recommended SSH config
    PrintSshConfig,
}

fn initialize_tls() {
    // OIDC (reqwest 0.12) enables ring; reqwest 0.13 enables AWS-LC.
    // WSS uses the process default, which cannot be inferred with both enabled.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    initialize_tls();
    bastion::install_panic_hook();
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "simple_idm_ssh_login=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Examples => {
            print_examples();
            return Ok(());
        }
        Commands::Bastion { hostname } => return bastion::run(hostname).await,
        Commands::Hostname(args) => {
            if args.len() == 2 && matches!(args[1].as_str(), "--help" | "-h") {
                let mut command = Cli::command();
                command.build();
                if let Some(bastion) = command.find_subcommand_mut("bastion") {
                    bastion.print_long_help()?;
                    println!();
                }
                return Ok(());
            }
            if args.len() != 1 {
                return Err("Usage: simple-idm-ssh-login <hostname> (or: simple-idm-ssh-login bastion <hostname>)".into());
            }
            return bastion::run(&args[0]).await;
        }
        _ => {}
    }

    // Load config
    let mut config = SshLoginConfig::load(cli.profile.as_deref())?;

    // Apply CLI overrides
    if let Some(issuer) = cli.issuer {
        config.oidc_issuer = issuer;
    }
    if let Some(client_id) = cli.client_id {
        config.client_id = client_id;
    }
    if let Some(tenant) = cli.tenant {
        let tenant = tenant.trim().to_string();
        config.tenant = if tenant.is_empty() {
            None
        } else {
            Some(tenant)
        };
    }
    if let Some(signer_url) = cli.signer_url {
        config.signer_url = signer_url;
    }
    if let Some(ttl) = cli.ttl_seconds {
        config.ttl_seconds = ttl;
    }
    if let Some(scopes) = cli.scopes {
        let scopes: Vec<String> = scopes
            .into_iter()
            .map(|scope| scope.trim().to_string())
            .filter(|scope| !scope.is_empty())
            .collect();
        if !scopes.is_empty() {
            config.scopes = scopes;
        }
    }

    match cli.command {
        Commands::Examples | Commands::Bastion { .. } | Commands::Hostname(_) => unreachable!(),
        Commands::Login { browser, device } => {
            commands::login(&config, browser, device).await?;
        }
        Commands::Ssh {
            browser,
            device,
            ssh_args,
        } => {
            commands::ssh(&config, ssh_args, browser, device).await?;
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

fn print_examples() {
    print!("{}", EXAMPLES);
}

const EXAMPLES: &str = r#"Bastion client V1 (Linux/macOS)

Create bastions.toml alongside config.toml in the OS configuration directory:
  macOS: ~/Library/Application Support/simple-idm-ssh-login/bastions.toml
  Linux: $XDG_CONFIG_HOME/simple-idm-ssh-login/bastions.toml
         (default ~/.config/simple-idm-ssh-login/bastions.toml)

[bastions."bastion.datalite.cz"]
url = "https://bastion.datalite.cz:8443"
issuer = "https://idm.datalite.cz"
client_id = "simple-idm-bastion"
# tenant = "datalite"
scopes = ["openid", "profile", "email", "groups", "bastion:connect"]

Hostname shortcut:
  simple-idm-ssh-login bastion.datalite.cz
Explicit command (also works for names that collide with subcommands):
  simple-idm-ssh-login bastion bastion.datalite.cz

Start in the host list. / edits the filter; Enter applies it and returns to the list.
Arrows select; Enter in the list connects; Esc in the filter cancels the edit.
Ctrl-U clears the filter while editing; q quits the host list; Esc goes back/cancels.
Multiple Linux accounts open an account picker. Ctrl-C goes to the remote
program. Exit the shell to return to the host list.
The dedicated public client ID is the access-token audience; configure the
OIDC client for PKCE and dynamic-port loopback callbacks. HTTPS is required,
except explicit localhost/loopback HTTP fixtures.

Existing direct SSH certificate login is preserved and uses config.toml:
  simple-idm-ssh-login login --browser
  simple-idm-ssh-login ssh user@host
  simple-idm-ssh-login status
  simple-idm-ssh-login print-ssh-config
  simple-idm-ssh-login logout

Deployment guide: docs/BASTION.md
Client guide: crates/simple-idm-ssh-login/README.bastion.md
Configuration example: crates/simple-idm-ssh-login/examples/bastions.toml
"#;

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn wss_tls_configuration_can_be_built() {
        use tokio::io::AsyncReadExt;
        super::initialize_tls();
        let _config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        // Exercise tungstenite's native-root TLS path, not only HTTP/cleartext WS.
        // A fixture closes after ClientHello: failure must be an error, not a panic.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut record_type = [0];
            stream.read_exact(&mut record_type).await.unwrap();
            assert_eq!(record_type[0], 22, "expected TLS handshake record");
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio_tungstenite::connect_async(format!("wss://{address}/api/v1/terminal")),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        server.await.unwrap();
    }
    use super::*;

    #[test]
    fn bastion_and_shortcut() {
        assert!(matches!(
            Cli::try_parse_from(["login", "bastion", "example.org"])
                .unwrap()
                .command,
            Commands::Bastion { .. }
        ));
        assert!(matches!(
            Cli::try_parse_from(["login", "example.org"])
                .unwrap()
                .command,
            Commands::Hostname(_)
        ));
        assert!(Cli::try_parse_from(["login", "bastion"]).is_err());
    }

    #[test]
    fn examples_is_static_and_parses() {
        assert!(matches!(
            Cli::try_parse_from(["login", "examples"]).unwrap().command,
            Commands::Examples
        ));
        for text in [
            "bastions.toml",
            "bastion.datalite.cz",
            "bastion bastion.datalite.cz",
            "login --browser",
            "docs/BASTION.md",
        ] {
            assert!(EXAMPLES.contains(text));
        }
    }

    #[test]
    fn existing_commands_still_parse() {
        for name in [
            "login",
            "ssh",
            "status",
            "logout",
            "print-ssh-config",
            "examples",
        ] {
            assert!(!matches!(
                Cli::try_parse_from(["login", name]).unwrap().command,
                Commands::Hostname(_)
            ));
        }
    }
}
