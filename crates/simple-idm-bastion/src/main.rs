#[cfg(unix)]
mod unix {
    use anyhow::{Context, Result, ensure};
    use clap::{CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind};
    use simple_idm_bastion::{
        audit::{Audit, Filters, InstanceLock},
        config::Config,
        server::{App, router},
    };
    use simple_idm_core::ssh_signer::jwt_validator::JwtValidator;
    use std::{
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::{Arc, atomic::AtomicBool},
    };

    #[derive(Parser)]
    #[command(version, about = "Certificate SSH bastion with durable session audit")]
    struct Cli {
        /// Configuration file. Auto-detects OS user config, then /etc/simple-idm-bastion.
        /// In each directory, config.toml takes precedence over legacy bastion.toml.
        #[arg(long, global = true, value_name = "FILE")]
        config: Option<PathBuf>,
        #[command(subcommand)]
        command: Command,
    }
    #[derive(Subcommand)]
    enum Command {
        /// Print configuration, operation and audit examples without reading config.
        Examples,
        Serve,
        CheckConfig,
        /// Add a host using arguments or an interactive wizard; never restart the service.
        AddHost(simple_idm_bastion::add_host::AddHost),
        Audit {
            #[command(flatten)]
            filters: Filters,
            #[arg(long, value_enum, default_value = "json")]
            format: Format,
        },
        /// Remove completed/reconciled records older than configured retention. Requires daemon stopped.
        Retain,
        #[command(hide = true)]
        Notify {
            #[arg(long)]
            socket: PathBuf,
            #[arg(long)]
            nonce: String,
        },
    }
    #[derive(Clone, ValueEnum)]
    enum Format {
        Json,
        Csv,
    }
    #[tokio::main]
    pub async fn run() -> Result<()> {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "simple_idm_bastion=info".into()),
            )
            .with_writer(std::io::stderr)
            .init();
        let cli = Cli::parse();
        if matches!(cli.command, Command::Examples) {
            print!("{}", include_str!("../examples/usage.txt"));
            return Ok(());
        }
        if let Command::Notify { socket, nonce } = &cli.command {
            return simple_idm_bastion::ssh::notify(socket, nonce);
        }
        let candidates = config_candidates(dirs::config_dir().as_deref());
        let config_path =
            select_config(cli.config.as_deref(), &candidates).unwrap_or_else(|message| {
                let kind = if cli.config.is_some() {
                    ErrorKind::InvalidValue
                } else {
                    ErrorKind::MissingRequiredArgument
                };
                Cli::command().error(kind, message).exit()
            });
        if let Command::AddHost(args) = cli.command {
            return simple_idm_bastion::add_host::run(&config_path, args);
        }
        let config = Config::read(&config_path)
            .with_context(|| format!("cannot load configuration {}", config_path.display()))?;
        match cli.command {
            Command::CheckConfig => {
                println!("configuration valid");
            }
            Command::Audit { filters, format } => {
                let audit = Audit::open(&config.audit_db, true).await?;
                let records = audit.records(&filters).await?;
                match format {
                    Format::Json => serde_json::to_writer_pretty(std::io::stdout(), &records)?,
                    Format::Csv => {
                        let mut csv = csv::Writer::from_writer(std::io::stdout());
                        for r in records {
                            csv.serialize(r)?;
                        }
                        csv.flush()?;
                    }
                }
            }
            Command::Retain => {
                let _lock = InstanceLock::acquire(&config.audit_db)?;
                let audit = Audit::open(&config.audit_db, false).await?;
                println!(
                    "removed {} records",
                    audit.retain(config.retention_days).await?
                );
            }
            Command::Serve => serve(config).await?,
            Command::Notify { .. } => unreachable!(),
            Command::Examples | Command::AddHost(_) => unreachable!(),
        }
        Ok(())
    }
    fn config_candidates(user_dir: Option<&Path>) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(dir) = user_dir {
            paths.push(dir.join("simple-idm-bastion/config.toml"));
            paths.push(dir.join("simple-idm-bastion/bastion.toml"));
        }
        paths.push(PathBuf::from("/etc/simple-idm-bastion/config.toml"));
        paths.push(PathBuf::from("/etc/simple-idm-bastion/bastion.toml"));
        paths
    }

    fn select_config(
        explicit: Option<&Path>,
        candidates: &[PathBuf],
    ) -> std::result::Result<PathBuf, String> {
        let paths = if let Some(path) = explicit {
            vec![path.to_owned()]
        } else {
            candidates.to_vec()
        };
        for path in &paths {
            match std::fs::metadata(path) {
                Ok(metadata) if metadata.is_file() => return Ok(path.clone()),
                Ok(_) => {
                    return Err(format!(
                        "configuration path is not a file: {}\nUse --config <FILE> to select a configuration.",
                        path.display()
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "cannot access configuration {}: {error}",
                        path.display()
                    ));
                }
            }
        }
        if let Some(path) = explicit {
            Err(format!(
                "configuration file does not exist: {}\nCheck --config <FILE>; an explicit path never falls back to another configuration.",
                path.display()
            ))
        } else {
            Err(format!(
                "no configuration file found. Searched (in order):\n{}\n\nProvide --config <FILE>, for example:\n  simple-idm-bastion --config /path/to/config.toml add-host\nSee 'simple-idm-bastion examples' for setup instructions.",
                paths
                    .iter()
                    .map(|p| format!("  {}", p.display()))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
        }
    }

    async fn serve(config: Config) -> Result<()> {
        ensure!(
            config.known_hosts.is_file(),
            "known_hosts must be an existing managed file"
        );
        let parent = config
            .audit_db
            .parent()
            .context("audit parent directory required")?;
        ensure!(
            parent.is_dir(),
            "create audit directory with mode 0700 before starting"
        );
        ensure!(
            std::fs::metadata(parent)?.permissions().mode() & 0o077 == 0,
            "audit directory must be private (0700)"
        );
        std::fs::create_dir_all(&config.session_dir)?;
        std::fs::set_permissions(&config.session_dir, std::fs::Permissions::from_mode(0o700))?;
        let _lock = InstanceLock::acquire(&config.audit_db)?;
        // All session directories are generated only by this daemon; single-instance lock is held.
        for entry in std::fs::read_dir(&config.session_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && entry.file_name().to_string_lossy().starts_with("session-")
            {
                std::fs::remove_dir_all(entry.path())?;
            }
        }
        let audit = Audit::open(&config.audit_db, false).await?;
        tracing::info!(
            count = audit.reconcile().await?,
            "reconciled interrupted sessions"
        );
        let secret = std::env::var(&config.bastion_key_env)
            .context("delegation service key environment variable missing")?;
        ensure!(
            secret.len() >= 32 && !secret.contains(['\n', '\r']),
            "delegation service key requires at least 32 bytes and no newline"
        );
        let jwt = JwtValidator::new(
            config.issuer.clone(),
            config.expected_audience.clone(),
            vec!["RS256".into()],
        )
        .await
        .map_err(|e| anyhow::anyhow!("JWT discovery: {e}"))?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let slots = Arc::new(tokio::sync::Semaphore::new(config.max_sessions));
        let listener = tokio::net::TcpListener::bind(config.bind).await?;
        tracing::info!(bind=%config.bind,"bastion listening behind TLS proxy");
        let app = Arc::new(App {
            config,
            audit,
            jwt,
            http,
            secret,
            slots,
            audit_failed: AtomicBool::new(false),
        });
        // Lock survives for the entire server lifecycle. Service stop closes PTYs on process exit;
        // reconciliation deliberately marks remaining sessions with unknown actual end times.
        axum::serve(
            listener,
            router(app).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn configuration_discovery_prioritizes_user_and_respects_explicit_path() {
            let dir = tempfile::tempdir().unwrap();
            let user = dir.path().join("user.toml");
            let system = dir.path().join("system.toml");
            let explicit = dir.path().join("explicit.toml");
            let candidates = vec![user.clone(), system.clone()];
            let missing = select_config(None, &candidates).unwrap_err();
            assert!(
                missing.contains("--config <FILE>") && missing.contains(user.to_str().unwrap())
            );
            std::fs::write(&system, "system").unwrap();
            assert_eq!(select_config(None, &candidates).unwrap(), system);
            std::fs::write(&user, "user").unwrap();
            assert_eq!(select_config(None, &candidates).unwrap(), user);
            assert!(
                select_config(Some(&explicit), &candidates)
                    .unwrap_err()
                    .contains("never falls back")
            );
            std::fs::write(&explicit, "explicit").unwrap();
            assert_eq!(
                select_config(Some(&explicit), &candidates).unwrap(),
                explicit
            );
            assert!(
                select_config(Some(dir.path()), &candidates)
                    .unwrap_err()
                    .contains("not a file")
            );
            assert_eq!(
                config_candidates(Some(dir.path()))[0],
                dir.path().join("simple-idm-bastion/config.toml")
            );
        }
        #[test]
        fn clap_config_is_optional_global_and_help_describes_discovery() {
            assert!(
                Cli::try_parse_from(["bastion", "add-host"])
                    .unwrap()
                    .config
                    .is_none()
            );
            assert_eq!(
                Cli::try_parse_from(["bastion", "add-host", "--config", "custom.toml"])
                    .unwrap()
                    .config,
                Some(PathBuf::from("custom.toml"))
            );
            let missing = Cli::try_parse_from(["bastion", "add-host", "--yes"])
                .err()
                .unwrap();
            assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);
            assert!(missing.to_string().contains("--address"));
            let help = Cli::try_parse_from(["bastion", "add-host", "--help"])
                .err()
                .unwrap()
                .to_string();
            assert!(help.contains("Auto-detects OS user config"));
        }
    }
}

#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    unix::run()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("simple-idm-bastion V1 daemon requires Linux or macOS");
    std::process::exit(1);
}
