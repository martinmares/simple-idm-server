use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use tabled::{settings::Style, Table, Tabled};
use std::process::Command;
use dirs::config_dir;
use chrono::{DateTime, Utc, Duration};
use tokio::sync::oneshot;
use std::fs;
use std::path::PathBuf;
use std::collections::HashMap;
use rand::Rng;

#[path = "../cli/tui.rs"]
mod tui;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Session {
    access_token: String,
    refresh_token: String,
    expires_at: DateTime<Utc>,
    base_url: String,
    created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_email: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    user_groups: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SessionsConfig {
    active: String,
    servers: std::collections::HashMap<String, Session>,
}

fn sessions_file_path() -> Result<PathBuf> {
    let config_dir = config_dir()
        .ok_or_else(|| anyhow!("Could not determine config directory"))?;
    Ok(config_dir.join("simple-idm-ctl").join("sessions.json"))
}

fn load_sessions() -> Result<SessionsConfig> {
    let path = sessions_file_path()?;
    if !path.exists() {
        return Ok(SessionsConfig {
            active: "default".to_string(),
            servers: HashMap::new(),
        });
    }
    let content = fs::read_to_string(&path)?;
    let config = serde_json::from_str(&content)?;
    Ok(config)
}

fn save_sessions(config: &SessionsConfig) -> Result<()> {
    let path = sessions_file_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(config)?;
    fs::write(&path, content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

fn get_active_session() -> Result<Option<Session>> {
    let config = load_sessions()?;
    Ok(config.servers.get(&config.active).cloned())
}

fn save_session(server_name: &str, session: Session) -> Result<()> {
    let mut config = load_sessions()?;
    config.servers.insert(server_name.to_string(), session);
    config.active = server_name.to_string();
    save_sessions(&config)
}

fn delete_session(server_name: Option<&str>) -> Result<()> {
    let mut config = load_sessions()?;

    if let Some(name) = server_name {
        config.servers.remove(name);
        if config.active == name && !config.servers.is_empty() {
            config.active = config.servers.keys().next().unwrap().clone();
        }
    } else {
        config.servers.clear();
    }

    save_sessions(&config)
}

fn is_session_valid(session: &Session) -> bool {
    session.expires_at > Utc::now() + Duration::seconds(60)
}

#[derive(Parser, Debug)]
#[command(name = "simple-idm-ctl", version, about = "Admin CLI for simple-idm-server")]
struct Cli {
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long)]
    token: Option<String>,
    #[arg(long, global = true)]
    server: Option<String>,
    #[arg(long, global = true)]
    insecure: Option<bool>,
    #[arg(short = 'o', long, default_value = "table", global = true)]
    output: OutputFormat,
    #[arg(long, default_value = "sharp", global = true)]
    style: TableStyle,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TableStyle {
    Sharp,
    Psql,
    Markdown,
    Modern,
    Rounded,
    Ascii,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(alias = "user")]
    Users {
        #[command(subcommand)]
        command: UsersCommand,
    },
    Groups {
        #[command(subcommand)]
        command: GroupsCommand,
    },
    Clients {
        #[command(subcommand)]
        command: ClientsCommand,
    },
    ClaimMaps {
        #[command(subcommand)]
        command: ClaimMapsCommand,
    },
    UserGroups {
        #[command(subcommand)]
        command: UserGroupsCommand,
    },
    #[command(alias = "ui")]
    Tui,
    #[command(name = "oauth")]
    OAuth {
        #[command(subcommand)]
        command: OAuthCommand,
    },
    Login {
        #[arg(long, required = true)]
        url: String,
        #[arg(long, default_value = "cli-tools")]
        client: String,
        #[arg(long, default_value = "8888")]
        port: u16,
        #[arg(long, default_value = "default")]
        server: String,
    },
    Logout {
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        all: bool,
    },
    Sessions {
        #[command(subcommand)]
        command: SessionsCommand,
    },
    Status,
    Ping,
}

#[derive(Subcommand, Debug)]
enum SessionsCommand {
    #[command(alias = "ls")]
    List,
    Use {
        #[arg(value_name = "SERVER")]
        server: String,
    },
}

#[derive(Subcommand, Debug)]
enum UsersCommand {
    #[command(alias = "ls")]
    List {
        #[arg(long)]
        page: Option<usize>,
        #[arg(long)]
        limit: Option<usize>,
    },
    Create {
        #[arg(long)]
        username: String,
        #[arg(long)]
        email: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        is_active: Option<bool>,
    },
    Update {
        #[arg(long)]
        id: String,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        is_active: Option<bool>,
    },
    Delete {
        #[arg(long)]
        id: String,
    },
    ResetPassword {
        #[arg(long)]
        id: String,
        #[arg(long)]
        open: bool,
    },
}

#[derive(Subcommand, Debug)]
enum GroupsCommand {
    #[command(alias = "ls")]
    List {
        #[arg(long)]
        page: Option<usize>,
        #[arg(long)]
        limit: Option<usize>,
    },
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        description: Option<String>,
    },
    Update {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    Delete {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum ClientsCommand {
    #[command(alias = "ls")]
    List {
        #[arg(long)]
        page: Option<usize>,
        #[arg(long)]
        limit: Option<usize>,
    },
    Create {
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        client_secret: String,
        #[arg(long)]
        name: String,
        #[arg(long, action = clap::ArgAction::Append)]
        redirect_uri: Vec<String>,
        #[arg(long, action = clap::ArgAction::Append)]
        grant_type: Vec<String>,
        #[arg(long, default_value = "openid profile email")]
        scope: String,
    },
    Update {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        client_secret: Option<String>,
        #[arg(long, action = clap::ArgAction::Append)]
        redirect_uri: Vec<String>,
        #[arg(long, action = clap::ArgAction::Append)]
        grant_type: Vec<String>,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        is_active: Option<bool>,
    },
    Delete {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum ClaimMapsCommand {
    #[command(alias = "ls")]
    List {
        #[arg(long)]
        page: Option<usize>,
        #[arg(long)]
        limit: Option<usize>,
    },
    Create {
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        claim_name: String,
        #[arg(long)]
        claim_value: Option<String>,
    },
    Delete {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum UserGroupsCommand {
    #[command(alias = "ls")]
    List {
        #[arg(long)]
        page: Option<usize>,
        #[arg(long)]
        limit: Option<usize>,
    },
    Add {
        #[arg(long)]
        user_id: String,
        #[arg(long)]
        group_id: String,
    },
    Remove {
        #[arg(long)]
        user_id: String,
        #[arg(long)]
        group_id: String,
    },
}

#[derive(Subcommand, Debug)]
enum OAuthCommand {
    AuthorizeUrl {
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        redirect_uri: String,
        #[arg(long, default_value = "code")]
        response_type: String,
        #[arg(long, default_value = "openid")]
        scope: String,
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        code_challenge: Option<String>,
        #[arg(long)]
        code_challenge_method: Option<String>,
    },
    Token {
        #[arg(long, default_value = "authorization_code")]
        grant_type: String,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        client_secret: String,
        #[arg(long)]
        code: Option<String>,
        #[arg(long)]
        redirect_uri: Option<String>,
        #[arg(long)]
        code_verifier: Option<String>,
        #[arg(long)]
        refresh_token: Option<String>,
    },
    Refresh {
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        client_secret: String,
        #[arg(long)]
        refresh_token: String,
    },
    UserInfo {
        #[arg(long)]
        access_token: String,
    },
    Introspect {
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        client_secret: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        token_type_hint: Option<String>,
    },
    Revoke {
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        client_secret: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        token_type_hint: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
pub(crate) struct ErrorResponse {
    error: String,
    error_description: String,
}

#[derive(Debug, Deserialize, Serialize, Tabled)]
pub(crate) struct UserRow {
    id: String,
    username: String,
    email: String,
    is_active: bool,
}

#[derive(Debug, Deserialize, Serialize, Tabled)]
pub(crate) struct GroupRow {
    id: String,
    name: String,
    #[tabled(display_with = "display_opt")]
    description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Tabled)]
pub(crate) struct ClientRow {
    id: String,
    client_id: String,
    name: String,
    #[tabled(display_with = "display_vec_limited")]
    redirect_uris: Vec<String>,
    #[tabled(display_with = "display_vec_limited")]
    grant_types: Vec<String>,
    scope: String,
    is_active: bool,
}

#[derive(Debug, Deserialize, Serialize, Tabled)]
pub(crate) struct ClaimMapRow {
    id: String,
    client_id: String,
    group_id: String,
    claim_name: String,
    #[tabled(display_with = "display_opt")]
    claim_value: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Tabled)]
pub(crate) struct UserGroupRow {
    user_id: String,
    username: String,
    email: String,
    group_id: String,
    group_name: String,
}

#[derive(Debug, Deserialize, Serialize, Tabled)]
pub(crate) struct PasswordResetRow {
    user_id: String,
    reset_token: String,
    reset_url: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct MessageResponse {
    message: String,
}

#[derive(Clone, Copy)]
struct OutputConfig {
    format: OutputFormat,
    style: TableStyle,
}

fn generate_pkce_pair() -> (String, String) {
    use sha2::{Sha256, Digest};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let code_verifier: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let hash = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(hash);

    (code_verifier, code_challenge)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Login { url, client, port, server } => {
            return handle_login(url, client, *port, server, cli.insecure.unwrap_or(false)).await;
        }
        Commands::Logout { server, all } => {
            return handle_logout(server.as_deref(), *all);
        }
        Commands::Sessions { command } => {
            return handle_sessions(command);
        }
        Commands::Status => {
            return handle_status();
        }
        _ => {}
    }

    let (base_url, token) = resolve_auth(&cli).await?;

    let http = HttpClient::new(base_url, token, cli.insecure.unwrap_or(false))?;
    let output = OutputConfig {
        format: cli.output,
        style: cli.style,
    };

    match cli.command {
        Commands::Users { command } => handle_users(&http, output, command).await?,
        Commands::Groups { command } => handle_groups(&http, output, command).await?,
        Commands::Clients { command } => handle_clients(&http, output, command).await?,
        Commands::ClaimMaps { command } => handle_claim_maps(&http, output, command).await?,
        Commands::UserGroups { command } => handle_user_groups(&http, output, command).await?,
        Commands::Tui => tui::run_tui(&http).await?,
        Commands::OAuth { command } => handle_oauth(&http, output, command).await?,
        Commands::Ping => handle_ping(&http).await?,
        Commands::Login { .. } | Commands::Logout { .. } | Commands::Sessions { .. } | Commands::Status => unreachable!(),
    }

    Ok(())
}

async fn resolve_auth(cli: &Cli) -> Result<(String, String)> {
    if let Some(token) = &cli.token {
        let base_url = cli.base_url.clone()
            .ok_or_else(|| anyhow!("--base-url is required when using --token"))?;
        return Ok((base_url, token.clone()));
    }

    let mut session = get_active_session()?
        .ok_or_else(|| anyhow!("Not logged in. Run 'simple-idm-ctl login' first."))?;

    if !is_session_valid(&session) || (session.expires_at - Utc::now()).num_seconds() < 300 {
        let config = load_sessions()?;
        session = refresh_session_async(session).await?;
        save_session(&config.active, session.clone())?;
    }

    let base_url = cli.base_url.clone().unwrap_or(session.base_url);
    Ok((base_url, session.access_token))
}

async fn handle_login(base_url: &str, client_id: &str, port: u16, server_name: &str, insecure: bool) -> Result<()> {

    let (code_verifier, code_challenge) = generate_pkce_pair();

    let (tx, rx) = oneshot::channel::<String>();
    let tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));

    let callback_app = axum::Router::new().route(
        "/callback",
        axum::routing::get(|axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>| async move {
            let tx_clone = tx.clone();
            if let Some(code) = params.get("code") {
                if let Some(sender) = tx_clone.lock().await.take() {
                    let _ = sender.send(code.clone());
                }
                return "✓ Login successful! You can close this window.";
            }
            "✗ Login failed: No authorization code received."
        }),
    );

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await
        .context(format!("Failed to bind to {}. Try different --port", addr))?;

    tokio::spawn(async move {
        axum::serve(listener, callback_app).await.ok();
    });

    let redirect_uri = format!("http://localhost:{}/callback", port);
    let authorize_url = format!(
        "{}/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email&code_challenge={}&code_challenge_method=S256",
        base_url, client_id, urlencoding::encode(&redirect_uri), code_challenge
    );

    println!("Opening browser for login...");
    println!("If browser doesn't open, visit: {}", authorize_url);

    if let Err(e) = open_url(&authorize_url) {
        eprintln!("Could not open browser: {}", e);
    }

    let code = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        rx
    ).await
        .context("Login timeout after 2 minutes")??;

    exchange_code_for_tokens(base_url, client_id, &code, &code_verifier, &redirect_uri, insecure, server_name).await
}

async fn exchange_code_for_tokens(
    base_url: &str,
    client_id: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    insecure: bool,
    server_name: &str,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .build()?;

    let params = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("client_secret", ""),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", code_verifier),
    ];

    let response = client
        .post(format!("{}/oauth2/token", base_url))
        .form(&params)
        .send()
        .await?;

    let status = response.status();
    let body_text = response.text().await?;

    if !status.is_success() {
        bail!("Token exchange failed (status {}): {}", status, body_text);
    }

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: i64,
    }

    let token_data: TokenResponse = serde_json::from_str(&body_text)
        .context(format!("Failed to parse token response: {}", body_text))?;

    let session = Session {
        access_token: token_data.access_token,
        refresh_token: token_data.refresh_token.unwrap_or_default(),
        expires_at: Utc::now() + Duration::seconds(token_data.expires_in),
        base_url: base_url.to_string(),
        created_at: Utc::now(),
        user_email: None,
        user_groups: vec![],
    };

    save_session(server_name, session)?;

    println!("✓ Login successful!");
    println!("Session saved to {}", sessions_file_path()?.display());
    println!("Server: {}", server_name);

    Ok(())
}

async fn handle_users(http: &HttpClient, output: OutputConfig, command: UsersCommand) -> Result<()> {
    match command {
        UsersCommand::List { page, limit } => {
            let path = append_pagination("/admin/users", page, limit);
            let body = http.get(&path).await?;
            let rows: Vec<UserRow> =
                serde_json::from_str(&body).context("Failed to parse response")?;
            print_table_rows_vec(output, rows)?;
        }
        UsersCommand::Create {
            username,
            email,
            password,
            is_active,
        } => {
            let payload = serde_json::json!({
                "username": username,
                "email": email,
                "password": password,
                "is_active": is_active,
            });
            let body = http.post_json("/admin/users", payload).await?;
            print_table_item::<UserRow>(output, &body)?;
        }
        UsersCommand::Update {
            id,
            email,
            password,
            is_active,
        } => {
            if email.is_none() && password.is_none() && is_active.is_none() {
                bail!("At least one field must be provided for update.");
            }
            let payload = serde_json::json!({
                "email": email,
                "password": password,
                "is_active": is_active,
            });
            let body = http.put_json(&format!("/admin/users/{id}"), payload).await?;
            print_table_item::<UserRow>(output, &body)?;
        }
        UsersCommand::Delete { id } => {
            let body = http.delete(&format!("/admin/users/{id}")).await?;
            print_message(output, &body)?;
        }
        UsersCommand::ResetPassword { id, open } => {
            let body = http.post_empty(&format!("/admin/users/{id}/password-reset")).await?;
            let reset = parse_reset_row(&body)?;
            print_reset_output(output, &reset, &body)?;
            if open {
                open_url(&reset.reset_url)?;
            }
        }
    }

    Ok(())
}

async fn handle_groups(http: &HttpClient, output: OutputConfig, command: GroupsCommand) -> Result<()> {
    match command {
        GroupsCommand::List { page, limit } => {
            let path = append_pagination("/admin/groups", page, limit);
            let body = http.get(&path).await?;
            let rows: Vec<GroupRow> =
                serde_json::from_str(&body).context("Failed to parse response")?;
            print_table_rows_vec(output, rows)?;
        }
        GroupsCommand::Create { name, description } => {
            let payload = serde_json::json!({
                "name": name,
                "description": description,
            });
            let body = http.post_json("/admin/groups", payload).await?;
            print_table_item::<GroupRow>(output, &body)?;
        }
        GroupsCommand::Update { id, name, description } => {
            if name.is_none() && description.is_none() {
                bail!("At least one field must be provided for update.");
            }
            let payload = serde_json::json!({
                "name": name,
                "description": description,
            });
            let body = http.put_json(&format!("/admin/groups/{id}"), payload).await?;
            print_table_item::<GroupRow>(output, &body)?;
        }
        GroupsCommand::Delete { id } => {
            let body = http.delete(&format!("/admin/groups/{id}")).await?;
            print_message(output, &body)?;
        }
    }
    Ok(())
}

async fn handle_clients(
    http: &HttpClient,
    output: OutputConfig,
    command: ClientsCommand,
) -> Result<()> {
    match command {
        ClientsCommand::List { page, limit } => {
            let path = append_pagination("/admin/oauth-clients", page, limit);
            let body = http.get(&path).await?;
            let rows: Vec<ClientRow> =
                serde_json::from_str(&body).context("Failed to parse response")?;
            print_clients_output(output, rows)?;
        }
        ClientsCommand::Create {
            client_id,
            client_secret,
            name,
            redirect_uri,
            grant_type,
            scope,
        } => {
            let payload = serde_json::json!({
                "client_id": client_id,
                "client_secret": client_secret,
                "name": name,
                "redirect_uris": redirect_uri,
                "grant_types": grant_type,
                "scope": scope,
            });
            let body = http.post_json("/admin/oauth-clients", payload).await?;
            print_table_item::<ClientRow>(output, &body)?;
        }
        ClientsCommand::Update {
            id,
            name,
            client_secret,
            redirect_uri,
            grant_type,
            scope,
            is_active,
        } => {
            if name.is_none()
                && client_secret.is_none()
                && redirect_uri.is_empty()
                && grant_type.is_empty()
                && scope.is_none()
                && is_active.is_none()
            {
                bail!("At least one field must be provided for update.");
            }
            let redirect_uris = if redirect_uri.is_empty() {
                None
            } else {
                Some(redirect_uri)
            };
            let grant_types = if grant_type.is_empty() {
                None
            } else {
                Some(grant_type)
            };
            let payload = serde_json::json!({
                "name": name,
                "client_secret": client_secret,
                "redirect_uris": redirect_uris,
                "grant_types": grant_types,
                "scope": scope,
                "is_active": is_active,
            });
            let body = http.put_json(&format!("/admin/oauth-clients/{id}"), payload).await?;
            print_table_item::<ClientRow>(output, &body)?;
        }
        ClientsCommand::Delete { id } => {
            let body = http.delete(&format!("/admin/oauth-clients/{id}")).await?;
            print_message(output, &body)?;
        }
    }
    Ok(())
}

async fn handle_claim_maps(
    http: &HttpClient,
    output: OutputConfig,
    command: ClaimMapsCommand,
) -> Result<()> {
    match command {
        ClaimMapsCommand::List { page, limit } => {
            let path = append_pagination("/admin/claim-maps", page, limit);
            let body = http.get(&path).await?;
            let rows: Vec<ClaimMapRow> =
                serde_json::from_str(&body).context("Failed to parse response")?;
            print_table_rows_vec(output, rows)?;
        }
        ClaimMapsCommand::Create {
            client_id,
            group_id,
            claim_name,
            claim_value,
        } => {
            let payload = serde_json::json!({
                "client_id": client_id,
                "group_id": group_id,
                "claim_name": claim_name,
                "claim_value": claim_value,
            });
            let body = http.post_json("/admin/claim-maps", payload).await?;
            print_table_item::<ClaimMapRow>(output, &body)?;
        }
        ClaimMapsCommand::Delete { id } => {
            let body = http.delete(&format!("/admin/claim-maps/{id}")).await?;
            print_message(output, &body)?;
        }
    }
    Ok(())
}

async fn handle_user_groups(
    http: &HttpClient,
    output: OutputConfig,
    command: UserGroupsCommand,
) -> Result<()> {
    match command {
        UserGroupsCommand::List { page, limit } => {
            let path = append_pagination("/admin/user-groups", page, limit);
            let body = http.get(&path).await?;
            let rows: Vec<UserGroupRow> =
                serde_json::from_str(&body).context("Failed to parse response")?;
            print_table_rows_vec(output, rows)?;
        }
        UserGroupsCommand::Add { user_id, group_id } => {
            let payload = serde_json::json!({ "group_id": group_id });
            let body = http
                .post_json(&format!("/admin/users/{user_id}/groups"), payload)
                .await?;
            print_message(output, &body)?;
        }
        UserGroupsCommand::Remove { user_id, group_id } => {
            let body = http
                .delete(&format!("/admin/users/{user_id}/groups/{group_id}"))
                .await?;
            print_message(output, &body)?;
        }
    }
    Ok(())
}

fn handle_logout(server_name: Option<&str>, all: bool) -> Result<()> {
    if all {
        delete_session(None)?;
        println!("✓ Logged out from all servers");
    } else if let Some(name) = server_name {
        delete_session(Some(name))?;
        println!("✓ Logged out from server: {}", name);
    } else {
        let config = load_sessions()?;
        delete_session(Some(&config.active))?;
        println!("✓ Logged out from active server: {}", config.active);
    }
    Ok(())
}

fn handle_sessions(command: &SessionsCommand) -> Result<()> {
    match command {
        SessionsCommand::List => {
            let config = load_sessions()?;
            if config.servers.is_empty() {
                println!("No sessions found. Run 'simple-idm-ctl login' first.");
                return Ok(());
            }

            println!("Sessions:");
            for (name, session) in &config.servers {
                let marker = if name == &config.active { "*" } else { " " };
                let valid = is_session_valid(session);
                let status = if valid { "✓" } else { "✗" };
                println!(
                    "{} {} - {} {} ({})",
                    marker,
                    name,
                    session.base_url,
                    status,
                    if valid { "valid" } else { "expired" }
                );
            }
        }
        SessionsCommand::Use { server } => {
            let mut config = load_sessions()?;
            if !config.servers.contains_key(server) {
                bail!("Server '{}' not found. Available servers: {}", server, config.servers.keys().map(|k| k.as_str()).collect::<Vec<_>>().join(", "));
            }
            config.active = server.clone();
            save_sessions(&config)?;
            println!("✓ Switched to server: {}", server);
        }
    }
    Ok(())
}

fn handle_status() -> Result<()> {
    let config = load_sessions()?;
    let session = config.servers.get(&config.active)
        .ok_or_else(|| anyhow!("Not logged in"))?;

    let valid = is_session_valid(session);
    let expires_in = (session.expires_at - Utc::now()).num_seconds();

    println!("Status: {}", if valid { "✓ Logged in" } else { "✗ Token expired" });
    println!("Active server: {}", config.active);
    println!("Server URL: {}", session.base_url);
    println!("Token expires in: {} seconds ({} minutes)", expires_in, expires_in / 60);
    println!("Session created: {}", session.created_at.format("%Y-%m-%d %H:%M:%S"));

    if !valid {
        println!("\nToken expired. Run 'simple-idm-ctl login' to re-authenticate.");
    }

    Ok(())
}

async fn handle_oauth(http: &HttpClient, output: OutputConfig, command: OAuthCommand) -> Result<()> {
    match command {
        OAuthCommand::AuthorizeUrl {
            client_id,
            redirect_uri,
            response_type,
            scope,
            state,
            code_challenge,
            code_challenge_method,
        } => {
            let mut params = vec![
                ("client_id".to_string(), client_id),
                ("redirect_uri".to_string(), redirect_uri),
                ("response_type".to_string(), response_type),
                ("scope".to_string(), scope),
            ];
            if let Some(state) = state {
                params.push(("state".to_string(), state));
            }
            if let Some(code_challenge) = code_challenge {
                params.push(("code_challenge".to_string(), code_challenge));
            }
            if let Some(code_challenge_method) = code_challenge_method {
                params.push(("code_challenge_method".to_string(), code_challenge_method));
            }

            let query = serde_urlencoded::to_string(params)
                .context("Failed to build authorize query")?;
            let mut url = http.url("/oauth2/authorize");
            url.push('?');
            url.push_str(&query);
            println!("{url}");
        }
        OAuthCommand::Token {
            grant_type,
            client_id,
            client_secret,
            code,
            redirect_uri,
            code_verifier,
            refresh_token,
        } => {
            let mut params = vec![
                ("grant_type".to_string(), grant_type.clone()),
                ("client_id".to_string(), client_id),
                ("client_secret".to_string(), client_secret),
            ];
            match grant_type.as_str() {
                "authorization_code" => {
                    let code = code.ok_or_else(|| anyhow!("Missing --code"))?;
                    let redirect_uri =
                        redirect_uri.ok_or_else(|| anyhow!("Missing --redirect-uri"))?;
                    params.push(("code".to_string(), code));
                    params.push(("redirect_uri".to_string(), redirect_uri));
                    if let Some(code_verifier) = code_verifier {
                        params.push(("code_verifier".to_string(), code_verifier));
                    }
                }
                "refresh_token" => {
                    let refresh_token =
                        refresh_token.ok_or_else(|| anyhow!("Missing --refresh-token"))?;
                    params.push(("refresh_token".to_string(), refresh_token));
                }
                other => bail!("Unsupported grant_type: {other}"),
            }
            let body = http.post_form_no_auth("/oauth2/token", params).await?;
            print_json_or_kv(output, &body)?;
        }
        OAuthCommand::Refresh {
            client_id,
            client_secret,
            refresh_token,
        } => {
            let params = vec![
                ("grant_type".to_string(), "refresh_token".to_string()),
                ("client_id".to_string(), client_id),
                ("client_secret".to_string(), client_secret),
                ("refresh_token".to_string(), refresh_token),
            ];
            let body = http.post_form_no_auth("/oauth2/token", params).await?;
            print_json_or_kv(output, &body)?;
        }
        OAuthCommand::UserInfo { access_token } => {
            let body = http.get_with_bearer("/oauth2/userinfo", &access_token).await?;
            print_json_or_kv(output, &body)?;
        }
        OAuthCommand::Introspect {
            client_id,
            client_secret,
            token,
            token_type_hint,
        } => {
            let mut params = vec![
                ("client_id".to_string(), client_id),
                ("client_secret".to_string(), client_secret),
                ("token".to_string(), token),
            ];
            if let Some(hint) = token_type_hint {
                params.push(("token_type_hint".to_string(), hint));
            }
            let body = http.post_form_no_auth("/oauth2/introspect", params).await?;
            print_json_or_kv(output, &body)?;
        }
        OAuthCommand::Revoke {
            client_id,
            client_secret,
            token,
            token_type_hint,
        } => {
            let mut params = vec![
                ("client_id".to_string(), client_id),
                ("client_secret".to_string(), client_secret),
                ("token".to_string(), token),
            ];
            if let Some(hint) = token_type_hint {
                params.push(("token_type_hint".to_string(), hint));
            }
            let body = http.post_form_no_auth("/oauth2/revoke", params).await?;
            if !body.trim().is_empty() {
                print_json_or_kv(output, &body)?;
            }
        }
    }

    Ok(())
}

async fn refresh_session_async(session: Session) -> Result<Session> {
    let client = reqwest::Client::new();

    let params = [
        ("grant_type", "refresh_token"),
        ("client_id", "cli-tools"),
        ("client_secret", ""),
        ("refresh_token", &session.refresh_token),
    ];

    let response = client
        .post(format!("{}/oauth2/token", session.base_url))
        .form(&params)
        .send()
        .await?;

    if !response.status().is_success() {
        bail!("Token refresh failed. Please login again with 'simple-idm-ctl login'");
    }

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: i64,
    }

    let token_data: TokenResponse = response.json().await?;

    Ok(Session {
        access_token: token_data.access_token,
        refresh_token: token_data.refresh_token.unwrap_or(session.refresh_token),
        expires_at: Utc::now() + Duration::seconds(token_data.expires_in),
        base_url: session.base_url,
        created_at: session.created_at,
        user_email: session.user_email,
        user_groups: session.user_groups,
    })
}

async fn handle_ping(http: &HttpClient) -> Result<()> {
    let body = http.get("/health").await?;
    println!("{}", body.trim());
    Ok(())
}

fn print_table_item<T>(output: OutputConfig, body: &str) -> Result<()>
where
    T: for<'de> Deserialize<'de> + Tabled,
{
    match output.format {
        OutputFormat::Json => println!("{}", body),
        OutputFormat::Table => {
            let parsed: T = serde_json::from_str(body).context("Failed to parse response")?;
            let mut table = Table::new(vec![parsed]);
            apply_style(&mut table, output.style);
            println!("{table}");
        }
    }
    Ok(())
}

fn print_table_rows_vec<T>(output: OutputConfig, rows: Vec<T>) -> Result<()>
where
    T: Serialize + Tabled,
{
    match output.format {
        OutputFormat::Json => {
            let json = serde_json::to_string(&rows).context("Failed to serialize response")?;
            println!("{json}");
        }
        OutputFormat::Table => {
            let mut table = Table::new(rows);
            apply_style(&mut table, output.style);
            println!("{table}");
        }
    }
    Ok(())
}

fn yellow_text(value: &str) -> String {
    format!("\x1b[33m{}\x1b[0m", value)
}

fn display_opt(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

fn display_vec_limited(value: &Vec<String>) -> String {
    let joined = value.join(", ");
    limit_text(&joined, 42)
}

fn limit_text(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }
    let trimmed: String = value.chars().take(max_len.saturating_sub(3)).collect();
    format!("{trimmed}...")
}

fn json_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "".to_string(),
        serde_json::Value::Bool(val) => val.to_string(),
        serde_json::Value::Number(val) => val.to_string(),
        serde_json::Value::String(val) => val.clone(),
        serde_json::Value::Array(values) => values
            .iter()
            .map(json_value_to_string)
            .collect::<Vec<_>>()
            .join(", "),
        serde_json::Value::Object(_) => value.to_string(),
    }
}

fn append_pagination(path: &str, page: Option<usize>, limit: Option<usize>) -> String {
    let mut params = Vec::new();
    if let Some(page) = page {
        params.push(format!("page={page}"));
    }
    if let Some(limit) = limit {
        params.push(format!("limit={limit}"));
    }

    if params.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{}", params.join("&"))
    }
}

fn apply_style(table: &mut Table, style: TableStyle) {
    match style {
        TableStyle::Sharp => {
            table.with(Style::sharp());
        }
        TableStyle::Psql => {
            table.with(Style::psql());
        }
        TableStyle::Markdown => {
            table.with(Style::markdown());
        }
        TableStyle::Modern => {
            table.with(Style::modern());
        }
        TableStyle::Rounded => {
            table.with(Style::rounded());
        }
        TableStyle::Ascii => {
            table.with(Style::ascii());
        }
    }
}

fn open_url(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(url).status()?;
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd").args(["/C", "start", url]).status()?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open").arg(url).status()?;
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(anyhow!("Unsupported OS for opening URLs"))
}

fn print_message(output: OutputConfig, body: &str) -> Result<()> {
    match output.format {
        OutputFormat::Json => println!("{}", body),
        OutputFormat::Table => {
            if let Ok(msg) = serde_json::from_str::<MessageResponse>(body) {
                println!("{}", msg.message);
            } else {
                println!("{}", body);
            }
        }
    }
    Ok(())
}

fn print_json_or_kv(output: OutputConfig, body: &str) -> Result<()> {
    if matches!(output.format, OutputFormat::Json) {
        println!("{}", body);
        return Ok(());
    }

    let value: serde_json::Value =
        serde_json::from_str(body).context("Failed to parse response")?;
    let obj = match value.as_object() {
        Some(obj) => obj,
        None => {
            println!("{}", body);
            return Ok(());
        }
    };

    let mut rows = Vec::new();
    for (key, value) in obj {
        rows.push(KeyValueRow::new(key, json_value_to_string(value)));
    }
    let mut table = Table::new(rows);
    apply_style(&mut table, output.style);
    println!("{table}");
    Ok(())
}

fn parse_reset_row(body: &str) -> Result<PasswordResetRow> {
    serde_json::from_str(body).context("Failed to parse response")
}

fn print_reset_output(output: OutputConfig, parsed: &PasswordResetRow, body: &str) -> Result<()> {
    match output.format {
        OutputFormat::Json => println!("{}", body),
        OutputFormat::Table => {
            let rows = vec![
                KeyValueRow::new("user_id", parsed.user_id.clone()),
                KeyValueRow::new("reset_token", parsed.reset_token.clone()),
                KeyValueRow::new("reset_url", parsed.reset_url.clone()),
                KeyValueRow::new("expires_at", parsed.expires_at.clone()),
            ];
            let mut table = Table::new(rows);
            apply_style(&mut table, output.style);
            println!("{table}");
        }
    }
    Ok(())
}

fn print_clients_output(output: OutputConfig, rows: Vec<ClientRow>) -> Result<()> {
    match output.format {
        OutputFormat::Json => {
            let json = serde_json::to_string(&rows).context("Failed to serialize response")?;
            println!("{json}");
        }
        OutputFormat::Table => {
            let total = rows.len();
            for (idx, client) in rows.into_iter().enumerate() {
                println!("{}", yellow_text(&format!(">> {}", client.client_id)));
                let rows = vec![
                    KeyValueRow::new("id", client.id),
                    KeyValueRow::new("client_id", client.client_id),
                    KeyValueRow::new("name", client.name),
                    KeyValueRow::new("redirect_uris", client.redirect_uris.join(", ")),
                    KeyValueRow::new("grant_types", client.grant_types.join(", ")),
                    KeyValueRow::new("scope", client.scope),
                    KeyValueRow::new("is_active", client.is_active.to_string()),
                ];
                let mut table = Table::new(rows);
                apply_style(&mut table, output.style);
                println!("{table}");
                if idx + 1 < total {
                    println!();
                }
            }
        }
    }
    Ok(())
}

#[derive(Tabled)]
struct KeyValueRow {
    field: String,
    value: String,
}

impl KeyValueRow {
    fn new(field: &str, value: String) -> Self {
        Self {
            field: field.to_string(),
            value,
        }
    }
}

pub(crate) struct HttpClient {
    base_url: String,
    token: String,
    client: reqwest::Client,
}

impl HttpClient {
    pub(crate) fn new(base_url: String, token: String, insecure: bool) -> Result<Self> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(insecure)
            .build()
            .context("Failed to build HTTP client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            client,
        })
    }

    pub(crate) async fn get(&self, path: &str) -> Result<String> {
        self.request_with_auth(self.client.get(self.url(path))).await
    }

    pub(crate) async fn delete(&self, path: &str) -> Result<String> {
        self.request_with_auth(self.client.delete(self.url(path))).await
    }

    pub(crate) async fn post_json<T: Serialize>(&self, path: &str, body: T) -> Result<String> {
        self.request_with_auth(self.client.post(self.url(path)).json(&body))
            .await
    }

    pub(crate) async fn put_json<T: Serialize>(&self, path: &str, body: T) -> Result<String> {
        self.request_with_auth(self.client.put(self.url(path)).json(&body))
            .await
    }

    pub(crate) async fn post_empty(&self, path: &str) -> Result<String> {
        self.request_with_auth(self.client.post(self.url(path))).await
    }

    pub(crate) async fn get_with_bearer(&self, path: &str, token: &str) -> Result<String> {
        self.request_no_auth(self.client.get(self.url(path)).bearer_auth(token))
            .await
    }

    pub(crate) async fn post_form_no_auth(
        &self,
        path: &str,
        body: Vec<(String, String)>,
    ) -> Result<String> {
        self.request_no_auth(self.client.post(self.url(path)).form(&body))
            .await
    }

    async fn request_with_auth(&self, req: reqwest::RequestBuilder) -> Result<String> {
        let resp = req.bearer_auth(&self.token).send().await?;
        Self::handle_response(resp).await
    }

    async fn request_no_auth(&self, req: reqwest::RequestBuilder) -> Result<String> {
        let resp = req.send().await?;
        Self::handle_response(resp).await
    }

    async fn handle_response(resp: reqwest::Response) -> Result<String> {
        let status = resp.status();
        let text = resp.text().await?;

        if status.is_success() {
            return Ok(text);
        }

        let err = match serde_json::from_str::<ErrorResponse>(&text) {
            Ok(err) => anyhow!("{}: {}", err.error, err.error_description),
            Err(_) => anyhow!("Request failed with {}: {}", status, text),
        };
        Err(err)
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}
