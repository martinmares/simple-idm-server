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
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreProviderMetadata},
    reqwest::async_http_client,
    AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope,
};
use openidconnect::{OAuth2TokenResponse, TokenResponse as OidcTokenResponseTrait};
use qrcode::QrCode;
use serde_json::Value;

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
    Login {
        #[arg(long, required = true)]
        url: String,
        #[arg(long, default_value = "cli-tools")]
        client: String,
        #[arg(long, default_value = "8888")]
        port: u16,
        #[arg(long, default_value = "default")]
        server: String,
        #[arg(long)]
        device: bool,
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
        #[arg(long)]
        is_virtual: Option<bool>,
    },
    Update {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        is_virtual: Option<bool>,
    },
    Delete {
        #[arg(long)]
        id: String,
    },
    AddChild {
        #[arg(long, help = "Parent group ID or name")]
        parent: String,
        #[arg(long, help = "Child group ID or name")]
        child: String,
    },
    RemoveChild {
        #[arg(long, help = "Parent group ID or name")]
        parent: String,
        #[arg(long, help = "Child group ID or name")]
        child: String,
    },
    ListChildren {
        #[arg(long, help = "Parent group ID or name")]
        parent: String,
        #[arg(long, help = "Expand to show all transitive children")]
        expand: bool,
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
        #[arg(long, default_value = "effective")]
        groups_claim_mode: String,
        #[arg(long, default_value_t = true)]
        include_claim_maps: bool,
        #[arg(long, default_value_t = false)]
        ignore_virtual_groups: bool,
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
        #[arg(long)]
        groups_claim_mode: Option<String>,
        #[arg(long, value_parser = clap::builder::BoolishValueParser::new())]
        include_claim_maps: Option<bool>,
        #[arg(long, value_parser = clap::builder::BoolishValueParser::new())]
        ignore_virtual_groups: Option<bool>,
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
        /// User UUID (use this OR --username)
        #[arg(long, conflicts_with = "username")]
        user_id: Option<String>,
        /// Username to lookup
        #[arg(long, conflicts_with = "user_id")]
        username: Option<String>,
        /// Group UUID (use this OR --group)
        #[arg(long, conflicts_with = "group")]
        group_id: Option<String>,
        /// Group name to lookup
        #[arg(long, conflicts_with = "group_id")]
        group: Option<String>,
    },
    Remove {
        /// User UUID (use this OR --username)
        #[arg(long, conflicts_with = "username")]
        user_id: Option<String>,
        /// Username to lookup
        #[arg(long, conflicts_with = "user_id")]
        username: Option<String>,
        /// Group UUID (use this OR --group)
        #[arg(long, conflicts_with = "group")]
        group_id: Option<String>,
        /// Group name to lookup
        #[arg(long, conflicts_with = "group_id")]
        group: Option<String>,
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

#[derive(Clone, Debug, Deserialize, Serialize, Tabled)]
pub(crate) struct GroupRow {
    id: String,
    name: String,
    #[tabled(display_with = "display_opt")]
    description: Option<String>,
    is_virtual: bool,
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
    is_public: bool,
    groups_claim_mode: String,
    include_claim_maps: bool,
    ignore_virtual_groups: bool,
}

#[derive(Debug, Deserialize, Serialize, Tabled)]
pub(crate) struct ClaimMapRow {
    id: String,
    client_id: String,
    group_id: String,
    claim_name: String,
    claim_value_kind: String,
    #[tabled(display_with = "display_claim_value")]
    claim_value: Option<serde_json::Value>,
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

async fn discover_provider(base_url: &str, insecure: bool) -> Result<CoreProviderMetadata> {
    let issuer_url = IssuerUrl::new(base_url.to_string())
        .context("Invalid issuer URL")?;
    if insecure {
        eprintln!("Warning: --insecure is not supported for OIDC discovery; proceeding with default TLS validation.");
    }
    let metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client).await?;
    Ok(metadata)
}

fn parse_raw_claims(id_token: &CoreIdToken) -> Result<HashMap<String, Value>> {
    let token_str = id_token.to_string();
    let parts: Vec<&str> = token_str.split('.').collect();
    if parts.len() != 3 {
        bail!("Invalid JWT format");
    }
    let payload = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1],
    )
    .context("Failed to decode JWT payload")?;
    let claims: HashMap<String, Value> = serde_json::from_slice(&payload)
        .context("Failed to parse JWT claims")?;
    Ok(claims)
}

fn extract_groups(claims: &HashMap<String, Value>) -> Vec<String> {
    claims
        .get("groups")
        .and_then(|value| value.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Login { url, client, port, server, device } => {
            if *device {
                return handle_device_login(url, client, server, cli.insecure.unwrap_or(false)).await;
            }
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
        Commands::Ping => handle_ping(&http).await?,
        Commands::Login { .. } | Commands::Logout { .. } | Commands::Sessions { .. } | Commands::Status => unreachable!(),
    }

    Ok(())
}

async fn resolve_auth(_cli: &Cli) -> Result<(String, String)> {
    let mut session = get_active_session()?
        .ok_or_else(|| anyhow!("Not logged in. Run 'simple-idm-ctl login --url <SERVER_URL>' first."))?;

    if !is_session_valid(&session) || (session.expires_at - Utc::now()).num_seconds() < 300 {
        let config = load_sessions()?;
        session = refresh_session_async(session).await?;
        save_session(&config.active, session.clone())?;
    }

    Ok((session.base_url.clone(), session.access_token))
}

async fn handle_login(base_url: &str, client_id: &str, port: u16, server_name: &str, insecure: bool) -> Result<()> {
    let provider_metadata = discover_provider(base_url, insecure).await
        .context("Failed to discover OIDC provider metadata")?;

    let redirect_uri = format!("http://localhost:{}/callback", port);
    let redirect_url = RedirectUrl::new(redirect_uri.clone())
        .context("Invalid redirect URL")?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.to_string()),
        None,
    )
    .set_redirect_uri(redirect_url);

    let (code_verifier, _code_challenge) = generate_pkce_pair();
    let pkce_challenge = PkceCodeChallenge::from_code_verifier_sha256(
        &PkceCodeVerifier::new(code_verifier.clone()),
    );

    let (auth_url, csrf_state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("groups".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let (tx, rx) = oneshot::channel::<(String, String)>();
    let tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));

    let callback_app = axum::Router::new().route(
        "/callback",
        axum::routing::get(|axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>| async move {
            let tx_clone = tx.clone();
            if let (Some(code), Some(state)) = (params.get("code"), params.get("state")) {
                if let Some(sender) = tx_clone.lock().await.take() {
                    let _ = sender.send((code.clone(), state.clone()));
                }
                return "✓ Login successful! You can close this window.";
            }
            "✗ Login failed: Missing authorization code or state."
        }),
    );

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await
        .context(format!("Failed to bind to {}. Try different --port", addr))?;

    tokio::spawn(async move {
        axum::serve(listener, callback_app).await.ok();
    });

    println!("Opening browser for login...");
    println!("If browser doesn't open, visit: {}", auth_url);

    if let Err(e) = open_url(auth_url.as_str()) {
        eprintln!("Could not open browser: {}", e);
    }

    let (code, returned_state) = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        rx
    ).await
        .context("Login timeout after 2 minutes")??;

    if returned_state != *csrf_state.secret() {
        bail!("State mismatch in OAuth2 callback");
    }

    exchange_code_for_tokens(
        &client,
        base_url,
        &code,
        &code_verifier,
        insecure,
        server_name,
        nonce,
    )
    .await
}

#[derive(Serialize)]
struct DeviceAuthorizationRequest {
    client_id: String,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: i64,
    interval: i64,
}

#[derive(Deserialize)]
struct DeviceTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct UserinfoResponse {
    email: Option<String>,
    groups: Option<Vec<String>>,
}

async fn handle_device_login(base_url: &str, client_id: &str, server_name: &str, insecure: bool) -> Result<()> {
    let client = if insecure {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .context("Failed to build HTTP client")?
    } else {
        reqwest::Client::new()
    };

    let payload = DeviceAuthorizationRequest {
        client_id: client_id.to_string(),
        scope: Some("openid profile email groups".to_string()),
    };

    let response = client
        .post(format!("{}/oauth2/device/authorize", base_url))
        .json(&payload)
        .send()
        .await?;

    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        if let Ok(err) = serde_json::from_str::<ErrorResponse>(&body) {
            bail!("Device authorization failed: {}: {}", err.error, err.error_description);
        }
        bail!("Device authorization failed ({}). Response: {}", status, body.trim());
    }

    let auth: DeviceAuthorizationResponse =
        serde_json::from_str(&body).context("Failed to parse device authorization response")?;

    println!("Device login started.");
    println!("User code: {}", auth.user_code);
    println!("Verify at: {}", auth.verification_uri);
    if let Some(uri) = &auth.verification_uri_complete {
        println!("Direct link: {}", uri);
        print_qr_code(uri);
    }

    let deadline = Utc::now() + Duration::seconds(auth.expires_in);
    let interval = Duration::seconds(auth.interval.max(1));

    loop {
        if Utc::now() >= deadline {
            bail!("Device authorization expired. Please run 'simple-idm-ctl login --device' again.");
        }

        tokio::time::sleep(std::time::Duration::from_secs(interval.num_seconds() as u64)).await;

        let token_payload = serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": auth.device_code,
            "client_id": client_id,
        });

        let token_response = client
            .post(format!("{}/oauth2/device/token", base_url))
            .json(&token_payload)
            .send()
            .await?;

        let token_status = token_response.status();
        let token_body = token_response.text().await?;

        if let Ok(err) = serde_json::from_str::<ErrorResponse>(&token_body) {
            match err.error.as_str() {
                "authorization_pending" => continue,
                "expired_token" => {
                    bail!("Device authorization expired. Please run 'simple-idm-ctl login --device' again.");
                }
                _ => {
                    bail!("Device token error: {}: {}", err.error, err.error_description);
                }
            }
        }

        if token_status.is_success() {
            let token_data: DeviceTokenResponse = serde_json::from_str(&token_body)
                .context("Failed to parse device token response")?;
            return save_device_session(
                base_url,
                server_name,
                token_data.access_token,
                token_data.expires_in,
                insecure,
            )
            .await;
        }

        bail!(
            "Device token request failed ({}). Response: {}",
            token_status,
            token_body.trim()
        );
    }
}

async fn save_device_session(
    base_url: &str,
    server_name: &str,
    access_token: String,
    expires_in: i64,
    insecure: bool,
) -> Result<()> {
    let client = if insecure {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .context("Failed to build HTTP client")?
    } else {
        reqwest::Client::new()
    };

    let response = client
        .get(format!("{}/oauth2/userinfo", base_url))
        .bearer_auth(&access_token)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    let (email, groups) = if status.is_success() {
        let userinfo: UserinfoResponse =
            serde_json::from_str(&body).context("Failed to parse userinfo response")?;
        (userinfo.email, userinfo.groups.unwrap_or_default())
    } else {
        (None, Vec::new())
    };

    let session = Session {
        access_token,
        refresh_token: String::new(),
        expires_at: Utc::now() + Duration::seconds(expires_in),
        base_url: base_url.to_string(),
        created_at: Utc::now(),
        user_email: email,
        user_groups: groups,
    };

    save_session(server_name, session)?;

    println!("✓ Device login successful!");
    println!("Session saved to {}", sessions_file_path()?.display());
    println!("Server: {}", server_name);

    Ok(())
}

fn print_qr_code(url: &str) {
    let Ok(code) = QrCode::new(url.as_bytes()) else {
        return;
    };
    let qr = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .build();
    println!("\n{}\n", qr);
}

async fn exchange_code_for_tokens(
    client: &CoreClient,
    base_url: &str,
    code: &str,
    code_verifier: &str,
    insecure: bool,
    server_name: &str,
    nonce: Nonce,
) -> Result<()> {
    if insecure {
        eprintln!("Warning: --insecure is not supported for OIDC token exchange; proceeding with default TLS validation.");
    }

    let token_response = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .set_pkce_verifier(PkceCodeVerifier::new(code_verifier.to_string()))
        .request_async(async_http_client)
        .await
        .context("Failed to exchange authorization code for tokens")?;

    let id_token = token_response
        .id_token()
        .context("No ID token in response")?;

    let claims = id_token
        .claims(&client.id_token_verifier(), move |nonce_opt: Option<&Nonce>| {
            match nonce_opt {
                Some(value) if value.secret() == nonce.secret() => Ok(()),
                Some(_) => Err("Nonce mismatch".to_string()),
                None => Err("No nonce in token".to_string()),
            }
        })
        .context("Failed to verify ID token")?;

    let email = claims
        .email()
        .map(|e| e.as_str().to_string())
        .filter(|e| !e.is_empty());

    let raw_claims = parse_raw_claims(id_token)?;
    let groups = extract_groups(&raw_claims);

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: i64,
    }

    let token_data = TokenResponse {
        access_token: token_response.access_token().secret().to_string(),
        refresh_token: token_response
            .refresh_token()
            .map(|token| token.secret().to_string()),
        expires_in: token_response
            .expires_in()
            .map(|exp| exp.as_secs() as i64)
            .unwrap_or(3600),
    };

    let session = Session {
        access_token: token_data.access_token,
        refresh_token: token_data.refresh_token.unwrap_or_default(),
        expires_at: Utc::now() + Duration::seconds(token_data.expires_in),
        base_url: base_url.to_string(),
        created_at: Utc::now(),
        user_email: email,
        user_groups: groups,
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
        GroupsCommand::Create { name, description, is_virtual } => {
            let payload = serde_json::json!({
                "name": name,
                "description": description,
                "is_virtual": is_virtual,
            });
            let body = http.post_json("/admin/groups", payload).await?;
            print_table_item::<GroupRow>(output, &body)?;
        }
        GroupsCommand::Update { id, name, description, is_virtual } => {
            if name.is_none() && description.is_none() && is_virtual.is_none() {
                bail!("At least one field must be provided for update.");
            }
            let payload = serde_json::json!({
                "name": name,
                "description": description,
                "is_virtual": is_virtual,
            });
            let body = http.put_json(&format!("/admin/groups/{id}"), payload).await?;
            print_table_item::<GroupRow>(output, &body)?;
        }
        GroupsCommand::Delete { id } => {
            let body = http.delete(&format!("/admin/groups/{id}")).await?;
            print_message(output, &body)?;
        }
        GroupsCommand::AddChild { parent, child } => {
            // Resolve parent and child IDs (support both UUID and name)
            let parent_id = resolve_group_id(http, &parent).await?;
            let child_id = resolve_group_id(http, &child).await?;

            let payload = serde_json::json!({
                "child_group_id": child_id,
            });
            let body = http.post_json(&format!("/admin/groups/{}/children", parent_id), payload).await?;
            print_message(output, &body)?;
        }
        GroupsCommand::RemoveChild { parent, child } => {
            let parent_id = resolve_group_id(http, &parent).await?;
            let child_id = resolve_group_id(http, &child).await?;

            let body = http.delete(&format!("/admin/groups/{}/children/{}", parent_id, child_id)).await?;
            print_message(output, &body)?;
        }
        GroupsCommand::ListChildren { parent, expand } => {
            let parent_id = resolve_group_id(http, &parent).await?;
            let path = if expand {
                format!("/admin/groups/{}/children?expand=true", parent_id)
            } else {
                format!("/admin/groups/{}/children", parent_id)
            };
            let body = http.get(&path).await?;
            let rows: Vec<GroupRow> = serde_json::from_str(&body).context("Failed to parse child groups")?;
            print_table_rows_vec(output, rows)?;
        }
    }
    Ok(())
}

// Helper function to resolve group ID from either UUID or name
async fn resolve_group_id(http: &HttpClient, id_or_name: &str) -> Result<String> {
    // Try to parse as UUID first
    if uuid::Uuid::parse_str(id_or_name).is_ok() {
        return Ok(id_or_name.to_string());
    }

    // Otherwise, search by name
    let body = http.get("/admin/groups").await?;
    let groups: Vec<serde_json::Value> = serde_json::from_str(&body)?;

    for group in groups {
        if let Some(name) = group.get("name").and_then(|n| n.as_str()) {
            if name == id_or_name {
                if let Some(id) = group.get("id").and_then(|i| i.as_str()) {
                    return Ok(id.to_string());
                }
            }
        }
    }

    bail!("Group not found: {}", id_or_name);
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
            groups_claim_mode,
            include_claim_maps,
            ignore_virtual_groups,
        } => {
            let payload = serde_json::json!({
                "client_id": client_id,
                "client_secret": client_secret,
                "name": name,
                "redirect_uris": redirect_uri,
                "grant_types": grant_type,
                "scope": scope,
                "groups_claim_mode": groups_claim_mode,
                "include_claim_maps": include_claim_maps,
                "ignore_virtual_groups": ignore_virtual_groups,
            });
            let body = http.post_json("/admin/oauth-clients", payload).await?;
            print_client_item(output, &body)?;
        }
        ClientsCommand::Update {
            id,
            name,
            client_secret,
            redirect_uri,
            grant_type,
            scope,
            is_active,
            groups_claim_mode,
            include_claim_maps,
            ignore_virtual_groups,
        } => {
            if name.is_none()
                && client_secret.is_none()
                && redirect_uri.is_empty()
                && grant_type.is_empty()
                && scope.is_none()
                && is_active.is_none()
                && groups_claim_mode.is_none()
                && include_claim_maps.is_none()
                && ignore_virtual_groups.is_none()
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
                "groups_claim_mode": groups_claim_mode,
                "include_claim_maps": include_claim_maps,
                "ignore_virtual_groups": ignore_virtual_groups,
            });
            let body = http.put_json(&format!("/admin/oauth-clients/{id}"), payload).await?;
            print_client_item(output, &body)?;
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
        UserGroupsCommand::Add {
            user_id,
            username,
            group_id,
            group,
        } => {
            // Resolve user_id from username if needed
            let resolved_user_id = if let Some(uid) = user_id {
                uid
            } else if let Some(uname) = username {
                lookup_user_id(http, &uname).await?
            } else {
                anyhow::bail!("Either --user-id or --username must be provided");
            };

            // Resolve group_id from group name if needed
            let resolved_group_id = if let Some(gid) = group_id {
                gid
            } else if let Some(gname) = group {
                lookup_group_id(http, &gname).await?
            } else {
                anyhow::bail!("Either --group-id or --group must be provided");
            };

            let payload = serde_json::json!({ "group_id": resolved_group_id });
            let body = http
                .post_json(&format!("/admin/users/{resolved_user_id}/groups"), payload)
                .await?;
            print_message(output, &body)?;
        }
        UserGroupsCommand::Remove {
            user_id,
            username,
            group_id,
            group,
        } => {
            // Resolve user_id from username if needed
            let resolved_user_id = if let Some(uid) = user_id {
                uid
            } else if let Some(uname) = username {
                lookup_user_id(http, &uname).await?
            } else {
                anyhow::bail!("Either --user-id or --username must be provided");
            };

            // Resolve group_id from group name if needed
            let resolved_group_id = if let Some(gid) = group_id {
                gid
            } else if let Some(gname) = group {
                lookup_group_id(http, &gname).await?
            } else {
                anyhow::bail!("Either --group-id or --group must be provided");
            };

            let body = http
                .delete(&format!(
                    "/admin/users/{resolved_user_id}/groups/{resolved_group_id}"
                ))
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

async fn refresh_session_async(session: Session) -> Result<Session> {
    if session.refresh_token.trim().is_empty() {
        bail!("No refresh token available. Please login again with 'simple-idm-ctl login'");
    }
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
    let status = response.status();
    let body = response.text().await?;

    if !status.is_success() {
        if let Ok(err) = serde_json::from_str::<ErrorResponse>(&body) {
            bail!(
                "Token refresh failed: {}: {}. Please login again with 'simple-idm-ctl login'",
                err.error,
                err.error_description
            );
        }
        bail!(
            "Token refresh failed ({}). Please login again with 'simple-idm-ctl login'. Response: {}",
            status,
            body.trim()
        );
    }

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: i64,
    }

    let token_data: TokenResponse = match serde_json::from_str(&body) {
        Ok(data) => data,
        Err(err) => {
            if let Ok(err_body) = serde_json::from_str::<ErrorResponse>(&body) {
                bail!(
                    "Token refresh failed: {}: {}. Please login again with 'simple-idm-ctl login'",
                    err_body.error,
                    err_body.error_description
                );
            }
            bail!(
                "Token refresh response missing access_token. Please login again with 'simple-idm-ctl login'. Parse error: {}. Response: {}",
                err,
                body.trim()
            );
        }
    };

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

fn display_claim_value(value: &Option<serde_json::Value>) -> String {
    match value {
        None => String::new(),
        Some(serde_json::Value::String(val)) => val.clone(),
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        Some(other) => other.to_string(),
    }
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
                    KeyValueRow::new("groups_claim_mode", client.groups_claim_mode),
                    KeyValueRow::new("include_claim_maps", client.include_claim_maps.to_string()),
                    KeyValueRow::new("ignore_virtual_groups", client.ignore_virtual_groups.to_string()),
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

fn print_client_item(output: OutputConfig, body: &str) -> Result<()> {
    match output.format {
        OutputFormat::Json => println!("{}", body),
        OutputFormat::Table => {
            let client: ClientRow = serde_json::from_str(body).context("Failed to parse response")?;
            let rows = vec![
                KeyValueRow::new("id", client.id),
                KeyValueRow::new("client_id", client.client_id),
                KeyValueRow::new("name", client.name),
                KeyValueRow::new("redirect_uris", client.redirect_uris.join(", ")),
                KeyValueRow::new("grant_types", client.grant_types.join(", ")),
                KeyValueRow::new("scope", client.scope),
                KeyValueRow::new("is_active", client.is_active.to_string()),
                KeyValueRow::new("groups_claim_mode", client.groups_claim_mode),
                KeyValueRow::new("include_claim_maps", client.include_claim_maps.to_string()),
                KeyValueRow::new("ignore_virtual_groups", client.ignore_virtual_groups.to_string()),
            ];
            let mut table = Table::new(rows);
            apply_style(&mut table, output.style);
            println!("{table}");
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

    async fn request_with_auth(&self, req: reqwest::RequestBuilder) -> Result<String> {
        let resp = req.bearer_auth(&self.token).send().await?;
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

/// Lookup user UUID by username
async fn lookup_user_id(http: &HttpClient, username: &str) -> Result<String> {
    let body = http.get("/admin/users?page=1&limit=1000").await?;
    let users: Vec<UserRow> =
        serde_json::from_str(&body).context("Failed to parse users list")?;

    users
        .iter()
        .find(|u| u.username == username)
        .map(|u| u.id.clone())
        .ok_or_else(|| anyhow!("User '{}' not found", username))
}

/// Lookup group UUID by name
async fn lookup_group_id(http: &HttpClient, group_name: &str) -> Result<String> {
    let body = http.get("/admin/groups?page=1&limit=1000").await?;
    let groups: Vec<GroupRow> =
        serde_json::from_str(&body).context("Failed to parse groups list")?;

    groups
        .iter()
        .find(|g| g.name == group_name)
        .map(|g| g.id.clone())
        .ok_or_else(|| anyhow!("Group '{}' not found", group_name))
}
