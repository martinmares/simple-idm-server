use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use tabled::{settings::Style, Table, Tabled};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(name = "simple-idm-ctl", version, about = "Admin CLI for simple-idm-server")]
struct Cli {
    #[arg(long)]
    base_url: String,
    #[arg(long)]
    token: String,
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
    Ping,
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

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
    error_description: String,
}

#[derive(Debug, Deserialize, Serialize, Tabled)]
struct UserRow {
    id: String,
    username: String,
    email: String,
    is_active: bool,
}

#[derive(Debug, Deserialize, Serialize, Tabled)]
struct GroupRow {
    id: String,
    name: String,
    #[tabled(display_with = "display_opt")]
    description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Tabled)]
struct ClientRow {
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
struct ClaimMapRow {
    id: String,
    client_id: String,
    group_id: String,
    claim_name: String,
    #[tabled(display_with = "display_opt")]
    claim_value: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Tabled)]
struct UserGroupRow {
    user_id: String,
    username: String,
    email: String,
    group_id: String,
    group_name: String,
}

#[derive(Debug, Deserialize, Serialize, Tabled)]
struct PasswordResetRow {
    user_id: String,
    reset_token: String,
    reset_url: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct MessageResponse {
    message: String,
}

#[derive(Clone, Copy)]
struct OutputConfig {
    format: OutputFormat,
    style: TableStyle,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let http = HttpClient::new(cli.base_url, cli.token);
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
        Commands::Ping => handle_ping(&http).await?,
    }

    Ok(())
}

async fn handle_users(http: &HttpClient, output: OutputConfig, command: UsersCommand) -> Result<()> {
    match command {
        UsersCommand::List { page, limit } => {
            let body = http.get("/admin/users").await?;
            let mut rows: Vec<UserRow> =
                serde_json::from_str(&body).context("Failed to parse response")?;
            rows = apply_paging(rows, page, limit);
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
            let body = http.get("/admin/groups").await?;
            let mut rows: Vec<GroupRow> =
                serde_json::from_str(&body).context("Failed to parse response")?;
            rows = apply_paging(rows, page, limit);
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
            let body = http.get("/admin/oauth-clients").await?;
            let mut rows: Vec<ClientRow> =
                serde_json::from_str(&body).context("Failed to parse response")?;
            rows = apply_paging(rows, page, limit);
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
            let body = http.get("/admin/claim-maps").await?;
            let mut rows: Vec<ClaimMapRow> =
                serde_json::from_str(&body).context("Failed to parse response")?;
            rows = apply_paging(rows, page, limit);
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
            let body = http.get("/admin/user-groups").await?;
            let mut rows: Vec<UserGroupRow> =
                serde_json::from_str(&body).context("Failed to parse response")?;
            rows = apply_paging(rows, page, limit);
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

fn apply_paging<T>(items: Vec<T>, page: Option<usize>, limit: Option<usize>) -> Vec<T> {
    let limit = limit.unwrap_or(items.len());
    let page = page.unwrap_or(1);
    let start = limit.saturating_mul(page.saturating_sub(1));
    items.into_iter().skip(start).take(limit).collect()
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

struct HttpClient {
    base_url: String,
    token: String,
    client: reqwest::Client,
}

impl HttpClient {
    fn new(base_url: String, token: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            client: reqwest::Client::new(),
        }
    }

    async fn get(&self, path: &str) -> Result<String> {
        self.request(self.client.get(self.url(path))).await
    }

    async fn delete(&self, path: &str) -> Result<String> {
        self.request(self.client.delete(self.url(path))).await
    }

    async fn post_json<T: Serialize>(&self, path: &str, body: T) -> Result<String> {
        self.request(self.client.post(self.url(path)).json(&body)).await
    }

    async fn put_json<T: Serialize>(&self, path: &str, body: T) -> Result<String> {
        self.request(self.client.put(self.url(path)).json(&body)).await
    }

    async fn post_empty(&self, path: &str) -> Result<String> {
        self.request(self.client.post(self.url(path))).await
    }

    async fn request(&self, req: reqwest::RequestBuilder) -> Result<String> {
        let resp = req.bearer_auth(&self.token).send().await?;
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

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}
