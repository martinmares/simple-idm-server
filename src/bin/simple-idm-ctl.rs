use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use tabled::{settings::Style, Table, Tabled};

#[derive(Parser, Debug)]
#[command(name = "simple-idm-ctl", version, about = "Admin CLI for simple-idm-server")]
struct Cli {
    #[arg(long)]
    base_url: String,
    #[arg(long)]
    token: String,
    #[arg(short = 'o', long, default_value = "table")]
    output: OutputFormat,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Subcommand, Debug)]
enum Commands {
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
}

#[derive(Subcommand, Debug)]
enum UsersCommand {
    List,
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
    },
}

#[derive(Subcommand, Debug)]
enum GroupsCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
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
    List,
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
    Delete {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum ClaimMapsCommand {
    List,
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

#[derive(Debug, Deserialize, Tabled)]
struct UserRow {
    id: String,
    username: String,
    email: String,
    is_active: bool,
}

#[derive(Debug, Deserialize, Tabled)]
struct GroupRow {
    id: String,
    name: String,
    #[tabled(display_with = "display_opt")]
    description: Option<String>,
}

#[derive(Debug, Deserialize, Tabled)]
struct ClientRow {
    id: String,
    client_id: String,
    name: String,
    #[tabled(display_with = "display_vec")]
    redirect_uris: Vec<String>,
    #[tabled(display_with = "display_vec")]
    grant_types: Vec<String>,
    scope: String,
    is_active: bool,
}

#[derive(Debug, Deserialize, Tabled)]
struct ClaimMapRow {
    id: String,
    client_id: String,
    group_id: String,
    claim_name: String,
    #[tabled(display_with = "display_opt")]
    claim_value: Option<String>,
}

#[derive(Debug, Deserialize, Tabled)]
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let http = HttpClient::new(cli.base_url, cli.token);

    match cli.command {
        Commands::Users { command } => handle_users(&http, cli.output, command).await?,
        Commands::Groups { command } => handle_groups(&http, cli.output, command).await?,
        Commands::Clients { command } => handle_clients(&http, cli.output, command).await?,
        Commands::ClaimMaps { command } => handle_claim_maps(&http, cli.output, command).await?,
        Commands::UserGroups { command } => handle_user_groups(&http, cli.output, command).await?,
    }

    Ok(())
}

async fn handle_users(http: &HttpClient, output: OutputFormat, command: UsersCommand) -> Result<()> {
    match command {
        UsersCommand::List => {
            let body = http.get("/admin/users").await?;
            print_table_rows::<UserRow>(output, &body)?;
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
        UsersCommand::ResetPassword { id } => {
            let body = http.post_empty(&format!("/admin/users/{id}/password-reset")).await?;
            print_table_item::<PasswordResetRow>(output, &body)?;
        }
    }

    Ok(())
}

async fn handle_groups(http: &HttpClient, output: OutputFormat, command: GroupsCommand) -> Result<()> {
    match command {
        GroupsCommand::List => {
            let body = http.get("/admin/groups").await?;
            print_table_rows::<GroupRow>(output, &body)?;
        }
        GroupsCommand::Create { name, description } => {
            let payload = serde_json::json!({
                "name": name,
                "description": description,
            });
            let body = http.post_json("/admin/groups", payload).await?;
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
    output: OutputFormat,
    command: ClientsCommand,
) -> Result<()> {
    match command {
        ClientsCommand::List => {
            let body = http.get("/admin/oauth-clients").await?;
            print_table_rows::<ClientRow>(output, &body)?;
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
        ClientsCommand::Delete { id } => {
            let body = http.delete(&format!("/admin/oauth-clients/{id}")).await?;
            print_message(output, &body)?;
        }
    }
    Ok(())
}

async fn handle_claim_maps(
    http: &HttpClient,
    output: OutputFormat,
    command: ClaimMapsCommand,
) -> Result<()> {
    match command {
        ClaimMapsCommand::List => {
            let body = http.get("/admin/claim-maps").await?;
            print_table_rows::<ClaimMapRow>(output, &body)?;
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
    output: OutputFormat,
    command: UserGroupsCommand,
) -> Result<()> {
    match command {
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

fn print_table_item<T>(output: OutputFormat, body: &str) -> Result<()>
where
    T: for<'de> Deserialize<'de> + Tabled,
{
    match output {
        OutputFormat::Json => println!("{}", body),
        OutputFormat::Table => {
            let parsed: T = serde_json::from_str(body).context("Failed to parse response")?;
            let mut table = Table::new(vec![parsed]);
            table.with(Style::ascii());
            println!("{table}");
        }
    }
    Ok(())
}

fn print_table_rows<T>(output: OutputFormat, body: &str) -> Result<()>
where
    T: for<'de> Deserialize<'de> + Tabled,
{
    match output {
        OutputFormat::Json => println!("{}", body),
        OutputFormat::Table => {
            let parsed: Vec<T> = serde_json::from_str(body).context("Failed to parse response")?;
            let mut table = Table::new(parsed);
            table.with(Style::ascii());
            println!("{table}");
        }
    }
    Ok(())
}

fn display_opt(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

fn display_vec(value: &Vec<String>) -> String {
    value.join(", ")
}

fn print_message(output: OutputFormat, body: &str) -> Result<()> {
    match output {
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
