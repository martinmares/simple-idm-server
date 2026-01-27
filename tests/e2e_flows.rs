use reqwest::{redirect::Policy, Client, Url};
use serde_json::json;
use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, OnceCell};
use tokio::time::sleep;

// Test configuration
const DOCKER_COMPOSE_FILE: &str = "docker-compose.yml";
const INIT_SCRIPT: &str = "scripts/init_test_data.sql";
const SERVER_HOST: &str = "127.0.0.1";
const SERVER_PORT: u16 = 8080;
const BASE_URL: &str = "http://127.0.0.1:8080";
const HEALTH_CHECK_URL: &str = "http://127.0.0.1:8080/health";

// Test data - from scripts/init_test_data.sql
const TEST_USERNAME: &str = "admin";
const TEST_EMAIL: &str = "admin@example.com";
const TEST_PASSWORD: &str = "password123";
const TEST_CLIENT_ID: &str = "webapp_dashboard";
const TEST_CLIENT_SECRET: &str = "client_secret_123";
const TEST_REDIRECT_URI: &str = "http://localhost:3000/callback";
const DEVICE_CLIENT_ID: &str = "smart_tv_app";

static TEST_MUTEX: OnceCell<Mutex<()>> = OnceCell::const_new();
static ENV: OnceCell<Arc<TestEnvironment>> = OnceCell::const_new();

struct TestEnvironment {
    server_process: Option<Child>,
}

impl TestEnvironment {
    fn new() -> Self {
        Self { server_process: None }
    }

    fn run_compose(args: &[&str]) -> Result<std::process::Output, std::io::Error> {
        let mut cmd = Command::new("docker");
        cmd.arg("compose")
            .arg("-f")
            .arg(DOCKER_COMPOSE_FILE)
            .args(args);
        cmd.output().or_else(|_| {
            let mut cmd = Command::new("docker-compose");
            cmd.arg("-f").arg(DOCKER_COMPOSE_FILE).args(args);
            cmd.output()
        })
    }

    async fn start_docker(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting Docker services...");
        let _ = Self::run_compose(&["down"]);

        let output = Self::run_compose(&["up", "-d"])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("docker compose up failed: {}", stderr.trim()).into());
        }
        println!("Docker services started");
        Ok(())
    }

    async fn wait_for_postgres(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Waiting for PostgreSQL to be ready...");
        let max_attempts = 120;
        let mut attempts = 0;

        loop {
            if let Ok(stream) = tokio::net::TcpStream::connect("127.0.0.1:5432").await {
                drop(stream);
                println!("PostgreSQL is ready!");
                return Ok(());
            }

            let health = Command::new("docker")
                .args([
                    "exec",
                    "simple-idm-postgres",
                    "pg_isready",
                    "-U",
                    "postgres",
                ])
                .output();

            if let Ok(output) = health {
                if output.status.success() {
                    println!("PostgreSQL is ready!");
                    return Ok(());
                }
            }

            attempts += 1;
            if attempts >= max_attempts {
                return Err("PostgreSQL failed to start in time".into());
            }

            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn setup_database(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running database setup and seed data...");
        sleep(Duration::from_secs(2)).await;

        let output = Command::new("bash")
            .arg("-c")
            .arg(format!(
                "docker compose -f {} exec -T postgres psql -U postgres -d simple_idm < {}",
                DOCKER_COMPOSE_FILE, INIT_SCRIPT
            ))
            .output()
            .or_else(|_| {
                Command::new("bash")
                    .arg("-c")
                    .arg(format!(
                        "docker-compose -f {} exec -T postgres psql -U postgres -d simple_idm < {}",
                        DOCKER_COMPOSE_FILE, INIT_SCRIPT
                    ))
                    .output()
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Database setup stderr: {}", stderr);
        }

        println!("Database setup completed");
        Ok(())
    }

    async fn start_server(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting application server...");

        let _ = Command::new("lsof")
            .args(&["-i", ":8080", "-t"])
            .output()
            .and_then(|output| {
                if output.status.success() {
                    let pid = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !pid.is_empty() {
                        let _ = Command::new("kill").arg("-9").arg(pid).output();
                    }
                }
                Ok(())
            });

        sleep(Duration::from_millis(500)).await;

        let binary_path = std::env::var("CARGO_BIN_EXE_simple-idm-server")
            .unwrap_or_else(|_| "target/debug/simple-idm-server".to_string());
        let mut cmd = Command::new(binary_path);
        cmd.env("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/simple_idm")
            .env("SERVER_HOST", SERVER_HOST)
            .env("SERVER_PORT", SERVER_PORT.to_string())
            .env("JWT_ISSUER", "http://localhost:8080")
            .env("ACCESS_TOKEN_EXPIRY_SECONDS", "3600")
            .env("REFRESH_TOKEN_EXPIRY_SECONDS", "2592000")
            .env("JWT_PRIVATE_KEY_PATH", "./keys/private.pem")
            .env("JWT_PUBLIC_KEY_PATH", "./keys/public.pem")
            .env("RUST_LOG", "simple_idm_server=debug");

        let process = cmd.spawn()?;
        self.server_process = Some(process);
        println!("Server process started, waiting for health check...");
        Ok(())
    }

    async fn wait_for_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Waiting for server to be ready...");
        let client = Client::new();
        let max_attempts = 60;
        let mut attempts = 0;

        loop {
            match client.get(HEALTH_CHECK_URL).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        println!("Server is ready!");
                        return Ok(());
                    }
                }
                Err(_) => {}
            }

            attempts += 1;
            if attempts >= max_attempts {
                return Err("Server failed to start in time".into());
            }

            sleep(Duration::from_secs(1)).await;
        }
    }
}

async fn setup_env() -> Arc<TestEnvironment> {
    ENV.get_or_init(|| async {
        let mut env = TestEnvironment::new();

        if let Err(e) = env.start_docker().await {
            panic!("Failed to start Docker: {}", e);
        }

        if let Err(e) = env.wait_for_postgres().await {
            panic!("PostgreSQL not ready: {}", e);
        }

        if let Err(e) = env.setup_database().await {
            panic!("Database setup failed: {}", e);
        }

        if let Err(e) = env.start_server().await {
            panic!("Server start failed: {}", e);
        }

        if let Err(e) = env.wait_for_server().await {
            panic!("Server not ready: {}", e);
        }

        Arc::new(env)
    })
    .await
    .clone()
}

fn build_client() -> Client {
    Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("Failed to build HTTP client")
}

fn extract_code_from_location(location: &str) -> String {
    let url = Url::parse(location).expect("Invalid redirect URL");
    let code = url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .expect("Missing code in redirect URL");
    assert!(!code.is_empty());
    code
}

async fn login_and_get_code(client: &Client) -> String {
    let encoded = serde_urlencoded::to_string([
        ("username", TEST_USERNAME),
        ("password", TEST_PASSWORD),
        ("client_id", TEST_CLIENT_ID),
        ("redirect_uri", TEST_REDIRECT_URI),
        ("scope", "openid profile email groups"),
    ])
    .expect("Failed to encode login form");

    let login_response = client
        .post(&format!("{}/oauth2/login", BASE_URL))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(encoded)
        .send()
        .await
        .expect("Failed to call login");

    assert_eq!(login_response.status(), 303);
    let location = login_response
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("Missing redirect location");

    extract_code_from_location(location)
}

async fn exchange_code_for_tokens(client: &Client, code: &str) -> serde_json::Value {
    let token_response = client
        .post(&format!("{}/oauth2/token", BASE_URL))
        .json(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": TEST_REDIRECT_URI,
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET
        }))
        .send()
        .await
        .expect("Failed to call token");

    assert_eq!(token_response.status(), 200);
    token_response.json().await.unwrap()
}

async fn device_authorize(client: &Client, scope: &str) -> serde_json::Value {
    let response = client
        .post(&format!("{}/oauth2/device/authorize", BASE_URL))
        .header("Content-Type", "application/json")
        .json(&json!({
            "client_id": DEVICE_CLIENT_ID,
            "scope": scope
        }))
        .send()
        .await
        .expect("Failed to call device authorize");
    let status = response.status();
    let body = response.text().await.unwrap();
    if status == reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE {
        let encoded = serde_urlencoded::to_string([
            ("client_id", DEVICE_CLIENT_ID),
            ("scope", scope),
        ])
        .expect("encode device authorize form");
        let response = client
            .post(&format!("{}/oauth2/device/authorize", BASE_URL))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(encoded)
            .send()
            .await
            .expect("Failed to call device authorize (form)");
        let status = response.status();
        let body = response.text().await.unwrap();
        assert_eq!(status, 200, "device authorize failed: {}", body);
        return serde_json::from_str(&body).unwrap();
    }
    assert_eq!(status, 200, "device authorize failed: {}", body);
    serde_json::from_str(&body).unwrap()
}

async fn device_verify(client: &Client, user_code: &str) {
    let encoded = serde_urlencoded::to_string([
        ("user_code", user_code),
        ("username", TEST_USERNAME),
        ("password", TEST_PASSWORD),
    ])
    .expect("Failed to encode device verify form");

    let response = client
        .post(&format!("{}/device", BASE_URL))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(encoded)
        .send()
        .await
        .expect("Failed to call device verify");
    assert_eq!(response.status(), 200);
}

async fn device_token_once(client: &Client, device_code: &str) -> (reqwest::StatusCode, String) {
    let response = client
        .post(&format!("{}/oauth2/device/token", BASE_URL))
        .header("Content-Type", "application/json")
        .json(&json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": DEVICE_CLIENT_ID
        }))
        .send()
        .await
        .expect("Failed to call device token");
    let status = response.status();
    let body = response.text().await.unwrap();
    if status == reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE {
        let encoded = serde_urlencoded::to_string([
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
            ("client_id", DEVICE_CLIENT_ID),
        ])
        .expect("encode device token form");
        let response = client
            .post(&format!("{}/oauth2/device/token", BASE_URL))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(encoded)
            .send()
            .await
            .expect("Failed to call device token (form)");
        let status = response.status();
        let body = response.text().await.unwrap();
        return (status, body);
    }
    (status, body)
}

async fn device_poll_token(
    client: &Client,
    device_code: &str,
    interval_secs: u64,
) -> serde_json::Value {
    let interval = Duration::from_secs(interval_secs.max(1));
    for _ in 0..30 {
        let (status, body) = device_token_once(client, device_code).await;
        if status == reqwest::StatusCode::OK {
            return serde_json::from_str(&body).unwrap();
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            sleep(interval).await;
            continue;
        }
        if let Ok(err) = serde_json::from_str::<serde_json::Value>(&body) {
            if err.get("error").and_then(|v| v.as_str()) == Some("authorization_pending") {
                sleep(interval).await;
                continue;
            }
        }
        panic!("device token failed: {}", body);
    }
    panic!("device token polling timed out");
}

async fn userinfo(client: &Client, access_token: &str) -> serde_json::Value {
    let response = client
        .get(&format!("{}/oauth2/userinfo", BASE_URL))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .expect("Failed to call userinfo");
    assert_eq!(response.status(), 200);
    response.json().await.unwrap()
}

#[tokio::test]
async fn e2e_web_auth_groups() {
    let mutex = TEST_MUTEX.get_or_init(|| async { Mutex::new(()) }).await;
    let _lock = mutex.lock().await;
    let _env = setup_env().await;

    let client = build_client();
    let code = login_and_get_code(&client).await;
    let token_json = exchange_code_for_tokens(&client, &code).await;

    let access_token = token_json["access_token"].as_str().unwrap();
    let userinfo_json = userinfo(&client, access_token).await;
    assert_eq!(userinfo_json["email"].as_str().unwrap(), TEST_EMAIL);
    assert!(userinfo_json["groups"].as_array().unwrap().len() > 0);
}

#[tokio::test]
async fn e2e_web_auth_claim_map() {
    let mutex = TEST_MUTEX.get_or_init(|| async { Mutex::new(()) }).await;
    let _lock = mutex.lock().await;
    let _env = setup_env().await;

    let client = build_client();
    let code = login_and_get_code(&client).await;
    let token_json = exchange_code_for_tokens(&client, &code).await;

    let access_token = token_json["access_token"].as_str().unwrap();
    let userinfo_json = userinfo(&client, access_token).await;
    assert_eq!(userinfo_json["is_admin"].as_bool().unwrap(), true);
}

#[tokio::test]
async fn e2e_device_flow_groups() {
    let mutex = TEST_MUTEX.get_or_init(|| async { Mutex::new(()) }).await;
    let _lock = mutex.lock().await;
    let _env = setup_env().await;

    let client = build_client();
    let auth = device_authorize(&client, "openid profile email groups").await;
    let device_code = auth["device_code"].as_str().unwrap();
    let user_code = auth["user_code"].as_str().unwrap();
    let interval = auth["interval"].as_u64().unwrap_or(5);

    device_verify(&client, user_code).await;
    let token_json = device_poll_token(&client, device_code, interval).await;

    let access_token = token_json["access_token"].as_str().unwrap();
    let userinfo_json = userinfo(&client, access_token).await;
    assert!(userinfo_json["groups"].as_array().unwrap().len() > 0);
}

#[tokio::test]
async fn e2e_device_flow_claim_map() {
    let mutex = TEST_MUTEX.get_or_init(|| async { Mutex::new(()) }).await;
    let _lock = mutex.lock().await;
    let _env = setup_env().await;

    let client = build_client();
    let auth = device_authorize(&client, "openid profile email groups").await;
    let device_code = auth["device_code"].as_str().unwrap();
    let user_code = auth["user_code"].as_str().unwrap();
    let interval = auth["interval"].as_u64().unwrap_or(5);

    device_verify(&client, user_code).await;
    let token_json = device_poll_token(&client, device_code, interval).await;

    let access_token = token_json["access_token"].as_str().unwrap();
    let userinfo_json = userinfo(&client, access_token).await;
    assert_eq!(userinfo_json["is_user"].as_bool().unwrap(), true);
}

fn parse_query(url: &str) -> HashMap<String, String> {
    Url::parse(url)
        .ok()
        .map(|url| {
            url.query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default()
}

fn get_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind free port")
        .local_addr()
        .expect("local addr")
        .port()
}

#[tokio::test]
async fn e2e_oauth2_proxy_headers() {
    let mutex = TEST_MUTEX.get_or_init(|| async { Mutex::new(()) }).await;
    let _lock = mutex.lock().await;
    let _env = setup_env().await;

    let proxy_port = get_free_port();
    let proxy_base = format!("http://127.0.0.1:{}", proxy_port);
    let config_file = NamedTempFile::new().expect("create proxy config");
    let config_contents = format!(
        r#"
listen_addr = "127.0.0.1:{proxy_port}"
public_base_url = "{proxy_base}"
cookie_name = "_simple_idm_proxy"
cookie_secret = "01234567890123456789012345678901"
cookie_samesite = "Lax"
session_max_age = 3600
session_backend = "memory"
oidc_issuer = "http://localhost:8080"
client_id = "{client_id}"
client_secret = "{client_secret}"
redirect_path = "/callback"
scopes = ["openid", "profile", "email", "groups"]
groups_claim = "groups"
username_claims = ["preferred_username", "sub"]
email_claim = "email"
pass_token_header = false
groups_header_name = "x-auth-groups"
groups_header_format = "csv"
"#,
        client_id = TEST_CLIENT_ID,
        client_secret = TEST_CLIENT_SECRET,
        proxy_port = proxy_port,
        proxy_base = proxy_base
    );
    std::fs::write(config_file.path(), config_contents).expect("write proxy config");

    let proxy_binary = std::env::var("CARGO_BIN_EXE_simple-idm-oauth2-proxy")
        .unwrap_or_else(|_| "target/debug/simple-idm-oauth2-proxy".to_string());
    let log_file = NamedTempFile::new().expect("proxy log file");
    let log_path = log_file.path().to_path_buf();
    let stdout = log_file.reopen().expect("proxy stdout");
    let stderr = log_file.reopen().expect("proxy stderr");
    let mut proxy = Command::new(proxy_binary)
        .env("OAUTH2_PROXY_CONFIG", config_file.path())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("start proxy");

    let proxy_client = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .expect("proxy client");

    let mut attempts = 0;
    loop {
        if attempts > 120 {
            let logs = std::fs::read_to_string(&log_path).unwrap_or_default();
            panic!("proxy failed to start. logs:\n{}", logs);
        }
        if let Ok(resp) = proxy_client
            .get(format!("{}/healthz", proxy_base))
            .send()
            .await
        {
            if resp.status().is_success() {
                break;
            }
        }
        attempts += 1;
        sleep(Duration::from_millis(250)).await;
    }

    let start = proxy_client
        .get(format!("{}/start?rd={}/", proxy_base, proxy_base))
        .send()
        .await
        .expect("start flow");
    assert_eq!(start.status(), 307);
    let auth_url = start
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("missing auth redirect");

    let params = parse_query(auth_url);
    let login_form = serde_urlencoded::to_string([
        ("username", TEST_USERNAME),
        ("password", TEST_PASSWORD),
        ("client_id", params.get("client_id").unwrap().as_str()),
        ("redirect_uri", params.get("redirect_uri").unwrap().as_str()),
        ("scope", params.get("scope").unwrap().as_str()),
        ("state", params.get("state").unwrap().as_str()),
        ("nonce", params.get("nonce").unwrap().as_str()),
        ("code_challenge", params.get("code_challenge").unwrap().as_str()),
        (
            "code_challenge_method",
            params.get("code_challenge_method").unwrap().as_str(),
        ),
    ])
    .expect("encode login form");

    let login_response = proxy_client
        .post(&format!("{}/oauth2/login", BASE_URL))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(login_form)
        .send()
        .await
        .expect("login");

    assert_eq!(login_response.status(), 303);
    let callback_url = login_response
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("missing callback url");

    let callback_response = proxy_client
        .get(callback_url)
        .send()
        .await
        .expect("callback");
    assert_eq!(callback_response.status(), 307);

    let auth_response = proxy_client
        .get(format!("{}/auth", proxy_base))
        .send()
        .await
        .expect("auth");
    assert_eq!(auth_response.status(), 200);
    let headers = auth_response.headers();
    assert!(headers.get("x-auth-user").is_some());
    assert!(headers.get("x-auth-email").is_some());
    assert!(headers.get("x-auth-groups").is_some());

    let _ = proxy.kill();
}
