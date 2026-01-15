use reqwest::{redirect::Policy, Client, Url};
use serde_json::json;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::OnceCell;
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

static TEST_MUTEX: Mutex<()> = Mutex::new(());
static ENV: OnceCell<Arc<TestEnvironment>> = OnceCell::const_new();

/// Test environment manager
struct TestEnvironment {
    server_process: Option<Child>,
}

impl TestEnvironment {
    fn new() -> Self {
        Self {
            server_process: None,
        }
    }

    /// Start Docker Compose services
    async fn start_docker(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting Docker services...");

        // Stop any existing containers
        let _ = Command::new("docker-compose")
            .arg("-f")
            .arg(DOCKER_COMPOSE_FILE)
            .arg("down")
            .output();

        // Start services
        Command::new("docker-compose")
            .arg("-f")
            .arg(DOCKER_COMPOSE_FILE)
            .arg("up")
            .arg("-d")
            .output()?;

        println!("Docker services started");
        Ok(())
    }

    /// Wait for PostgreSQL to be ready
    async fn wait_for_postgres(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Waiting for PostgreSQL to be ready...");

        let max_attempts = 30;
        let mut attempts = 0;

        loop {
            let output = Command::new("docker-compose")
                .arg("-f")
                .arg(DOCKER_COMPOSE_FILE)
                .arg("exec")
                .arg("-T")
                .arg("postgres")
                .arg("pg_isready")
                .arg("-U")
                .output();

            if let Ok(output) = output {
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

    /// Setup database with migrations and seed data
    async fn setup_database(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running database setup and seed data...");

        sleep(Duration::from_secs(2)).await;

        // Run seed script using bash
        let output = Command::new("bash")
            .arg("-c")
            .arg(format!(
                "docker-compose -f {} exec -T postgres psql -U postgres -d simple_idm < {}",
                DOCKER_COMPOSE_FILE, INIT_SCRIPT
            ))
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Database setup stderr: {}", stderr);
        }

        println!("Database setup completed");
        Ok(())
    }

    /// Build the application
    async fn build_app(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Building application...");

        let output = Command::new("cargo")
            .arg("build")
            .env("SQLX_OFFLINE", "true")
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Build failed: {}", stderr).into());
        }

        println!("Application built successfully");
        Ok(())
    }

    /// Start the application server in background
    async fn start_server(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting application server...");

        // Kill any existing server on port 8080
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

        // Use the built binary directly
        let binary_path = "target/debug/simple-idm-server";

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

    /// Wait for server to be ready
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

        if let Err(e) = env.build_app().await {
            panic!("Build failed: {}", e);
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

// Helper function to generate PKCE challenge
fn generate_pkce_challenge(verifier: &str, method: &str) -> String {
    match method {
        "plain" => verifier.to_string(),
        "S256" => {
            use sha2::{Digest, Sha256};
            use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
            let hash = Sha256::digest(verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(hash)
        }
        _ => panic!("Unknown PKCE method"),
    }
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

async fn login_and_get_code(
    client: &Client,
    username: &str,
    password: &str,
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
) -> String {
    let mut form = vec![
        ("username".to_string(), username.to_string()),
        ("password".to_string(), password.to_string()),
        ("client_id".to_string(), TEST_CLIENT_ID.to_string()),
        ("redirect_uri".to_string(), TEST_REDIRECT_URI.to_string()),
        ("scope".to_string(), "openid profile email".to_string()),
    ];

    if let Some(challenge) = code_challenge {
        form.push(("code_challenge".to_string(), challenge.to_string()));
    }
    if let Some(method) = code_challenge_method {
        form.push(("code_challenge_method".to_string(), method.to_string()));
    }

    let encoded = serde_urlencoded::to_string(form).expect("Failed to encode login form");

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

#[tokio::test]
async fn test_authorization_code_flow_success() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _env = setup_env().await;

    let client = build_client();

    let authorize_query = serde_urlencoded::to_string([
        ("response_type", "code"),
        ("client_id", TEST_CLIENT_ID),
        ("redirect_uri", TEST_REDIRECT_URI),
        ("scope", "openid profile email"),
        ("state", "test-state-123"),
    ])
    .expect("Failed to encode authorize query");

    let authorize_response = client
        .get(&format!("{}/oauth2/authorize?{}", BASE_URL, authorize_query))
        .send()
        .await
        .expect("Failed to call authorize");

    assert_eq!(authorize_response.status(), 200);

    let code = login_and_get_code(&client, TEST_USERNAME, TEST_PASSWORD, None, None).await;
    let token_json = exchange_code_for_tokens(&client, &code).await;

    assert!(token_json["access_token"].as_str().is_some());
    assert!(token_json["refresh_token"].as_str().is_some());

    let access_token = token_json["access_token"].as_str().unwrap();
    let userinfo_response = client
        .get(&format!("{}/oauth2/userinfo", BASE_URL))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .expect("Failed to call userinfo");

    assert_eq!(userinfo_response.status(), 200);
    let userinfo_json: serde_json::Value = userinfo_response.json().await.unwrap();
    assert_eq!(userinfo_json["email"].as_str().unwrap(), TEST_EMAIL);
    assert!(userinfo_json["groups"].as_array().unwrap().len() > 0);
}

#[tokio::test]
async fn test_login_with_invalid_password() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _env = setup_env().await;

    let client = build_client();

    let encoded = serde_urlencoded::to_string([
        ("username", TEST_USERNAME),
        ("password", "wrong-password"),
        ("client_id", TEST_CLIENT_ID),
        ("redirect_uri", TEST_REDIRECT_URI),
    ])
    .expect("Failed to encode login form");

    let login_response = client
        .post(&format!("{}/oauth2/login", BASE_URL))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(encoded)
        .send()
        .await
        .expect("Failed to call login");

    assert_eq!(login_response.status(), 200);
    let body = login_response.text().await.unwrap();
    assert!(body.contains("Invalid username or password"));
}

#[tokio::test]
async fn test_invalid_authorization_code() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _env = setup_env().await;

    let client = build_client();

    let token_response = client
        .post(&format!("{}/oauth2/token", BASE_URL))
        .json(&json!({
            "grant_type": "authorization_code",
            "code": "invalid-code-12345",
            "redirect_uri": TEST_REDIRECT_URI,
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET
        }))
        .send()
        .await
        .expect("Failed to call token");

    assert_eq!(token_response.status(), 200);
    let token_json: serde_json::Value = token_response.json().await.unwrap();
    assert_eq!(token_json["error"].as_str().unwrap(), "invalid_grant");
}

#[tokio::test]
async fn test_pkce_s256_validation() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _env = setup_env().await;

    let client = build_client();

    let code_verifier = "test-verifier-1234567890-abcdefghijklmnop";
    let code_challenge = generate_pkce_challenge(code_verifier, "S256");

    let code = login_and_get_code(
        &client,
        TEST_USERNAME,
        TEST_PASSWORD,
        Some(&code_challenge),
        Some("S256"),
    )
    .await;

    let token_response = client
        .post(&format!("{}/oauth2/token", BASE_URL))
        .json(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": TEST_REDIRECT_URI,
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET,
            "code_verifier": code_verifier
        }))
        .send()
        .await
        .expect("Failed to call token");

    assert_eq!(token_response.status(), 200);
    let token_json: serde_json::Value = token_response.json().await.unwrap();
    assert!(token_json["access_token"].as_str().is_some());
}

#[tokio::test]
async fn test_pkce_wrong_verifier() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _env = setup_env().await;

    let client = build_client();

    let code_verifier = "correct-verifier-1234567890-abcdefghijklmnop";
    let code_challenge = generate_pkce_challenge(code_verifier, "S256");

    let code = login_and_get_code(
        &client,
        TEST_USERNAME,
        TEST_PASSWORD,
        Some(&code_challenge),
        Some("S256"),
    )
    .await;

    let token_response = client
        .post(&format!("{}/oauth2/token", BASE_URL))
        .json(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": TEST_REDIRECT_URI,
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET,
            "code_verifier": "wrong-verifier"
        }))
        .send()
        .await
        .expect("Failed to call token");

    assert_eq!(token_response.status(), 200);
    let token_json: serde_json::Value = token_response.json().await.unwrap();
    assert_eq!(token_json["error"].as_str().unwrap(), "invalid_grant");
}

#[tokio::test]
async fn test_refresh_token_rotation() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _env = setup_env().await;

    let client = build_client();

    let code = login_and_get_code(&client, TEST_USERNAME, TEST_PASSWORD, None, None).await;
    let token_json = exchange_code_for_tokens(&client, &code).await;
    let refresh_token = token_json["refresh_token"].as_str().unwrap().to_string();

    let refresh_response = client
        .post(&format!("{}/oauth2/token", BASE_URL))
        .json(&json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET
        }))
        .send()
        .await
        .expect("Failed to call refresh token");

    assert_eq!(refresh_response.status(), 200);
    let refresh_json: serde_json::Value = refresh_response.json().await.unwrap();
    assert!(refresh_json["access_token"].as_str().is_some());
    let new_refresh_token = refresh_json["refresh_token"].as_str().unwrap();
    assert_ne!(new_refresh_token, token_json["refresh_token"].as_str().unwrap());
}

#[tokio::test]
async fn test_refresh_token_reuse_detection() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _env = setup_env().await;

    let client = build_client();

    let code = login_and_get_code(&client, TEST_USERNAME, TEST_PASSWORD, None, None).await;
    let token_json = exchange_code_for_tokens(&client, &code).await;
    let refresh_token = token_json["refresh_token"].as_str().unwrap().to_string();

    let refresh_response = client
        .post(&format!("{}/oauth2/token", BASE_URL))
        .json(&json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET
        }))
        .send()
        .await
        .expect("Failed to call refresh token");

    assert_eq!(refresh_response.status(), 200);
    let refresh_json: serde_json::Value = refresh_response.json().await.unwrap();
    let new_refresh_token = refresh_json["refresh_token"].as_str().unwrap().to_string();

    let reuse_response = client
        .post(&format!("{}/oauth2/token", BASE_URL))
        .json(&json!({
            "grant_type": "refresh_token",
            "refresh_token": token_json["refresh_token"].as_str().unwrap(),
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET
        }))
        .send()
        .await
        .expect("Failed to call refresh token");

    assert_eq!(reuse_response.status(), 200);
    let reuse_json: serde_json::Value = reuse_response.json().await.unwrap();
    assert_eq!(reuse_json["error"].as_str().unwrap(), "invalid_grant");

    let revoked_response = client
        .post(&format!("{}/oauth2/token", BASE_URL))
        .json(&json!({
            "grant_type": "refresh_token",
            "refresh_token": new_refresh_token,
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET
        }))
        .send()
        .await
        .expect("Failed to call refresh token");

    assert_eq!(revoked_response.status(), 200);
    let revoked_json: serde_json::Value = revoked_response.json().await.unwrap();
    assert_eq!(revoked_json["error"].as_str().unwrap(), "invalid_grant");
}

#[tokio::test]
async fn test_userinfo_without_token() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _env = setup_env().await;

    let client = build_client();

    let userinfo_response = client
        .get(&format!("{}/oauth2/userinfo", BASE_URL))
        .send()
        .await
        .expect("Failed to call userinfo");

    assert_eq!(userinfo_response.status(), 401);
}
