use reqwest::Client;
use serde_json::json;
use std::process::{Child, Command};
use std::time::Duration;
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
const TEST_PASSWORD: &str = "password123";
const TEST_CLIENT_ID: &str = "webapp_dashboard";
const TEST_CLIENT_SECRET: &str = "client_secret_123";
const TEST_REDIRECT_URI: &str = "http://localhost:3000/callback";

/// Test environment manager
struct TestEnvironment {
    docker_process: Option<Child>,
    server_process: Option<Child>,
}

impl TestEnvironment {
    fn new() -> Self {
        Self {
            docker_process: None,
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
                .arg("postgres")
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

        let output = Command::new("cargo").arg("build").output()?;

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

    /// Cleanup resources
    async fn cleanup(&mut self) {
        println!("Cleaning up...");

        // Kill server
        if let Some(mut process) = self.server_process.take() {
            let _ = process.kill();
        }

        // Stop Docker services
        let _ = Command::new("docker-compose")
            .arg("-f")
            .arg(DOCKER_COMPOSE_FILE)
            .arg("down")
            .output();

        println!("Cleanup completed");
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        // Ensure cleanup on drop
        if let Some(mut process) = self.server_process.take() {
            let _ = process.kill();
        }
    }
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

#[tokio::test]
async fn test_authorization_code_full_integration() {
    let mut env = TestEnvironment::new();

    // Setup
    if let Err(e) = env.start_docker().await {
        panic!("Failed to start Docker: {}", e);
    }

    if let Err(e) = env.wait_for_postgres().await {
        env.cleanup().await;
        panic!("PostgreSQL not ready: {}", e);
    }

    if let Err(e) = env.setup_database().await {
        env.cleanup().await;
        panic!("Database setup failed: {}", e);
    }

    if let Err(e) = env.build_app().await {
        env.cleanup().await;
        panic!("Build failed: {}", e);
    }

    if let Err(e) = env.start_server().await {
        env.cleanup().await;
        panic!("Server start failed: {}", e);
    }

    if let Err(e) = env.wait_for_server().await {
        env.cleanup().await;
        panic!("Server not ready: {}", e);
    }

    println!("\n=== Running Authorization Code Flow Tests ===\n");

    let client = Client::new();

    // Test 1: Successful Authorization Code Flow
    println!("Test 1: Successfully complete Authorization Code Flow");
    {
        // Step 1: Authorize
        let authorize_response = client
            .post(&format!("{}/oauth2/authorize", BASE_URL))
            .json(&json!({
                "response_type": "code",
                "client_id": TEST_CLIENT_ID,
                "redirect_uri": TEST_REDIRECT_URI,
                "scope": "openid profile email",
                "state": "test-state-123"
            }))
            .send()
            .await
            .expect("Failed to call authorize");

        assert_eq!(authorize_response.status(), 200);

        // Step 2: Login
        let login_response = client
            .post(&format!("{}/oauth2/login", BASE_URL))
            .json(&json!({
                "username": TEST_USERNAME,
                "password": TEST_PASSWORD,
                "client_id": TEST_CLIENT_ID,
                "redirect_uri": TEST_REDIRECT_URI,
                "scope": "openid profile email",
                "state": "test-state-123"
            }))
            .send()
            .await
            .expect("Failed to call login");

        assert_eq!(login_response.status(), 200);
        let login_json: serde_json::Value = login_response.json().await.unwrap();
        let code = login_json["code"].as_str().unwrap();
        assert!(!code.is_empty());

        // Step 3: Exchange code for token
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
        let token_json: serde_json::Value = token_response.json().await.unwrap();
        assert!(token_json["access_token"].as_str().is_some());
        assert!(token_json["refresh_token"].as_str().is_some());

        // Step 4: Call userinfo
        let access_token = token_json["access_token"].as_str().unwrap();
        let userinfo_response = client
            .get(&format!("{}/oauth2/userinfo", BASE_URL))
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .expect("Failed to call userinfo");

        assert_eq!(userinfo_response.status(), 200);
        let userinfo_json: serde_json::Value = userinfo_response.json().await.unwrap();
        assert_eq!(userinfo_json["email"].as_str().unwrap(), "admin@example.com");
        assert!(userinfo_json["groups"].as_array().unwrap().len() > 0);

        println!("✅ Test 1 PASSED: Authorization Code Flow successful\n");
    }

    // Test 2: Invalid credentials
    println!("Test 2: Failure with incorrect password");
    {
        let login_response = client
            .post(&format!("{}/oauth2/login", BASE_URL))
            .json(&json!({
                "username": TEST_USERNAME,
                "password": "wrong-password",
                "client_id": TEST_CLIENT_ID,
                "redirect_uri": TEST_REDIRECT_URI
            }))
            .send()
            .await
            .expect("Failed to call login");

        assert_eq!(login_response.status(), 200);
        let login_json: serde_json::Value = login_response.json().await.unwrap();
        assert_eq!(login_json["error"].as_str().unwrap(), "invalid_grant");

        println!("✅ Test 2 PASSED: Correctly rejected invalid credentials\n");
    }

    // Test 3: Invalid authorization code
    println!("Test 3: Failure with invalid authorization code");
    {
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

        println!("✅ Test 3 PASSED: Correctly rejected invalid code\n");
    }

    // Test 4: PKCE S256 validation
    println!("Test 4: PKCE S256 validation");
    {
        let code_verifier = "test-verifier-1234567890-abcdefghijklmnop";
        let code_challenge = generate_pkce_challenge(code_verifier, "S256");

        // Login with PKCE challenge
        let login_response = client
            .post(&format!("{}/oauth2/login", BASE_URL))
            .json(&json!({
                "username": TEST_USERNAME,
                "password": TEST_PASSWORD,
                "client_id": TEST_CLIENT_ID,
                "redirect_uri": TEST_REDIRECT_URI,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256"
            }))
            .send()
            .await
            .expect("Failed to call login");

        let login_json: serde_json::Value = login_response.json().await.unwrap();
        let code = login_json["code"].as_str().unwrap();

        // Exchange with correct verifier
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

        println!("✅ Test 4 PASSED: PKCE S256 validation successful\n");
    }

    // Test 5: PKCE with wrong verifier
    println!("Test 5: PKCE validation failure with wrong verifier");
    {
        let code_verifier = "correct-verifier-1234567890-abcdefghijklmnop";
        let code_challenge = generate_pkce_challenge(code_verifier, "S256");

        // Login with PKCE challenge
        let login_response = client
            .post(&format!("{}/oauth2/login", BASE_URL))
            .json(&json!({
                "username": TEST_USERNAME,
                "password": TEST_PASSWORD,
                "client_id": TEST_CLIENT_ID,
                "redirect_uri": TEST_REDIRECT_URI,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256"
            }))
            .send()
            .await
            .expect("Failed to call login");

        let login_json: serde_json::Value = login_response.json().await.unwrap();
        let code = login_json["code"].as_str().unwrap();

        // Exchange with WRONG verifier
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

        println!("✅ Test 5 PASSED: Correctly rejected wrong PKCE verifier\n");
    }

    // Test 6: Refresh token flow
    println!("Test 6: Refresh token flow");
    {
        // First get tokens
        let login_response = client
            .post(&format!("{}/oauth2/login", BASE_URL))
            .json(&json!({
                "username": TEST_USERNAME,
                "password": TEST_PASSWORD,
                "client_id": TEST_CLIENT_ID,
                "redirect_uri": TEST_REDIRECT_URI
            }))
            .send()
            .await
            .expect("Failed to call login");

        let login_json: serde_json::Value = login_response.json().await.unwrap();
        let code = login_json["code"].as_str().unwrap();

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

        let token_json: serde_json::Value = token_response.json().await.unwrap();
        let refresh_token = token_json["refresh_token"].as_str().unwrap();

        // Use refresh token
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

        println!("✅ Test 6 PASSED: Refresh token flow successful\n");
    }

    // Test 7: Userinfo without token
    println!("Test 7: Userinfo endpoint without token");
    {
        let userinfo_response = client
            .get(&format!("{}/oauth2/userinfo", BASE_URL))
            .send()
            .await
            .expect("Failed to call userinfo");

        assert_eq!(userinfo_response.status(), 401);

        println!("✅ Test 7 PASSED: Correctly rejected missing token\n");
    }

    // Cleanup
    env.cleanup().await;

    println!("=== All Authorization Code Flow Tests Passed! ===");
}
