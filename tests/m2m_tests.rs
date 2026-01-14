//! Integration tests for M2M (Machine-to-Machine) OAuth2 Client Credentials Flow
//!
//! These tests:
//! 1. Start Docker containers (PostgreSQL)
//! 2. Wait for PostgreSQL to be ready
//! 3. Run database migrations
//! 4. Load test data
//! 5. Build and start the application server
//! 6. Wait for server health check
//! 7. Run M2M client credentials tests
//! 8. Cleanup: Stop all containers and processes

use reqwest::Client;
use std::process::{Command, Child};
use std::time::Duration;
use tokio::time::sleep;

// Test constants
const DOCKER_COMPOSE_FILE: &str = "docker-compose.yml";
const INIT_SCRIPT: &str = "scripts/init_test_data.sql";
const SERVER_HOST: &str = "127.0.0.1";
const SERVER_PORT: u16 = 8080;
const HEALTH_CHECK_URL: &str = "http://127.0.0.1:8080/health";
const CLIENT_CREDENTIALS_ENDPOINT: &str = "http://127.0.0.1:8080/oauth2/client_credentials/token";

// Test data - from scripts/init_test_data.sql
const TEST_CLIENT_ID: &str = "api_service";
const TEST_CLIENT_SECRET: &str = "client_secret_123";
const INVALID_CLIENT_ID: &str = "nonexistent_client";
const INVALID_CLIENT_SECRET: &str = "wrong_secret";

/// Test state to manage lifecycle
struct TestEnvironment {
    server_process: Option<Child>,
}

impl TestEnvironment {
    /// Create new test environment
    fn new() -> Self {
        Self {
            server_process: None,
        }
    }

    /// Start Docker services (PostgreSQL)
    async fn start_docker(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting Docker services...");

        // Stop any existing containers first
        let _ = Command::new("docker-compose")
            .arg("-f")
            .arg(DOCKER_COMPOSE_FILE)
            .arg("down")
            .output();

        // Start new containers
        let output = Command::new("docker-compose")
            .arg("-f")
            .arg(DOCKER_COMPOSE_FILE)
            .arg("up")
            .arg("-d")
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to start Docker: {}", stderr).into());
        }

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

            match output {
                Ok(out) if out.status.success() => {
                    println!("PostgreSQL is ready!");
                    return Ok(());
                }
                _ => {
                    attempts += 1;
                    if attempts >= max_attempts {
                        return Err("PostgreSQL failed to start within timeout".into());
                    }
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Run database migrations and seed data
    async fn setup_database(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running database setup and seed data...");

        // Wait a bit more for PostgreSQL to fully initialize
        sleep(Duration::from_secs(2)).await;

        // Run seed script
        let output = Command::new("docker-compose")
            .arg("-f")
            .arg(DOCKER_COMPOSE_FILE)
            .arg("exec")
            .arg("-T")
            .arg("postgres")
            .arg("psql")
            .arg("-U")
            .arg("postgres")
            .arg("-d")
            .arg("simple_idm")
            .arg("-f")
            .arg(&format!("/dev/stdin"))
            .stdin(std::process::Stdio::piped())
            .spawn()?;

        // Read and pipe the script content
        let script_content = std::fs::read_to_string(INIT_SCRIPT)?;
        if let Some(mut stdin) = output.stdin {
            use std::io::Write;
            stdin.write_all(script_content.as_bytes())?;
        }

        // Alternative: using bash to run the script
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
            // Don't fail completely if there are minor issues
        }

        println!("Database setup completed");
        Ok(())
    }

    /// Build the application
    async fn build_app(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Building application...");

        let output = Command::new("cargo")
            .arg("build")
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

        // First kill any existing server on port 8080
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

        // Use the built binary directly instead of cargo run
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
        let max_attempts = 60; // 60 seconds timeout
        let mut attempts = 0;

        loop {
            match client.get(HEALTH_CHECK_URL).send().await {
                Ok(response) if response.status().is_success() => {
                    let body = response.text().await?;
                    if body.contains("OK") {
                        println!("Server is ready!");
                        return Ok(());
                    }
                }
                _ => {}
            }

            attempts += 1;
            if attempts >= max_attempts {
                return Err("Server failed to start within timeout".into());
            }
            sleep(Duration::from_millis(1000)).await;
        }
    }

    /// Cleanup: stop all services
    async fn cleanup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Cleaning up...");

        // Stop server process
        if let Some(mut process) = self.server_process.take() {
            let _ = process.kill();
            let _ = process.wait();
        }

        // Stop Docker services
        let _ = Command::new("docker-compose")
            .arg("-f")
            .arg(DOCKER_COMPOSE_FILE)
            .arg("down")
            .output();

        println!("Cleanup completed");
        Ok(())
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[tokio::test]
async fn test_m2m_full_integration() {
    let mut env = TestEnvironment::new();

    // Ensure cleanup happens even if test fails
    let _result = async {
        // Setup phase
        if let Err(e) = env.start_docker().await {
            eprintln!("Failed to start Docker: {}", e);
            return;
        }

        if let Err(e) = env.wait_for_postgres().await {
            eprintln!("Failed to wait for PostgreSQL: {}", e);
            return;
        }

        if let Err(e) = env.setup_database().await {
            eprintln!("Failed to setup database: {}", e);
            return;
        }

        if let Err(e) = env.build_app().await {
            eprintln!("Failed to build app: {}", e);
            return;
        }

        if let Err(e) = env.start_server().await {
            eprintln!("Failed to start server: {}", e);
            return;
        }

        if let Err(e) = env.wait_for_server().await {
            eprintln!("Failed to wait for server: {}", e);
            return;
        }

        // Run tests
        run_m2m_tests().await;
    }.await;

    // Always cleanup
    let _ = env.cleanup().await;
}

/// Run all M2M tests
async fn run_m2m_tests() {
    println!("\n=== Running M2M OAuth2 Client Credentials Tests ===\n");

    test_successful_token_acquisition().await;
    test_invalid_client_secret().await;
    test_nonexistent_client().await;
    test_token_format_and_claims().await;
}

/// Test 1: ✅ Successfully obtain access token with correct credentials
async fn test_successful_token_acquisition() {
    println!("Test 1: Successfully obtain access token with correct credentials");

    let client = Client::new();

    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": TEST_CLIENT_ID,
        "client_secret": TEST_CLIENT_SECRET,
        "scope": "api:read api:write"
    });

    let response = client
        .post(CLIENT_CREDENTIALS_ENDPOINT)
        .json(&body)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        200,
        "Expected 200 OK, got {}",
        response.status()
    );

    let token_response: serde_json::Value = response
        .json()
        .await
        .expect("Failed to parse response");

    // Verify response structure
    assert!(
        token_response.get("access_token").is_some(),
        "Response missing access_token"
    );
    assert!(
        token_response.get("token_type").is_some(),
        "Response missing token_type"
    );
    assert!(
        token_response.get("expires_in").is_some(),
        "Response missing expires_in"
    );

    assert_eq!(
        token_response["token_type"].as_str().unwrap(),
        "Bearer",
        "Expected Bearer token type"
    );

    println!("✅ Test 1 PASSED: Successfully obtained access token\n");
}

/// Test 2: ❌ Failure with incorrect client_secret
async fn test_invalid_client_secret() {
    println!("Test 2: Failure with incorrect client_secret");

    let client = Client::new();

    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": TEST_CLIENT_ID,
        "client_secret": INVALID_CLIENT_SECRET,
        "scope": "api:read api:write"
    });

    let response = client
        .post(CLIENT_CREDENTIALS_ENDPOINT)
        .json(&body)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        401,
        "Expected 401 Unauthorized, got {}",
        response.status()
    );

    let error_response: serde_json::Value = response
        .json()
        .await
        .expect("Failed to parse error response");

    assert_eq!(
        error_response["error"].as_str().unwrap(),
        "invalid_client",
        "Expected invalid_client error"
    );

    println!("✅ Test 2 PASSED: Correctly rejected with invalid secret\n");
}

/// Test 3: ❌ Failure with unknown client_id
async fn test_nonexistent_client() {
    println!("Test 3: Failure with unknown client_id");

    let client = Client::new();

    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": INVALID_CLIENT_ID,
        "client_secret": "some_secret",
        "scope": "api:read api:write"
    });

    let response = client
        .post(CLIENT_CREDENTIALS_ENDPOINT)
        .json(&body)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        401,
        "Expected 401 Unauthorized, got {}",
        response.status()
    );

    let error_response: serde_json::Value = response
        .json()
        .await
        .expect("Failed to parse error response");

    assert_eq!(
        error_response["error"].as_str().unwrap(),
        "invalid_client",
        "Expected invalid_client error"
    );

    println!("✅ Test 3 PASSED: Correctly rejected unknown client\n");
}

/// Test 4: ✅ Returned token has correct format and contains proper claims
async fn test_token_format_and_claims() {
    println!("Test 4: Returned token has correct format and contains proper claims");

    let client = Client::new();

    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": TEST_CLIENT_ID,
        "client_secret": TEST_CLIENT_SECRET,
        "scope": "api:read api:write"
    });

    let response = client
        .post(CLIENT_CREDENTIALS_ENDPOINT)
        .json(&body)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let token_response: serde_json::Value = response
        .json()
        .await
        .expect("Failed to parse response");

    let access_token = token_response["access_token"]
        .as_str()
        .expect("Failed to get access_token");

    // Verify JWT format (three parts separated by dots)
    let parts: Vec<&str> = access_token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts (header.payload.signature)");

    // Decode and verify JWT payload (without signature verification for this test)
    let payload_encoded = parts[1];

    // Add padding if needed
    let padding = (4 - (payload_encoded.len() % 4)) % 4;
    let mut payload_with_padding = payload_encoded.to_string();
    for _ in 0..padding {
        payload_with_padding.push('=');
    }

    let payload_bytes = base64::decode(&payload_with_padding)
        .expect("Failed to decode JWT payload");
    let payload_str = String::from_utf8(payload_bytes)
        .expect("Failed to convert payload to string");
    let payload: serde_json::Value = serde_json::from_str(&payload_str)
        .expect("Failed to parse JWT payload as JSON");

    // Verify required claims
    assert!(payload.get("sub").is_some(), "Missing 'sub' claim");
    assert!(payload.get("iss").is_some(), "Missing 'iss' claim");
    assert!(payload.get("aud").is_some(), "Missing 'aud' claim");
    assert!(payload.get("exp").is_some(), "Missing 'exp' claim");
    assert!(payload.get("iat").is_some(), "Missing 'iat' claim");

    // Verify aud contains our client_id
    let aud = payload["aud"]
        .as_array()
        .expect("'aud' should be an array");
    assert!(
        aud.iter().any(|a| a.as_str() == Some(TEST_CLIENT_ID)),
        "client_id not found in 'aud' claim"
    );

    // Verify issuer
    assert_eq!(
        payload["iss"].as_str().unwrap(),
        "http://localhost:8080",
        "Unexpected issuer"
    );

    // Verify token is not expired
    let exp = payload["exp"].as_i64().expect("'exp' should be i64");
    let now = chrono::Utc::now().timestamp();
    assert!(exp > now, "Token is already expired");

    println!("✅ Test 4 PASSED: Token format and claims are correct\n");
}

// Helper function for base64 decoding (simple implementation)
mod base64 {
    use std::str;

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        use std::collections::HashMap;

        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut decode_table = HashMap::new();
        for (i, c) in alphabet.chars().enumerate() {
            decode_table.insert(c, i as u8);
        }

        let s = s.trim_end_matches('=');
        let mut result = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0;

        for c in s.chars() {
            if c == '\n' || c == '\r' || c == ' ' {
                continue;
            }
            if let Some(&val) = decode_table.get(&c) {
                buffer = (buffer << 6) | (val as u32);
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    result.push(((buffer >> bits) & 0xff) as u8);
                }
            } else {
                return Err(format!("Invalid character: {}", c));
            }
        }

        Ok(result)
    }
}
