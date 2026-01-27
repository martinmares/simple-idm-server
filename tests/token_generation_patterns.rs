use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::{Child, Command};
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell};
use tokio::time::{sleep, Duration};

// Test configuration
const DOCKER_COMPOSE_FILE: &str = "docker-compose.yml";
const BASE_URL: &str = "http://127.0.0.1:3003";
const HEALTH_CHECK_URL: &str = "http://127.0.0.1:3003/health";

// Admin credentials for API access
const ADMIN_USERNAME: &str = "admin";
const ADMIN_PASSWORD: &str = "password123";

static TEST_MUTEX: OnceCell<Mutex<()>> = OnceCell::const_new();
static ENV: OnceCell<Arc<TestEnvironment>> = OnceCell::const_new();

struct TestEnvironment {
    server_process: Option<Child>,
}

impl TestEnvironment {
    fn new() -> Self {
        Self {
            server_process: None,
        }
    }

    async fn start_docker(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting Docker services...");
        let _ = Command::new("docker-compose")
            .arg("-f")
            .arg(DOCKER_COMPOSE_FILE)
            .arg("down")
            .output();

        Command::new("docker-compose")
            .arg("-f")
            .arg(DOCKER_COMPOSE_FILE)
            .arg("up")
            .arg("-d")
            .output()?;

        println!("Docker services started");
        Ok(())
    }

    async fn wait_for_postgres(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Waiting for PostgreSQL to be ready...");
        let max_attempts = 90;
        let mut attempts = 0;

        loop {
            let health = Command::new("docker")
                .arg("inspect")
                .arg("-f")
                .arg("{{.State.Health.Status}}")
                .arg("simple-idm-postgres")
                .output();

            if let Ok(output) = health {
                if output.status.success() {
                    let status = String::from_utf8_lossy(&output.stdout);
                    if status.trim() == "healthy" {
                        println!("PostgreSQL is ready!");
                        return Ok(());
                    }
                }
            }

            attempts += 1;
            if attempts >= max_attempts {
                return Err("PostgreSQL failed to become healthy".into());
            }

            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn start_server(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting server...");
        let server = Command::new("cargo")
            .arg("run")
            .arg("--bin")
            .arg("simple-idm-server")
            .spawn()?;

        self.server_process = Some(server);
        println!("Server process started");
        Ok(())
    }

    async fn wait_for_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Waiting for server to be ready...");
        let client = Client::new();
        let max_attempts = 60;

        for _ in 0..max_attempts {
            if let Ok(resp) = client.get(HEALTH_CHECK_URL).send().await {
                if resp.status().is_success() {
                    println!("Server is ready!");
                    return Ok(());
                }
            }
            sleep(Duration::from_millis(500)).await;
        }

        Err("Server failed to start".into())
    }

    async fn init_test_data(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Initializing test data...");
        Command::new("docker")
            .arg("exec")
            .arg("-i")
            .arg("simple-idm-postgres")
            .arg("psql")
            .arg("-U")
            .arg("postgres")
            .arg("-d")
            .arg("simple_idm")
            .arg("-f")
            .arg("/docker-entrypoint-initdb.d/init_test_data.sql")
            .output()?;

        println!("Test data initialized");
        Ok(())
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        if let Some(mut process) = self.server_process.take() {
            let _ = process.kill();
        }
    }
}

async fn setup() -> Arc<TestEnvironment> {
    let mutex = TEST_MUTEX
        .get_or_init(|| async { Mutex::new(()) })
        .await;
    let _guard = mutex.lock().await;

    ENV.get_or_init(|| async {
        let mut env = TestEnvironment::new();
        env.start_docker().await.expect("Failed to start Docker");
        env.wait_for_postgres()
            .await
            .expect("PostgreSQL not ready");
        env.init_test_data()
            .await
            .expect("Failed to init test data");
        env.start_server().await.expect("Failed to start server");
        env.wait_for_server().await.expect("Server not ready");
        Arc::new(env)
    })
    .await
    .clone()
}

async fn get_admin_token() -> String {
    // Use admin root token from .env for admin API access
    // This is simpler than OAuth2 flows for testing admin endpoints
    "dev-admin-token-123".to_string()
}

// Helper to create test data
struct TestClient {
    id: String,
    client_id: String,
    client_secret: String,
}

struct TestUser {
    id: String,
    username: String,
    password: String,
    groups: Vec<String>, // group IDs
}

struct TestGroup {
    id: String,
    name: String,
}

async fn create_test_group(token: &str, name: &str) -> TestGroup {
    let client = Client::new();
    let resp = client
        .post(format!("{}/admin/groups", BASE_URL))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "name": name,
            "description": format!("Test group {}", name)
        }))
        .send()
        .await
        .expect("Failed to create group");

    let group: Value = resp.json().await.expect("Failed to parse group");
    TestGroup {
        id: group["id"].as_str().unwrap().to_string(),
        name: group["name"].as_str().unwrap().to_string(),
    }
}

async fn create_test_user(token: &str, username: &str, group_ids: Vec<&str>) -> TestUser {
    let client = Client::new();
    let password = "testpass123";

    let resp = client
        .post(format!("{}/admin/users", BASE_URL))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "username": username,
            "email": format!("{}@test.com", username),
            "password": password,
            "is_active": true
        }))
        .send()
        .await
        .expect("Failed to create user");

    let user: Value = resp.json().await.expect("Failed to parse user");
    let user_id = user["id"].as_str().unwrap().to_string();

    // Add user to groups
    for group_id in &group_ids {
        client
            .put(format!("{}/admin/users/{}/groups/{}", BASE_URL, user_id, group_id))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("Failed to add user to group");
    }

    TestUser {
        id: user_id,
        username: username.to_string(),
        password: password.to_string(),
        groups: group_ids.iter().map(|s| s.to_string()).collect(),
    }
}

async fn create_test_client(token: &str, client_id: &str) -> TestClient {
    let client = Client::new();
    let secret = "test_secret_123";

    let resp = client
        .post(format!("{}/admin/clients", BASE_URL))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "client_id": client_id,
            "client_secret": secret,
            "name": format!("Test client {}", client_id),
            "redirect_uris": ["http://localhost:3000/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "openid profile email",
            "is_active": true
        }))
        .send()
        .await
        .expect("Failed to create client");

    let client_data: Value = resp.json().await.expect("Failed to parse client");
    TestClient {
        id: client_data["id"].as_str().unwrap().to_string(),
        client_id: client_id.to_string(),
        client_secret: secret.to_string(),
    }
}

async fn create_claim_map_with_patterns(
    token: &str,
    client_id: &str,
    claim_name: &str,
    patterns: Vec<(&str, bool, i32)>, // (pattern, is_include, priority)
) -> String {
    let client = Client::new();

    // Create claim map without group_id (pattern-only)
    let resp = client
        .post(format!("{}/admin/clients/{}/claim-maps", BASE_URL, client_id))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "claim_name": claim_name,
            "claim_value_kind": "array",
            "claim_value": null,
            "group_id": null
        }))
        .send()
        .await
        .expect("Failed to create claim map");

    let claim_map: Value = resp.json().await.expect("Failed to parse claim map");
    let claim_map_id = claim_map["id"].as_str().unwrap().to_string();

    // Add patterns
    for (pattern, is_include, priority) in patterns {
        client
            .post(format!(
                "{}/admin/claim-maps/{}/patterns",
                BASE_URL, claim_map_id
            ))
            .header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "pattern": pattern,
                "is_include": is_include,
                "priority": priority
            }))
            .send()
            .await
            .expect("Failed to create pattern");
    }

    claim_map_id
}

fn decode_jwt_payload(token: &str) -> HashMap<String, Value> {
    use base64::prelude::*;

    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "Invalid JWT format");

    let payload = parts[1];
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(payload)
        .expect("Failed to decode JWT");

    serde_json::from_slice(&decoded).expect("Failed to parse JWT payload")
}

#[tokio::test]
async fn test_claim_map_with_include_wildcard_pattern() {
    let _env = setup().await;
    let admin_token = get_admin_token().await;

    // Create test groups
    let ssh_admin = create_test_group(&admin_token, "ssh:admin").await;
    let ssh_user = create_test_group(&admin_token, "ssh:user").await;
    let web_admin = create_test_group(&admin_token, "web:admin").await;

    // Create test user with all groups
    let user = create_test_user(
        &admin_token,
        "test_ssh_user",
        vec![&ssh_admin.id, &ssh_user.id, &web_admin.id],
    )
    .await;

    // Create test client
    let test_client = create_test_client(&admin_token, "test_ssh_client").await;

    // Create claim map with pattern "ssh:*" (include only ssh groups)
    create_claim_map_with_patterns(
        &admin_token,
        &test_client.id,
        "ssh_groups",
        vec![("ssh:*", true, 1)],
    )
    .await;

    // Get token for user
    let client = Client::new();
    let token_resp = client
        .post(format!("{}/oauth2/token", BASE_URL))
        .form(&[
            ("grant_type", "password"),
            ("username", &user.username),
            ("password", &user.password),
            ("client_id", &test_client.client_id),
            ("client_secret", &test_client.client_secret),
        ])
        .send()
        .await
        .expect("Failed to get token");

    let token_data: Value = token_resp.json().await.expect("Failed to parse token");
    let access_token = token_data["access_token"].as_str().unwrap();

    // Decode and verify JWT
    let payload = decode_jwt_payload(access_token);
    let ssh_groups = payload.get("ssh_groups").expect("No ssh_groups claim");
    let groups_array = ssh_groups.as_array().expect("ssh_groups is not array");

    // Should contain only ssh:admin and ssh:user, NOT web:admin
    assert_eq!(groups_array.len(), 2);
    assert!(groups_array.contains(&json!("ssh:admin")));
    assert!(groups_array.contains(&json!("ssh:user")));
    assert!(!groups_array.contains(&json!("web:admin")));
}

#[tokio::test]
async fn test_claim_map_with_exclude_pattern() {
    let _env = setup().await;
    let admin_token = get_admin_token().await;

    // Create test groups
    let prod = create_test_group(&admin_token, "prod").await;
    let test_env = create_test_group(&admin_token, "test-env").await;
    let staging = create_test_group(&admin_token, "staging").await;

    // Create test user
    let user = create_test_user(
        &admin_token,
        "test_exclude_user",
        vec![&prod.id, &test_env.id, &staging.id],
    )
    .await;

    // Create test client
    let test_client = create_test_client(&admin_token, "test_exclude_client").await;

    // Create claim map with patterns: include all (*), then exclude test*
    create_claim_map_with_patterns(
        &admin_token,
        &test_client.id,
        "environments",
        vec![
            ("*", true, 1),       // Include all
            ("test*", false, 2),  // Exclude test*
        ],
    )
    .await;

    // Get token
    let client = Client::new();
    let token_resp = client
        .post(format!("{}/oauth2/token", BASE_URL))
        .form(&[
            ("grant_type", "password"),
            ("username", &user.username),
            ("password", &user.password),
            ("client_id", &test_client.client_id),
            ("client_secret", &test_client.client_secret),
        ])
        .send()
        .await
        .expect("Failed to get token");

    let token_data: Value = token_resp.json().await.expect("Failed to parse token");
    let access_token = token_data["access_token"].as_str().unwrap();

    // Decode and verify
    let payload = decode_jwt_payload(access_token);
    let environments = payload.get("environments").expect("No environments claim");
    let groups_array = environments.as_array().expect("environments is not array");

    // Should contain prod and staging, but NOT test-env
    assert_eq!(groups_array.len(), 2);
    assert!(groups_array.contains(&json!("prod")));
    assert!(groups_array.contains(&json!("staging")));
    assert!(!groups_array.contains(&json!("test-env")));
}

#[tokio::test]
async fn test_claim_map_sequential_pattern_priority() {
    let _env = setup().await;
    let admin_token = get_admin_token().await;

    // Create test groups
    let ssh_admin = create_test_group(&admin_token, "ssh:admin").await;
    let ssh_test = create_test_group(&admin_token, "ssh:test").await;
    let ssh_prod = create_test_group(&admin_token, "ssh:prod").await;

    // Create test user
    let user = create_test_user(
        &admin_token,
        "test_priority_user",
        vec![&ssh_admin.id, &ssh_test.id, &ssh_prod.id],
    )
    .await;

    // Create test client
    let test_client = create_test_client(&admin_token, "test_priority_client").await;

    // Create claim map with sequential patterns:
    // 1. Include ssh:* (priority 1)
    // 2. Exclude ssh:test* (priority 2)
    create_claim_map_with_patterns(
        &admin_token,
        &test_client.id,
        "ssh_access",
        vec![
            ("ssh:*", true, 1),      // Include all ssh
            ("ssh:test*", false, 2), // Exclude test
        ],
    )
    .await;

    // Get token
    let client = Client::new();
    let token_resp = client
        .post(format!("{}/oauth2/token", BASE_URL))
        .form(&[
            ("grant_type", "password"),
            ("username", &user.username),
            ("password", &user.password),
            ("client_id", &test_client.client_id),
            ("client_secret", &test_client.client_secret),
        ])
        .send()
        .await
        .expect("Failed to get token");

    let token_data: Value = token_resp.json().await.expect("Failed to parse token");
    let access_token = token_data["access_token"].as_str().unwrap();

    // Decode and verify
    let payload = decode_jwt_payload(access_token);
    let ssh_access = payload.get("ssh_access").expect("No ssh_access claim");
    let groups_array = ssh_access.as_array().expect("ssh_access is not array");

    // Should contain ssh:admin and ssh:prod, but NOT ssh:test
    assert_eq!(groups_array.len(), 2);
    assert!(groups_array.contains(&json!("ssh:admin")));
    assert!(groups_array.contains(&json!("ssh:prod")));
    assert!(!groups_array.contains(&json!("ssh:test")));
}

#[tokio::test]
async fn test_claim_map_empty_patterns_includes_nothing() {
    let _env = setup().await;
    let admin_token = get_admin_token().await;

    // Create test groups
    let group1 = create_test_group(&admin_token, "group1").await;
    let group2 = create_test_group(&admin_token, "group2").await;

    // Create test user
    let user = create_test_user(
        &admin_token,
        "test_empty_user",
        vec![&group1.id, &group2.id],
    )
    .await;

    // Create test client
    let test_client = create_test_client(&admin_token, "test_empty_client").await;

    // Create claim map with NO patterns (should match nothing)
    create_claim_map_with_patterns(&admin_token, &test_client.id, "empty_groups", vec![]).await;

    // Get token
    let client = Client::new();
    let token_resp = client
        .post(format!("{}/oauth2/token", BASE_URL))
        .form(&[
            ("grant_type", "password"),
            ("username", &user.username),
            ("password", &user.password),
            ("client_id", &test_client.client_id),
            ("client_secret", &test_client.client_secret),
        ])
        .send()
        .await
        .expect("Failed to get token");

    let token_data: Value = token_resp.json().await.expect("Failed to parse token");
    let access_token = token_data["access_token"].as_str().unwrap();

    // Decode and verify
    let payload = decode_jwt_payload(access_token);

    // Claim should not exist or be empty
    if let Some(empty_groups) = payload.get("empty_groups") {
        let groups_array = empty_groups.as_array().expect("empty_groups is not array");
        assert_eq!(groups_array.len(), 0, "Expected no groups with empty patterns");
    }
}
