use reqwest::Client;
use serde_json::{json, Value};
use std::process::{Child, Command};
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell};
use tokio::time::{sleep, Duration};

// Test configuration
const DOCKER_COMPOSE_FILE: &str = "docker-compose.yml";
const BASE_URL: &str = "http://127.0.0.1:3003";
const HEALTH_CHECK_URL: &str = "http://127.0.0.1:3003/health";
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
    let client = Client::new();

    let token_resp = client
        .post(format!("{}/oauth2/token", BASE_URL))
        .form(&[
            ("grant_type", "password"),
            ("username", ADMIN_USERNAME),
            ("password", ADMIN_PASSWORD),
            ("client_id", "webapp_dashboard"),
            ("client_secret", "client_secret_123"),
        ])
        .send()
        .await
        .expect("Failed to get token");

    let token_data: Value = token_resp.json().await.expect("Failed to parse token");
    token_data["access_token"]
        .as_str()
        .expect("No access token")
        .to_string()
}

// Get existing claim map ID from test data
async fn get_test_claim_map_id(token: &str) -> String {
    let client = Client::new();

    // Get client ID first
    let clients_resp = client
        .get(format!("{}/admin/clients", BASE_URL))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .expect("Failed to get clients");

    let clients: Value = clients_resp.json().await.expect("Failed to parse clients");
    let client_id = clients[0]["id"].as_str().unwrap();

    // Get claim maps for this client
    let claim_maps_resp = client
        .get(format!("{}/admin/clients/{}/claim-maps", BASE_URL, client_id))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .expect("Failed to get claim maps");

    let claim_maps: Value = claim_maps_resp
        .json()
        .await
        .expect("Failed to parse claim maps");

    claim_maps[0]["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn test_create_claim_map_pattern() {
    let _env = setup().await;
    let admin_token = get_admin_token().await;
    let claim_map_id = get_test_claim_map_id(&admin_token).await;

    let client = Client::new();

    // Create a new pattern
    let resp = client
        .post(format!(
            "{}/admin/claim-maps/{}/patterns",
            BASE_URL, claim_map_id
        ))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&json!({
            "pattern": "test:*",
            "is_include": true,
            "priority": 10
        }))
        .send()
        .await
        .expect("Failed to create pattern");

    assert!(resp.status().is_success());

    let pattern: Value = resp.json().await.expect("Failed to parse pattern");
    assert_eq!(pattern["pattern"].as_str().unwrap(), "test:*");
    assert_eq!(pattern["is_include"].as_bool().unwrap(), true);
    assert_eq!(pattern["priority"].as_i64().unwrap(), 10);
    assert!(pattern["id"].as_str().is_some());
    assert_eq!(pattern["claim_map_id"].as_str().unwrap(), claim_map_id);
}

#[tokio::test]
async fn test_list_claim_map_patterns() {
    let _env = setup().await;
    let admin_token = get_admin_token().await;
    let claim_map_id = get_test_claim_map_id(&admin_token).await;

    let client = Client::new();

    // Create two patterns
    client
        .post(format!(
            "{}/admin/claim-maps/{}/patterns",
            BASE_URL, claim_map_id
        ))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&json!({
            "pattern": "prod:*",
            "is_include": true,
            "priority": 1
        }))
        .send()
        .await
        .expect("Failed to create pattern 1");

    client
        .post(format!(
            "{}/admin/claim-maps/{}/patterns",
            BASE_URL, claim_map_id
        ))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&json!({
            "pattern": "test:*",
            "is_include": false,
            "priority": 2
        }))
        .send()
        .await
        .expect("Failed to create pattern 2");

    // List patterns
    let resp = client
        .get(format!(
            "{}/admin/claim-maps/{}/patterns",
            BASE_URL, claim_map_id
        ))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .expect("Failed to list patterns");

    assert!(resp.status().is_success());

    let patterns: Value = resp.json().await.expect("Failed to parse patterns");
    let patterns_array = patterns.as_array().expect("Patterns is not array");

    assert!(patterns_array.len() >= 2, "Expected at least 2 patterns");

    // Check ordering by priority
    let priorities: Vec<i64> = patterns_array
        .iter()
        .map(|p| p["priority"].as_i64().unwrap())
        .collect();

    for i in 0..priorities.len() - 1 {
        assert!(
            priorities[i] <= priorities[i + 1],
            "Patterns should be ordered by priority ASC"
        );
    }
}

#[tokio::test]
async fn test_update_claim_map_pattern() {
    let _env = setup().await;
    let admin_token = get_admin_token().await;
    let claim_map_id = get_test_claim_map_id(&admin_token).await;

    let client = Client::new();

    // Create a pattern
    let create_resp = client
        .post(format!(
            "{}/admin/claim-maps/{}/patterns",
            BASE_URL, claim_map_id
        ))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&json!({
            "pattern": "old:*",
            "is_include": true,
            "priority": 5
        }))
        .send()
        .await
        .expect("Failed to create pattern");

    let created: Value = create_resp.json().await.expect("Failed to parse created");
    let pattern_id = created["id"].as_str().unwrap();

    // Update the pattern
    let update_resp = client
        .put(format!(
            "{}/admin/claim-maps/{}/patterns/{}",
            BASE_URL, claim_map_id, pattern_id
        ))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&json!({
            "pattern": "new:*",
            "is_include": false,
            "priority": 10
        }))
        .send()
        .await
        .expect("Failed to update pattern");

    assert!(update_resp.status().is_success());

    let updated: Value = update_resp.json().await.expect("Failed to parse updated");
    assert_eq!(updated["id"].as_str().unwrap(), pattern_id);
    assert_eq!(updated["pattern"].as_str().unwrap(), "new:*");
    assert_eq!(updated["is_include"].as_bool().unwrap(), false);
    assert_eq!(updated["priority"].as_i64().unwrap(), 10);
}

#[tokio::test]
async fn test_delete_claim_map_pattern() {
    let _env = setup().await;
    let admin_token = get_admin_token().await;
    let claim_map_id = get_test_claim_map_id(&admin_token).await;

    let client = Client::new();

    // Create a pattern
    let create_resp = client
        .post(format!(
            "{}/admin/claim-maps/{}/patterns",
            BASE_URL, claim_map_id
        ))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&json!({
            "pattern": "delete:*",
            "is_include": true,
            "priority": 1
        }))
        .send()
        .await
        .expect("Failed to create pattern");

    let created: Value = create_resp.json().await.expect("Failed to parse created");
    let pattern_id = created["id"].as_str().unwrap();

    // Delete the pattern
    let delete_resp = client
        .delete(format!(
            "{}/admin/claim-maps/{}/patterns/{}",
            BASE_URL, claim_map_id, pattern_id
        ))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .expect("Failed to delete pattern");

    assert!(delete_resp.status().is_success());

    // Verify it's deleted - try to get all patterns and check it's not there
    let list_resp = client
        .get(format!(
            "{}/admin/claim-maps/{}/patterns",
            BASE_URL, claim_map_id
        ))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .expect("Failed to list patterns");

    let patterns: Value = list_resp.json().await.expect("Failed to parse patterns");
    let patterns_array = patterns.as_array().expect("Patterns is not array");

    // Pattern should not exist
    let found = patterns_array
        .iter()
        .any(|p| p["id"].as_str().unwrap() == pattern_id);
    assert!(!found, "Pattern should be deleted");
}

#[tokio::test]
async fn test_pattern_priority_ordering() {
    let _env = setup().await;
    let admin_token = get_admin_token().await;
    let claim_map_id = get_test_claim_map_id(&admin_token).await;

    let client = Client::new();

    // Create patterns with different priorities (in reverse order)
    for i in (1..=5).rev() {
        client
            .post(format!(
                "{}/admin/claim-maps/{}/patterns",
                BASE_URL, claim_map_id
            ))
            .header("Authorization", format!("Bearer {}", admin_token))
            .json(&json!({
                "pattern": format!("priority{}:*", i),
                "is_include": true,
                "priority": i
            }))
            .send()
            .await
            .expect("Failed to create pattern");
    }

    // List and verify ordering
    let resp = client
        .get(format!(
            "{}/admin/claim-maps/{}/patterns",
            BASE_URL, claim_map_id
        ))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .expect("Failed to list patterns");

    let patterns: Value = resp.json().await.expect("Failed to parse patterns");
    let patterns_array = patterns.as_array().expect("Patterns is not array");

    // Verify patterns are ordered by priority ASC
    let priorities: Vec<i64> = patterns_array
        .iter()
        .map(|p| p["priority"].as_i64().unwrap())
        .collect();

    for i in 0..priorities.len() - 1 {
        assert!(
            priorities[i] <= priorities[i + 1],
            "Pattern priorities should be in ascending order"
        );
    }
}

#[tokio::test]
async fn test_invalid_claim_map_id_returns_404() {
    let _env = setup().await;
    let admin_token = get_admin_token().await;

    let client = Client::new();
    let fake_uuid = "00000000-0000-0000-0000-999999999999";

    // Try to create pattern for non-existent claim map
    let resp = client
        .post(format!(
            "{}/admin/claim-maps/{}/patterns",
            BASE_URL, fake_uuid
        ))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&json!({
            "pattern": "test:*",
            "is_include": true,
            "priority": 1
        }))
        .send()
        .await
        .expect("Failed to send request");

    // Should return 404 or 400
    assert!(
        resp.status().is_client_error(),
        "Expected 4xx error for invalid claim map ID"
    );
}

#[tokio::test]
async fn test_duplicate_patterns_allowed() {
    let _env = setup().await;
    let admin_token = get_admin_token().await;
    let claim_map_id = get_test_claim_map_id(&admin_token).await;

    let client = Client::new();

    // Create first pattern
    let resp1 = client
        .post(format!(
            "{}/admin/claim-maps/{}/patterns",
            BASE_URL, claim_map_id
        ))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&json!({
            "pattern": "dup:*",
            "is_include": true,
            "priority": 1
        }))
        .send()
        .await
        .expect("Failed to create first pattern");

    assert!(resp1.status().is_success());

    // Create duplicate pattern (should be allowed - user might want include then exclude)
    let resp2 = client
        .post(format!(
            "{}/admin/claim-maps/{}/patterns",
            BASE_URL, claim_map_id
        ))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&json!({
            "pattern": "dup:*",
            "is_include": false,
            "priority": 2
        }))
        .send()
        .await
        .expect("Failed to create second pattern");

    assert!(
        resp2.status().is_success(),
        "Duplicate patterns should be allowed"
    );
}
