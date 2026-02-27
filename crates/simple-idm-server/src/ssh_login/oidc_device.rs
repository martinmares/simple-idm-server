use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Debug, Serialize)]
struct DeviceTokenRequest {
    grant_type: String,
    device_code: String,
    client_id: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TokenResponse {
    id_token: Option<String>,
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub async fn device_flow(
    issuer: &str,
    client_id: &str,
    tenant: Option<&str>,
    scopes: &[String],
) -> Result<String, String> {
    tracing::info!("Starting device flow");

    let http_client = reqwest::Client::new();

    // Discover OIDC metadata
    let discovery_url = format!("{}/.well-known/openid-configuration", issuer);
    let metadata: serde_json::Value = http_client
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch OIDC metadata: {}", e))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse OIDC metadata: {}", e))?;

    let device_authorization_endpoint = metadata["device_authorization_endpoint"]
        .as_str()
        .ok_or("No device_authorization_endpoint in metadata")?;

    let token_endpoint = metadata["token_endpoint"]
        .as_str()
        .ok_or("No token_endpoint in metadata")?;

    // Request device authorization
    let scope_str = scopes.join(" ");
    let mut auth_form: Vec<(&str, String)> = vec![
        ("client_id", client_id.to_string()),
        ("scope", scope_str),
    ];
    if let Some(tenant) = tenant.filter(|t| !t.trim().is_empty()) {
        auth_form.push(("tenant", tenant.to_string()));
    }

    let auth_response: DeviceAuthorizationResponse = http_client
        .post(device_authorization_endpoint)
        .form(&auth_form)
        .send()
        .await
        .map_err(|e| format!("Device authorization request failed: {}", e))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse device auth response: {}", e))?;

    // Display user instructions
    println!("\n🔐 Device Flow Authentication");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Please visit: {}", auth_response.verification_uri);
    println!("And enter code: {}", auth_response.user_code);

    if let Some(complete_uri) = &auth_response.verification_uri_complete {
        println!("\nOr open this URL directly:");
        println!("{}", complete_uri);

        // Try to open complete URI
        if let Err(e) = open::that(complete_uri) {
            tracing::debug!("Failed to open browser: {}", e);
        }
    }

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Poll for token
    let interval = Duration::from_secs(auth_response.interval.unwrap_or(5));
    let expires_at = std::time::Instant::now() + Duration::from_secs(auth_response.expires_in);

    let mut poll_interval = interval;

    loop {
        if std::time::Instant::now() > expires_at {
            return Err("Device code expired".to_string());
        }

        tokio::time::sleep(poll_interval).await;

        let token_request = DeviceTokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            device_code: auth_response.device_code.clone(),
            client_id: client_id.to_string(),
        };

        let mut token_form: Vec<(&str, String)> = vec![
            ("grant_type", token_request.grant_type),
            ("device_code", token_request.device_code),
            ("client_id", token_request.client_id),
        ];
        if let Some(tenant) = tenant.filter(|t| !t.trim().is_empty()) {
            token_form.push(("tenant", tenant.to_string()));
        }

        let response: TokenResponse = http_client
            .post(token_endpoint)
            .form(&token_form)
            .send()
            .await
            .map_err(|e| format!("Token request failed: {}", e))?
            .json()
            .await
            .map_err(|e| format!("Failed to parse token response: {}", e))?;

        if let Some(error) = response.error {
            match error.as_str() {
                "authorization_pending" => {
                    // Keep waiting
                    print!(".");
                    std::io::Write::flush(&mut std::io::stdout()).ok();
                    continue;
                }
                "slow_down" => {
                    // Increase interval by 5 seconds
                    poll_interval += Duration::from_secs(5);
                    tracing::debug!("Slowing down polling to {:?}", poll_interval);
                    continue;
                }
                "access_denied" => {
                    return Err("User denied authorization".to_string());
                }
                "expired_token" => {
                    return Err("Device code expired".to_string());
                }
                _ => {
                    return Err(format!(
                        "Token error: {} - {}",
                        error,
                        response.error_description.unwrap_or_default()
                    ));
                }
            }
        }

        // Success!
        let id_token = response
            .id_token
            .ok_or("No ID token in response")?;

        println!("\n✅ Authentication successful!");
        tracing::info!("Device flow completed successfully");

        return Ok(id_token);
    }
}
