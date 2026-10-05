use serde::{Deserialize, Serialize};
use std::{io::IsTerminal, time::Duration};

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
    device_token_flow(issuer, client_id, tenant, scopes, false).await
}

/// Headless API authentication: never launches a browser and returns the access
/// token for validation by the API (not the ID token used by direct SSH mode).
pub async fn device_access_token_flow(
    issuer: &str,
    client_id: &str,
    tenant: Option<&str>,
    scopes: &[String],
) -> Result<String, String> {
    device_token_flow(issuer, client_id, tenant, scopes, true).await
}

async fn device_token_flow(
    issuer: &str,
    client_id: &str,
    tenant: Option<&str>,
    scopes: &[String],
    access_token: bool,
) -> Result<String, String> {
    tracing::info!("Starting device flow");
    secure_endpoint(issuer)?;

    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| format!("Cannot initialize HTTP client: {error}"))?;

    // Discover OIDC metadata
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let metadata: serde_json::Value = http_client
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch OIDC metadata: {}", e))?
        .error_for_status()
        .map_err(|e| format!("OIDC discovery failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse OIDC metadata: {}", e))?;

    let device_authorization_endpoint = metadata["device_authorization_endpoint"]
        .as_str()
        .ok_or("No device_authorization_endpoint in metadata")?;

    let token_endpoint = metadata["token_endpoint"]
        .as_str()
        .ok_or("No token_endpoint in metadata")?;

    for endpoint in [issuer, device_authorization_endpoint, token_endpoint] {
        secure_endpoint(endpoint)?;
    }

    // Request device authorization
    let scope_str = scopes.join(" ");
    let mut auth_form: Vec<(&str, String)> =
        vec![("client_id", client_id.to_string()), ("scope", scope_str)];
    if let Some(tenant) = tenant.filter(|t| !t.trim().is_empty()) {
        auth_form.push(("tenant", tenant.to_string()));
    }

    let response = http_client
        .post(device_authorization_endpoint)
        .form(&auth_form)
        .send()
        .await
        .map_err(|e| format!("Device authorization request failed: {e}"))?;
    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse device authorization response: {e}"))?;
    if !status.is_success() || body.get("error").is_some() {
        return Err(format!(
            "Device authorization failed ({status}): {} — {}. Ensure OAuth client '{client_id}' allows grant urn:ietf:params:oauth:grant-type:device_code.",
            body["error"].as_str().unwrap_or("unknown error"),
            body["error_description"].as_str().unwrap_or("")
        ));
    }
    let auth_response: DeviceAuthorizationResponse = serde_json::from_value(body)
        .map_err(|e| format!("Invalid device authorization response: {e}"))?;

    // Display user instructions
    println!("\n🔐 Device Flow Authentication");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Please visit: {}", auth_response.verification_uri);
    println!("And enter code: {}", auth_response.user_code);
    if access_token {
        println!(
            "Open the URL on your phone or another computer. Complete login and any MFA required by IDM there."
        );
        println!("This terminal waits for approval; do not enter your password or MFA code here.");
    }

    if let Some(complete_uri) = &auth_response.verification_uri_complete {
        println!("\nOr open this URL directly:");
        println!("{}", complete_uri);

        // Try to open complete URI
        if !access_token {
            if let Err(e) = open::that(complete_uri) {
                tracing::debug!("Failed to open browser: {}", e);
            }
        }
    }

    // Encode the same browser URL that is printed above, never the private device_code.
    let qr_uri = auth_response
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&auth_response.verification_uri);
    match qr_code::QrCode::new(qr_uri.as_bytes()) {
        Ok(code) => {
            println!("\nScan with your phone camera:");
            if std::io::stdout().is_terminal() {
                println!(
                    "Keep the QR code unwrapped ({} terminal columns required).",
                    code.width() + 8
                );
                print!("{}", terminal_qr(&code));
            } else {
                println!("{}", code.to_string(false, 4));
            }
        }
        Err(error) => tracing::debug!("Cannot render device QR code; use the printed URL: {error}"),
    }

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Poll for token
    let interval = Duration::from_secs(auth_response.interval.unwrap_or(5).max(1));
    let expires_at = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(auth_response.expires_in))
        .ok_or("Invalid device code expiration")?;

    let mut poll_interval = interval;

    loop {
        if tokio::time::Instant::now() >= expires_at {
            return Err("Device code expired".to_string());
        }

        tokio::time::timeout_at(expires_at, tokio::time::sleep(poll_interval))
            .await
            .map_err(|_| "Device code expired".to_string())?;

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

        let response = tokio::time::timeout_at(
            expires_at,
            http_client.post(token_endpoint).form(&token_form).send(),
        )
        .await
        .map_err(|_| "Device code expired".to_string())?
        .map_err(|e| format!("Token request failed: {e}"))?;
        let status = response.status();
        let response: TokenResponse = tokio::time::timeout_at(expires_at, response.json())
            .await
            .map_err(|_| "Device code expired".to_string())?
            .map_err(|e| format!("Failed to parse token response: {e}"))?;

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

        if !status.is_success() {
            return Err(format!("Token request failed: {status}"));
        }
        let token = if access_token {
            response.access_token.ok_or("No access token in response")?
        } else {
            response.id_token.ok_or("No ID token in response")?
        };
        if token.is_empty() {
            return Err("Empty token in response".into());
        }

        println!("\n✅ Authentication successful!");
        tracing::info!("Device flow completed successfully");

        return Ok(token);
    }
}

/// Keep the MIT-licensed qr_code renderer's compact geometry and quiet zone.
/// Only style its output: solid modules use cell backgrounds, and mixed modules
/// use lower blocks with foreground/background inversion to avoid font gaps.
fn terminal_qr(code: &qr_code::QrCode) -> String {
    let mut output = String::new();
    for line in code.to_string(false, 4).trim_end_matches('\n').lines() {
        for cell in line.chars() {
            output.push_str(match cell {
                '█' => "\x1b[48;5;16m ",
                '▀' => "\x1b[38;5;231;48;5;16m▄",
                '▄' => "\x1b[38;5;16;48;5;231m▄",
                _ => "\x1b[48;5;231m ",
            });
        }
        output.push_str("\x1b[0m\n");
    }
    output
}

fn secure_endpoint(value: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(value).map_err(|_| "Invalid device flow endpoint")?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || url.scheme() == "http" && loopback)
    {
        return Err("Device Flow endpoints require HTTPS (loopback HTTP is allowed for tests), without credentials or fragments".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::{Form, State},
        http::StatusCode,
        routing::{get, post},
    };
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    #[test]
    fn terminal_qr_is_compact_with_white_border_and_no_upper_blocks() {
        let code =
            qr_code::QrCode::new(b"https://example.test/device?user_code=TEST-1234").unwrap();
        let rendered = terminal_qr(&code);
        let mut plain = String::new();
        let mut escape = false;
        for ch in rendered.chars() {
            if ch == '\u{1b}' {
                escape = true;
            } else if escape {
                if ch == 'm' {
                    escape = false;
                }
            } else {
                plain.push(ch);
            }
        }
        let side = code.width() + 8;
        let lines: Vec<_> = plain.lines().collect();
        assert_eq!(lines.len(), side.div_ceil(2));
        assert!(lines.iter().all(|line| line.chars().count() == side));
        assert!(!plain.contains(['▀', '█']));
        assert!(plain.contains('▄'));
        for line in lines.iter().take(2).chain(lines.iter().rev().take(2)) {
            assert_eq!(*line, " ".repeat(side));
        }
        assert!(
            lines
                .iter()
                .all(|line| line.starts_with("    ") && line.ends_with("    "))
        );
        assert!(rendered.contains("\x1b[38;5;231;48;5;16m▄"));
        assert!(rendered.contains("\x1b[38;5;16;48;5;231m▄"));
    }

    #[derive(Clone)]
    struct Fixture {
        url: String,
        mode: &'static str,
        polls: Arc<AtomicUsize>,
    }
    async fn metadata(State(state): State<Fixture>) -> Json<serde_json::Value> {
        Json(
            serde_json::json!({"issuer":state.url, "device_authorization_endpoint":format!("{}/authorize-device",state.url), "token_endpoint":format!("{}/token",state.url)}),
        )
    }
    async fn authorize(
        State(state): State<Fixture>,
        Form(form): Form<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        assert_eq!(form["client_id"], "bastion-client");
        assert_eq!(form["tenant"], "default");
        assert_eq!(form["scope"], "openid bastion:connect");
        if state.mode == "unauthorized" {
            return Json(
                serde_json::json!({"error":"unauthorized_client","error_description":"Client is not authorized for device flow"}),
            );
        }
        Json(
            serde_json::json!({"device_code":"private-device-code", "user_code":"ABCD-EFGH", "verification_uri":format!("{}/device",state.url), "expires_in":if state.mode == "expired" {0} else {60}, "interval":1}),
        )
    }
    async fn token(
        State(state): State<Fixture>,
        Form(form): Form<HashMap<String, String>>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        assert_eq!(form["device_code"], "private-device-code");
        assert_eq!(form["client_id"], "bastion-client");
        assert_eq!(form["tenant"], "default");
        assert_eq!(
            form["grant_type"],
            "urn:ietf:params:oauth:grant-type:device_code"
        );
        let poll = state.polls.fetch_add(1, Ordering::SeqCst);
        let error = if state.mode == "pending" && poll == 0 {
            Some("authorization_pending")
        } else if state.mode == "pending" && poll == 1 {
            Some("slow_down")
        } else if state.mode == "denied" {
            Some("access_denied")
        } else {
            None
        };
        if let Some(error) = error {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":error})),
            );
        }
        let value = if state.mode == "missing" {
            serde_json::json!({"id_token":"id-token"})
        } else {
            serde_json::json!({"id_token":"id-token", "access_token":"api-access-token"})
        };
        (StatusCode::OK, Json(value))
    }
    async fn fixture(mode: &'static str, access_token: bool) -> (Result<String, String>, usize) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Fixture {
            url: url.clone(),
            mode,
            polls: Arc::new(AtomicUsize::new(0)),
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(metadata))
            .route("/authorize-device", post(authorize))
            .route("/token", post(token))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let result = device_token_flow(
            &url,
            "bastion-client",
            Some("default"),
            &["openid".into(), "bastion:connect".into()],
            access_token,
        )
        .await;
        server.abort();
        (result, state.polls.load(Ordering::SeqCst))
    }
    #[tokio::test]
    async fn device_access_flow_waits_for_approval_and_returns_access_not_id_token() {
        let (result, polls) = fixture("pending", true).await;
        assert_eq!(result.unwrap(), "api-access-token");
        assert_eq!(polls, 3);
    }
    #[tokio::test]
    async fn device_flow_preserves_direct_ssh_id_token_contract() {
        assert_eq!(fixture("success", false).await.0.unwrap(), "id-token");
    }
    #[tokio::test]
    async fn device_access_flow_reports_denial_expiration_and_missing_grant_or_token() {
        assert!(
            fixture("denied", true)
                .await
                .0
                .unwrap_err()
                .contains("denied")
        );
        let (expired, polls) = fixture("expired", true).await;
        assert!(expired.unwrap_err().contains("expired"));
        assert_eq!(polls, 0);
        assert!(
            fixture("missing", true)
                .await
                .0
                .unwrap_err()
                .contains("No access token")
        );
        assert!(
            fixture("unauthorized", true)
                .await
                .0
                .unwrap_err()
                .contains("urn:ietf:params:oauth:grant-type:device_code")
        );
    }
    #[test]
    fn rejects_unsafe_device_endpoints() {
        assert!(secure_endpoint("https://sso.example/token").is_ok());
        assert!(secure_endpoint("http://127.0.0.1/token").is_ok());
        for endpoint in [
            "http://remote.example/token",
            "https://user:password@sso.example/token",
            "https://sso.example/token#fragment",
        ] {
            assert!(secure_endpoint(endpoint).is_err());
        }
    }
}
