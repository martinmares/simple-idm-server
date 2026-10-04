use axum::{
    Router,
    extract::{Query, State},
    response::Html,
    routing::get,
};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope,
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    reqwest,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::oneshot;

use crate::oauth2::templates::callback_page;

#[derive(Clone)]
#[allow(dead_code)]
struct CallbackState {
    tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<CallbackResult>>>>,
    expected_state: Arc<String>,
}

struct CallbackResult {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub async fn browser_flow(
    issuer: &str,
    client_id: &str,
    tenant: Option<&str>,
    scopes: &[String],
) -> Result<String, String> {
    browser_token_flow(issuer, client_id, tenant, scopes, false).await
}

/// Browser login for an API client. Validates the ID token/nonce before returning
/// the access token; the API remains responsible for audience and scope checks.
pub async fn browser_access_token_flow(
    issuer: &str,
    client_id: &str,
    tenant: Option<&str>,
    scopes: &[String],
) -> Result<String, String> {
    browser_token_flow(issuer, client_id, tenant, scopes, true).await
}

async fn browser_token_flow(
    issuer: &str,
    client_id: &str,
    tenant: Option<&str>,
    scopes: &[String],
    access_token: bool,
) -> Result<String, String> {
    tracing::info!("Starting browser flow");

    // Discover OIDC metadata
    let issuer_url =
        IssuerUrl::new(issuer.to_string()).map_err(|e| format!("Invalid issuer URL: {}", e))?;

    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .map_err(|e| format!("OIDC discovery failed: {}", e))?;

    // Create OIDC client
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(client_id.to_string()),
        None, // Public client (no secret)
    );

    // Start local callback server on random port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("Failed to bind callback server: {}", e))?;

    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("Failed to get local address: {}", e))?;

    let redirect_url = format!("http://127.0.0.1:{}/callback", local_addr.port());
    tracing::info!("Callback server listening on {}", redirect_url);

    // Parse redirect URL once for reuse in authorization and token requests
    let redirect_url_parsed = RedirectUrl::new(redirect_url.clone())
        .map_err(|e| format!("Invalid redirect URL: {}", e))?;

    // Generate PKCE challenge
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate authorization URL
    let mut auth_req = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(pkce_challenge)
        .set_redirect_uri(std::borrow::Cow::Borrowed(&redirect_url_parsed));

    // Add scopes
    for scope in scopes {
        auth_req = auth_req.add_scope(Scope::new(scope.to_string()));
    }

    if let Some(tenant) = tenant.filter(|t| !t.trim().is_empty()) {
        auth_req = auth_req.add_extra_param("tenant", tenant.to_string());
    }

    let (auth_url, csrf_state, nonce) = auth_req.url();

    // Setup callback handler
    let (tx, rx) = oneshot::channel();
    let expected_state = Arc::new(csrf_state.secret().to_string());
    let expected_nonce = nonce.secret().to_string();

    let callback_state = CallbackState {
        tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
        expected_state: expected_state.clone(),
    };

    let app = Router::new()
        .route("/callback", get(handle_callback))
        .with_state(callback_state);

    // Spawn server
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    // Abort even if this future is cancelled or authentication times out.
    let _server_guard = CallbackServerGuard(server.abort_handle());

    // Open browser
    println!("\n🔐 Opening browser for authentication...");
    println!("If browser doesn't open, visit:\n{}\n", auth_url);

    if let Err(e) = open::that(auth_url.to_string()) {
        tracing::warn!("Failed to open browser: {}", e);
    }

    // Wait for callback
    tracing::info!("Waiting for callback...");
    let callback_result = match tokio::time::timeout(std::time::Duration::from_secs(300), rx).await
    {
        Ok(Ok(result)) => {
            tracing::info!("Callback received successfully");
            result
        }
        Ok(Err(_)) => {
            tracing::error!("Callback channel closed unexpectedly");
            return Err("Callback channel closed".to_string());
        }
        Err(_) => {
            tracing::error!("Authentication timeout after 5 minutes");
            return Err("Authentication timeout (5 minutes)".to_string());
        }
    };

    // Abort server
    server.abort();

    // Verify state
    if callback_result.state != *expected_state {
        return Err("State mismatch (CSRF)".to_string());
    }

    // Exchange code for token
    // IMPORTANT: redirect_uri MUST be included per OAuth2 RFC 6749 section 4.1.3
    tracing::debug!("Exchanging authorization code for tokens");
    let mut token_request = client
        .exchange_code(AuthorizationCode::new(callback_result.code))
        .map_err(|e| format!("Failed to build token request: {}", e))?
        .set_pkce_verifier(pkce_verifier)
        .set_redirect_uri(std::borrow::Cow::Borrowed(&redirect_url_parsed));
    if let Some(tenant) = tenant.filter(|t| !t.trim().is_empty()) {
        token_request = token_request.add_extra_param("tenant", tenant.to_string());
    }
    let token_response = token_request
        .request_async(&http_client)
        .await
        .map_err(|e| {
            tracing::error!("Token exchange error: {:?}", e);
            format!("Token exchange failed: {}", e)
        })?;

    tracing::debug!("Token exchange successful");

    let id_token = token_response
        .extra_fields()
        .id_token()
        .ok_or("No ID token in response")?;

    // Verify ID token
    let verifier = client.id_token_verifier();
    let claims = id_token
        .claims(&verifier, &Nonce::new(expected_nonce))
        .map_err(|e| format!("ID token validation failed: {}", e))?;

    tracing::info!("Browser flow successful: sub={:?}", claims.subject());

    if access_token {
        Ok(token_response.access_token().secret().to_owned())
    } else {
        Ok(id_token.to_string())
    }
}

struct CallbackServerGuard(tokio::task::AbortHandle);

impl Drop for CallbackServerGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn handle_callback(
    State(state): State<CallbackState>,
    Query(query): Query<CallbackQuery>,
) -> Html<String> {
    if let Some(error) = query.error {
        let desc = query.error_description.unwrap_or_default();
        tracing::error!("OAuth error: {} - {}", error, desc);
        // return Html(
        //     "<h1>❌ Authentication failed</h1><p>You can close this window.</p>".to_string(),
        // );

        return callback_page(
            false,
            "Login",
            "❌ Authentication failed! You can close this window.",
        );
    }

    let code = match query.code {
        Some(c) => c,
        None => {
            tracing::error!("No code in callback");
            // return Html("<h1>❌ No authorization code received</h1>".to_string());
            return callback_page(
                false,
                "Login",
                "❌ No authorization code received! You can close this window.",
            );
        }
    };

    let callback_state = match query.state {
        Some(s) => s,
        None => {
            tracing::error!("No state in callback");
            // return Html("<h1>❌ No state parameter</h1>".to_string());
            return callback_page(
                false,
                "Login",
                "❌ No state parameter! You can close this window.",
            );
        }
    };

    if callback_state != *state.expected_state {
        return callback_page(false, "Login", "Invalid authentication state.");
    }

    // Send result back to main flow
    if let Some(tx) = state.tx.lock().await.take() {
        tracing::info!("Sending callback result to main flow");
        if tx
            .send(CallbackResult {
                code,
                state: callback_state,
            })
            .is_err()
        {
            tracing::error!("Failed to send callback result - receiver dropped");
        } else {
            tracing::info!("Callback result sent successfully");
        }
    } else {
        tracing::warn!("Callback handler already consumed");
    }

    callback_page(
        true,
        "Login",
        "✓ Login successful! You can close this window.",
    )
}

#[cfg(test)]
mod browser_flow_tests {
    use super::*;

    #[tokio::test]
    async fn wrong_state_does_not_consume_callback_slot() {
        let (tx, rx) = oneshot::channel();
        let state = CallbackState {
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
            expected_state: Arc::new("expected".into()),
        };
        let query = |value: &str| CallbackQuery {
            code: Some("code".into()),
            state: Some(value.into()),
            error: None,
            error_description: None,
        };
        let _ = handle_callback(State(state.clone()), Query(query("wrong"))).await;
        assert!(state.tx.lock().await.is_some());
        let _ = handle_callback(State(state.clone()), Query(query("expected"))).await;
        assert_eq!(rx.await.unwrap().state, "expected");
        assert!(state.tx.lock().await.is_none());
    }

    #[tokio::test]
    async fn abort_guard_cancels_callback_server() {
        let task = tokio::spawn(std::future::pending::<()>());
        let guard = CallbackServerGuard(task.abort_handle());
        drop(guard);
        assert!(task.await.unwrap_err().is_cancelled());
    }
}
