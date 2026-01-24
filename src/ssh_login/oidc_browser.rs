use axum::{
    extract::{Query, State},
    response::Html,
    routing::get,
    Router,
};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    reqwest::async_http_client,
    AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, RedirectUrl, Scope,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::oneshot;

#[derive(Clone)]
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
    scopes: &[String],
) -> Result<String, String> {
    tracing::info!("Starting browser flow");

    // Discover OIDC metadata
    let issuer_url =
        IssuerUrl::new(issuer.to_string()).map_err(|e| format!("Invalid issuer URL: {}", e))?;

    let metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client)
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
        .set_redirect_uri(std::borrow::Cow::Owned(
            RedirectUrl::new(redirect_url.clone())
                .map_err(|e| format!("Invalid redirect URL: {}", e))?,
        ));

    // Add scopes
    for scope in scopes {
        auth_req = auth_req.add_scope(Scope::new(scope.to_string()));
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

    // Open browser
    println!("\n🔐 Opening browser for authentication...");
    println!("If browser doesn't open, visit:\n{}\n", auth_url);

    if let Err(e) = open::that(auth_url.to_string()) {
        tracing::warn!("Failed to open browser: {}", e);
    }

    // Wait for callback
    tracing::info!("Waiting for callback...");
    let callback_result = match tokio::time::timeout(std::time::Duration::from_secs(300), rx).await {
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
    tracing::debug!("Exchanging authorization code for tokens");
    let token_response = client
        .exchange_code(AuthorizationCode::new(callback_result.code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
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

    Ok(id_token.to_string())
}

async fn handle_callback(
    State(state): State<CallbackState>,
    Query(query): Query<CallbackQuery>,
) -> Html<&'static str> {
    if let Some(error) = query.error {
        let desc = query.error_description.unwrap_or_default();
        tracing::error!("OAuth error: {} - {}", error, desc);
        return Html("<h1>❌ Authentication failed</h1><p>You can close this window.</p>");
    }

    let code = match query.code {
        Some(c) => c,
        None => {
            tracing::error!("No code in callback");
            return Html("<h1>❌ No authorization code received</h1>");
        }
    };

    let callback_state = match query.state {
        Some(s) => s,
        None => {
            tracing::error!("No state in callback");
            return Html("<h1>❌ No state parameter</h1>");
        }
    };

    // Send result back to main flow
    if let Some(tx) = state.tx.lock().await.take() {
        tracing::info!("Sending callback result to main flow");
        if tx.send(CallbackResult {
            code,
            state: callback_state,
        }).is_err() {
            tracing::error!("Failed to send callback result - receiver dropped");
        } else {
            tracing::info!("Callback result sent successfully");
        }
    } else {
        tracing::warn!("Callback handler already consumed");
    }

    Html("<h1>✅ Authentication successful!</h1><p>You can close this window and return to the terminal.</p>")
}
