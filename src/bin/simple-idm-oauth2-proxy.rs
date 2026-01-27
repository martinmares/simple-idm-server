use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use base64::Engine;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use simple_idm_server::proxy::config::Config;
use simple_idm_server::proxy::oidc::OidcClient;
use simple_idm_server::proxy::session::SessionStore;

#[derive(Clone)]
struct AppState {
    config: Config,
    oidc_client: Arc<OidcClient>,
    session_store: Arc<SessionStore>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "simple_idm_oauth2_proxy=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting simple-idm-oauth2-proxy");

    // Load configuration
    let config = Config::load()?;
    tracing::info!("Loaded configuration from: {}", config.config_file.display());
    tracing::info!("Listen address: {}", config.listen_addr);
    tracing::info!("Public base URL: {}", config.public_base_url);
    tracing::info!("OIDC issuer: {}", config.oidc_issuer);

    // Initialize OIDC client
    let oidc_client = Arc::new(OidcClient::new(&config).await?);
    tracing::info!("OIDC client initialized");

    // Initialize session store
    let session_store = Arc::new(SessionStore::new(&config).await?);
    tracing::info!("Session store initialized: {:?}", config.session_backend);

    let state = AppState {
        config: config.clone(),
        oidc_client,
        session_store,
    };

    // Build router
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/auth", get(handle_auth))
        .route("/start", get(handle_start))
        .route("/callback", get(handle_callback))
        .route("/logout", post(handle_logout))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    // Start server
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("Listening on {}", config.listen_addr);

    axum::serve(listener, app).await?;

    Ok(())
}

/// Health check endpoint
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Auth request endpoint - used by nginx auth_request
async fn handle_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Extract session cookie
    let session_id = match extract_session_cookie(&headers, &state.config.cookie_name) {
        Some(id) => id,
        None => {
            tracing::debug!("No session cookie found");
            return (StatusCode::UNAUTHORIZED, HeaderMap::new()).into_response();
        }
    };

    // Validate session
    let session = match state.session_store.get(&session_id).await {
        Some(s) if !s.is_expired() => s,
        Some(s) => {
            if let Some(refresh_token) = s.refresh_token.clone() {
                match state.oidc_client.refresh_token(&refresh_token).await {
                    Ok(refresh) => match state
                        .session_store
                        .refresh_session(&session_id, &refresh, &state.config)
                        .await
                    {
                        Some(updated) => updated,
                        None => {
                            tracing::warn!("Failed to refresh session: {}", session_id);
                            return (StatusCode::UNAUTHORIZED, HeaderMap::new()).into_response();
                        }
                    },
                    Err(err) => {
                        tracing::warn!("Token refresh failed for session {}: {:?}", session_id, err);
                        return (StatusCode::UNAUTHORIZED, HeaderMap::new()).into_response();
                    }
                }
            } else {
                tracing::debug!("Session expired without refresh token: {}", session_id);
                return (StatusCode::UNAUTHORIZED, HeaderMap::new()).into_response();
            }
        }
        None => {
            tracing::debug!("Session not found: {}", session_id);
            return (StatusCode::UNAUTHORIZED, HeaderMap::new()).into_response();
        }
    };

    // Build auth headers
    let mut response_headers = HeaderMap::new();

    // X-Auth-User
    response_headers.insert(
        HeaderName::from_static("x-auth-user"),
        HeaderValue::from_str(&session.username).unwrap(),
    );

    // X-Auth-Email (if present)
    if let Some(ref email) = session.email {
        response_headers.insert(
            HeaderName::from_static("x-auth-email"),
            HeaderValue::from_str(email).unwrap(),
        );
    }

    // X-Auth-Groups
    let groups_header = serialize_groups(&session.groups, &state.config.groups_header_format);
    let header_name: HeaderName = state.config.groups_header_name.parse().unwrap();
    response_headers.insert(
        header_name,
        HeaderValue::from_str(&groups_header).unwrap(),
    );

    tracing::debug!(
        "Auth OK for user: {}, groups: {:?}",
        session.username,
        session.groups
    );

    (StatusCode::OK, response_headers).into_response()
}

/// Start login flow
async fn handle_start(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let redirect_url = params.get("rd").cloned().unwrap_or_else(|| "/".to_string());

    // Start OIDC flow
    match state.oidc_client.start_flow(&redirect_url).await {
        Ok((auth_url, flow_state)) => {
            // Store flow state in session store temporarily
            state.session_store.store_flow_state(&flow_state).await;

            // Set state cookie
            let cookie = format!(
                "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600",
                "__oauth_state", flow_state.state
            );

            let mut response = Redirect::temporary(&auth_url).into_response();
            response.headers_mut().insert(
                header::SET_COOKIE,
                cookie.parse().unwrap(),
            );

            response
        }
        Err(e) => {
            tracing::error!("Failed to start OIDC flow: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to start login").into_response()
        }
    }
}

/// OAuth callback handler
async fn handle_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // Extract state from cookie
    let state_from_cookie = match extract_session_cookie(&headers, "__oauth_state") {
        Some(s) => s,
        None => {
            tracing::error!("No state cookie found in callback");
            return (StatusCode::BAD_REQUEST, "Missing state").into_response();
        }
    };

    // Validate callback
    let code = match params.get("code") {
        Some(c) => c,
        None => {
            tracing::error!("No code parameter in callback");
            return (StatusCode::BAD_REQUEST, "Missing code").into_response();
        }
    };

    let state_param = match params.get("state") {
        Some(s) => s,
        None => {
            tracing::error!("No state parameter in callback");
            return (StatusCode::BAD_REQUEST, "Missing state").into_response();
        }
    };

    // Verify state matches
    if &state_from_cookie != state_param {
        tracing::error!("State mismatch");
        return (StatusCode::BAD_REQUEST, "State mismatch").into_response();
    }

    // Get flow state
    let flow_state = match state.session_store.get_flow_state(state_param).await {
        Some(fs) => fs,
        None => {
            tracing::error!("Flow state not found: {}", state_param);
            return (StatusCode::BAD_REQUEST, "Invalid state").into_response();
        }
    };

    // Exchange code for tokens
    let token_response = match state.oidc_client.exchange_code(code, &flow_state).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Failed to exchange code: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Token exchange failed").into_response();
        }
    };

    // Create session
    let session_id = state.session_store.create_session(&token_response, &state.config).await;

    // Set session cookie
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        state.config.cookie_name,
        session_id,
        state.config.session_max_age
    );

    // Clear state cookie
    let clear_state_cookie = "__oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0".to_string();

    let mut response = Redirect::temporary(&flow_state.redirect_url).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie.parse().unwrap(),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        clear_state_cookie.parse().unwrap(),
    );

    tracing::info!("Login successful for user: {}", token_response.username);

    response
}

/// Logout endpoint
async fn handle_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Extract and delete session
    if let Some(session_id) = extract_session_cookie(&headers, &state.config.cookie_name) {
        state.session_store.delete(&session_id).await;
        tracing::info!("Session deleted: {}", session_id);
    }

    // Clear cookie
    let cookie = format!(
        "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        state.config.cookie_name
    );

    let mut response = Html("<html><body><h1>Logged out</h1><p>You have been logged out successfully.</p></body></html>")
        .into_response();

    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie.parse().unwrap(),
    );

    response
}

/// Helper: Extract session cookie
fn extract_session_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;

    cookie_header
        .split(';')
        .find_map(|cookie| {
            let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
            if parts.len() == 2 && parts[0] == cookie_name {
                Some(parts[1].to_string())
            } else {
                None
            }
        })
}

/// Helper: Serialize groups for header
fn serialize_groups(groups: &[String], format: &str) -> String {
    match format {
        "jsonb64" => {
            let json = serde_json::to_string(groups).unwrap();
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes())
        }
        _ => {
            // Default: CSV
            groups.join(",")
        }
    }
}
