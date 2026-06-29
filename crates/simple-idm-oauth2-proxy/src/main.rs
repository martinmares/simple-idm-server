use anyhow::{Context, Result};
use axum::{
    Router,
    body::Body,
    extract::{
        Query, Request, State,
        ws::{
            Message as AxumWsMessage, WebSocket, WebSocketUpgrade,
            rejection::WebSocketUpgradeRejection,
        },
    },
    http::{HeaderMap, HeaderName, HeaderValue, Request as HttpRequest, StatusCode, Uri, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, get},
};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use reqwest::Client;
use simple_idm_core::proxy::config::{Config, ProxyMode};
use simple_idm_core::proxy::oidc::OidcClient;
use simple_idm_core::proxy::session::{Session, SessionStore};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Bytes as WsBytes, Message as TungsteniteMessage},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct AppState {
    config: Config,
    oidc_client: Arc<OidcClient>,
    session_store: Arc<SessionStore>,
    http_client: Client,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "simple_idm_oauth2_proxy=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting simple-idm-oauth2-proxy");

    let config = Config::load()?;
    tracing::info!(
        "Loaded configuration from: {}",
        config.config_file.display()
    );
    tracing::info!("Mode: {:?}", config.mode);
    tracing::info!("Listen address: {}", config.listen_addr);
    tracing::info!("Public base URL: {}", config.public_base_url);
    if let Some(upstream_url) = config.upstream_url.as_deref() {
        tracing::info!("Upstream URL: {}", upstream_url);
    }
    tracing::info!("OIDC issuer: {}", config.oidc_issuer);

    let oidc_client = Arc::new(OidcClient::new(&config).await?);
    tracing::info!("OIDC client initialized");

    let session_store = Arc::new(SessionStore::new(&config).await?);
    tracing::info!("Session store initialized: {:?}", config.session_backend);

    let http_client = Client::builder()
        .timeout(Duration::from_secs(config.upstream_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let state = AppState {
        config: config.clone(),
        oidc_client,
        session_store,
        http_client,
    };

    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .route("/auth", get(handle_auth))
        .route("/start", get(handle_start))
        .route("/callback", get(handle_callback))
        .route("/logout", get(handle_logout).post(handle_logout));

    if config.mode == ProxyMode::ReverseProxy {
        app = app.fallback(any(handle_reverse_proxy));
    }

    let app = app
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("Listening on {}", config.listen_addr);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn handle_auth(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(session) = authorize_session(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, HeaderMap::new()).into_response();
    };

    let response_headers = build_auth_headers(&state.config, &session);

    tracing::debug!(
        "Auth OK for user: {}, groups: {:?}",
        session.username,
        session.groups
    );

    (StatusCode::OK, response_headers).into_response()
}

async fn handle_reverse_proxy(
    State(state): State<AppState>,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    req: Request,
) -> Response {
    let path = req.uri().path().to_string();
    let protected = is_protected_path(&state.config, &path);

    let session = if protected {
        match authorize_session(&state, req.headers()).await {
            Some(session) => Some(session),
            None => return redirect_to_login(req.uri()).into_response(),
        }
    } else {
        None
    };

    if is_websocket_request(&req) {
        let Ok(ws) = ws else {
            return (StatusCode::BAD_REQUEST, "Invalid websocket upgrade").into_response();
        };
        return handle_websocket_proxy(state, session, ws, req).await;
    }

    match forward_http_request(state, session.as_ref(), req).await {
        Ok(response) => response,
        Err(err) => {
            tracing::error!("reverse proxy request failed: {:?}", err);
            (StatusCode::BAD_GATEWAY, "upstream request failed").into_response()
        }
    }
}

async fn forward_http_request(
    state: AppState,
    session: Option<&Session>,
    req: Request,
) -> Result<Response> {
    let (parts, body) = req.into_parts();
    let upstream_url = build_upstream_url(&state.config, &parts.uri)?;

    let mut builder = state
        .http_client
        .request(parts.method.clone(), upstream_url)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()));

    let mut headers = sanitize_upstream_headers(&parts.headers);
    if let Some(session) = session {
        inject_auth_headers(&state.config, session, &mut headers);
    }
    builder = builder.headers(headers);

    let upstream = builder.send().await?;
    let status = upstream.status();
    let mut response_builder = Response::builder().status(status);

    for (name, value) in upstream.headers() {
        if should_forward_response_header(name) {
            response_builder = response_builder.header(name, value);
        }
    }

    let body = Body::from_stream(upstream.bytes_stream());
    response_builder
        .body(body)
        .context("failed to build upstream response")
}

async fn handle_websocket_proxy(
    state: AppState,
    session: Option<Session>,
    ws: WebSocketUpgrade,
    req: Request,
) -> Response {
    let upstream_url = match build_websocket_upstream_url(&state.config, req.uri()) {
        Ok(url) => url,
        Err(err) => {
            tracing::error!("failed to build websocket upstream URL: {:?}", err);
            return (StatusCode::BAD_GATEWAY, "invalid websocket upstream").into_response();
        }
    };
    let headers = sanitize_upstream_headers(req.headers());

    ws.on_upgrade(move |downstream| async move {
        if let Err(err) =
            proxy_websocket(state, session.as_ref(), downstream, upstream_url, headers).await
        {
            tracing::warn!("websocket proxy failed: {:?}", err);
        }
    })
}

async fn proxy_websocket(
    state: AppState,
    session: Option<&Session>,
    downstream: WebSocket,
    upstream_url: String,
    mut headers: HeaderMap,
) -> Result<()> {
    if let Some(session) = session {
        inject_auth_headers(&state.config, session, &mut headers);
    }

    let mut request = HttpRequest::builder().uri(&upstream_url);
    for (name, value) in &headers {
        if should_forward_request_header(name) {
            request = request.header(name, value);
        }
    }
    let request = request.body(())?;

    let (upstream, _) = connect_async(request).await?;
    let (mut upstream_write, mut upstream_read) = upstream.split();
    let (mut downstream_write, mut downstream_read) = downstream.split();

    let client_to_upstream = async {
        while let Some(message) = downstream_read.next().await {
            let message = message?;
            if let Some(message) = axum_to_tungstenite_message(message) {
                upstream_write.send(message).await?;
            }
        }
        Result::<()>::Ok(())
    };

    let upstream_to_client = async {
        while let Some(message) = upstream_read.next().await {
            let message = message?;
            if let Some(message) = tungstenite_to_axum_message(message) {
                downstream_write.send(message).await?;
            }
        }
        Result::<()>::Ok(())
    };

    tokio::select! {
        result = client_to_upstream => result?,
        result = upstream_to_client => result?,
    }

    Ok(())
}

async fn handle_start(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let redirect_url = params.get("rd").cloned().unwrap_or_else(|| "/".to_string());

    match state.oidc_client.start_flow(&redirect_url).await {
        Ok((auth_url, flow_state)) => {
            state.session_store.store_flow_state(&flow_state).await;

            let cookie = format!(
                "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600",
                "__oauth_state", flow_state.state
            );

            let mut response = Redirect::temporary(&auth_url).into_response();
            response
                .headers_mut()
                .insert(header::SET_COOKIE, cookie.parse().unwrap());

            response
        }
        Err(e) => {
            tracing::error!("Failed to start OIDC flow: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to start login").into_response()
        }
    }
}

async fn handle_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let state_from_cookie = match extract_session_cookie(&headers, "__oauth_state") {
        Some(s) => s,
        None => {
            tracing::error!("No state cookie found in callback");
            return (StatusCode::BAD_REQUEST, "Missing state").into_response();
        }
    };

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

    if &state_from_cookie != state_param {
        tracing::error!("State mismatch");
        return (StatusCode::BAD_REQUEST, "State mismatch").into_response();
    }

    let flow_state = match state.session_store.get_flow_state(state_param).await {
        Some(fs) => fs,
        None => {
            tracing::error!("Flow state not found: {}", state_param);
            return (StatusCode::BAD_REQUEST, "Invalid state").into_response();
        }
    };

    let token_response = match state.oidc_client.exchange_code(code, &flow_state).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Failed to exchange code: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Token exchange failed").into_response();
        }
    };

    let session_id = state
        .session_store
        .create_session(&token_response, &state.config)
        .await;

    let secure = if state.config.public_base_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{}={}; Path=/; HttpOnly{}; SameSite=Lax; Max-Age={}",
        state.config.cookie_name, session_id, secure, state.config.session_max_age
    );

    let clear_state_cookie =
        "__oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0".to_string();

    let mut response = Redirect::temporary(&flow_state.redirect_url).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.parse().unwrap());
    response
        .headers_mut()
        .append(header::SET_COOKIE, clear_state_cookie.parse().unwrap());

    tracing::info!("Login successful for user: {}", token_response.username);

    response
}

async fn handle_logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(session_id) = extract_session_cookie(&headers, &state.config.cookie_name) {
        state.session_store.delete(&session_id).await;
        tracing::info!("Session deleted: {}", session_id);
    }

    let cookie = format!(
        "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        state.config.cookie_name
    );

    let body = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Signed out</title>
  <style>
    :root { color-scheme: light dark; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0f172a;
      color: #e5e7eb;
    }
    main {
      width: min(440px, calc(100vw - 32px));
      border: 1px solid #334155;
      border-radius: 10px;
      background: #111827;
      padding: 28px;
      box-shadow: 0 20px 50px rgba(0,0,0,.25);
    }
    h1 { margin: 0 0 10px; font-size: 24px; }
    p { margin: 0 0 18px; color: #9ca3af; line-height: 1.45; }
    a {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 38px;
      padding: 0 14px;
      border-radius: 7px;
      background: #2563eb;
      color: white;
      text-decoration: none;
      font-weight: 600;
    }
  </style>
</head>
<body>
  <main>
    <h1>Signed out</h1>
    <p>You have been signed out from this application. Your SSO session may still be active.</p>
    <a href="start?rd=%2F">Sign in again</a>
  </main>
</body>
</html>"#;

    let mut response = Html(body).into_response();

    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.parse().unwrap());

    response
}

async fn authorize_session(state: &AppState, headers: &HeaderMap) -> Option<Session> {
    let session_id = match extract_session_cookie(headers, &state.config.cookie_name) {
        Some(id) => id,
        None => {
            tracing::debug!("No session cookie found");
            return None;
        }
    };

    match state.session_store.get(&session_id).await {
        Some(s) if !s.is_expired() => Some(s),
        Some(s) => {
            let Some(refresh_token) = s.refresh_token.clone() else {
                tracing::debug!("Session expired without refresh token: {}", session_id);
                return None;
            };
            match state.oidc_client.refresh_token(&refresh_token).await {
                Ok(refresh) => {
                    match state
                        .session_store
                        .refresh_session(&session_id, &refresh, &state.config)
                        .await
                    {
                        Some(updated) => Some(updated),
                        None => {
                            tracing::warn!("Failed to refresh session: {}", session_id);
                            None
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!("Token refresh failed for session {}: {:?}", session_id, err);
                    None
                }
            }
        }
        None => {
            tracing::debug!("Session not found: {}", session_id);
            None
        }
    }
}

fn build_auth_headers(config: &Config, session: &Session) -> HeaderMap {
    let mut headers = HeaderMap::new();
    inject_auth_headers(config, session, &mut headers);
    headers
}

fn inject_auth_headers(config: &Config, session: &Session, headers: &mut HeaderMap) {
    headers.insert(
        HeaderName::from_static("x-auth-user"),
        HeaderValue::from_str(&session.username).unwrap(),
    );
    headers.insert(
        HeaderName::from_static("x-auth-subject"),
        HeaderValue::from_str(&session.subject).unwrap(),
    );
    if let Some(ref email) = session.email {
        headers.insert(
            HeaderName::from_static("x-auth-email"),
            HeaderValue::from_str(email).unwrap(),
        );
    }
    let groups_header = serialize_groups(&session.groups, &config.groups_header_format);
    let header_name: HeaderName = config.groups_header_name.parse().unwrap();
    headers.insert(header_name, HeaderValue::from_str(&groups_header).unwrap());
}

fn is_protected_path(config: &Config, path: &str) -> bool {
    if config
        .public_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return false;
    }
    config
        .protected_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn redirect_to_login(uri: &Uri) -> Redirect {
    let rd = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    Redirect::temporary(&format!("/start?rd={}", urlencoding::encode(rd)))
}

fn build_upstream_url(config: &Config, uri: &Uri) -> Result<String> {
    let upstream = config
        .upstream_url
        .as_deref()
        .context("upstream_url is not configured")?
        .trim_end_matches('/');
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    Ok(format!("{upstream}{path}"))
}

fn build_websocket_upstream_url(config: &Config, uri: &Uri) -> Result<String> {
    let http_url = build_upstream_url(config, uri)?;
    if let Some(rest) = http_url.strip_prefix("http://") {
        Ok(format!("ws://{rest}"))
    } else if let Some(rest) = http_url.strip_prefix("https://") {
        Ok(format!("wss://{rest}"))
    } else {
        anyhow::bail!("unsupported upstream URL scheme")
    }
}

fn sanitize_upstream_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if should_forward_request_header(name) && !is_auth_header(name) {
            out.append(name, value.clone());
        }
    }
    out
}

fn should_forward_request_header(name: &HeaderName) -> bool {
    !is_hop_by_hop_header(name)
}

fn should_forward_response_header(name: &HeaderName) -> bool {
    !is_hop_by_hop_header(name)
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_auth_header(name: &HeaderName) -> bool {
    let name = name.as_str().to_ascii_lowercase();
    name == "x-auth-user"
        || name == "x-auth-subject"
        || name == "x-auth-email"
        || name == "x-auth-groups"
        || name == "x-auth-token"
}

fn is_websocket_request(req: &Request) -> bool {
    req.headers()
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

fn extract_session_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;

    cookie_header.split(';').find_map(|cookie| {
        let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
        if parts.len() == 2 && parts[0] == cookie_name {
            Some(parts[1].to_string())
        } else {
            None
        }
    })
}

fn serialize_groups(groups: &[String], format: &str) -> String {
    match format {
        "jsonb64" => {
            let json = serde_json::to_string(groups).unwrap();
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes())
        }
        _ => groups.join(","),
    }
}

fn axum_to_tungstenite_message(message: AxumWsMessage) -> Option<TungsteniteMessage> {
    match message {
        AxumWsMessage::Text(text) => Some(TungsteniteMessage::Text(text.to_string().into())),
        AxumWsMessage::Binary(bytes) => Some(TungsteniteMessage::Binary(WsBytes::from(bytes))),
        AxumWsMessage::Ping(bytes) => Some(TungsteniteMessage::Ping(WsBytes::from(bytes))),
        AxumWsMessage::Pong(bytes) => Some(TungsteniteMessage::Pong(WsBytes::from(bytes))),
        AxumWsMessage::Close(frame) => Some(TungsteniteMessage::Close(frame.map(|frame| {
            tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: frame.code.into(),
                reason: frame.reason.to_string().into(),
            }
        }))),
    }
}

fn tungstenite_to_axum_message(message: TungsteniteMessage) -> Option<AxumWsMessage> {
    match message {
        TungsteniteMessage::Text(text) => Some(AxumWsMessage::Text(text.to_string().into())),
        TungsteniteMessage::Binary(bytes) => Some(AxumWsMessage::Binary(bytes.into())),
        TungsteniteMessage::Ping(bytes) => Some(AxumWsMessage::Ping(bytes.into())),
        TungsteniteMessage::Pong(bytes) => Some(AxumWsMessage::Pong(bytes.into())),
        TungsteniteMessage::Close(frame) => Some(AxumWsMessage::Close(frame.map(|frame| {
            axum::extract::ws::CloseFrame {
                code: frame.code.into(),
                reason: frame.reason.to_string().into(),
            }
        }))),
        TungsteniteMessage::Frame(_) => None,
    }
}
