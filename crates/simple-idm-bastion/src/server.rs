use crate::{
    audit::Audit,
    config::{Config, Host, dimensions, terminal},
    ssh::{Prepared, Transport},
};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    extract::{
        ConnectInfo, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use futures_util::SinkExt;
use serde::{Deserialize, Serialize};
use simple_idm_core::ssh_signer::jwt_validator::{JwtValidator, TokenClaims};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub struct App {
    pub config: Config,
    pub audit: Audit,
    pub jwt: JwtValidator,
    pub http: reqwest::Client,
    pub secret: String,
    pub slots: Arc<Semaphore>,
    pub audit_failed: AtomicBool,
}
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/api/v1/hosts", get(hosts))
        .route("/api/v1/terminal", get(open))
        .with_state(app)
}
fn bearer(headers: &HeaderMap) -> Result<&str> {
    let header = headers
        .get("authorization")
        .context("Bearer access token required")?
        .to_str()?;
    let (kind, token) = header
        .split_once(' ')
        .context("Bearer access token required")?;
    ensure!(
        kind.eq_ignore_ascii_case("Bearer")
            && !token.is_empty()
            && !token.contains(char::is_whitespace),
        "Bearer access token required"
    );
    Ok(token)
}
async fn authenticate(app: &App, token: &str) -> Result<TokenClaims> {
    tokio::time::timeout(Duration::from_secs(15), app.jwt.validate_token(token))
        .await?
        .map_err(|_| anyhow::anyhow!("invalid access token"))
}
fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({"version":1,"type":"error","message":message})),
    )
        .into_response()
}
async fn hosts(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let token = match bearer(&headers) {
        Ok(t) => t,
        Err(_) => return error(StatusCode::UNAUTHORIZED, "Bearer access token required"),
    };
    let claims = match authenticate(&app, token).await {
        Ok(c) => c,
        Err(_) => return error(StatusCode::UNAUTHORIZED, "invalid access token"),
    };
    if app.config.authorize_identity(&claims).is_err() {
        return error(StatusCode::FORBIDDEN, "tenant or access scope denied");
    }
    // Resolve only authorized destinations, concurrently under a single short deadline.
    // DNS metadata is informational: failure must not prevent choosing a host.
    let hosts = futures_util::future::join_all(app.config.catalog(&claims).into_iter().map(
        |mut host| async move {
            if let Ok(Ok(addresses)) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                tokio::net::lookup_host((host.address.as_str(), host.port)),
            )
            .await
            {
                host.resolved_ips = addresses
                    .map(|address| address.ip().to_string())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect();
            }
            host
        },
    ))
    .await;
    Json(serde_json::json!({
        "identity": {"username": claims.preferred_username.as_deref().unwrap_or(&claims.sub),
                     "subject": claims.sub, "tenant": claims.tenant_id},
        "bastion": {"id": app.config.bastion_id},
        "hosts": hosts
    }))
    .into_response()
}
#[derive(Clone, Deserialize)]
pub struct TerminalQuery {
    pub host_id: String,
    pub login: String,
    #[serde(default = "default_cols")]
    pub cols: u16,
    #[serde(default = "default_rows")]
    pub rows: u16,
    #[serde(default = "default_term")]
    pub term: String,
}
fn default_cols() -> u16 {
    80
}
fn default_rows() -> u16 {
    24
}
fn default_term() -> String {
    "xterm-256color".into()
}
fn client_ip(config: &Config, peer: IpAddr, headers: &HeaderMap) -> String {
    if config.trusted_proxies.contains(&peer)
        && let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<IpAddr>().ok())
    {
        return ip.to_string();
    }
    peer.to_string()
}
async fn finish(
    app: &App,
    session: &str,
    result: &str,
    reason: &str,
    status: Option<i32>,
    started: Option<Instant>,
) {
    if app
        .audit
        .ended(
            session,
            result,
            reason,
            status,
            started.map(|t| t.elapsed().as_millis().min(i64::MAX as u128) as i64),
        )
        .await
        .is_err()
    {
        // Refuse subsequent sessions after a lost end write. Restart reconciliation repairs unknown ends.
        app.audit_failed.store(true, Ordering::SeqCst);
        tracing::error!(
            session_id = session,
            "audit unhealthy; refusing new terminals until restart"
        );
    }
}
async fn open(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<TerminalQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    if app.audit_failed.load(Ordering::SeqCst) {
        return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
    }
    if let Err(e) = app
        .audit
        .requested(
            &app.config,
            &id,
            &query.host_id,
            &query.login,
            &client_ip(&app.config, peer.ip(), &headers),
        )
        .await
    {
        tracing::error!(error=%e,"cannot durably start session");
        return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
    }
    let token = match bearer(&headers) {
        Ok(t) => t.to_string(),
        Err(_) => {
            finish(&app, &id, "denied", "missing_access_token", None, None).await;
            return error(StatusCode::UNAUTHORIZED, "Bearer access token required");
        }
    };
    let claims = match authenticate(&app, &token).await {
        Ok(c) => c,
        Err(_) => {
            finish(&app, &id, "denied", "invalid_access_token", None, None).await;
            return error(StatusCode::UNAUTHORIZED, "invalid access token");
        }
    };
    if let Err(e) = app.audit.identity(&id, &claims, None).await {
        tracing::error!(session_id=%id,error=%e,"identity audit failed");
        finish(&app, &id, "failed", "audit_unavailable", None, None).await;
        return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
    }
    let host = match app.config.select(&query.host_id, &query.login, &claims) {
        Ok(h) => h,
        Err(_) => {
            finish(
                &app,
                &id,
                "denied",
                "host_login_tenant_or_scope_denied",
                None,
                None,
            )
            .await;
            return error(StatusCode::FORBIDDEN, "host or login denied");
        }
    };
    if dimensions(query.cols, query.rows)
        .and_then(|_| terminal(&query.term))
        .is_err()
    {
        finish(&app, &id, "denied", "invalid_terminal", None, None).await;
        return error(
            StatusCode::BAD_REQUEST,
            "invalid terminal type or dimensions",
        );
    }
    if app.audit.identity(&id, &claims, Some(&host)).await.is_err() {
        finish(&app, &id, "failed", "audit_unavailable", None, None).await;
        return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
    }
    let slot = match app.slots.clone().try_acquire_owned() {
        Ok(s) => s,
        Err(_) => {
            finish(&app, &id, "failed", "capacity", None, None).await;
            return error(StatusCode::SERVICE_UNAVAILABLE, "session capacity reached");
        }
    };
    let failed_app = app.clone();
    let failed_id = id.clone();
    ws.max_message_size(65536)
        .max_frame_size(65536)
        .on_failed_upgrade(move |_| {
            tokio::spawn(async move {
                finish(
                    &failed_app,
                    &failed_id,
                    "failed",
                    "websocket_upgrade",
                    None,
                    None,
                )
                .await;
            });
        })
        .on_upgrade(move |socket| session(app, socket, id, query, host, token, slot))
        .into_response()
}
#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum ClientMessage {
    #[serde(rename = "resize")]
    Resize { version: u8, cols: u16, rows: u16 },
}
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage<'a> {
    Ready { version: u8, session_id: &'a str },
    Error { version: u8, message: &'a str },
    Exit { version: u8, status: i32 },
}
async fn send(socket: &mut WebSocket, message: Message) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(15), socket.send(message)).await??;
    Ok(())
}
async fn control(socket: &mut WebSocket, message: ServerMessage<'_>) -> Result<()> {
    send(
        socket,
        Message::Text(serde_json::to_string(&message)?.into()),
    )
    .await
}
async fn session(
    app: Arc<App>,
    mut socket: WebSocket,
    id: String,
    query: TerminalQuery,
    host: Host,
    token: String,
    _slot: OwnedSemaphorePermit,
) {
    let mut started = None;
    let result = run_session(&app, &mut socket, &id, &query, &host, &token, &mut started).await;
    match result {
        Ok((status, reason)) => {
            let outcome = if reason == "client_disconnected" {
                "disconnected"
            } else if status == Some(255) {
                "failed"
            } else {
                "exited"
            };
            finish(&app, &id, outcome, reason, status, started).await;
            if let Some(status) = status {
                let _ = control(&mut socket, ServerMessage::Exit { version: 1, status }).await;
            }
        }
        Err(e) => {
            // Operational errors never include tokens, signer bodies or terminal bytes.
            tracing::warn!(session_id=%id,error=%e,"terminal session failed");
            finish(&app, &id, "failed", "session_error", None, started).await;
            let _ = control(
                &mut socket,
                ServerMessage::Error {
                    version: 1,
                    message: "SSH session failed; check bastion service logs and known_hosts",
                },
            )
            .await;
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), socket.close()).await;
}
async fn run_session(
    app: &App,
    socket: &mut WebSocket,
    id: &str,
    query: &TerminalQuery,
    host: &Host,
    token: &str,
    started: &mut Option<Instant>,
) -> Result<(Option<i32>, &'static str)> {
    let prepared = Prepared::new(&app.config, host, id, token, &app.secret, &app.http).await?;
    app.audit.certificate(id, &prepared.certificate_id).await?;
    let mut transport = prepared.spawn(
        &app.config,
        host,
        &query.login,
        query.cols,
        query.rows,
        &query.term,
    )?;
    let mut poll = tokio::time::interval(Duration::from_millis(100));
    let marker = prepared.marker();
    tokio::pin!(marker);
    let connect_timeout = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(connect_timeout);
    loop {
        tokio::select! {
            marker = &mut marker => {
                let stream = marker?;
                app.audit.connected(id).await?;
                *started = Some(Instant::now());
                crate::ssh::release(stream).await?;
                let raw_deadline = Instant::now() + Duration::from_secs(5);
                while !transport.entered_raw_mode()? {
                    ensure!(Instant::now() < raw_deadline,"OpenSSH did not enter local raw mode");
                    ensure!(transport.child.try_wait()?.is_none(),"OpenSSH exited before local terminal ready");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                control(socket,ServerMessage::Ready{version:1,session_id:id}).await?;
                break;
            }
            _ = &mut connect_timeout => anyhow::bail!("SSH authentication timed out"),
            _ = poll.tick() => if let Some(status) = transport.child.try_wait()? { anyhow::bail!("SSH authentication failed (exit {})",status.exit_code()); },
            message = socket.recv() => match message {
                None | Some(Ok(Message::Close(_))) => return Ok((None,"client_disconnected")),
                Some(Ok(Message::Ping(b))) => send(socket,Message::Pong(b)).await?,
                Some(Ok(Message::Pong(_))) => {},
                Some(Err(e)) => return Err(e.into()),
                _ => anyhow::bail!("terminal input before ready"),
            }
        }
    }
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_seen = Instant::now();
    let mut exit_status = None;
    loop {
        tokio::select! {
            output = transport.output.recv() => match output {
                Some(bytes) => send(socket,Message::Binary(bytes.into())).await?,
                None => {
                    let status = match exit_status { Some(s) => s, None => transport.child.wait()?.exit_code() as i32 };
                    return Ok((Some(status),"shell_exit"));
                }
            },
            _ = poll.tick(), if exit_status.is_none() => {
                if let Some(status) = transport.child.try_wait()? { exit_status = Some(status.exit_code() as i32); }
            }
            _ = heartbeat.tick() => {
                ensure!(last_seen.elapsed() < Duration::from_secs(65),"WebSocket keepalive lost");
                send(socket,Message::Ping(Vec::new().into())).await?;
            }
            message = socket.recv() => {
                last_seen = Instant::now();
                match message {
                    None | Some(Ok(Message::Close(_))) => return Ok((None,"client_disconnected")),
                    Some(Err(_)) => return Ok((None,"client_disconnected")),
                    Some(Ok(Message::Binary(bytes))) => {
                        tokio::time::timeout(Duration::from_secs(15),transport.input.send(bytes.to_vec())).await??;
                    }
                    Some(Ok(Message::Text(text))) => resize(&transport,&text)?,
                    Some(Ok(Message::Ping(bytes))) => send(socket,Message::Pong(bytes)).await?,
                    Some(Ok(Message::Pong(_))) => {},
                }
            }
        }
    }
}
fn resize(transport: &Transport, text: &str) -> Result<()> {
    match serde_json::from_str::<ClientMessage>(text)? {
        ClientMessage::Resize {
            version,
            cols,
            rows,
        } => {
            ensure!(version == 1, "unsupported terminal protocol version");
            dimensions(cols, rows)?;
            transport.master.resize(crate::ssh::size(cols, rows))?;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn missing_token_hidden_host_is_durably_audited() {
        let issuer_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", issuer_listener.local_addr().unwrap());
        let discovery = serde_json::json!({"jwks_uri":format!("{issuer}/jwks")});
        let issuer_task = tokio::spawn(async move {
            axum::serve(
                issuer_listener,
                Router::new().route(
                    "/.well-known/openid-configuration",
                    get(move || {
                        let discovery = discovery.clone();
                        async move { Json(discovery) }
                    }),
                ),
            )
            .await
            .unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let _lock = crate::audit::InstanceLock::acquire(&db).unwrap();
        let audit = Audit::open(&db, false).await.unwrap();
        let config: Config = toml::from_str(include_str!("../examples/bastion.toml")).unwrap();
        let jwt = JwtValidator::new(issuer, "ssh-login".into(), vec!["RS256".into()])
            .await
            .unwrap();
        let app = Arc::new(App {
            config,
            audit: audit.clone(),
            jwt,
            http: reqwest::Client::new(),
            secret: "x".repeat(32),
            slots: Arc::new(Semaphore::new(1)),
            audit_failed: AtomicBool::new(false),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let daemon = tokio::spawn(async move {
            axum::serve(
                listener,
                router(app).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let response = reqwest::Client::new()
            .get(format!(
                "http://{address}/api/v1/terminal?host_id=hidden&login=root"
            ))
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let rows = audit
            .records(&crate::audit::Filters::default())
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].host_id, "hidden");
        assert_eq!(rows[0].result, "denied");
        assert!(rows[0].subject.is_none());
        assert!(rows[0].connected_at.is_none());
        assert!(rows[0].ended_at.is_some());
        daemon.abort();
        issuer_task.abort();
    }
    #[test]
    fn protocol_and_proxy_contract() {
        let c: Config = toml::from_str(include_str!("../examples/bastion.toml")).unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "192.0.2.4".parse().unwrap());
        assert_eq!(client_ip(&c, "10.0.0.1".parse().unwrap(), &h), "10.0.0.1");
        assert_eq!(client_ip(&c, "127.0.0.1".parse().unwrap(), &h), "192.0.2.4");
        assert!(
            serde_json::from_str::<ClientMessage>(
                r#"{"type":"resize","version":1,"cols":80,"rows":24}"#
            )
            .is_ok()
        );
        assert!(
            serde_json::from_str::<ClientMessage>(r#"{"type":"resize","cols":80,"rows":24}"#)
                .is_err()
        );
        let ready = serde_json::to_value(ServerMessage::Ready {
            version: 1,
            session_id: "s",
        })
        .unwrap();
        assert_eq!(
            ready,
            serde_json::json!({"type":"ready","version":1,"session_id":"s"})
        );
    }
}
