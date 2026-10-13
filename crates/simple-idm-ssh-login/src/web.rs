//! Local browser frontend. The IDM token never leaves this Rust process.
use crate::{
    bastion,
    file_ops::{self, InspectKind, Inspection, Location, SftpSession, Task},
};
use axum::{
    Router,
    extract::{
        Json, Query, Request, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex as AsyncMutex;
use tokio_tungstenite::tungstenite::{Message as Upstream, client::IntoClientRequest};
use url::Url;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
type ApiResult<T> = std::result::Result<T, (StatusCode, Json<Value>)>;
fn failure(status: StatusCode, message: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({"message":bastion::label(&message.to_string())})),
    )
}
fn operation_error(e: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    failure(StatusCode::BAD_REQUEST, e)
}
struct Remote {
    id: String,
    host: String,
    login: String,
    readonly: bool,
    sftp: SftpSession,
    _bridge: Task,
}
#[derive(Clone, Serialize)]
struct JobState {
    running: bool,
    bytes: u64,
    total: u64,
    message: String,
    failed: bool,
    result: Option<Inspection>,
}
struct Job {
    state: Mutex<JobState>,
    cancel: AtomicBool,
}
struct App {
    base: Url,
    token: String,
    catalog: bastion::Catalog,
    origin: String,
    host: String,
    bootstrap: String,
    consumed: AtomicBool,
    cookie: String,
    session: String,
    remote: AsyncMutex<Option<Arc<Remote>>>,
    job: Mutex<Option<Arc<Job>>>,
    shutdown: tokio::sync::Notify,
}
impl App {
    fn new(
        base: Url,
        token: String,
        catalog: bastion::Catalog,
        address: std::net::SocketAddr,
    ) -> Self {
        Self {
            base,
            token,
            catalog,
            origin: format!("http://{address}"),
            host: address.to_string(),
            bootstrap: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
            consumed: AtomicBool::new(false),
            cookie: format!("idm_bastion_{}", address.port()),
            session: uuid::Uuid::new_v4().to_string(),
            remote: AsyncMutex::new(None),
            job: Mutex::new(None),
            shutdown: tokio::sync::Notify::new(),
        }
    }
    fn busy(&self) -> bool {
        self.job
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|job| job.state.lock().unwrap().running)
    }
    fn allowed(&self, host: &str, login: &str) -> bool {
        self.catalog
            .hosts
            .iter()
            .any(|h| h.id == host && h.logins.iter().any(|l| l == login))
    }
}

async fn guard(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    if headers.get_all("host").iter().count() != 1
        || headers.get("host").and_then(|h| h.to_str().ok()) != Some(app.host.as_str())
    {
        return failure(StatusCode::FORBIDDEN, "Invalid local Host").into_response();
    }
    let origin = headers.get("origin").and_then(|h| h.to_str().ok());
    if headers.get_all("origin").iter().count() > 1
        || origin.is_some_and(|origin| origin != app.origin)
    {
        return failure(StatusCode::FORBIDDEN, "Invalid local Origin").into_response();
    }
    let path = request.uri().path();
    let protected = path.starts_with("/api/");
    if (request.method() != axum::http::Method::GET || path == "/api/terminal")
        && origin != Some(app.origin.as_str())
    {
        return failure(StatusCode::FORBIDDEN, "Local Origin required").into_response();
    }
    if protected {
        let expected = format!("{}={}", app.cookie, app.session);
        let valid = headers
            .get("cookie")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|cookies| cookies.split(';').any(|c| c.trim() == expected));
        if !valid {
            return failure(StatusCode::UNAUTHORIZED, "Local session required").into_response();
        }
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("Cache-Control", HeaderValue::from_static("no-store"));
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    let csp = format!(
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws://{}; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        app.host
    );
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_str(&csp).unwrap(),
    );
    response
}
fn asset(content: &'static [u8], kind: &'static str) -> Response {
    ([(axum::http::header::CONTENT_TYPE, kind)], content).into_response()
}
fn router(app: Arc<App>) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async {
                asset(
                    include_bytes!("../web/index.html"),
                    "text/html; charset=utf-8",
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                asset(
                    include_bytes!("../web/app.js"),
                    "text/javascript; charset=utf-8",
                )
            }),
        )
        .route(
            "/app.css",
            get(|| async { asset(include_bytes!("../web/app.css"), "text/css; charset=utf-8") }),
        )
        .route(
            "/xterm.js",
            get(|| async {
                asset(
                    include_bytes!("../web/vendor/xterm.js"),
                    "text/javascript; charset=utf-8",
                )
            }),
        )
        .route(
            "/xterm.css",
            get(|| async {
                asset(
                    include_bytes!("../web/vendor/xterm.css"),
                    "text/css; charset=utf-8",
                )
            }),
        )
        .route(
            "/addon-fit.js",
            get(|| async {
                asset(
                    include_bytes!("../web/vendor/addon-fit.js"),
                    "text/javascript; charset=utf-8",
                )
            }),
        )
        .route(
            "/terminal-font.ttf",
            get(|| async {
                asset(
                    include_bytes!("../web/vendor/JetBrainsMonoNLNerdFontMono-Regular.ttf"),
                    "font/ttf",
                )
            }),
        )
        .route("/session", post(bootstrap))
        .route("/api/catalog", get(catalog))
        .route("/api/connect", post(connect))
        .route("/api/list", get(list))
        .route("/api/operation", post(operation))
        .route("/api/job", get(job))
        .route("/api/cancel", post(cancel))
        .route("/api/terminal", get(terminal))
        .route("/api/quit", post(quit))
        .layer(axum::extract::DefaultBodyLimit::max(65536))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    token: String,
}
async fn bootstrap(
    State(app): State<Arc<App>>,
    Json(request): Json<Bootstrap>,
) -> ApiResult<Response> {
    if request.token != app.bootstrap || app.consumed.swap(true, Ordering::SeqCst) {
        return Err(failure(
            StatusCode::UNAUTHORIZED,
            "Invalid or used launch token",
        ));
    }
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict",
        app.cookie, app.session
    );
    Ok((
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(json!({"ok":true})),
    )
        .into_response())
}
async fn catalog(State(app): State<Arc<App>>) -> Json<Value> {
    Json(
        json!({"catalog":app.catalog,"context":app.catalog.context(&app.base),"cwd":std::env::current_dir().ok().and_then(|p|p.to_str().map(str::to_owned)),"version":env!("CARGO_PKG_VERSION")}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Connect {
    host: String,
    login: String,
    #[serde(default)]
    readonly: bool,
    path: Option<String>,
}
async fn connect(
    State(app): State<Arc<App>>,
    Json(request): Json<Connect>,
) -> ApiResult<Json<Value>> {
    if !app.allowed(&request.host, &request.login) {
        return Err(failure(StatusCode::FORBIDDEN, "Host/account denied"));
    }
    if app.busy() {
        return Err(failure(
            StatusCode::CONFLICT,
            "Wait for or cancel the active operation",
        ));
    }
    let mut slot = app
        .remote
        .try_lock()
        .map_err(|_| failure(StatusCode::CONFLICT, "Connection already in progress"))?;
    let (sftp, bridge) = file_ops::connect(
        &app.base,
        &app.token,
        &request.host,
        &request.login,
        request.readonly,
    )
    .await
    .map_err(operation_error)?;
    let home = sftp.canonicalize(".").await.map_err(operation_error)?;
    let path = if let Some(path) = request.path.filter(|p| p.starts_with('/')) {
        if sftp.read_dir(path.clone()).await.is_ok() {
            path
        } else {
            home
        }
    } else {
        home
    };
    // Prove the new subsystem is usable before replacing the old session.
    sftp.read_dir(path.clone()).await.map_err(operation_error)?;
    let remote = Arc::new(Remote {
        id: uuid::Uuid::new_v4().to_string(),
        host: request.host,
        login: request.login,
        readonly: request.readonly,
        sftp,
        _bridge: bridge,
    });
    let response = json!({"session":remote.id,"host":remote.host,"login":remote.login,"readonly":remote.readonly,"path":path});
    *slot = Some(remote);
    Ok(Json(response))
}
async fn remote(app: &App, expected: &str) -> ApiResult<Arc<Remote>> {
    let remote = app
        .remote
        .lock()
        .await
        .clone()
        .ok_or_else(|| failure(StatusCode::CONFLICT, "Open a file session first"))?;
    if remote.id != expected {
        return Err(failure(
            StatusCode::CONFLICT,
            "File session changed; refresh the panel",
        ));
    }
    Ok(remote)
}
#[derive(Deserialize)]
struct List {
    session: String,
    side: String,
    path: String,
}
async fn list(State(app): State<Arc<App>>, Query(request): Query<List>) -> ApiResult<Json<Value>> {
    let remote = remote(&app, &request.session).await?;
    let path = location(&request.side, &request.path)?;
    let entries = file_ops::list(&remote.sftp, &path)
        .await
        .map_err(operation_error)?;
    let entries=entries.into_iter().filter(|e| e.name != "..").map(|e|json!({"name":e.name.to_string_lossy(),"directory":e.kind.is_dir(),"file":e.kind.is_file(),"symlink":e.kind.is_symlink(),"size":e.size,"disabled":e.name.to_str().is_none()})).collect::<Vec<_>>();
    Ok(Json(json!({"path":path,"entries":entries})))
}
fn location(side: &str, path: &str) -> ApiResult<Location> {
    let loc = match side {
        "local" => Location::Local(path.into()),
        "remote" => Location::Remote(path.into()),
        _ => return Err(operation_error("Invalid panel")),
    };
    validate_location(&loc)?;
    Ok(loc)
}
fn validate_location(loc: &Location) -> ApiResult<()> {
    let valid = match loc {
        Location::Local(p) => p.is_absolute(),
        Location::Remote(p) => p.starts_with('/') && !p.contains('\0'),
    };
    if !valid {
        return Err(operation_error("Absolute path required"));
    }
    Ok(())
}
#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum OperationKind {
    Copy,
    Rename,
    Mkdir,
    Delete,
    Hash,
    View,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    session: String,
    action: OperationKind,
    source: Location,
    destination: Option<Location>,
    #[serde(default)]
    overwrite: bool,
    #[serde(default)]
    directory: bool,
}
async fn operation(
    State(app): State<Arc<App>>,
    Json(request): Json<Operation>,
) -> ApiResult<Json<Value>> {
    validate_location(&request.source)?;
    if let Some(dest) = &request.destination {
        validate_location(dest)?;
    }
    let remote = remote(&app, &request.session).await?;
    let writes_remote = match request.action {
        OperationKind::Copy => request
            .destination
            .as_ref()
            .is_some_and(|p| matches!(p, Location::Remote(_))),
        OperationKind::Rename | OperationKind::Mkdir | OperationKind::Delete => {
            matches!(request.source, Location::Remote(_))
        }
        _ => false,
    };
    if remote.readonly && writes_remote {
        return Err(failure(StatusCode::FORBIDDEN, "Root panel is read-only"));
    }
    if matches!(request.action, OperationKind::Copy | OperationKind::Rename) {
        let dest = request
            .destination
            .as_ref()
            .ok_or_else(|| operation_error("Destination required"))?;
        if file_ops::exists(&remote.sftp, dest)
            .await
            .map_err(operation_error)?
            && (!request.overwrite || matches!(request.action, OperationKind::Rename))
        {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({"message":"Destination exists","collision":true})),
            ));
        }
    }
    let current = Arc::new(Job {
        state: Mutex::new(JobState {
            running: true,
            bytes: 0,
            total: 0,
            message: "Working…".into(),
            failed: false,
            result: None,
        }),
        cancel: AtomicBool::new(false),
    });
    {
        let mut slot = app.job.lock().unwrap();
        if slot
            .as_ref()
            .is_some_and(|j| j.state.lock().unwrap().running)
        {
            return Err(failure(StatusCode::CONFLICT, "Operation already running"));
        }
        *slot = Some(current.clone());
    }
    tokio::spawn(async move {
        let progress = |bytes, total| {
            let mut state = current.state.lock().unwrap();
            state.bytes = bytes;
            state.total = total;
        };
        let result: std::result::Result<Option<Inspection>, String> = match request.action {
            OperationKind::Copy => file_ops::copy(
                &remote.sftp,
                &request.source,
                request.destination.as_ref().unwrap(),
                request.overwrite,
                &current.cancel,
                &progress,
            )
            .await
            .map(|_| None),
            OperationKind::Rename => file_ops::rename(
                &remote.sftp,
                &request.source,
                request.destination.as_ref().unwrap(),
            )
            .await
            .map(|_| None),
            OperationKind::Mkdir => match &request.source {
                Location::Local(p) => tokio::fs::create_dir(p).await.map_err(|e| e.to_string()),
                Location::Remote(p) => remote
                    .sftp
                    .create_dir(p.clone())
                    .await
                    .map_err(|e| e.to_string()),
            }
            .map(|_| None),
            OperationKind::Delete => {
                file_ops::remove(&remote.sftp, &request.source, request.directory)
                    .await
                    .map(|_| None)
            }
            OperationKind::Hash | OperationKind::View => file_ops::inspect(
                &remote.sftp,
                &request.source,
                if matches!(request.action, OperationKind::Hash) {
                    InspectKind::Hash
                } else {
                    InspectKind::Preview
                },
                &current.cancel,
                &progress,
            )
            .await
            .map(Some),
        };
        let mut state = current.state.lock().unwrap();
        state.running = false;
        match result {
            Ok(value) => {
                state.message = "Completed".into();
                state.result = value;
            }
            Err(e) => {
                state.failed = true;
                state.message = bastion::label(&e);
            }
        }
    });
    Ok(Json(json!({"started":true})))
}
async fn job(State(app): State<Arc<App>>) -> Json<Value> {
    let slot = app.job.lock().unwrap();
    Json(
        slot.as_ref()
            .map(|j| serde_json::to_value(&*j.state.lock().unwrap()).unwrap())
            .unwrap_or(json!({"running":false,"message":"Ready"})),
    )
}
async fn cancel(State(app): State<Arc<App>>) -> Json<Value> {
    if let Some(job) = app.job.lock().unwrap().as_ref() {
        job.cancel.store(true, Ordering::Relaxed);
    }
    Json(json!({"ok":true}))
}
#[derive(Deserialize)]
struct TerminalQuery {
    host: String,
    login: String,
    cols: u16,
    rows: u16,
}
async fn terminal(
    State(app): State<Arc<App>>,
    Query(query): Query<TerminalQuery>,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    if !app.allowed(&query.host, &query.login)
        || !(1..=1000).contains(&query.cols)
        || !(1..=1000).contains(&query.rows)
    {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "Invalid terminal target or dimensions",
        ));
    }
    Ok(ws
        .max_message_size(65536)
        .max_frame_size(65536)
        .on_upgrade(move |socket| terminal_relay(app, socket, query))
        .into_response())
}
async fn terminal_relay(app: Arc<App>, mut socket: WebSocket, query: TerminalQuery) {
    let result = async {
        let url = bastion::terminal_url(&app.base, &query.host, &query.login, query.cols, query.rows, "xterm-256color")
            .map_err(|e| e.to_string())?;
        let mut request = url.as_str().into_client_request().map_err(|e| e.to_string())?;
        request.headers_mut().insert("Authorization", format!("Bearer {}", app.token).parse().map_err(|e:axum::http::header::InvalidHeaderValue| e.to_string())?);
        let (mut upstream, _) = tokio::time::timeout(Duration::from_secs(30), tokio_tungstenite::connect_async(request))
            .await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
        loop {
            tokio::select! {
                message = socket.recv() => {
                    let frame = match message {
                        Some(Ok(Message::Binary(bytes))) => Upstream::Binary(bytes),
                        Some(Ok(Message::Text(text))) => Upstream::Text(text.to_string().into()),
                        Some(Ok(Message::Ping(bytes))) => { let _ = socket.send(Message::Pong(bytes)).await; continue; }
                        Some(Ok(Message::Pong(_))) => continue,
                        _ => break,
                    };
                    tokio::time::timeout(Duration::from_secs(15), upstream.send(frame))
                        .await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
                }
                message = upstream.next() => {
                    let frame = match message {
                        Some(Ok(Upstream::Binary(bytes))) => Message::Binary(bytes),
                        Some(Ok(Upstream::Text(text))) => Message::Text(text.to_string().into()),
                        Some(Ok(Upstream::Ping(bytes))) => { let _ = upstream.send(Upstream::Pong(bytes)).await; continue; }
                        Some(Ok(Upstream::Pong(_))) => continue,
                        _ => break,
                    };
                    tokio::time::timeout(Duration::from_secs(15), socket.send(frame))
                        .await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
                }
            }
        }
        Ok::<(), String>(())
    }.await;
    if result.is_err() {
        let message = json!({"type":"error","message":"Terminal connection failed; login may have expired. Restart the local client."});
        let _ = socket.send(Message::Text(message.to_string().into())).await;
    }
    let _ = socket.close().await;
}

async fn quit(State(app): State<Arc<App>>) -> Json<Value> {
    if let Some(job) = app.job.lock().unwrap().as_ref() {
        job.cancel.store(true, Ordering::Relaxed);
    }
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        app.shutdown.notify_one();
    });
    Json(json!({"ok":true}))
}
async fn serve(app: Arc<App>, listener: tokio::net::TcpListener) -> Result<()> {
    tokio::select! {
        result=axum::serve(listener,router(app.clone()))=>result?,
        _=tokio::signal::ctrl_c()=>{},
        _=app.shutdown.notified()=>{},
    }
    Ok(())
}
pub async fn run(hostname: &str, device: bool, browser: Option<&str>) -> Result<()> {
    let profile = bastion::load_profile(hostname)?;
    let base = bastion::secure_url(&profile.url)?;
    let token = bastion::authenticate_with_browser(&profile, device, browser).await?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let catalog = bastion::load_catalog(&http, &base, &token).await?;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let app = Arc::new(App::new(base, token, catalog, listener.local_addr()?));
    let launch = format!("{}/#token={}", app.origin, app.bootstrap);
    println!("Local Bastion web UI: {} (Ctrl-C to stop)", app.origin);
    let opened = match browser {
        Some(browser) => open::with(&launch, browser),
        None => open::that(&launch),
    };
    if let Err(error) = opened {
        eprintln!("Could not open web browser: {error}");
        println!("Open this one-time local URL: {launch}");
    }
    serve(app, listener).await
}

#[cfg(test)]
mod tests {
    use super::*;
    fn catalog_fixture() -> bastion::Catalog {
        serde_json::from_value(json!({"identity":{"username":"fixture","subject":"test-subject","tenant":"test-tenant"},"bastion":{"id":"test-bastion"},"hosts":[{"id":"fixture","name":"Test host","address":"target.internal","resolved_ips":["192.0.2.1"],"environment":"test","description":"","logins":["fixture"]}]})).unwrap()
    }
    async fn test_server(base: Url) -> (Arc<App>, Task) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let app = Arc::new(App::new(
            base,
            "fixture-token".into(),
            catalog_fixture(),
            listener.local_addr().unwrap(),
        ));
        let state = app.clone();
        let server = Task(tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        }));
        (app, server)
    }
    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }
    fn post(
        client: &reqwest::Client,
        app: &App,
        path: &str,
        body: Value,
    ) -> reqwest::RequestBuilder {
        client
            .post(format!("{}{}", app.origin, path))
            .header("Origin", &app.origin)
            .header("Cookie", format!("{}={}", app.cookie, app.session))
            .json(&body)
    }
    #[tokio::test]
    async fn local_session_origin_host_and_token_boundary() {
        let (app, _server) = test_server(Url::parse("http://127.0.0.1:1").unwrap()).await;
        let http = client();
        assert_eq!(
            http.get(format!("{}/api/catalog", app.origin))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            http.get(&app.origin)
                .header("Host", "attacker.example")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            http.post(format!("{}/session", app.origin))
                .json(&json!({"token":app.bootstrap}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(&http, &app, "/session", json!({"token":app.bootstrap}))
                .header("Origin", "https://attacker.example")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(&http, &app, "/session", json!({"token":"wrong"}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = post(&http, &app, "/session", json!({"token":app.bootstrap}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()["set-cookie"].to_str().unwrap();
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
        assert_eq!(
            post(&http, &app, "/session", json!({"token":app.bootstrap}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = http
            .get(format!("{}/api/catalog", app.origin))
            .header("Cookie", format!("{}={}", app.cookie, app.session))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let content = response.text().await.unwrap();
        assert!(!content.contains(&app.token));
        assert!(!content.contains(&app.bootstrap));
        assert_eq!(
            post(
                &http,
                &app,
                "/api/connect",
                json!({"host":"denied","login":"fixture"})
            )
            .send()
            .await
            .unwrap()
            .status(),
            StatusCode::FORBIDDEN
        );
        let mut request = format!(
            "ws://{}/api/terminal?host=fixture&login=fixture&cols=80&rows=24",
            app.host
        )
        .into_client_request()
        .unwrap();
        request.headers_mut().insert(
            "Cookie",
            format!("{}={}", app.cookie, app.session).parse().unwrap(),
        );
        assert!(tokio_tungstenite::connect_async(request).await.is_err()); // WS needs Origin even with a valid session.
    }
    #[tokio::test]
    #[ignore = "requires installed OpenSSH sftp-server"]
    async fn web_operations_and_readonly_enforcement() {
        tokio::time::timeout(Duration::from_secs(30),async {
            let root=tempfile::tempdir().unwrap();tokio::fs::write(root.path().join("proof.txt"),b"web proof").await.unwrap();
            let (base,_upstream)=crate::files::tests::fixture(root.path()).await;
            let (app,_server)=test_server(base).await;let http=client();
            let response=post(&http,&app,"/api/connect",json!({"host":"fixture","login":"fixture","readonly":true})).send().await.unwrap();
            assert_eq!(response.status(),StatusCode::OK);let remote:Value=response.json().await.unwrap();let sid=remote["session"].as_str().unwrap();
            for (action,source,destination) in [
                ("mkdir",json!({"side":"remote","path":root.path().join("blocked")}),Value::Null),
                ("delete",json!({"side":"remote","path":root.path().join("proof.txt")}),Value::Null),
                ("rename",json!({"side":"remote","path":root.path().join("proof.txt")}),json!({"side":"remote","path":root.path().join("blocked")})),
                ("copy",json!({"side":"local","path":root.path().join("proof.txt")}),json!({"side":"remote","path":root.path().join("blocked")})),
            ] {
                assert_eq!(post(&http,&app,"/api/operation",json!({"session":sid,"action":action,"source":source,"destination":destination})).send().await.unwrap().status(),StatusCode::FORBIDDEN);
            }
            for action in ["view","hash","copy"] {
                let dest=root.path().join("download.txt");
                let response=post(&http,&app,"/api/operation",json!({"session":sid,"action":action,"source":{"side":"remote","path":root.path().join("proof.txt")},"destination":{"side":"local","path":dest}})).send().await.unwrap();assert_eq!(response.status(),StatusCode::OK);
                loop {let job:Value=http.get(format!("{}/api/job",app.origin)).header("Cookie",format!("{}={}",app.cookie,app.session)).send().await.unwrap().json().await.unwrap();if job["running"]==false{assert_eq!(job["failed"],false);if action=="view"{assert!(job["result"]["lines"].to_string().contains("web proof"));}break;}tokio::time::sleep(Duration::from_millis(10)).await;}
                if action=="copy"{assert_eq!(tokio::fs::read(dest).await.unwrap(),b"web proof");}
            }
            let mut request=format!("ws://{}/api/terminal?host=fixture&login=fixture&cols=80&rows=24",app.host).into_client_request().unwrap();request.headers_mut().insert("Origin",app.origin.parse().unwrap());request.headers_mut().insert("Cookie",format!("{}={}",app.cookie,app.session).parse().unwrap());
            let (mut ws,_)=tokio_tungstenite::connect_async(request).await.unwrap();assert!(matches!(ws.next().await.unwrap().unwrap(),Upstream::Text(_)));assert!(matches!(ws.next().await.unwrap().unwrap(),Upstream::Binary(_)));
            ws.send(Upstream::Binary(b"hello\n".to_vec().into())).await.unwrap();assert_eq!(ws.next().await.unwrap().unwrap(),Upstream::Binary(b"hello\n".to_vec().into()));
            ws.send(Upstream::Text(json!({"type":"resize","version":1,"cols":100,"rows":30}).to_string().into())).await.unwrap();ws.close(None).await.unwrap();
        }).await.unwrap();
    }
    #[tokio::test]
    #[ignore = "interactive browser fixture; WEB_FIXTURE_ROOT and WEB_FIXTURE_INFO required"]
    async fn web_browser_fixture() {
        let root = std::path::PathBuf::from(std::env::var("WEB_FIXTURE_ROOT").unwrap());
        let (base, _upstream) = crate::files::tests::fixture(&root).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let app = Arc::new(App::new(
            base,
            "fixture-token".into(),
            catalog_fixture(),
            listener.local_addr().unwrap(),
        ));
        let info =
            json!({"url":format!("{}/#token={}",app.origin,app.bootstrap),"origin":app.origin});
        tokio::fs::write(std::env::var("WEB_FIXTURE_INFO").unwrap(), info.to_string())
            .await
            .unwrap();
        serve(app, listener).await.unwrap();
    }
}
