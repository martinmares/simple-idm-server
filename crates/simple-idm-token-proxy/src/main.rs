use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    body::Bytes,
    extract::{OriginalUri, State},
    http::{HeaderMap, HeaderName, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
};
use clap::Parser;
use reqwest::Url;
use tokio::{fs, net::TcpListener};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt};

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (git ",
    env!("SIMPLE_IDM_GIT_SHA"),
    ")"
);

#[derive(Parser, Debug)]
#[command(
    name = "simple-idm-token-proxy",
    version = VERSION,
    about = "Small localhost reverse proxy that injects a fresh workload identity bearer token"
)]
struct Cli {
    /// Local listen address for the workload client.
    #[arg(
        long,
        env = "SIMPLE_IDM_TOKEN_PROXY_LISTEN",
        default_value = "127.0.0.1:9999"
    )]
    listen: SocketAddr,

    /// Upstream HTTP API base URL.
    #[arg(long, env = "SIMPLE_IDM_TOKEN_PROXY_UPSTREAM")]
    upstream: Url,

    /// Projected workload identity token file. Required.
    #[arg(long, env = "SIMPLE_IDM_TOKEN_PROXY_TOKEN_FILE")]
    token_file: PathBuf,

    /// Upstream request timeout in seconds.
    #[arg(
        long,
        env = "SIMPLE_IDM_TOKEN_PROXY_TIMEOUT_SECONDS",
        default_value_t = 30
    )]
    timeout_seconds: u64,

    /// Allow invalid upstream TLS certificates. Use only in controlled sandboxes.
    #[arg(
        long,
        env = "SIMPLE_IDM_TOKEN_PROXY_INSECURE_UPSTREAM_TLS",
        default_value_t = false
    )]
    insecure_upstream_tls: bool,
}

#[derive(Clone)]
struct AppState {
    client: reqwest::Client,
    upstream: Url,
    token_file: Arc<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    if !cli.token_file.is_file() {
        anyhow::bail!(
            "token file does not exist or is not a file: {}",
            cli.token_file.display()
        );
    }

    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(cli.timeout_seconds))
        .redirect(reqwest::redirect::Policy::none());
    if cli.insecure_upstream_tls {
        warn!("insecure upstream TLS verification is enabled");
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    let state = AppState {
        client: client_builder.build()?,
        upstream: cli.upstream.clone(),
        token_file: Arc::new(cli.token_file.clone()),
    };

    info!("starting simple-idm-token-proxy");
    info!("listen address: {}", cli.listen);
    info!("upstream: {}", redact_url(&cli.upstream));
    info!("token file: {}", cli.token_file.display());

    let app = Router::new()
        .route("/healthz", any(healthz))
        .fallback(any(proxy))
        .with_state(state);

    let listener = TcpListener::bind(cli.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn proxy(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match proxy_inner(state, method, uri, headers, body).await {
        Ok(response) => response,
        Err(err) => {
            error!("proxy request failed: {err:#}");
            (StatusCode::BAD_GATEWAY, "upstream request failed").into_response()
        }
    }
}

async fn proxy_inner(
    state: AppState,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> anyhow::Result<Response> {
    let token = read_token(&state.token_file).await?;
    let upstream_url = build_upstream_url(&state.upstream, &uri)?;

    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())?;
    let mut request = state
        .client
        .request(reqwest_method, upstream_url.clone())
        .bearer_auth(token);

    for (name, value) in &headers {
        if should_forward_request_header(name) {
            request = request.header(name, value);
        }
    }

    if !body.is_empty() {
        request = request.body(body);
    }

    let upstream_response = request.send().await?;
    let status = upstream_response.status();
    info!(
        "proxy {} {} -> {}",
        method,
        upstream_url.path(),
        status.as_u16()
    );
    let upstream_headers = upstream_response.headers().clone();
    let bytes = upstream_response.bytes().await?;

    let mut response = Response::new(axum::body::Body::from(bytes));
    *response.status_mut() = StatusCode::from_u16(status.as_u16())?;
    for (name, value) in &upstream_headers {
        if should_forward_response_header(name) {
            response.headers_mut().append(name, value.clone());
        }
    }

    Ok(response)
}

async fn read_token(path: &Path) -> anyhow::Result<String> {
    let token = fs::read_to_string(path).await?;
    let token = token.trim();
    if token.is_empty() {
        anyhow::bail!("token file is empty: {}", path.display());
    }
    Ok(token.to_string())
}

fn build_upstream_url(base: &Url, uri: &Uri) -> anyhow::Result<Url> {
    let request_path = uri.path();
    let base_path = base.path().trim_end_matches('/');

    let path = if base_path.is_empty() || base_path == "/" {
        request_path.to_string()
    } else if request_path == base_path || request_path.starts_with(&format!("{base_path}/")) {
        request_path.to_string()
    } else if request_path == "/" {
        base_path.to_string()
    } else {
        format!("{base_path}{request_path}")
    };

    let mut url = base.clone();
    url.set_path(&path);
    url.set_query(uri.query());
    Ok(url)
}

fn should_forward_request_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "authorization"
            | "connection"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn should_forward_response_header(name: &HeaderName) -> bool {
    !matches!(
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

fn redact_url(url: &Url) -> String {
    let mut url = url.clone();
    if url.password().is_some() {
        let _ = url.set_password(Some("***"));
    }
    url.to_string()
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;

    #[test]
    fn appends_request_path_to_upstream_base_path() {
        let base = Url::parse("https://example.com/config").unwrap();
        let uri: Uri = "/api/v1/items?x=1".parse().unwrap();

        let out = build_upstream_url(&base, &uri).unwrap();
        assert_eq!(out.as_str(), "https://example.com/config/api/v1/items?x=1");
    }

    #[test]
    fn avoids_duplicate_upstream_base_path() {
        let base = Url::parse("https://example.com/config").unwrap();
        let uri: Uri = "/config/api/v1/items".parse().unwrap();

        let out = build_upstream_url(&base, &uri).unwrap();
        assert_eq!(out.as_str(), "https://example.com/config/api/v1/items");
    }

    #[test]
    fn root_upstream_keeps_request_path() {
        let base = Url::parse("https://example.com").unwrap();
        let uri: Uri = "/healthz".parse().unwrap();

        let out = build_upstream_url(&base, &uri).unwrap();
        assert_eq!(out.as_str(), "https://example.com/healthz");
    }

    #[test]
    fn strips_sensitive_request_headers() {
        assert!(!should_forward_request_header(&header::AUTHORIZATION));
        assert!(!should_forward_request_header(&header::HOST));
        assert!(should_forward_request_header(&header::ACCEPT));
    }

    #[test]
    fn redacts_password_in_logged_upstream_url() {
        let url = Url::parse("https://user:secret@example.com/config").unwrap();
        assert_eq!(redact_url(&url), "https://user:***@example.com/config");
    }
}
