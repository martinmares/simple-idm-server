use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use clap::Parser;
use reqwest::{Client, Url};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (git ",
    env!("SIMPLE_IDM_GIT_SHA"),
    ")"
);

#[derive(Parser, Debug)]
#[command(
    name = "simple-idm-oidc-metadata-proxy",
    version = VERSION,
    about = "Read-only OIDC discovery/JWKS metadata proxy"
)]
struct Cli {
    #[arg(
        long,
        env = "SIMPLE_IDM_OIDC_METADATA_PROXY_LISTEN",
        default_value = "0.0.0.0:8080"
    )]
    listen: SocketAddr,

    #[arg(long, env = "SIMPLE_IDM_OIDC_METADATA_PROXY_UPSTREAM_BASE_URL")]
    upstream_base_url: String,

    #[arg(long, env = "SIMPLE_IDM_OIDC_METADATA_PROXY_UPSTREAM_JWKS_URL")]
    upstream_jwks_url: Option<String>,

    #[arg(long, env = "SIMPLE_IDM_OIDC_METADATA_PROXY_PUBLIC_BASE_URL")]
    public_base_url: String,

    #[arg(long, env = "SIMPLE_IDM_OIDC_METADATA_PROXY_ISSUER_OVERRIDE")]
    issuer_override: Option<String>,

    #[arg(
        long,
        env = "SIMPLE_IDM_OIDC_METADATA_PROXY_CACHE_TTL_SECONDS",
        default_value_t = 300
    )]
    cache_ttl_seconds: u64,

    #[arg(
        long,
        env = "SIMPLE_IDM_OIDC_METADATA_PROXY_TIMEOUT_SECONDS",
        default_value_t = 10
    )]
    timeout_seconds: u64,

    #[arg(long, env = "SIMPLE_IDM_OIDC_METADATA_PROXY_UPSTREAM_CA_FILE")]
    upstream_ca_file: Option<PathBuf>,

    #[arg(
        long,
        env = "SIMPLE_IDM_OIDC_METADATA_PROXY_UPSTREAM_BEARER_TOKEN_FILE"
    )]
    upstream_bearer_token_file: Option<PathBuf>,

    #[arg(
        long,
        env = "SIMPLE_IDM_OIDC_METADATA_PROXY_INSECURE_UPSTREAM_TLS",
        default_value_t = false
    )]
    insecure_upstream_tls: bool,
}

#[derive(Clone)]
struct AppState {
    upstream_base_url: Url,
    upstream_jwks_url: Option<Url>,
    public_base_url: Url,
    issuer_override: Option<String>,
    upstream_bearer_token_file: Option<PathBuf>,
    cache_ttl: Duration,
    http: Client,
    discovery_cache: Arc<RwLock<Option<Cached<Value>>>>,
    jwks_cache: Arc<RwLock<Option<Cached<Value>>>>,
}

#[derive(Clone)]
struct Cached<T> {
    value: T,
    expires_at: Instant,
}

impl<T> Cached<T> {
    fn is_fresh(&self) -> bool {
        Instant::now() < self.expires_at
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "simple_idm_oidc_metadata_proxy=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let upstream_base_url =
        normalize_base_url(&cli.upstream_base_url).context("invalid upstream base URL")?;
    let upstream_jwks_url = cli
        .upstream_jwks_url
        .as_deref()
        .map(Url::parse)
        .transpose()
        .context("invalid upstream JWKS URL")?;
    let public_base_url =
        normalize_base_url(&cli.public_base_url).context("invalid public base URL")?;

    let mut client_builder = Client::builder()
        .timeout(Duration::from_secs(cli.timeout_seconds))
        .redirect(reqwest::redirect::Policy::none());

    if cli.insecure_upstream_tls {
        tracing::warn!("upstream TLS certificate verification is disabled");
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    if let Some(ca_file) = &cli.upstream_ca_file {
        let pem = std::fs::read(ca_file)
            .with_context(|| format!("failed to read CA file {}", ca_file.display()))?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .with_context(|| format!("failed to parse CA bundle {}", ca_file.display()))?;
        tracing::info!(
            "loaded {} upstream CA certificate(s) from {}",
            certs.len(),
            ca_file.display()
        );
        for cert in certs {
            client_builder = client_builder.add_root_certificate(cert);
        }
    }

    let state = AppState {
        upstream_base_url,
        upstream_jwks_url,
        public_base_url,
        issuer_override: cli.issuer_override,
        upstream_bearer_token_file: cli.upstream_bearer_token_file,
        cache_ttl: Duration::from_secs(cli.cache_ttl_seconds),
        http: client_builder.build()?,
        discovery_cache: Arc::new(RwLock::new(None)),
        jwks_cache: Arc::new(RwLock::new(None)),
    };

    tracing::info!("starting simple-idm-oidc-metadata-proxy");
    tracing::info!("listen address: {}", cli.listen);
    tracing::info!("upstream base URL: {}", state.upstream_base_url);
    if let Some(upstream_jwks_url) = &state.upstream_jwks_url {
        tracing::info!("upstream JWKS URL: {}", upstream_jwks_url);
    }
    tracing::info!("public base URL: {}", state.public_base_url);
    tracing::info!("cache TTL: {} seconds", cli.cache_ttl_seconds);

    let app = Router::new()
        .route("/health", get(health))
        .route("/healthz", get(health))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/openid/v1/jwks", get(jwks))
        .fallback(not_found)
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, axum::Json(json!({ "status": "ok" })))
}

async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "not found")
}

async fn openid_configuration(State(state): State<AppState>) -> Response {
    match cached_json(
        &state,
        &state.discovery_cache,
        UpstreamEndpoint::Discovery,
        rewrite_discovery,
    )
    .await
    {
        Ok(value) => (StatusCode::OK, axum::Json(value)).into_response(),
        Err(err) => {
            tracing::error!("failed to fetch OIDC discovery document: {err:?}");
            (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({ "error": "upstream discovery unavailable" })),
            )
                .into_response()
        }
    }
}

async fn jwks(State(state): State<AppState>) -> Response {
    match cached_json(
        &state,
        &state.jwks_cache,
        UpstreamEndpoint::Jwks,
        |_, value| value,
    )
    .await
    {
        Ok(value) => (StatusCode::OK, axum::Json(value)).into_response(),
        Err(err) => {
            tracing::error!("failed to fetch OIDC JWKS document: {err:?}");
            (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({ "error": "upstream jwks unavailable" })),
            )
                .into_response()
        }
    }
}

async fn cached_json<F>(
    state: &AppState,
    cache: &Arc<RwLock<Option<Cached<Value>>>>,
    endpoint: UpstreamEndpoint,
    rewrite: F,
) -> Result<Value>
where
    F: Fn(&AppState, Value) -> Value,
{
    if let Some(cached) = cache.read().await.as_ref()
        && cached.is_fresh()
    {
        return Ok(cached.value.clone());
    }

    let value = fetch_json(state, endpoint).await?;
    let value = rewrite(state, value);
    let cached = Cached {
        value: value.clone(),
        expires_at: Instant::now() + state.cache_ttl,
    };

    *cache.write().await = Some(cached);
    Ok(value)
}

#[derive(Clone, Copy)]
enum UpstreamEndpoint {
    Discovery,
    Jwks,
}

async fn fetch_json(state: &AppState, endpoint: UpstreamEndpoint) -> Result<Value> {
    let url = match endpoint {
        UpstreamEndpoint::Discovery => {
            join_url(&state.upstream_base_url, ".well-known/openid-configuration")?
        }
        UpstreamEndpoint::Jwks => match &state.upstream_jwks_url {
            Some(url) => url.clone(),
            None => join_url(&state.upstream_base_url, "openid/v1/jwks")?,
        },
    };
    let mut request = state.http.get(url.clone());
    if let Some(token_file) = &state.upstream_bearer_token_file {
        let token = std::fs::read_to_string(token_file).with_context(|| {
            format!("failed to read bearer token file {}", token_file.display())
        })?;
        let token = token.trim();
        if !token.is_empty() {
            request = request.bearer_auth(token);
        }
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("failed to call upstream {url}"))?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "upstream {url} returned HTTP {}",
            response.status()
        ));
    }

    response
        .json::<Value>()
        .await
        .with_context(|| format!("failed to decode upstream JSON from {url}"))
}

fn rewrite_discovery(state: &AppState, mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        let jwks_uri = join_url(&state.public_base_url, "openid/v1/jwks")
            .map(|url| url.to_string())
            .unwrap_or_else(|_| format!("{}openid/v1/jwks", state.public_base_url));
        object.insert("jwks_uri".to_string(), Value::String(jwks_uri));

        if let Some(issuer) = &state.issuer_override {
            object.insert("issuer".to_string(), Value::String(issuer.clone()));
        }
    }
    value
}

fn normalize_base_url(input: &str) -> Result<Url> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("URL must not be empty");
    }
    let mut url = Url::parse(trimmed)?;
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

fn join_url(base: &Url, relative_path: &str) -> Result<Url> {
    let relative_path = relative_path.trim_start_matches('/');
    base.join(relative_path)
        .with_context(|| format!("failed to join URL path {relative_path:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_url_preserves_base_path() {
        let base = normalize_base_url("https://example.com/proxy").unwrap();
        let joined = join_url(&base, "/openid/v1/jwks").unwrap();
        assert_eq!(joined.as_str(), "https://example.com/proxy/openid/v1/jwks");
    }

    #[test]
    fn rewrite_discovery_rewrites_only_jwks_by_default() {
        let state = test_state("https://internal.example", "https://public.example");
        let value = json!({
            "issuer": "https://internal.example",
            "jwks_uri": "https://internal.example/openid/v1/jwks"
        });

        let rewritten = rewrite_discovery(&state, value);

        assert_eq!(rewritten["issuer"], "https://internal.example");
        assert_eq!(
            rewritten["jwks_uri"],
            "https://public.example/openid/v1/jwks"
        );
    }

    #[test]
    fn rewrite_discovery_can_override_issuer() {
        let mut state = test_state("https://internal.example", "https://public.example");
        state.issuer_override = Some("https://issuer.example".to_string());
        let value = json!({
            "issuer": "https://internal.example",
            "jwks_uri": "https://internal.example/openid/v1/jwks"
        });

        let rewritten = rewrite_discovery(&state, value);

        assert_eq!(rewritten["issuer"], "https://issuer.example");
        assert_eq!(
            rewritten["jwks_uri"],
            "https://public.example/openid/v1/jwks"
        );
    }

    fn test_state(upstream_base_url: &str, public_base_url: &str) -> AppState {
        AppState {
            upstream_base_url: normalize_base_url(upstream_base_url).unwrap(),
            upstream_jwks_url: None,
            public_base_url: normalize_base_url(public_base_url).unwrap(),
            issuer_override: None,
            upstream_bearer_token_file: None,
            cache_ttl: Duration::from_secs(300),
            http: Client::new(),
            discovery_cache: Arc::new(RwLock::new(None)),
            jwks_cache: Arc::new(RwLock::new(None)),
        }
    }
}
