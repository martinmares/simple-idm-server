use std::{
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use axum::{
    Router,
    body::Bytes,
    extract::{OriginalUri, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
};
use clap::{Args, Parser, Subcommand};
use reqwest::Url;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::{fs, io::AsyncWriteExt, net::TcpListener};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt};

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (git ",
    env!("SIMPLE_IDM_GIT_SHA"),
    ")"
);
const CONFIG_RELEASE_HEADER: &str = "x-config-release-id";
const CONFIG_CUSTOMER_RELEASE_HEADER: &str = "x-config-customer-release-id";

#[derive(Parser, Debug)]
#[command(
    name = "simple-idm-token-proxy",
    version = VERSION,
    about = "Workload identity bearer-token proxy and authenticated asset fetcher"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a localhost reverse proxy that injects a fresh bearer token.
    Serve(ServeArgs),

    /// Download authenticated runtime assets and exit.
    Fetch(FetchArgs),
}

#[derive(Args, Debug, Clone)]
struct CommonArgs {
    /// Upstream HTTP API base URL.
    #[arg(long, env = "SIMPLE_IDM_TOKEN_PROXY_UPSTREAM")]
    upstream: Url,

    /// Projected workload identity token file.
    #[arg(long, env = "SIMPLE_IDM_TOKEN_PROXY_TOKEN_FILE")]
    token_file: PathBuf,

    /// Upstream request timeout in seconds.
    #[arg(
        long,
        env = "SIMPLE_IDM_TOKEN_PROXY_TIMEOUT_SECONDS",
        default_value_t = 30
    )]
    timeout_seconds: u64,

    /// PEM bundle with additional trusted upstream certificate authorities.
    #[arg(long, env = "SIMPLE_IDM_TOKEN_PROXY_CA_FILE", value_name = "FILE")]
    ca_file: Option<PathBuf>,

    /// Allow invalid upstream TLS certificates. Use only in controlled sandboxes.
    #[arg(
        long,
        env = "SIMPLE_IDM_TOKEN_PROXY_INSECURE_UPSTREAM_TLS",
        default_value_t = false
    )]
    insecure_upstream_tls: bool,
}

#[derive(Args, Debug)]
struct ServeArgs {
    /// Local listen address for the workload client.
    #[arg(
        long,
        env = "SIMPLE_IDM_TOKEN_PROXY_LISTEN",
        default_value = "127.0.0.1:9999"
    )]
    listen: SocketAddr,

    /// Environment variable containing the image release ID.
    #[arg(
        long,
        env = "SIMPLE_IDM_TOKEN_PROXY_RELEASE_ID_ENV_NAME",
        default_value = "RELEASE_ID"
    )]
    release_id_env_name: String,

    /// Environment variable containing the optional customer release ID.
    #[arg(
        long,
        env = "SIMPLE_IDM_TOKEN_PROXY_CUSTOMER_RELEASE_ID_ENV_NAME",
        default_value = "CUSTOMER_RELEASE_ID"
    )]
    customer_release_id_env_name: String,

    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args, Debug)]
struct FetchArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// Root directory below which fetched files are materialized.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,

    /// JSON array of objects with source, target, optional mode and sha256.
    #[arg(long, value_name = "JSON")]
    files_json: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchFile {
    source: String,
    target: String,
    #[serde(default = "default_file_mode")]
    mode: String,
    #[serde(default)]
    sha256: String,
}

#[derive(Clone)]
struct AppState {
    client: reqwest::Client,
    upstream: Url,
    token_file: Arc<PathBuf>,
    release_id: Option<HeaderValue>,
    customer_release_id: Option<HeaderValue>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => serve(args).await,
        Command::Fetch(args) => fetch(args).await,
    }
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    validate_token_file(&args.common.token_file)?;
    let client = build_client(&args.common)?;
    if args.release_id_env_name.is_empty()
        || args.customer_release_id_env_name.is_empty()
        || args.release_id_env_name == args.customer_release_id_env_name
    {
        anyhow::bail!("release ID environment variable names must be nonempty and distinct");
    }
    let release_id = release_header(
        std::env::var(&args.release_id_env_name).ok(),
        &args.release_id_env_name,
    )?;
    let customer_release_id = release_header(
        std::env::var(&args.customer_release_id_env_name)
            .ok()
            .filter(|value| !value.is_empty()),
        &args.customer_release_id_env_name,
    )?;
    if customer_release_id.is_some() && release_id.is_none() {
        anyhow::bail!("CUSTOMER_RELEASE_ID requires RELEASE_ID");
    }

    let state = AppState {
        client,
        upstream: args.common.upstream.clone(),
        token_file: Arc::new(args.common.token_file.clone()),
        release_id,
        customer_release_id,
    };

    info!("starting simple-idm-token-proxy");
    info!("listen address: {}", args.listen);
    info!("upstream: {}", redact_url(&args.common.upstream));
    info!("token file: {}", args.common.token_file.display());

    let app = Router::new()
        .route("/healthz", any(healthz))
        .fallback(any(proxy))
        .with_state(state);

    let listener = TcpListener::bind(args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn fetch(args: FetchArgs) -> anyhow::Result<()> {
    validate_token_file(&args.common.token_file)?;
    let files: Vec<FetchFile> =
        serde_json::from_str(&args.files_json).context("invalid --files-json")?;
    validate_fetch_files(&files)?;
    if files.is_empty() {
        anyhow::bail!("--files-json must contain at least one file");
    }

    let client = build_client(&args.common)?;
    let token = read_token(&args.common.token_file).await?;
    let output_dir = absolute_output_dir(&args.output_dir)?;
    fs::create_dir_all(&output_dir)
        .await
        .with_context(|| format!("create output directory {}", output_dir.display()))?;

    validate_private_output(&output_dir)?;
    let staging = tempfile::Builder::new()
        .prefix(".runtime-assets-")
        .tempdir_in(&output_dir)?;
    let staging_dir = staging.path();

    let result = fetch_all_to_staging(&client, &args.common.upstream, &token, staging_dir, &files)
        .await
        .and_then(|_| commit_staged_files(staging_dir, &output_dir, &files));

    staging.close()?;
    result?;

    info!("runtime assets ready: {} files", files.len());
    Ok(())
}

fn validate_token_file(token_file: &Path) -> anyhow::Result<()> {
    if !token_file.is_file() {
        anyhow::bail!(
            "token file does not exist or is not a file: {}",
            token_file.display()
        );
    }
    Ok(())
}

fn build_client(args: &CommonArgs) -> anyhow::Result<reqwest::Client> {
    if args.ca_file.is_some() && args.insecure_upstream_tls {
        anyhow::bail!("--ca-file cannot be combined with --insecure-upstream-tls");
    }

    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout_seconds))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(path) = &args.ca_file {
        let certificates = load_ca_certificates(path)?;
        info!(
            "loaded {} additional CA certificate(s) from {}",
            certificates.len(),
            path.display()
        );
        client_builder = client_builder.tls_certs_merge(certificates);
    }
    if args.insecure_upstream_tls {
        warn!("insecure upstream TLS verification is enabled");
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    Ok(client_builder.build()?)
}

fn load_ca_certificates(path: &Path) -> anyhow::Result<Vec<reqwest::Certificate>> {
    let pem = std::fs::read(path)
        .with_context(|| format!("read CA certificate bundle {}", path.display()))?;
    let certificates = reqwest::Certificate::from_pem_bundle(&pem)
        .with_context(|| format!("parse CA certificate bundle {}", path.display()))?;
    if certificates.is_empty() {
        anyhow::bail!(
            "CA certificate bundle contains no certificates: {}",
            path.display()
        );
    }
    Ok(certificates)
}

fn default_file_mode() -> String {
    "0440".to_string()
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
    if let Some(value) = &state.release_id {
        request = request.header(CONFIG_RELEASE_HEADER, value);
    }
    if let Some(value) = &state.customer_release_id {
        request = request.header(CONFIG_CUSTOMER_RELEASE_HEADER, value);
    }

    if !body.is_empty() {
        request = request.body(body);
    }

    let upstream_response = request.send().await?;
    let status = upstream_response.status();
    debug!(
        release_id = ?state.release_id.as_ref().and_then(|value| value.to_str().ok()),
        customer_release_id = ?state.customer_release_id.as_ref().and_then(|value| value.to_str().ok()),
        "forwarded release context headers"
    );
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

fn validate_fetch_files(files: &[FetchFile]) -> anyhow::Result<()> {
    let mut targets = std::collections::HashSet::new();
    for file in files {
        let source = file.source.trim();
        if source.is_empty() || !source.starts_with('/') {
            anyhow::bail!("fetch source must be an absolute HTTP path: {source:?}");
        }
        let source_uri: Uri = source
            .parse()
            .with_context(|| format!("invalid fetch source URI: {source}"))?;
        if source_uri.path().split('/').any(|part| part == "..") {
            anyhow::bail!("fetch source must not contain '..': {source}");
        }

        let target = safe_relative_target(&file.target)?;
        if !targets.insert(target.to_path_buf()) {
            anyhow::bail!("duplicate fetch target: {}", target.display());
        }
        parse_file_mode(&file.mode)?;
        validate_sha256(&file.sha256)?;
    }
    Ok(())
}

fn safe_relative_target(target: &str) -> anyhow::Result<&Path> {
    let raw = target.trim();
    if raw.contains('\\')
        || raw
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        anyhow::bail!("fetch target contains an unsafe path segment: {raw:?}");
    }
    let target = Path::new(raw);
    if target.as_os_str().is_empty() || target.is_absolute() {
        anyhow::bail!("fetch target must be a non-empty relative path: {target:?}");
    }
    if target.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        anyhow::bail!("fetch target must stay below --output-dir: {target:?}");
    }
    Ok(target)
}

fn parse_file_mode(mode: &str) -> anyhow::Result<u32> {
    let mode = mode.trim();
    if mode.len() != 4 || !mode.starts_with('0') || !mode.chars().all(|c| ('0'..='7').contains(&c))
    {
        anyhow::bail!("file mode must use four octal digits such as 0440: {mode:?}");
    }
    let parsed = u32::from_str_radix(mode, 8)?;
    if parsed > 0o777 {
        anyhow::bail!("special permission bits are not supported: {mode}");
    }
    Ok(parsed)
}

fn validate_sha256(expected: &str) -> anyhow::Result<()> {
    let expected = expected.trim();
    if expected.is_empty() {
        return Ok(());
    }
    let digest = expected.strip_prefix("sha256:").unwrap_or(expected);
    if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("invalid SHA-256 digest: {expected:?}");
    }
    Ok(())
}

fn absolute_output_dir(output_dir: &Path) -> anyhow::Result<PathBuf> {
    if !output_dir.is_absolute() {
        anyhow::bail!(
            "--output-dir must be an absolute path: {}",
            output_dir.display()
        );
    }
    Ok(output_dir.to_path_buf())
}

async fn fetch_all_to_staging(
    client: &reqwest::Client,
    upstream: &Url,
    token: &str,
    staging_dir: &Path,
    files: &[FetchFile],
) -> anyhow::Result<()> {
    for file in files {
        let uri: Uri = file.source.parse()?;
        let url = build_upstream_url(upstream, &uri)?;
        info!("fetching {}", url.path());
        let response = client
            .get(url.clone())
            .bearer_auth(token)
            .send()
            .await
            .with_context(|| format!("request {}", url.path()))?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("fetch {} failed: HTTP {}", url.path(), status.as_u16());
        }
        let bytes = response
            .bytes()
            .await
            .with_context(|| format!("read response {}", url.path()))?;
        verify_sha256(&bytes, &file.sha256).with_context(|| format!("verify {}", url.path()))?;

        let target = staging_dir.join(safe_relative_target(&file.target)?);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).await?;
        }
        let mut output = fs::File::create(&target)
            .await
            .with_context(|| format!("create {}", target.display()))?;
        output.write_all(&bytes).await?;
        output.sync_all().await?;
        set_file_mode(&target, parse_file_mode(&file.mode)?).await?;
        info!(
            "staged {} mode={} bytes={}",
            file.target,
            file.mode,
            bytes.len()
        );
    }
    Ok(())
}

fn verify_sha256(bytes: &[u8], expected: &str) -> anyhow::Result<()> {
    let expected = expected.trim();
    if expected.is_empty() {
        return Ok(());
    }
    let expected = expected.strip_prefix("sha256:").unwrap_or(expected);
    let actual: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if !actual.eq_ignore_ascii_case(expected) {
        anyhow::bail!("SHA-256 mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

async fn set_file_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        warn!("file modes are not supported on this platform");
    }
    Ok(())
}

fn commit_staged_files(
    staging_dir: &Path,
    output_dir: &Path,
    files: &[FetchFile],
) -> anyhow::Result<()> {
    for file in files {
        let relative = safe_relative_target(&file.target)?;
        let target = output_dir.join(relative);
        commit_one(staging_dir, output_dir, relative)?;
        info!(
            "stored {} mode={} path={}",
            file.source,
            file.mode,
            target.display()
        );
    }
    Ok(())
}

fn build_upstream_url(base: &Url, uri: &Uri) -> anyhow::Result<Url> {
    let request_path = uri.path();
    let base_path = base.path().trim_end_matches('/');

    let path = if base_path.is_empty()
        || base_path == "/"
        || request_path == base_path
        || request_path.starts_with(&format!("{base_path}/"))
    {
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
            | CONFIG_RELEASE_HEADER
            | CONFIG_CUSTOMER_RELEASE_HEADER
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

fn release_header(value: Option<String>, name: &str) -> anyhow::Result<Option<HeaderValue>> {
    let Some(value) = value else { return Ok(None) };
    let bytes = value.as_bytes();
    let is_alphanumeric = |byte: u8| byte.is_ascii_alphanumeric();
    if bytes.is_empty()
        || bytes.len() > 63
        || !is_alphanumeric(bytes[0])
        || !is_alphanumeric(bytes[bytes.len() - 1])
        || !bytes
            .iter()
            .all(|byte| is_alphanumeric(*byte) || matches!(*byte, b'.' | b'_' | b'-'))
    {
        anyhow::bail!("{name} must be a Kubernetes label value of at most 63 characters");
    }
    Ok(Some(
        HeaderValue::from_str(&value).context(format!("invalid {name} HTTP header value"))?,
    ))
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
    use axum::{
        http::{HeaderValue, header},
        routing::get,
    };
    use tempfile::tempdir;

    const TEST_CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
Um9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG
A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg
Q0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKl
ui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6j
QjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSr
ttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkr
BqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteM
YyRIHN8wfdVoOw==
-----END CERTIFICATE-----"#;

    #[test]
    fn loads_additional_ca_bundle() {
        let root = tempdir().unwrap();
        let path = root.path().join("ca.pem");
        std::fs::write(&path, TEST_CA_PEM).unwrap();

        let certificates = load_ca_certificates(&path).unwrap();

        assert_eq!(certificates.len(), 1);
    }

    #[test]
    fn rejects_invalid_ca_bundle() {
        let root = tempdir().unwrap();
        let path = root.path().join("ca.pem");
        std::fs::write(
            &path,
            "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let args = CommonArgs {
            upstream: Url::parse("https://example.com").unwrap(),
            token_file: root.path().join("token"),
            timeout_seconds: 5,
            ca_file: Some(path),
            insecure_upstream_tls: false,
        };

        assert!(build_client(&args).is_err());
    }

    #[test]
    fn rejects_ca_file_with_insecure_tls() {
        let args = CommonArgs {
            upstream: Url::parse("https://example.com").unwrap(),
            token_file: PathBuf::from("/tmp/token"),
            timeout_seconds: 5,
            ca_file: Some(PathBuf::from("/tmp/ca.pem")),
            insecure_upstream_tls: true,
        };

        let error = build_client(&args).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("--ca-file cannot be combined with --insecure-upstream-tls")
        );
    }

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
        assert!(!should_forward_request_header(&HeaderName::from_static(
            CONFIG_RELEASE_HEADER
        )));
        assert!(!should_forward_request_header(&HeaderName::from_static(
            CONFIG_CUSTOMER_RELEASE_HEADER
        )));
        assert!(should_forward_request_header(&header::ACCEPT));
    }

    #[test]
    fn validates_release_headers() {
        assert!(release_header(None, "RELEASE_ID").unwrap().is_none());
        assert_eq!(
            release_header(
                Some("TSM-Core_RE61_SP_04.01".to_string()),
                "CUSTOMER_RELEASE_ID"
            )
            .unwrap(),
            Some(HeaderValue::from_static("TSM-Core_RE61_SP_04.01"))
        );
        for invalid in [
            "",
            " release",
            "release ",
            "release\nother",
            "release/other",
            "release_",
        ] {
            assert!(release_header(Some(invalid.to_string()), "RELEASE_ID").is_err());
        }
        assert!(release_header(Some("a".repeat(64)), "RELEASE_ID").is_err());
    }

    #[test]
    fn serve_accepts_custom_release_environment_names() {
        let cli = Cli::try_parse_from([
            "simple-idm-token-proxy",
            "serve",
            "--upstream",
            "https://config.example.com",
            "--token-file",
            "/tmp/token",
            "--release-id-env-name",
            "APP_RELEASE_ID",
            "--customer-release-id-env-name",
            "APP_CUSTOMER_RELEASE_ID",
        ])
        .unwrap();
        let Command::Serve(args) = cli.command else {
            panic!("expected serve command")
        };
        assert_eq!(args.release_id_env_name, "APP_RELEASE_ID");
        assert_eq!(args.customer_release_id_env_name, "APP_CUSTOMER_RELEASE_ID");
    }

    #[tokio::test]
    async fn proxy_overrides_client_release_header() {
        let app = Router::new()
            .route(
                "/config/api/v1/config",
                get(|headers: HeaderMap| async move {
                    assert_eq!(
                        headers.get(CONFIG_RELEASE_HEADER),
                        Some(&HeaderValue::from_static("2026.09.10.02"))
                    );
                    assert_eq!(
                        headers.get(CONFIG_CUSTOMER_RELEASE_HEADER),
                        Some(&HeaderValue::from_static("TSM-Core_RE61_SP_04.01"))
                    );
                    assert_eq!(
                        headers.get(header::AUTHORIZATION),
                        Some(&HeaderValue::from_static("Bearer projected-token"))
                    );
                    "ok"
                }),
            )
            .route(
                "/config/api/v1/dev",
                get(|headers: HeaderMap| async move {
                    assert_eq!(
                        headers.get(CONFIG_RELEASE_HEADER),
                        Some(&HeaderValue::from_static("2026.09.10.02"))
                    );
                    assert!(headers.get(CONFIG_CUSTOMER_RELEASE_HEADER).is_none());
                    "ok"
                }),
            );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let root = tempdir().unwrap();
        let token_file = root.path().join("token");
        fs::write(&token_file, "projected-token\n").await.unwrap();
        let state = AppState {
            client: reqwest::Client::new(),
            upstream: Url::parse(&format!("http://{address}/config")).unwrap(),
            token_file: Arc::new(token_file),
            release_id: release_header(Some("2026.09.10.02".to_string()), "RELEASE_ID").unwrap(),
            customer_release_id: release_header(
                Some("TSM-Core_RE61_SP_04.01".to_string()),
                "CUSTOMER_RELEASE_ID",
            )
            .unwrap(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(CONFIG_RELEASE_HEADER, HeaderValue::from_static("spoofed"));
        headers.insert(
            CONFIG_CUSTOMER_RELEASE_HEADER,
            HeaderValue::from_static("spoofed"),
        );
        let response = proxy_inner(
            state.clone(),
            Method::GET,
            "/api/v1/config".parse().unwrap(),
            headers,
            Bytes::new(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut dev_state = state;
        dev_state.customer_release_id = None;
        let mut dev_headers = HeaderMap::new();
        dev_headers.insert(
            CONFIG_CUSTOMER_RELEASE_HEADER,
            HeaderValue::from_static("spoofed"),
        );
        let response = proxy_inner(
            dev_state,
            Method::GET,
            "/api/v1/dev".parse().unwrap(),
            dev_headers,
            Bytes::new(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        server.abort();
    }

    #[test]
    fn redacts_password_in_logged_upstream_url() {
        let url = Url::parse("https://user:secret@example.com/config").unwrap();
        assert_eq!(redact_url(&url), "https://user:***@example.com/config");
    }

    #[test]
    fn validates_relative_fetch_targets_and_modes() {
        let files = vec![FetchFile {
            source: "/api/v1/assets/file.bin".to_string(),
            target: "ssl/file.bin".to_string(),
            mode: "0440".to_string(),
            sha256: String::new(),
        }];
        validate_fetch_files(&files).unwrap();

        let mut invalid = files.clone();
        invalid[0].target = "../token".to_string();
        assert!(validate_fetch_files(&invalid).is_err());

        let mut invalid = files;
        invalid[0].mode = "440".to_string();
        assert!(validate_fetch_files(&invalid).is_err());

        assert!(safe_relative_target("ssl//file.bin").is_err());
        assert!(safe_relative_target(r"ssl\file.bin").is_err());
    }

    #[tokio::test]
    async fn fetches_binary_file_with_bearer_token() {
        const BODY: &[u8] = b"\0binary\xffcontent";
        let app = Router::new().route(
            "/config/api/v1/assets/file.bin",
            get(|headers: HeaderMap| async move {
                assert_eq!(
                    headers.get(header::AUTHORIZATION),
                    Some(&HeaderValue::from_static("Bearer projected-token"))
                );
                BODY
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = tempdir().unwrap();
        let token_file = root.path().join("token");
        fs::write(&token_file, "projected-token\n").await.unwrap();
        let output_dir = root.path().join("output");
        let digest: String = Sha256::digest(BODY)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let files = serde_json::to_string(&[serde_json::json!({
            "source": "/api/v1/assets/file.bin",
            "target": "ssl/file.bin",
            "mode": "0440",
            "sha256": digest,
        })])
        .unwrap();

        fetch(FetchArgs {
            common: CommonArgs {
                upstream: Url::parse(&format!("http://{address}/config")).unwrap(),
                token_file,
                timeout_seconds: 5,
                ca_file: None,
                insecure_upstream_tls: false,
            },
            output_dir: output_dir.clone(),
            files_json: files,
        })
        .await
        .unwrap();

        assert_eq!(
            fs::read(output_dir.join("ssl/file.bin")).await.unwrap(),
            BODY
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(output_dir.join("ssl/file.bin"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o440);
        }
        server.abort();
    }
}

fn validate_private_output(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("Output must be a real private directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != rustix::process::getuid().as_raw() {
            anyhow::bail!("Output directory must belong to the current user");
        }
        // Protect staging and output from other local users throughout the fetch.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn commit_one(staging: &Path, output: &Path, relative: &Path) -> anyhow::Result<()> {
    use rustix::fs::{Mode, OFlags, mkdirat, open, openat, renameat};
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut destination = open(output, flags, Mode::empty())?;
    let components: Vec<_> = relative.components().collect();
    for part in &components[..components.len() - 1] {
        let name = part.as_os_str();
        match mkdirat(&destination, name, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(error.into()),
        }
        destination = openat(&destination, name, flags, Mode::empty())?;
    }
    let source = open(staging, flags, Mode::empty())?;
    // Parent descriptors are held open; no symlink is followed at the target.
    renameat(
        &source,
        relative,
        &destination,
        components.last().unwrap().as_os_str(),
    )?;
    Ok(())
}

#[cfg(not(unix))]
fn commit_one(staging: &Path, output: &Path, relative: &Path) -> anyhow::Result<()> {
    let mut parent = output.to_path_buf();
    let components: Vec<_> = relative.components().collect();
    for part in &components[..components.len() - 1] {
        parent.push(part.as_os_str());
        if parent.exists() && std::fs::symlink_metadata(&parent)?.file_type().is_symlink() {
            anyhow::bail!("Output parent must not be a symlink");
        }
        std::fs::create_dir_all(&parent)?;
    }
    std::fs::rename(
        staging.join(relative),
        parent.join(components.last().unwrap().as_os_str()),
    )?;
    Ok(())
}

#[cfg(all(test, unix))]
mod filesystem_security_tests {
    use super::*;
    #[test]
    fn publishing_never_follows_output_parent_symlinks() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("output");
        let staging = root.path().join("staging");
        let external = root.path().join("external");
        for path in [&output, &staging, &external] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::create_dir(staging.join("ssl")).unwrap();
        std::fs::write(staging.join("ssl/key.pem"), "test asset").unwrap();
        symlink(&external, output.join("ssl")).unwrap();
        assert!(commit_one(&staging, &output, Path::new("ssl/key.pem")).is_err());
        assert!(!external.join("key.pem").exists());
    }
}
