use anyhow::{Context, Result, anyhow};
use axum::{
    Form, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use clap::Parser;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use simple_idm_ad_auth::{
    LdapAuthConfig, LdapExternalIdentity, LdapTlsMode, LdapUserData, fetch_ldap_user_data,
    fetch_ldap_user_data_with_user_bind, verify_ldap_password,
};
use simple_idm_common::{escape_html, tabler_standalone_page};
use std::{path::PathBuf, sync::Arc};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (git ",
    env!("SIMPLE_IDM_GIT_SHA"),
    ")"
);

#[derive(Parser, Debug)]
#[command(
    name = "simple-idm-ad-proxy",
    version = VERSION,
    about = "Small AD/LDAP auth proxy for nginx auth_request"
)]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Config {
    #[serde(skip)]
    config_file: PathBuf,

    #[serde(default = "default_listen_addr")]
    listen_addr: String,
    public_base_url: String,
    #[serde(default = "default_external_base_path")]
    external_base_path: String,

    #[serde(default = "default_cookie_name")]
    cookie_name: String,
    cookie_secret: String,
    #[serde(default = "default_cookie_samesite")]
    cookie_samesite: String,
    #[serde(default = "default_session_max_age_seconds")]
    session_max_age_seconds: i64,
    #[serde(default = "default_redirect_path")]
    default_redirect_path: String,

    #[serde(default = "default_login_title")]
    login_title: String,
    #[serde(default = "default_login_description")]
    login_description: String,

    ldap: LdapConfig,

    #[serde(default)]
    authz: AuthzConfig,

    #[serde(default)]
    headers: HeaderConfig,

    #[serde(default)]
    role_mappings: Vec<RoleMapping>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct LdapConfig {
    #[serde(default)]
    mode: LdapAuthMode,
    host: String,
    #[serde(default = "default_ldaps_port")]
    port: u16,
    base_dn: String,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    user_bind_format: Option<String>,
    #[serde(default = "default_user_filter")]
    user_filter: String,
    #[serde(default = "default_tls_mode")]
    tls_mode: LdapTlsModeConfig,
    #[serde(default = "default_ldap_timeout_seconds")]
    timeout_seconds: u64,
    #[serde(default)]
    allow_insecure: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum LdapAuthMode {
    ServiceAccount,
    BindAsUser,
}

impl Default for LdapAuthMode {
    fn default() -> Self {
        Self::ServiceAccount
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum LdapTlsModeConfig {
    Ldaps,
    Starttls,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AuthzConfig {
    #[serde(default = "default_require_mapped_group")]
    require_mapped_group: bool,
}

impl Default for AuthzConfig {
    fn default() -> Self {
        Self {
            require_mapped_group: default_require_mapped_group(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct HeaderConfig {
    #[serde(default = "default_true")]
    emit_x_auth: bool,
    #[serde(default)]
    emit_webauth: bool,
    #[serde(default = "default_groups_header_name")]
    groups_header_name: String,
    #[serde(default = "default_groups_header_format")]
    groups_header_format: String,
}

impl Default for HeaderConfig {
    fn default() -> Self {
        Self {
            emit_x_auth: true,
            emit_webauth: false,
            groups_header_name: default_groups_header_name(),
            groups_header_format: default_groups_header_format(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RoleMapping {
    ad_group_cn: Option<String>,
    ad_group_dn: Option<String>,
    emit_group: Option<String>,
    emit_header_role: Option<String>,
    #[serde(default = "default_role_priority")]
    priority: i32,
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    sessions: Arc<SessionStore>,
}

#[derive(Debug, Clone)]
struct Session {
    session_id: String,
    username: String,
    email: Option<String>,
    subject: String,
    groups: Vec<String>,
    header_role: Option<String>,
    raw_ad_groups: Vec<String>,
    expires_at: DateTime<Utc>,
}

impl Session {
    fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

#[derive(Default)]
struct SessionStore {
    sessions: DashMap<String, Session>,
}

impl SessionStore {
    fn get(&self, session_id: &str) -> Option<Session> {
        let session = self.sessions.get(session_id)?.clone();
        if session.is_expired() {
            self.sessions.remove(session_id);
            return None;
        }
        Some(session)
    }

    fn insert(&self, session: Session) {
        self.sessions.insert(session.session_id.clone(), session);
    }

    fn delete(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }
}

#[derive(Debug, Deserialize)]
struct LoginQuery {
    rd: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    rd: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "simple_idm_ad_proxy=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Arc::new(Config::load(cli.config)?);
    tracing::info!("starting simple-idm-ad-proxy");
    tracing::info!("config file: {}", config.config_file.display());
    tracing::info!("listen address: {}", config.listen_addr);
    tracing::info!("public base URL: {}", config.public_base_url);
    tracing::info!("external base path: {}", config.external_base_path);
    tracing::info!("LDAP server: {}:{}", config.ldap.host, config.ldap.port);
    tracing::info!("role mappings: {}", config.role_mappings.len());

    let state = AppState {
        config: config.clone(),
        sessions: Arc::new(SessionStore::default()),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/auth", get(handle_auth))
        .route("/login", get(show_login).post(handle_login))
        .route("/logout", get(handle_logout).post(handle_logout))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("listening on {}", config.listen_addr);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn handle_auth(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session) = authorize_session(&state, &headers) else {
        let login_url = login_url_for_request(&state.config, &headers);
        let mut response = (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        insert_header(response.headers_mut(), header::LOCATION, &login_url);
        insert_header(
            response.headers_mut(),
            HeaderName::from_static("x-auth-login"),
            &login_url,
        );
        return response;
    };

    tracing::debug!(
        username = %session.username,
        groups = ?session.groups,
        raw_ad_groups_count = session.raw_ad_groups.len(),
        "auth request accepted"
    );

    (StatusCode::OK, build_auth_headers(&state.config, &session)).into_response()
}

async fn show_login(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> impl IntoResponse {
    login_page(&state.config, query.rd.as_deref(), query.error.as_deref())
}

async fn handle_login(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    let rd = safe_redirect_path_or_default(form.rd.as_deref(), &state.config.default_redirect_path);
    let username = form.username.trim();
    let password = form.password.as_str();

    if username.is_empty() || password.is_empty() {
        return redirect_see_other(&format!(
            "{}?rd={}&error={}",
            login_path(&state.config),
            urlencoding::encode(&rd),
            urlencoding::encode("Username and password are required")
        ));
    }

    let ldap_user = match authenticate_and_fetch_user(&state.config.ldap, username, password).await
    {
        Ok(user) => user,
        Err(err) => {
            tracing::warn!(username = %username, error = ?err, "AD login failed");
            return redirect_see_other(&format!(
                "{}?rd={}&error={}",
                login_path(&state.config),
                urlencoding::encode(&rd),
                urlencoding::encode(login_error_message(&err))
            ));
        }
    };

    let mapped = map_roles(&state.config, &ldap_user.roles);
    if state.config.authz.require_mapped_group && mapped.groups.is_empty() && mapped.role.is_none()
    {
        tracing::warn!(
            username = %username,
            raw_ad_groups_count = ldap_user.roles.len(),
            "AD login denied because no configured role mapping matched"
        );
        return redirect_see_other(&format!(
            "{}?rd={}&error={}",
            login_path(&state.config),
            urlencoding::encode(&rd),
            urlencoding::encode("You do not have permission to access this application")
        ));
    }

    let session = build_session(&state.config, username, ldap_user, mapped);
    let session_id = session.session_id.clone();
    let username = session.username.clone();
    let mapped_groups = session.groups.clone();
    let mapped_role = session.header_role.clone();
    state.sessions.insert(session);

    tracing::info!(
        username = %username,
        groups = ?mapped_groups,
        header_role = ?mapped_role,
        "AD login accepted"
    );

    let cookie = session_cookie(&state.config, &session_id);
    let mut response = redirect_see_other(&rd);
    append_set_cookie(response.headers_mut(), &cookie);
    response
}

fn redirect_see_other(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    insert_header(response.headers_mut(), header::LOCATION, location);
    response
}

async fn authenticate_and_fetch_user(
    ldap: &LdapConfig,
    username: &str,
    password: &str,
) -> Result<LdapUserData> {
    let ldap_cfg = ldap.to_auth_config();
    match ldap.mode {
        LdapAuthMode::ServiceAccount => {
            verify_ldap_password(&ldap_cfg, username, password)
                .await
                .context("Invalid username or password")?;
            fetch_ldap_user_data(&ldap_cfg, username)
                .await
                .context("Login succeeded, but roles could not be loaded")
        }
        LdapAuthMode::BindAsUser => {
            let bind_login = ldap.bind_login(username);
            fetch_ldap_user_data_with_user_bind(&ldap_cfg, &bind_login, password, username)
                .await
                .context("Invalid username/password, or roles could not be loaded")
        }
    }
}

fn login_error_message(err: &anyhow::Error) -> &'static str {
    let text = format!("{err:#}");
    if text.contains("Login succeeded, but roles could not be loaded") {
        "Login succeeded, but roles could not be loaded"
    } else if text.contains("roles could not be loaded") {
        "Invalid username/password, or roles could not be loaded"
    } else {
        "Invalid username or password"
    }
}

async fn handle_logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(session_id) = extract_session_cookie(&headers, &state.config.cookie_name) {
        state.sessions.delete(&session_id);
        tracing::info!("session deleted: {}", session_id);
    }

    let cookie = clear_session_cookie(&state.config);
    let login_url = format!(
        "{}?rd={}",
        login_path(&state.config),
        urlencoding::encode(&state.config.default_redirect_path)
    );
    let body = format!(
        r#"<div class="alert alert-info" role="alert">
  You have been signed out from this application.
</div>
<a class="btn btn-primary w-100" href="{login_url}">Sign in again</a>"#
    );
    let html = tabler_standalone_page(
        "Signed out",
        "Simple IDM AD Proxy",
        "Signed out",
        "You have been signed out from this application.",
        &body,
        "Your AD session cookie was cleared.",
        "",
    );
    let mut response = Html(html).into_response();
    append_set_cookie(response.headers_mut(), &cookie);
    response
}

fn authorize_session(state: &AppState, headers: &HeaderMap) -> Option<Session> {
    let session_id = extract_session_cookie(headers, &state.config.cookie_name)?;
    state.sessions.get(&session_id)
}

fn login_page(config: &Config, rd: Option<&str>, error: Option<&str>) -> Html<String> {
    let rd = safe_redirect_path_or_default(rd, &config.default_redirect_path);
    let error_html = error
        .filter(|error| !error.trim().is_empty())
        .map(|error| {
            format!(
                r#"<div class="alert alert-danger" role="alert">{}</div>"#,
                escape_html(error)
            )
        })
        .unwrap_or_default();

    let body = format!(
        r#"{error_html}
<form method="post" action="{login_path}" autocomplete="on">
  <input type="hidden" name="rd" value="{rd}">
  <div class="mb-3">
    <label class="form-label">Username</label>
    <input class="form-control" name="username" autocomplete="username" autofocus>
  </div>
  <div class="mb-3">
    <label class="form-label">Password</label>
    <input class="form-control" name="password" type="password" autocomplete="current-password">
  </div>
  <button class="btn btn-primary w-100" type="submit">
    <i class="ti ti-login-2 me-2"></i>
    Sign in
  </button>
</form>"#,
        error_html = error_html,
        login_path = login_path(config),
        rd = escape_html(&rd)
    );

    Html(tabler_standalone_page(
        "Sign in",
        "Simple IDM AD Proxy",
        &config.login_title,
        &config.login_description,
        &body,
        "AD/LDAP authentication",
        "",
    ))
}

fn build_session(config: &Config, login: &str, user: LdapUserData, mapped: MappedRoles) -> Session {
    let username = best_username(login, &user.identity);
    let email = user.profile.recovery_email.clone();
    let subject = best_subject(&username, &user.identity);
    let issued_at = Utc::now();

    Session {
        session_id: generate_session_id(),
        username,
        email,
        subject,
        groups: mapped.groups,
        header_role: mapped.role,
        raw_ad_groups: user.roles,
        expires_at: issued_at + Duration::seconds(config.session_max_age_seconds),
    }
}

fn best_username(login: &str, identity: &LdapExternalIdentity) -> String {
    identity
        .login_name
        .clone()
        .or_else(|| identity.upn.clone())
        .unwrap_or_else(|| login.to_string())
}

fn best_subject(username: &str, identity: &LdapExternalIdentity) -> String {
    identity
        .external_user_id
        .clone()
        .or_else(|| identity.upn.clone())
        .unwrap_or_else(|| username.to_string())
}

#[derive(Debug, Default)]
struct MappedRoles {
    groups: Vec<String>,
    role: Option<String>,
}

fn map_roles(config: &Config, ad_groups: &[String]) -> MappedRoles {
    let mut emitted_groups = Vec::new();
    let mut role_candidates = Vec::new();

    for mapping in &config.role_mappings {
        if !mapping.matches(ad_groups) {
            continue;
        }

        if let Some(group) = mapping.emit_group.as_deref()
            && !emitted_groups.iter().any(|existing| existing == group)
        {
            emitted_groups.push(group.to_string());
        }

        if let Some(role) = mapping.emit_header_role.as_deref() {
            role_candidates.push((mapping.priority, normalize_header_role(role)));
        }
    }

    emitted_groups.sort();

    role_candidates.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| header_role_rank(&b.1).cmp(&header_role_rank(&a.1)))
    });

    MappedRoles {
        groups: emitted_groups,
        role: role_candidates.into_iter().map(|(_, role)| role).next(),
    }
}

impl RoleMapping {
    fn matches(&self, ad_groups: &[String]) -> bool {
        let dn_match = self
            .ad_group_dn
            .as_deref()
            .map(|expected| {
                ad_groups
                    .iter()
                    .any(|group| group.eq_ignore_ascii_case(expected))
            })
            .unwrap_or(false);
        if dn_match {
            return true;
        }

        self.ad_group_cn
            .as_deref()
            .map(|expected| {
                ad_groups.iter().any(|group| {
                    extract_cn(group)
                        .map(|cn| cn.eq_ignore_ascii_case(expected))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }
}

fn extract_cn(dn: &str) -> Option<&str> {
    let rest = dn.strip_prefix("CN=")?;
    rest.split(',').next()
}

fn normalize_header_role(role: &str) -> String {
    match role.trim().to_ascii_lowercase().as_str() {
        "admin" => "Admin".to_string(),
        "edit" | "editor" => "Editor".to_string(),
        "view" | "viewer" => "Viewer".to_string(),
        other => other.to_string(),
    }
}

fn header_role_rank(role: &str) -> i32 {
    match role {
        "Admin" => 3,
        "Editor" => 2,
        "Viewer" => 1,
        _ => 0,
    }
}

fn build_auth_headers(config: &Config, session: &Session) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if config.headers.emit_x_auth {
        insert_header(
            &mut headers,
            HeaderName::from_static("x-auth-user"),
            &session.username,
        );
        insert_header(
            &mut headers,
            HeaderName::from_static("x-auth-subject"),
            &session.subject,
        );
        if let Some(email) = session.email.as_deref() {
            insert_header(&mut headers, HeaderName::from_static("x-auth-email"), email);
        }
        let groups = serialize_groups(&session.groups, &config.headers.groups_header_format);
        match config.headers.groups_header_name.parse::<HeaderName>() {
            Ok(name) => insert_header(&mut headers, name, &groups),
            Err(err) => tracing::warn!(
                "invalid groups header name '{}': {}",
                config.headers.groups_header_name,
                err
            ),
        }
        if let Some(role) = session.header_role.as_deref() {
            insert_header(&mut headers, HeaderName::from_static("x-auth-role"), role);
        }
    }

    if config.headers.emit_webauth {
        insert_header(
            &mut headers,
            HeaderName::from_static("x-webauth-user"),
            &session.username,
        );
        if let Some(email) = session.email.as_deref() {
            insert_header(
                &mut headers,
                HeaderName::from_static("x-webauth-email"),
                email,
            );
        }
        if let Some(role) = session.header_role.as_deref() {
            insert_header(
                &mut headers,
                HeaderName::from_static("x-webauth-role"),
                role,
            );
        }
        if !session.groups.is_empty() {
            insert_header(
                &mut headers,
                HeaderName::from_static("x-webauth-groups"),
                &session.groups.join(","),
            );
        }
    }

    headers
}

fn insert_header(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    match HeaderValue::from_str(value) {
        Ok(value) => {
            headers.insert(name, value);
        }
        Err(err) => tracing::warn!("skipping invalid header '{}': {}", name, err),
    }
}

fn append_set_cookie(headers: &mut HeaderMap, cookie: &str) {
    match HeaderValue::from_str(cookie) {
        Ok(value) => {
            headers.append(header::SET_COOKIE, value);
        }
        Err(err) => tracing::error!("invalid Set-Cookie value generated by AD proxy: {}", err),
    }
}

fn session_cookie(config: &Config, session_id: &str) -> String {
    let secure = if config.public_base_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{}={}; Path=/; HttpOnly{}; SameSite={}; Max-Age={}",
        config.cookie_name,
        session_id,
        secure,
        config.cookie_samesite,
        config.session_max_age_seconds
    )
}

fn clear_session_cookie(config: &Config) -> String {
    format!(
        "{}=; Path=/; HttpOnly; SameSite={}; Max-Age=0",
        config.cookie_name, config.cookie_samesite
    )
}

fn extract_session_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie_header.split(';').find_map(|cookie| {
        let (name, value) = cookie.trim().split_once('=')?;
        (name == cookie_name).then(|| value.to_string())
    })
}

fn login_url_for_request(config: &Config, headers: &HeaderMap) -> String {
    let rd = headers
        .get("x-original-uri")
        .and_then(|value| value.to_str().ok())
        .map(|value| safe_redirect_path(Some(value)))
        .unwrap_or_else(|| "/".to_string());
    format!("{}?rd={}", login_path(config), urlencoding::encode(&rd))
        .trim_start_matches(&config.public_base_url)
        .to_string()
}

fn login_path(config: &Config) -> String {
    mounted_path(&config.external_base_path, "/login")
}

fn mounted_path(base: &str, suffix: &str) -> String {
    if base.is_empty() {
        suffix.to_string()
    } else {
        format!("{base}{suffix}")
    }
}

fn safe_redirect_path(value: Option<&str>) -> String {
    let value = value.unwrap_or("/").trim();
    if value.starts_with('/') && !value.starts_with("//") {
        value.to_string()
    } else {
        "/".to_string()
    }
}

fn safe_redirect_path_or_default(value: Option<&str>, default: &str) -> String {
    match value {
        Some(value) if !value.trim().is_empty() => safe_redirect_path(Some(value)),
        _ => safe_redirect_path(Some(default)),
    }
}

fn serialize_groups(groups: &[String], format: &str) -> String {
    match format {
        "jsonb64" => {
            let json = serde_json::to_string(groups).unwrap_or_else(|_| "[]".to_string());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes())
        }
        _ => groups.join(","),
    }
}

fn generate_session_id() -> String {
    use rand::RngExt;
    let random_bytes: Vec<u8> = (0..32).map(|_| rand::rng().random()).collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&random_bytes)
}

impl Config {
    fn load(config_file: Option<PathBuf>) -> Result<Self> {
        let config_file = match config_file {
            Some(path) => path,
            None => Self::find_config_file()?,
        };

        let config_content = std::fs::read_to_string(&config_file)
            .with_context(|| format!("failed to read config file: {}", config_file.display()))?;
        let mut config: Config = toml::from_str(&config_content)
            .with_context(|| format!("failed to parse config file: {}", config_file.display()))?;
        config.config_file = config_file;
        config.apply_env_overrides();
        config.validate()?;
        Ok(config)
    }

    fn find_config_file() -> Result<PathBuf> {
        if let Ok(path) = std::env::var("AD_PROXY_CONFIG") {
            return Ok(PathBuf::from(path));
        }

        for candidate in [
            PathBuf::from("./ad-proxy.toml"),
            PathBuf::from("./config.toml"),
            PathBuf::from("/etc/simple-idm-ad-proxy/config.toml"),
        ] {
            if candidate.exists() {
                return Ok(candidate);
            }
        }

        Err(anyhow!(
            "config file not found. Set AD_PROXY_CONFIG or pass --config"
        ))
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(value) = std::env::var("AD_PROXY_LISTEN_ADDR") {
            self.listen_addr = value;
        }
        if let Ok(value) = std::env::var("AD_PROXY_PUBLIC_BASE_URL") {
            self.public_base_url = value;
        }
        if let Ok(value) = std::env::var("AD_PROXY_COOKIE_SECRET") {
            self.cookie_secret = value;
        }
        if let Ok(value) = std::env::var("AD_PROXY_LDAP_BIND_PASSWORD") {
            self.ldap.bind_password = Some(value);
        }
    }

    fn validate(&self) -> Result<()> {
        if !self.public_base_url.starts_with("http://")
            && !self.public_base_url.starts_with("https://")
        {
            anyhow::bail!("public_base_url must start with http:// or https://");
        }
        if self.cookie_secret.len() < 32 {
            anyhow::bail!("cookie_secret must be at least 32 characters");
        }
        if self.session_max_age_seconds <= 0 {
            anyhow::bail!("session_max_age_seconds must be > 0");
        }
        if !self.external_base_path.is_empty() {
            if !self.external_base_path.starts_with('/')
                || self.external_base_path.starts_with("//")
                || self.external_base_path.ends_with('/')
            {
                anyhow::bail!(
                    "external_base_path must be empty or a relative path like /_auth/grafana without trailing /"
                );
            }
        }
        if safe_redirect_path(Some(&self.default_redirect_path)) != self.default_redirect_path {
            anyhow::bail!("default_redirect_path must be a relative path starting with /");
        }
        self.ldap.validate_mode()?;
        self.ldap.to_auth_config().validate()?;
        for mapping in &self.role_mappings {
            if mapping.ad_group_cn.is_none() && mapping.ad_group_dn.is_none() {
                anyhow::bail!("role_mappings entry must set ad_group_cn or ad_group_dn");
            }
            if mapping.emit_group.is_none() && mapping.emit_header_role.is_none() {
                anyhow::bail!("role_mappings entry must set emit_group or emit_header_role");
            }
        }
        Ok(())
    }
}

impl LdapConfig {
    fn validate_mode(&self) -> Result<()> {
        match self.mode {
            LdapAuthMode::ServiceAccount => {
                if self
                    .bind_dn
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .is_empty()
                {
                    anyhow::bail!("ldap.bind_dn is required when ldap.mode = \"service_account\"");
                }
                if self
                    .bind_password
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .is_empty()
                {
                    anyhow::bail!(
                        "ldap.bind_password is required when ldap.mode = \"service_account\""
                    );
                }
            }
            LdapAuthMode::BindAsUser => {
                if self
                    .user_bind_format
                    .as_deref()
                    .unwrap_or("{login}")
                    .trim()
                    .is_empty()
                {
                    anyhow::bail!("ldap.user_bind_format must not be empty");
                }
            }
        }
        Ok(())
    }

    fn bind_login(&self, username: &str) -> String {
        self.user_bind_format
            .as_deref()
            .unwrap_or("{login}")
            .replace("{login}", username)
            .replace("{username}", username)
    }

    fn to_auth_config(&self) -> LdapAuthConfig {
        LdapAuthConfig {
            host: self.host.clone(),
            port: self.port,
            base_dn: self.base_dn.clone(),
            bind_dn: self.bind_dn.clone(),
            bind_password: self.bind_password.clone(),
            user_filter: self.user_filter.clone(),
            tls_mode: match self.tls_mode {
                LdapTlsModeConfig::Ldaps => LdapTlsMode::Ldaps,
                LdapTlsModeConfig::Starttls => LdapTlsMode::StartTls,
            },
            timeout_seconds: self.timeout_seconds,
            allow_insecure: self.allow_insecure,
        }
    }
}

fn default_listen_addr() -> String {
    "127.0.0.1:4181".to_string()
}

fn default_external_base_path() -> String {
    "".to_string()
}

fn default_cookie_name() -> String {
    "_simple_ad_proxy".to_string()
}

fn default_cookie_samesite() -> String {
    "Lax".to_string()
}

fn default_session_max_age_seconds() -> i64 {
    8 * 60 * 60
}

fn default_redirect_path() -> String {
    "/".to_string()
}

fn default_login_title() -> String {
    "Sign in".to_string()
}

fn default_login_description() -> String {
    "Use your AD account to continue.".to_string()
}

fn default_ldaps_port() -> u16 {
    636
}

fn default_user_filter() -> String {
    "(|(sAMAccountName={login})(userPrincipalName={login})(mail={login}))".to_string()
}

fn default_tls_mode() -> LdapTlsModeConfig {
    LdapTlsModeConfig::Ldaps
}

fn default_ldap_timeout_seconds() -> u64 {
    5
}

fn default_require_mapped_group() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_groups_header_name() -> String {
    "X-Auth-Groups".to_string()
}

fn default_groups_header_format() -> String {
    "csv".to_string()
}

fn default_role_priority() -> i32 {
    100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_headers_are_the_default() {
        let headers = HeaderConfig::default();
        assert!(headers.emit_x_auth);
        assert!(!headers.emit_webauth);
        assert_eq!(headers.groups_header_name, "X-Auth-Groups");
    }

    #[test]
    fn extracts_cn_from_dn() {
        assert_eq!(
            extract_cn("CN=Icinga_Grafana_Viewer,OU=ICINGA,DC=ad,DC=cetin"),
            Some("Icinga_Grafana_Viewer")
        );
    }

    #[test]
    fn maps_cn_to_group_and_role() {
        let config = Config {
            config_file: PathBuf::from("test"),
            listen_addr: default_listen_addr(),
            public_base_url: "https://app.example.test".to_string(),
            external_base_path: default_external_base_path(),
            cookie_name: default_cookie_name(),
            cookie_secret: "01234567890123456789012345678901".to_string(),
            cookie_samesite: default_cookie_samesite(),
            session_max_age_seconds: default_session_max_age_seconds(),
            default_redirect_path: default_redirect_path(),
            login_title: default_login_title(),
            login_description: default_login_description(),
            ldap: LdapConfig {
                mode: LdapAuthMode::ServiceAccount,
                host: "ad.example.test".to_string(),
                port: 636,
                base_dn: "DC=example,DC=test".to_string(),
                bind_dn: Some("CN=svc,DC=example,DC=test".to_string()),
                bind_password: Some("secret".to_string()),
                user_bind_format: None,
                user_filter: default_user_filter(),
                tls_mode: LdapTlsModeConfig::Ldaps,
                timeout_seconds: 5,
                allow_insecure: false,
            },
            authz: AuthzConfig::default(),
            headers: HeaderConfig::default(),
            role_mappings: vec![RoleMapping {
                ad_group_cn: Some("Icinga_Grafana_Viewer".to_string()),
                ad_group_dn: None,
                emit_group: Some("grafana_viewer".to_string()),
                emit_header_role: Some("Viewer".to_string()),
                priority: 100,
            }],
        };

        let mapped = map_roles(
            &config,
            &["CN=Icinga_Grafana_Viewer,OU=ICINGA,DC=ad,DC=cetin".to_string()],
        );
        assert_eq!(mapped.groups, vec!["grafana_viewer"]);
        assert_eq!(mapped.role.as_deref(), Some("Viewer"));
    }

    #[test]
    fn safe_redirect_rejects_absolute_url() {
        assert_eq!(safe_redirect_path(Some("https://evil.example/")), "/");
        assert_eq!(safe_redirect_path(Some("//evil.example/")), "/");
        assert_eq!(safe_redirect_path(Some("/dashboard")), "/dashboard");
    }

    #[test]
    fn safe_redirect_uses_configured_default() {
        assert_eq!(
            safe_redirect_path_or_default(None, "/grafana/"),
            "/grafana/"
        );
        assert_eq!(
            safe_redirect_path_or_default(Some(""), "/grafana/"),
            "/grafana/"
        );
        assert_eq!(
            safe_redirect_path_or_default(Some("/custom"), "/grafana/"),
            "/custom"
        );
    }

    #[test]
    fn mounted_paths_use_external_base_path() {
        let mut config = Config {
            config_file: PathBuf::from("test"),
            listen_addr: default_listen_addr(),
            public_base_url: "https://app.example.test".to_string(),
            external_base_path: "/_auth/grafana".to_string(),
            cookie_name: default_cookie_name(),
            cookie_secret: "01234567890123456789012345678901".to_string(),
            cookie_samesite: default_cookie_samesite(),
            session_max_age_seconds: default_session_max_age_seconds(),
            default_redirect_path: default_redirect_path(),
            login_title: default_login_title(),
            login_description: default_login_description(),
            ldap: LdapConfig {
                mode: LdapAuthMode::ServiceAccount,
                host: "ad.example.test".to_string(),
                port: 636,
                base_dn: "DC=example,DC=test".to_string(),
                bind_dn: Some("CN=svc,DC=example,DC=test".to_string()),
                bind_password: Some("secret".to_string()),
                user_bind_format: None,
                user_filter: default_user_filter(),
                tls_mode: LdapTlsModeConfig::Ldaps,
                timeout_seconds: 5,
                allow_insecure: false,
            },
            authz: AuthzConfig::default(),
            headers: HeaderConfig::default(),
            role_mappings: vec![RoleMapping {
                ad_group_cn: Some("Icinga_Grafana_Viewer".to_string()),
                ad_group_dn: None,
                emit_group: Some("grafana_viewer".to_string()),
                emit_header_role: Some("Viewer".to_string()),
                priority: 100,
            }],
        };

        assert_eq!(login_path(&config), "/_auth/grafana/login");
        assert_eq!(
            mounted_path(&config.external_base_path, "/logout"),
            "/_auth/grafana/logout"
        );
        assert_eq!(
            mounted_path(&config.external_base_path, "/auth"),
            "/_auth/grafana/auth"
        );

        config.external_base_path = "".to_string();
        assert_eq!(login_path(&config), "/login");
        assert_eq!(
            mounted_path(&config.external_base_path, "/logout"),
            "/logout"
        );
        assert_eq!(mounted_path(&config.external_base_path, "/auth"), "/auth");
    }

    #[test]
    fn bind_as_user_formats_login() {
        let ldap = LdapConfig {
            mode: LdapAuthMode::BindAsUser,
            host: "ad.example.test".to_string(),
            port: 636,
            base_dn: "DC=example,DC=test".to_string(),
            bind_dn: None,
            bind_password: None,
            user_bind_format: Some("{login}@AD.CETIN".to_string()),
            user_filter: default_user_filter(),
            tls_mode: LdapTlsModeConfig::Ldaps,
            timeout_seconds: 5,
            allow_insecure: false,
        };

        assert_eq!(ldap.bind_login("x0549983"), "x0549983@AD.CETIN");
        assert!(ldap.validate_mode().is_ok());
    }

    #[test]
    fn service_account_requires_bind_credentials() {
        let ldap = LdapConfig {
            mode: LdapAuthMode::ServiceAccount,
            host: "ad.example.test".to_string(),
            port: 636,
            base_dn: "DC=example,DC=test".to_string(),
            bind_dn: None,
            bind_password: None,
            user_bind_format: None,
            user_filter: default_user_filter(),
            tls_mode: LdapTlsModeConfig::Ldaps,
            timeout_seconds: 5,
            allow_insecure: false,
        };

        assert!(ldap.validate_mode().is_err());
    }
}
