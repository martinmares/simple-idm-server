use askama::Template;
use axum::{
    extract::{Form, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use simple_idm_server::{admin::middleware::AdminAuth, db::DbPool};
use sqlx::FromRow;
use std::collections::BTreeMap;
use uuid::Uuid;

const ADMIN_TOKEN_COOKIE: &str = "sidm_admin_token";

#[derive(Clone)]
pub struct WebAdminState {
    pub db_pool: DbPool,
    pub admin_auth: AdminAuth,
    pub secure_cookies: bool,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    token: String,
}

#[derive(Debug, Deserialize)]
pub struct UserCreateForm {
    username: String,
    email: String,
    password: String,
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UserUpdateForm {
    email: String,
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GroupCreateForm {
    name: String,
    description: String,
    is_virtual: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GroupUpdateForm {
    name: String,
    description: String,
    is_virtual: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClientCreateForm {
    client_id: String,
    name: String,
    redirect_uris: String,
    grant_types: String,
    scope: String,
    is_public: Option<String>,
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClientUpdateForm {
    name: String,
    redirect_uris: String,
    grant_types: String,
    scope: String,
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClaimMapCreateForm {
    client_id: String,
    group_id: Option<String>,
    claim_name: String,
    claim_value: String,
    claim_value_kind: String,
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    message: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
struct UserRow {
    id: Uuid,
    username: String,
    email: String,
    is_active: bool,
}

#[derive(Debug, Clone, FromRow)]
struct GroupRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    is_virtual: bool,
}

#[derive(Debug, Clone, FromRow)]
struct ClientRow {
    id: Uuid,
    client_id: String,
    name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scope: String,
    is_active: bool,
    is_public: bool,
}

#[derive(Debug, Clone, FromRow)]
struct ClaimMapRow {
    client_name: String,
    group_name: Option<String>,
    claim_name: String,
    claim_value: serde_json::Value,
    claim_value_kind: String,
}

#[derive(Debug, Clone, FromRow)]
struct UserGroupRow {
    username: String,
    email: String,
    group_name: String,
}

#[derive(Debug, Clone)]
struct GroupUsersRow {
    group_name: String,
    users: String,
}

#[derive(Debug, Clone)]
struct ClientClaimsRow {
    client_name: String,
    claims: String,
}

#[derive(Debug, Clone)]
struct GroupClaimsRow {
    group_name: String,
    claims: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminSection {
    Users,
    Groups,
    UserGroups,
    GroupUsers,
    Clients,
    ClientClaims,
    GroupClaims,
}

impl AdminSection {
    fn all() -> [Self; 7] {
        [
            Self::Users,
            Self::Groups,
            Self::UserGroups,
            Self::GroupUsers,
            Self::Clients,
            Self::ClientClaims,
            Self::GroupClaims,
        ]
    }

    fn title(self) -> &'static str {
        match self {
            Self::Users => "Users",
            Self::Groups => "Groups",
            Self::UserGroups => "User groups",
            Self::GroupUsers => "Group users",
            Self::Clients => "Clients",
            Self::ClientClaims => "Client claims",
            Self::GroupClaims => "Group claims",
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::Users => "/admin/ui/users",
            Self::Groups => "/admin/ui/groups",
            Self::UserGroups => "/admin/ui/user-groups",
            Self::GroupUsers => "/admin/ui/group-users",
            Self::Clients => "/admin/ui/clients",
            Self::ClientClaims => "/admin/ui/client-claims",
            Self::GroupClaims => "/admin/ui/group-claims",
        }
    }
}

#[derive(Template)]
#[template(path = "admin/login.html")]
struct LoginTemplate<'a> {
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "admin/users.html")]
struct UsersTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<UserRow>,
}

#[derive(Template)]
#[template(path = "admin/groups.html")]
struct GroupsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<GroupRow>,
}

#[derive(Template)]
#[template(path = "admin/user_groups.html")]
struct UserGroupsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<UserGroupRow>,
}

#[derive(Template)]
#[template(path = "admin/group_users.html")]
struct GroupUsersTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<GroupUsersRow>,
}

#[derive(Template)]
#[template(path = "admin/clients.html")]
struct ClientsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<ClientRow>,
}

#[derive(Template)]
#[template(path = "admin/client_claims.html")]
struct ClientClaimsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<ClientClaimsRow>,
    clients: Vec<(Uuid, String)>,
    groups: Vec<(Uuid, String)>,
}

#[derive(Template)]
#[template(path = "admin/group_claims.html")]
struct GroupClaimsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<GroupClaimsRow>,
}

#[derive(Clone)]
struct NavItem {
    title: &'static str,
    path: &'static str,
    active: bool,
}

pub fn router(state: WebAdminState) -> Router {
    Router::new()
        .route("/admin/ui", get(ui_root))
        .route("/admin/ui/login", get(login_page).post(login_submit))
        .route("/admin/ui/logout", post(logout_submit))
        .route("/admin/ui/users", get(users_page))
        .route("/admin/ui/users/create", post(users_create))
        .route("/admin/ui/users/{id}/update", post(users_update))
        .route("/admin/ui/users/{id}/deactivate", post(users_deactivate))
        .route("/admin/ui/groups", get(groups_page))
        .route("/admin/ui/groups/create", post(groups_create))
        .route("/admin/ui/groups/{id}/update", post(groups_update))
        .route("/admin/ui/user-groups", get(user_groups_page))
        .route("/admin/ui/group-users", get(group_users_page))
        .route("/admin/ui/clients", get(clients_page))
        .route("/admin/ui/clients/create", post(clients_create))
        .route("/admin/ui/clients/{id}/update", post(clients_update))
        .route("/admin/ui/clients/{id}/deactivate", post(clients_deactivate))
        .route("/admin/ui/client-claims", get(client_claims_page))
        .route("/admin/ui/client-claims/create", post(client_claims_create))
        .route("/admin/ui/group-claims", get(group_claims_page))
        .with_state(state)
}

fn parse_checkbox(v: &Option<String>) -> bool {
    v.as_deref().is_some_and(|x| x == "on" || x == "true" || x == "1")
}

fn split_csv(v: &str) -> Vec<String> {
    v.split(',')
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(|x| x.to_string())
        .collect()
}

fn nav_items(active: AdminSection) -> Vec<NavItem> {
    AdminSection::all()
        .into_iter()
        .map(|s| NavItem {
            title: s.title(),
            path: s.path(),
            active: s == active,
        })
        .collect()
}

fn redirect_with(path: &str, key: &str, value: &str) -> Redirect {
    let encoded = urlencoding::encode(value);
    Redirect::to(&format!("{path}?{key}={encoded}"))
}

fn render_template<T: Template>(tmpl: T) -> Response {
    match tmpl.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template error: {e}"),
        )
            .into_response(),
    }
}

fn token_from_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .map(|part| part.trim())
        .find_map(|p| p.strip_prefix(&format!("{ADMIN_TOKEN_COOKIE}=")))
        .map(|s| s.to_string())
}

async fn validate_admin_token(state: &WebAdminState, token: &str) -> bool {
    if let Some(root) = &state.admin_auth.admin_root_token {
        if token == root {
            return true;
        }
    }

    let audiences = match sqlx::query_scalar::<_, String>(
        "SELECT client_id FROM oauth_clients WHERE is_active = true AND deleted_at IS NULL",
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) if !v.is_empty() => v,
        _ => return false,
    };

    let claims = match state
        .admin_auth
        .jwt_service
        .verify_access_token(token, &audiences, &[])
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    if claims.groups.contains(&"simple-idm:role:admin".to_string()) {
        return true;
    }
    if state.admin_auth.allow_legacy_admin_group && claims.groups.contains(&"admin".to_string()) {
        return true;
    }
    if state.admin_auth.allow_admin_substring_claim {
        return claims
            .custom_claims
            .keys()
            .any(|k| k.starts_with("admin") || k.contains("admin"));
    }
    false
}

async fn require_admin_token(state: &WebAdminState, headers: &HeaderMap) -> Result<String, Redirect> {
    let Some(token) = token_from_cookie(headers) else {
        return Err(Redirect::to("/admin/ui/login"));
    };
    if validate_admin_token(state, &token).await {
        Ok(token)
    } else {
        Err(Redirect::to("/admin/ui/login?error=Invalid%20admin%20token"))
    }
}

async fn ui_root() -> Redirect {
    Redirect::to("/admin/ui/users")
}

async fn login_page(Query(query): Query<PageQuery>) -> Response {
    render_template(LoginTemplate {
        error: query.error.as_deref(),
    })
}

async fn login_submit(
    State(state): State<WebAdminState>,
    Form(form): Form<LoginForm>,
) -> Response {
    if !validate_admin_token(&state, &form.token).await {
        return Redirect::to("/admin/ui/login?error=Invalid%20admin%20token").into_response();
    }

    let secure = if state.secure_cookies { "; Secure" } else { "" };
    let cookie = format!(
        "{ADMIN_TOKEN_COOKIE}={}; Path=/; HttpOnly; SameSite=Lax{}",
        form.token, secure
    );

    (
        [(header::SET_COOKIE, cookie)],
        Redirect::to("/admin/ui/users"),
    )
        .into_response()
}

async fn logout_submit(State(state): State<WebAdminState>) -> Response {
    let secure = if state.secure_cookies { "; Secure" } else { "" };
    let cookie = format!(
        "{ADMIN_TOKEN_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{}",
        secure
    );
    ([(header::SET_COOKIE, cookie)], Redirect::to("/admin/ui/login")).into_response()
}

async fn users_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, UserRow>(
        r#"SELECT id, username, email, is_active FROM users WHERE deleted_at IS NULL ORDER BY username ASC"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/users", "error", &format!("DB error: {e}")).into_response();
        }
    };

    render_template(UsersTemplate {
        sections: nav_items(AdminSection::Users),
        message: query.message,
        error: query.error,
        rows,
    })
}

async fn users_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<UserCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let password_hash = match simple_idm_server::auth::password::hash_password(&form.password) {
        Ok(h) => h,
        Err(e) => {
            return redirect_with("/admin/ui/users", "error", &format!("Password hash failed: {e}"))
                .into_response();
        }
    };

    let is_active = parse_checkbox(&form.is_active);

    let result = sqlx::query(
        r#"INSERT INTO users (tenant_id, username, email, password_hash, is_active)
           VALUES ('11111111-1111-1111-1111-111111111111', $1, $2, $3, $4)"#,
    )
    .bind(form.username.trim())
    .bind(form.email.trim().to_lowercase())
    .bind(password_hash)
    .bind(is_active)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/users", "message", "User created").into_response(),
        Err(e) => redirect_with("/admin/ui/users", "error", &format!("Create failed: {e}"))
            .into_response(),
    }
}

async fn users_update(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<UserUpdateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let is_active = parse_checkbox(&form.is_active);

    let result = sqlx::query(
        r#"UPDATE users SET email = $2, is_active = $3, updated_at = NOW() WHERE id = $1"#,
    )
    .bind(id)
    .bind(form.email.trim().to_lowercase())
    .bind(is_active)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/users", "message", "User updated").into_response(),
        Err(e) => redirect_with("/admin/ui/users", "error", &format!("Update failed: {e}"))
            .into_response(),
    }
}

async fn users_deactivate(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let result = sqlx::query(
        r#"UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1"#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/users", "message", "User deactivated (safe delete)")
            .into_response(),
        Err(e) => redirect_with("/admin/ui/users", "error", &format!("Deactivate failed: {e}"))
            .into_response(),
    }
}

async fn groups_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, GroupRow>(
        r#"SELECT id, name, description, is_virtual FROM groups WHERE deleted_at IS NULL ORDER BY name ASC"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/groups", "error", &format!("DB error: {e}")).into_response();
        }
    };

    render_template(GroupsTemplate {
        sections: nav_items(AdminSection::Groups),
        message: query.message,
        error: query.error,
        rows,
    })
}

async fn groups_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<GroupCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let result = sqlx::query(r#"INSERT INTO groups (name, description, is_virtual) VALUES ($1, $2, $3)"#)
        .bind(form.name.trim())
        .bind(Some(form.description.trim()).filter(|v| !v.is_empty()))
        .bind(parse_checkbox(&form.is_virtual))
        .execute(&state.db_pool)
        .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/groups", "message", "Group created").into_response(),
        Err(e) => redirect_with("/admin/ui/groups", "error", &format!("Create failed: {e}"))
            .into_response(),
    }
}

async fn groups_update(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<GroupUpdateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let result = sqlx::query(r#"UPDATE groups SET name=$2, description=$3, is_virtual=$4 WHERE id=$1"#)
        .bind(id)
        .bind(form.name.trim())
        .bind(Some(form.description.trim()).filter(|v| !v.is_empty()))
        .bind(parse_checkbox(&form.is_virtual))
        .execute(&state.db_pool)
        .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/groups", "message", "Group updated").into_response(),
        Err(e) => redirect_with("/admin/ui/groups", "error", &format!("Update failed: {e}"))
            .into_response(),
    }
}

async fn user_groups_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, UserGroupRow>(
        r#"SELECT u.username, u.email, g.name AS group_name
           FROM user_groups ug
           JOIN users u ON u.id = ug.user_id
           JOIN groups g ON g.id = ug.group_id
           WHERE u.deleted_at IS NULL AND g.deleted_at IS NULL
           ORDER BY u.username, g.name"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/user-groups", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    render_template(UserGroupsTemplate {
        sections: nav_items(AdminSection::UserGroups),
        message: query.message,
        error: query.error,
        rows,
    })
}

async fn group_users_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, UserGroupRow>(
        r#"SELECT u.username, u.email, g.name AS group_name
           FROM user_groups ug
           JOIN users u ON u.id = ug.user_id
           JOIN groups g ON g.id = ug.group_id
           WHERE u.deleted_at IS NULL AND g.deleted_at IS NULL
           ORDER BY g.name, u.username"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/group-users", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in rows {
        grouped
            .entry(r.group_name)
            .or_default()
            .push(format!("{} <{}>", r.username, r.email));
    }

    let rows = grouped
        .into_iter()
        .map(|(group_name, users)| GroupUsersRow {
            group_name,
            users: users.join(", "),
        })
        .collect::<Vec<_>>();

    render_template(GroupUsersTemplate {
        sections: nav_items(AdminSection::GroupUsers),
        message: query.message,
        error: query.error,
        rows,
    })
}

async fn clients_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, ClientRow>(
        r#"SELECT id, client_id, name, redirect_uris, grant_types, scope, is_active, is_public
           FROM oauth_clients WHERE deleted_at IS NULL ORDER BY name ASC"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/clients", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    render_template(ClientsTemplate {
        sections: nav_items(AdminSection::Clients),
        message: query.message,
        error: query.error,
        rows,
    })
}

async fn clients_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<ClientCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let is_public = parse_checkbox(&form.is_public);
    let is_active = parse_checkbox(&form.is_active);
    let client_secret_hash = if is_public {
        None
    } else {
        match simple_idm_server::auth::password::hash_password("change-me") {
            Ok(v) => Some(v),
            Err(e) => {
                return redirect_with("/admin/ui/clients", "error", &format!("Hash failed: {e}"))
                    .into_response();
            }
        }
    };

    let result = sqlx::query(
        r#"INSERT INTO oauth_clients
           (tenant_id, client_id, client_secret_hash, name, redirect_uris, grant_types, scope, is_active, is_public,
            groups_claim_mode, include_claim_maps, ignore_virtual_groups)
           VALUES ('11111111-1111-1111-1111-111111111111', $1, $2, $3, $4, $5, $6, $7, $8, 'effective', true, false)"#,
    )
    .bind(form.client_id.trim())
    .bind(client_secret_hash)
    .bind(form.name.trim())
    .bind(split_csv(&form.redirect_uris))
    .bind(split_csv(&form.grant_types))
    .bind(form.scope.trim())
    .bind(is_active)
    .bind(is_public)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/clients", "message", "Client created").into_response(),
        Err(e) => redirect_with("/admin/ui/clients", "error", &format!("Create failed: {e}"))
            .into_response(),
    }
}

async fn clients_update(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<ClientUpdateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let is_active = parse_checkbox(&form.is_active);

    let result = sqlx::query(
        r#"UPDATE oauth_clients
           SET name=$2, redirect_uris=$3, grant_types=$4, scope=$5, is_active=$6, updated_at=NOW()
           WHERE id=$1"#,
    )
    .bind(id)
    .bind(form.name.trim())
    .bind(split_csv(&form.redirect_uris))
    .bind(split_csv(&form.grant_types))
    .bind(form.scope.trim())
    .bind(is_active)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/clients", "message", "Client updated").into_response(),
        Err(e) => redirect_with("/admin/ui/clients", "error", &format!("Update failed: {e}"))
            .into_response(),
    }
}

async fn clients_deactivate(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let result = sqlx::query(
        r#"UPDATE oauth_clients SET is_active=false, updated_at=NOW() WHERE id=$1"#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/clients", "message", "Client deactivated (safe delete)")
            .into_response(),
        Err(e) => redirect_with("/admin/ui/clients", "error", &format!("Deactivate failed: {e}"))
            .into_response(),
    }
}

async fn client_claims_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, ClaimMapRow>(
        r#"SELECT oc.name AS client_name,
                  g.name AS group_name,
                  cm.claim_name,
                  cm.claim_value,
                  cm.claim_value_kind
           FROM claim_maps cm
           JOIN oauth_clients oc ON oc.id = cm.client_id
           LEFT JOIN groups g ON g.id = cm.group_id
           WHERE cm.deleted_at IS NULL
             AND oc.deleted_at IS NULL
             AND (g.id IS NULL OR g.deleted_at IS NULL)
           ORDER BY oc.name, cm.claim_name"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/client-claims", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    let mut client_claims: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in rows {
        client_claims.entry(row.client_name).or_default().push(format!(
            "{}={} ({}, group={})",
            row.claim_name,
            row.claim_value,
            row.claim_value_kind,
            row.group_name.unwrap_or_else(|| "*".to_string())
        ));
    }

    let rows = client_claims
        .into_iter()
        .map(|(client_name, claims)| ClientClaimsRow {
            client_name,
            claims: claims.join(" | "),
        })
        .collect::<Vec<_>>();

    let clients = sqlx::query_as::<_, (Uuid, String)>("SELECT id, name FROM oauth_clients WHERE deleted_at IS NULL ORDER BY name")
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();
    let groups = sqlx::query_as::<_, (Uuid, String)>("SELECT id, name FROM groups WHERE deleted_at IS NULL ORDER BY name")
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();

    render_template(ClientClaimsTemplate {
        sections: nav_items(AdminSection::ClientClaims),
        message: query.message,
        error: query.error,
        rows,
        clients,
        groups,
    })
}

async fn client_claims_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<ClaimMapCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let client_id = match Uuid::parse_str(form.client_id.trim()) {
        Ok(v) => v,
        Err(_) => return redirect_with("/admin/ui/client-claims", "error", "Invalid client_id").into_response(),
    };

    let group_id = form
        .group_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| Uuid::parse_str(v).ok());

    let claim_value_json = if form.claim_value_kind == "array" {
        serde_json::json!(split_csv(&form.claim_value))
    } else {
        serde_json::json!(form.claim_value.trim())
    };

    let result = sqlx::query(
        r#"INSERT INTO claim_maps (tenant_id, client_id, group_id, claim_name, claim_value, claim_value_kind)
           VALUES ('11111111-1111-1111-1111-111111111111', $1, $2, $3, $4, $5::claim_value_kind)"#,
    )
    .bind(client_id)
    .bind(group_id)
    .bind(form.claim_name.trim())
    .bind(claim_value_json)
    .bind(form.claim_value_kind.trim())
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/client-claims", "message", "Claim map created").into_response(),
        Err(e) => redirect_with("/admin/ui/client-claims", "error", &format!("Create failed: {e}"))
            .into_response(),
    }
}

async fn group_claims_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, ClaimMapRow>(
        r#"SELECT oc.name AS client_name,
                  g.name AS group_name,
                  cm.claim_name,
                  cm.claim_value,
                  cm.claim_value_kind
           FROM claim_maps cm
           JOIN oauth_clients oc ON oc.id = cm.client_id
           LEFT JOIN groups g ON g.id = cm.group_id
           WHERE cm.deleted_at IS NULL
             AND oc.deleted_at IS NULL
             AND (g.id IS NULL OR g.deleted_at IS NULL)
           ORDER BY g.name NULLS LAST, oc.name, cm.claim_name"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/group-claims", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in rows {
        let g = row.group_name.unwrap_or_else(|| "*".to_string());
        grouped.entry(g).or_default().push(format!(
            "{}: {}={} ({})",
            row.client_name, row.claim_name, row.claim_value, row.claim_value_kind
        ));
    }

    let rows = grouped
        .into_iter()
        .map(|(group_name, claims)| GroupClaimsRow {
            group_name,
            claims: claims.join(" | "),
        })
        .collect::<Vec<_>>();

    render_template(GroupClaimsTemplate {
        sections: nav_items(AdminSection::GroupClaims),
        message: query.message,
        error: query.error,
        rows,
    })
}
