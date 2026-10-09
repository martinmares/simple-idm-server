use super::handlers::ErrorResponse;
use crate::db::DbPool;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryUser {
    google_id: String,
    email: String,
    first_name: String,
    last_name: String,
    is_active: bool,
    suspended: bool,
    archived: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {
    tenant_id: Uuid,
    provider: String,
    domain: String,
    users: Vec<DirectoryUser>,
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default)]
    apply: bool,
    #[serde(default)]
    approve: bool,
}

#[derive(FromRow)]
struct Provider {
    id: Uuid,
    issuer: String,
    hd_domain: Option<String>,
}

#[derive(FromRow)]
struct ExistingUser {
    id: Uuid,
    email: String,
    username: String,
    auth_mode: String,
    auth_provider_id: Option<Uuid>,
    is_active: bool,
    deleted: bool,
}

#[derive(FromRow)]
struct Identity {
    user_id: Uuid,
    idp_id: Uuid,
    issuer: String,
    subject: String,
    approval_status: String,
}

#[derive(Serialize)]
struct ImportRow {
    email: String,
    username: String,
    google_id: String,
    action: &'static str,
    detail: String,
}

fn short_username(email: &str) -> &str {
    email.split_once('@').map_or(email, |(local, _)| local)
}

fn normalize_domain(domain: &str) -> Result<String, String> {
    let domain = domain.trim().to_ascii_lowercase();
    if domain.is_empty()
        || !domain.is_ascii()
        || domain
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
    {
        return Err("Invalid domain".into());
    }
    Ok(domain)
}

#[derive(Serialize)]
struct ImportReport {
    applied: bool,
    provider: String,
    tenant_id: Uuid,
    approval_status: &'static str,
    create: usize,
    skip: usize,
    conflicts: usize,
    rows: Vec<ImportRow>,
}

fn validate(req: &mut ImportRequest) -> Result<(), String> {
    if req.users.is_empty() || req.users.len() > 1000 {
        return Err("Import must contain between 1 and 1000 users".into());
    }
    req.domain = normalize_domain(&req.domain)?;
    let mut ids = HashSet::new();
    let mut emails = HashSet::new();
    for user in &mut req.users {
        user.email = user.email.trim().to_ascii_lowercase();
        let parts: Vec<_> = user.email.split('@').collect();
        if user.email.len() > 255
            || parts.len() != 2
            || parts[0].is_empty()
            || parts[1] != req.domain
            || user
                .email
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(format!(
                "Invalid email or email outside requested domain: {}",
                user.email
            ));
        }
        if user.google_id.is_empty()
            || user.google_id.len() > 255
            || !user.google_id.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!(
                "Google ID must be a nonempty digit string: {}",
                user.email
            ));
        }
        if !ids.insert(user.google_id.clone()) || !emails.insert(user.email.clone()) {
            return Err("Duplicate Google ID or email in input".into());
        }
        if user.first_name.len() > 1024
            || user.last_name.len() > 1024
            || user
                .first_name
                .chars()
                .chain(user.last_name.chars())
                .any(char::is_control)
        {
            return Err("Invalid profile name".into());
        }
        if user.is_active != !(user.suspended || user.archived) {
            return Err(format!(
                "Inconsistent active/suspended/archived flags: {}",
                user.email
            ));
        }
    }
    for email in &mut req.emails {
        *email = email.trim().to_ascii_lowercase();
        if !emails.contains(email) {
            return Err(format!("Selected email not found in export: {email}"));
        }
    }
    Ok(())
}

fn plan(
    req: &ImportRequest,
    provider: &Provider,
    users: &[ExistingUser],
    identities: &[Identity],
) -> ImportReport {
    let mut rows = Vec::new();
    for user in &req.users {
        let mut row = ImportRow {
            email: user.email.clone(),
            username: short_username(&user.email).into(),
            google_id: user.google_id.clone(),
            action: "create",
            detail: "Create passwordless federated user and identity".into(),
        };
        let matches: Vec<_> = users
            .iter()
            .filter(|u| u.email.eq_ignore_ascii_case(&user.email))
            .collect();
        if !req.emails.is_empty() && !req.emails.contains(&user.email) {
            row.action = "skip";
            row.detail = "Not selected".into();
        } else if !user.is_active {
            row.action = "skip";
            row.detail = "Suspended or archived Google account".into();
        } else if matches.len() == 1
            && !matches[0].deleted
            && matches[0].is_active
            && matches[0].auth_mode == "federated"
            && matches[0].auth_provider_id == Some(provider.id)
            && identities.iter().any(|i| {
                i.user_id == matches[0].id
                    && i.idp_id == provider.id
                    && i.issuer == provider.issuer
                    && i.subject == user.google_id
            })
        {
            let identity = identities
                .iter()
                .find(|i| {
                    i.user_id == matches[0].id
                        && i.idp_id == provider.id
                        && i.issuer == provider.issuer
                        && i.subject == user.google_id
                })
                .unwrap();
            row.action = "skip";
            row.username = matches[0].username.clone();
            row.detail = format!(
                "Already linked; existing {} approval unchanged",
                identity.approval_status
            );
        } else if !matches.is_empty() {
            row.action = "conflict";
            row.detail =
                "Existing email account must be resolved manually; no conversion or relinking"
                    .into();
        } else if users
            .iter()
            .any(|u| !u.deleted && u.username.eq_ignore_ascii_case(&row.username))
        {
            row.action = "conflict";
            row.detail = "Short username already exists on a non-archived account".into();
        } else if identities.iter().any(|i| {
            i.subject == user.google_id && (i.issuer == provider.issuer || i.idp_id == provider.id)
        }) {
            row.action = "conflict";
            row.detail = "Google identity already belongs to another account".into();
        }
        rows.push(row);
    }
    ImportReport {
        applied: false,
        provider: req.provider.clone(),
        tenant_id: req.tenant_id,
        approval_status: if req.approve { "approved" } else { "pending" },
        create: rows.iter().filter(|r| r.action == "create").count(),
        skip: rows.iter().filter(|r| r.action == "skip").count(),
        conflicts: rows.iter().filter(|r| r.action == "conflict").count(),
        rows,
    }
}

type ImportError = (StatusCode, String);

async fn load_provider(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    slug: &str,
    domain: &str,
) -> Result<Provider, ImportError> {
    let provider = sqlx::query_as::<_, Provider>(
        "SELECT ip.id, ip.issuer, ip.hd_domain FROM identity_providers ip JOIN tenants t ON t.id = ip.tenant_id
         WHERE ip.tenant_id = $1 AND ip.slug = $2 AND ip.provider_type = 'google'
         AND ip.is_active AND ip.deleted_at IS NULL AND t.is_active AND t.deleted_at IS NULL FOR SHARE OF ip, t")
        .bind(tenant_id).bind(slug).fetch_optional(&mut **tx).await.map_err(db_error)?
        .ok_or((StatusCode::BAD_REQUEST, "Active Google provider not found in requested tenant".into()))?;
    if provider.issuer != "https://accounts.google.com" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Google provider issuer must be https://accounts.google.com".into(),
        ));
    }
    if provider
        .hd_domain
        .as_deref()
        .is_some_and(|d| !d.is_empty() && !d.eq_ignore_ascii_case(domain))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Domain does not match provider hosted domain".into(),
        ));
    }
    Ok(provider)
}

async fn run(db: &DbPool, mut req: ImportRequest) -> Result<ImportReport, ImportError> {
    validate(&mut req).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let mut tx = db.begin().await.map_err(db_error)?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    // This rare administrative batch blocks writes while planning and inserting,
    // including case-insensitive conflicts not covered by the DB unique indexes.
    if req.apply {
        sqlx::query("LOCK TABLE users, user_identities IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
    } else {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
    }
    let provider = load_provider(&mut tx, req.tenant_id, &req.provider, &req.domain).await?;
    let allowed: bool =
        sqlx::query_scalar("SELECT domain_authentication_allowed($1, $2, 'federated', $3)")
            .bind(req.tenant_id)
            .bind(format!("import@{}", req.domain))
            .bind(provider.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_error)?;
    if !allowed {
        return Err((
            StatusCode::BAD_REQUEST,
            "Domain authentication policy does not allow this Google provider".into(),
        ));
    }
    let emails: Vec<_> = req.users.iter().map(|u| u.email.clone()).collect();
    let usernames: Vec<_> = emails
        .iter()
        .map(|e| short_username(e).to_string())
        .collect();
    let subjects: Vec<_> = req.users.iter().map(|u| u.google_id.clone()).collect();
    let existing = sqlx::query_as::<_, ExistingUser>(
        "SELECT id, email, username, auth_mode, auth_provider_id, is_active, deleted_at IS NOT NULL AS deleted
         FROM users WHERE tenant_id = $1 AND (lower(email) = ANY($2) OR lower(username) = ANY($3))")
        .bind(req.tenant_id).bind(&emails).bind(&usernames).fetch_all(&mut *tx).await.map_err(db_error)?;
    let user_ids: Vec<_> = existing.iter().map(|u| u.id).collect();
    let identities = sqlx::query_as::<_, Identity>(
        "SELECT user_id, idp_id, issuer, subject, approval_status FROM user_identities
         WHERE tenant_id = $1 AND deleted_at IS NULL AND (user_id = ANY($2) OR subject = ANY($3))",
    )
    .bind(req.tenant_id)
    .bind(&user_ids)
    .bind(&subjects)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_error)?;
    let mut report = plan(&req, &provider, &existing, &identities);
    if !req.apply || report.conflicts > 0 {
        tx.rollback().await.map_err(db_error)?;
        return Ok(report);
    }
    for (user, row) in req.users.iter().zip(&report.rows) {
        if row.action != "create" {
            continue;
        }
        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO users (tenant_id, username, email, first_name, last_name, password_hash,
             password_disabled, auth_mode, auth_provider_id, is_active)
             VALUES ($1, $2, $3, $4, $5, NULL, true, 'federated', $6, true) RETURNING id",
        )
        .bind(req.tenant_id)
        .bind(&row.username)
        .bind(&user.email)
        .bind(&user.first_name)
        .bind(&user.last_name)
        .bind(provider.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
        sqlx::query(
            "INSERT INTO user_identities (tenant_id, user_id, idp_id, issuer, subject, email_at_link,
             email_verified, approval_status, approved_at)
             VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, CASE WHEN $7 = 'approved' THEN NOW() ELSE NULL END)")
            .bind(req.tenant_id).bind(id).bind(provider.id).bind(&provider.issuer).bind(&user.google_id)
            .bind(&user.email).bind(report.approval_status).execute(&mut *tx).await.map_err(db_error)?;
        // Directory import is administrative attestation, not an email_verified OIDC claim.
        sqlx::query("INSERT INTO audit_events (action, resource_type, resource_id, outcome, details)
                     VALUES ('admin.user.import_google', 'user', $1, 'success', $2)")
            .bind(id).bind(serde_json::json!({"tenant_id": req.tenant_id, "provider_id": provider.id,
                "email": user.email, "username": row.username, "subject": user.google_id, "approval_status": report.approval_status,
                "source": "google_workspace_directory_export"}))
            .execute(&mut *tx).await.map_err(db_error)?;
    }
    tx.commit().await.map_err(db_error)?;
    report.applied = true;
    Ok(report)
}

fn db_error(error: sqlx::Error) -> ImportError {
    tracing::error!("Google user import failed: {error}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Import failed; no partial batch committed. Check server logs and retry preview.".into(),
    )
}

pub async fn import_google(
    State(db): State<DbPool>,
    Json(req): Json<ImportRequest>,
) -> axum::response::Response {
    match run(&db, req).await {
        Ok(report) => Json(report).into_response(),
        Err((status, description)) => (
            status,
            Json(ErrorResponse {
                error: "google_import_failed".into(),
                error_description: description,
            }),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizeRequest {
    tenant_id: Uuid,
    provider: String,
    domain: String,
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default)]
    apply: bool,
}

#[derive(Serialize)]
struct RenameRow {
    id: Uuid,
    email: String,
    old_username: String,
    new_username: String,
    action: &'static str,
    detail: &'static str,
}

#[derive(Serialize)]
struct RenameReport {
    applied: bool,
    tenant_id: Uuid,
    provider: String,
    rename: usize,
    skip: usize,
    conflicts: usize,
    rows: Vec<RenameRow>,
}

fn rename_plan(
    req: &NormalizeRequest,
    candidates: &[ExistingUser],
    reserved: &[ExistingUser],
) -> RenameReport {
    let mut rows = Vec::new();
    for user in candidates {
        let mut row = RenameRow {
            id: user.id,
            email: user.email.clone(),
            old_username: user.username.clone(),
            new_username: short_username(&user.email).to_ascii_lowercase(),
            action: "rename",
            detail: "Shorten username; keep identity and memberships",
        };
        if (!req.emails.is_empty()
            && !req
                .emails
                .iter()
                .any(|e| e.eq_ignore_ascii_case(&user.email)))
            || !user.username.eq_ignore_ascii_case(&user.email)
            || !user.is_active
        {
            row.action = "skip";
            row.new_username = user.username.clone();
            row.detail = "Custom username, inactive account or not selected";
        } else if row.new_username.is_empty()
            || user.email.matches('@').count() != 1
            || user
                .email
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            row.action = "conflict";
            row.detail = "Email cannot be safely converted to a username";
        } else if reserved.iter().any(|other| {
            !other.deleted
                && other.id != user.id
                && other.username.eq_ignore_ascii_case(&row.new_username)
        }) || candidates.iter().any(|other| {
            other.id != user.id
                && other.is_active
                && other.username.eq_ignore_ascii_case(&other.email)
                && (req.emails.is_empty()
                    || req
                        .emails
                        .iter()
                        .any(|e| e.eq_ignore_ascii_case(&other.email)))
                && short_username(&other.email).eq_ignore_ascii_case(&row.new_username)
        }) {
            row.action = "conflict";
            row.detail = "Short username already reserved or proposed for another account";
        }
        rows.push(row);
    }
    RenameReport {
        applied: false,
        tenant_id: req.tenant_id,
        provider: req.provider.clone(),
        rename: rows.iter().filter(|r| r.action == "rename").count(),
        skip: rows.iter().filter(|r| r.action == "skip").count(),
        conflicts: rows.iter().filter(|r| r.action == "conflict").count(),
        rows,
    }
}

async fn run_normalize(
    db: &DbPool,
    mut req: NormalizeRequest,
) -> Result<RenameReport, ImportError> {
    req.domain = normalize_domain(&req.domain).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    for email in &mut req.emails {
        *email = email.trim().to_ascii_lowercase();
    }
    if req.emails.len() > 1000 {
        return Err((
            StatusCode::BAD_REQUEST,
            "At most 1000 selected emails are allowed".into(),
        ));
    }
    let mut tx = db.begin().await.map_err(db_error)?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    if req.apply {
        sqlx::query("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
    } else {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
    }
    let provider = load_provider(&mut tx, req.tenant_id, &req.provider, &req.domain).await?;
    let candidates = sqlx::query_as::<_, ExistingUser>(
        "SELECT id, email, username, auth_mode, auth_provider_id, is_active, false AS deleted FROM users
         WHERE tenant_id = $1 AND auth_mode = 'federated' AND auth_provider_id = $2 AND deleted_at IS NULL
         AND lower(split_part(email, '@', 2)) = $3 AND (cardinality($4::text[]) = 0 OR lower(email) = ANY($4))
         ORDER BY lower(email), id LIMIT 1001")
        .bind(req.tenant_id).bind(provider.id).bind(&req.domain).bind(&req.emails).fetch_all(&mut *tx).await.map_err(db_error)?;
    if candidates.len() > 1000 {
        return Err((
            StatusCode::BAD_REQUEST,
            "More than 1000 federated accounts selected; use --email for a smaller batch".into(),
        ));
    }
    for email in &req.emails {
        if !candidates
            .iter()
            .any(|u| u.email.eq_ignore_ascii_case(email))
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Selected email not found for provider and domain: {email}"),
            ));
        }
    }
    let usernames: Vec<_> = candidates
        .iter()
        .map(|u| short_username(&u.email).to_ascii_lowercase())
        .collect();
    let reserved = sqlx::query_as::<_, ExistingUser>(
        "SELECT id, email, username, auth_mode, auth_provider_id, is_active, deleted_at IS NOT NULL AS deleted
         FROM users WHERE tenant_id = $1 AND deleted_at IS NULL AND lower(username) = ANY($2)")
        .bind(req.tenant_id).bind(usernames).fetch_all(&mut *tx).await.map_err(db_error)?;
    let mut report = rename_plan(&req, &candidates, &reserved);
    if !req.apply || report.conflicts > 0 {
        tx.rollback().await.map_err(db_error)?;
        return Ok(report);
    }
    for row in &report.rows {
        if row.action != "rename" {
            continue;
        }
        sqlx::query(
            "UPDATE users SET username = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
        )
        .bind(&row.new_username)
        .bind(row.id)
        .bind(req.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        sqlx::query(
            "INSERT INTO audit_events (action, resource_type, resource_id, outcome, details)
            VALUES ('admin.user.normalize_google_username', 'user', $1, 'success', $2)",
        )
        .bind(row.id)
        .bind(
            serde_json::json!({"tenant_id": req.tenant_id, "provider_id": provider.id,
                "old_username": row.old_username, "new_username": row.new_username}),
        )
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    }
    tx.commit().await.map_err(db_error)?;
    report.applied = true;
    Ok(report)
}

pub async fn normalize_google_usernames(
    State(db): State<DbPool>,
    Json(req): Json<NormalizeRequest>,
) -> axum::response::Response {
    match run_normalize(&db, req).await {
        Ok(report) => Json(report).into_response(),
        Err((status, description)) => (
            status,
            Json(ErrorResponse {
                error: "google_username_repair_failed".into(),
                error_description: description,
            }),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database in GOOGLE_IMPORT_TEST_DATABASE_URL"]
    async fn database_import_is_atomic_and_idempotent() {
        let url =
            std::env::var("GOOGLE_IMPORT_TEST_DATABASE_URL").expect("disposable test database URL");
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let migrations = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        sqlx::migrate::Migrator::new(migrations)
            .await
            .unwrap()
            .run(&db)
            .await
            .unwrap();
        let tenant = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, slug, name, mode) VALUES ($1, $2, 'Import test', 'single')",
        )
        .bind(tenant)
        .bind(format!("import-{tenant}"))
        .execute(&db)
        .await
        .unwrap();
        let provider_id = sqlx::query_scalar::<_, Uuid>("INSERT INTO identity_providers
            (tenant_id, slug, provider_type, issuer, client_id, client_secret_encrypted)
            VALUES ($1, 'google', 'google', 'https://accounts.google.com', 'test', 'test') RETURNING id")
            .bind(tenant).fetch_one(&db).await.unwrap();
        let mut req = request();
        req.tenant_id = tenant;
        let preview = run(&db, req).await.unwrap();
        assert_eq!(preview.create, 1);
        assert!(!preview.applied);
        let count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 0);
        let mut req = request();
        req.tenant_id = tenant;
        req.apply = true;
        req.approve = true;
        assert!(run(&db, req).await.unwrap().applied);
        let (password, disabled, mode, provider, username): (
            Option<String>,
            bool,
            String,
            Option<Uuid>,
            String,
        ) = sqlx::query_as(
            "SELECT password_hash, password_disabled, auth_mode, auth_provider_id, username
                FROM users WHERE tenant_id = $1 AND email = 'a@example.com'",
        )
        .bind(tenant)
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(password.is_none() && disabled);
        assert_eq!(mode, "federated");
        assert_eq!(provider, Some(provider_id));
        assert_eq!(username, "a");
        let (status, approved, verified): (String, bool, Option<bool>) = sqlx::query_as(
            "SELECT approval_status, approved_at IS NOT NULL, email_verified FROM user_identities WHERE tenant_id = $1")
            .bind(tenant).fetch_one(&db).await.unwrap();
        assert_eq!(status, "approved");
        assert!(approved);
        assert_eq!(verified, None);
        let groups = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_groups ug JOIN users u ON u.id = ug.user_id WHERE u.tenant_id = $1")
            .bind(tenant).fetch_one(&db).await.unwrap();
        assert_eq!(groups, 0);
        let mut req = request();
        req.tenant_id = tenant;
        req.apply = true;
        let repeat = run(&db, req).await.unwrap();
        assert_eq!(repeat.create, 0);
        assert_eq!(repeat.skip, 1);
        sqlx::query(
            "INSERT INTO users (tenant_id, username, email, auth_mode, password_hash)
            VALUES ($1, 'b', 'b@example.com', 'local', 'placeholder')",
        )
        .bind(tenant)
        .execute(&db)
        .await
        .unwrap();
        let mut req = request();
        req.tenant_id = tenant;
        req.apply = true;
        req.users[0].email = "b@example.com".into();
        req.users[0].google_id = "222".into();
        req.users.push(DirectoryUser {
            email: "c@example.com".into(),
            google_id: "333".into(),
            first_name: "C".into(),
            last_name: "Example".into(),
            is_active: true,
            suspended: false,
            archived: false,
        });
        let conflict = run(&db, req).await.unwrap();
        assert!(!conflict.applied);
        assert_eq!(conflict.conflicts, 1);
        let count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 2);
        // Force a late failure after user/identity insertion to verify rollback.
        sqlx::query("ALTER TABLE audit_events ADD CONSTRAINT reject_test_import CHECK (action <> 'admin.user.import_google') NOT VALID")
            .execute(&db).await.unwrap();
        let mut req = request();
        req.tenant_id = tenant;
        req.apply = true;
        req.users[0].email = "c@example.com".into();
        req.users[0].google_id = "333".into();
        assert!(run(&db, req).await.is_err());
        let count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 2);
        sqlx::query("ALTER TABLE audit_events DROP CONSTRAINT reject_test_import")
            .execute(&db)
            .await
            .unwrap();
        let mut req = request();
        req.tenant_id = tenant;
        req.apply = true;
        req.users[0].email = "c@example.com".into();
        req.users[0].google_id = "333".into();
        assert!(run(&db, req).await.unwrap().applied);
        let (status, approved): (String, bool) = sqlx::query_as(
            "SELECT approval_status, approved_at IS NOT NULL
            FROM user_identities WHERE tenant_id = $1 AND subject = '333'",
        )
        .bind(tenant)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(status, "pending");
        assert!(!approved);

        // Emulate the previous importer, then repair without changing identities/groups.
        sqlx::query(
            "UPDATE users SET username = email WHERE tenant_id = $1 AND auth_mode = 'federated'",
        )
        .bind(tenant)
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO users (tenant_id, username, email, auth_mode, auth_provider_id)
            VALUES ($1, 'user', 'user@example.com', 'federated', $2)",
        )
        .bind(tenant)
        .bind(provider_id)
        .execute(&db)
        .await
        .unwrap();
        let user_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM users WHERE tenant_id = $1 AND email = 'a@example.com'",
        )
        .bind(tenant)
        .fetch_one(&db)
        .await
        .unwrap();
        let group_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO groups (tenant_id, name) VALUES ($1, 'test-membership') RETURNING id",
        )
        .bind(tenant)
        .fetch_one(&db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)")
            .bind(user_id)
            .bind(group_id)
            .execute(&db)
            .await
            .unwrap();
        let identities_before = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT jsonb_agg(to_jsonb(ui) ORDER BY id) FROM user_identities ui WHERE tenant_id = $1")
            .bind(tenant).fetch_one(&db).await.unwrap();
        let preview = run_normalize(&db, normalize_request(tenant, false))
            .await
            .unwrap();
        assert!(!preview.applied);
        assert_eq!(preview.rename, 2);
        assert_eq!(preview.skip, 1);
        let reserved_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO users (tenant_id, username, email, auth_mode)
            VALUES ($1, 'C', 'reserved@example.com', 'local') RETURNING id",
        )
        .bind(tenant)
        .fetch_one(&db)
        .await
        .unwrap();
        let conflict = run_normalize(&db, normalize_request(tenant, true))
            .await
            .unwrap();
        assert!(!conflict.applied);
        assert_eq!(conflict.conflicts, 1);
        sqlx::query("UPDATE users SET deleted_at = NOW() WHERE id = $1")
            .bind(reserved_id)
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(
            run_normalize(&db, normalize_request(tenant, false))
                .await
                .unwrap()
                .conflicts,
            0
        );
        sqlx::query("ALTER TABLE audit_events ADD CONSTRAINT reject_test_rename CHECK (action <> 'admin.user.normalize_google_username') NOT VALID")
            .execute(&db).await.unwrap();
        assert!(
            run_normalize(&db, normalize_request(tenant, true))
                .await
                .is_err()
        );
        let old = sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(old, "a@example.com");
        sqlx::query("ALTER TABLE audit_events DROP CONSTRAINT reject_test_rename")
            .execute(&db)
            .await
            .unwrap();
        let applied = run_normalize(&db, normalize_request(tenant, true))
            .await
            .unwrap();
        assert!(applied.applied);
        assert_eq!(applied.rename, 2);
        let identities_after = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT jsonb_agg(to_jsonb(ui) ORDER BY id) FROM user_identities ui WHERE tenant_id = $1")
            .bind(tenant).fetch_one(&db).await.unwrap();
        assert_eq!(identities_before, identities_after);
        let membership = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM user_groups WHERE user_id = $1 AND group_id = $2",
        )
        .bind(user_id)
        .bind(group_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(membership, 1);
        let names: Vec<String> = sqlx::query_scalar("SELECT username FROM users WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY username")
            .bind(tenant).fetch_all(&db).await.unwrap();
        assert_eq!(names, ["a", "b", "c", "user"]);
        let repeat = run_normalize(&db, normalize_request(tenant, true))
            .await
            .unwrap();
        assert_eq!(repeat.rename, 0);
        assert_eq!(repeat.skip, 3);
        let mut scoped = normalize_request(tenant, false);
        scoped.emails.push(" A@EXAMPLE.COM ".into());
        assert_eq!(run_normalize(&db, scoped).await.unwrap().rows.len(), 1);
        assert!(
            run_normalize(&db, normalize_request(Uuid::new_v4(), true))
                .await
                .is_err()
        );
        db.close().await;
    }

    fn request() -> ImportRequest {
        serde_json::from_value(serde_json::json!({"tenant_id": Uuid::nil(), "provider": "google",
            "domain": "example.com", "users": [{"google_id": "123456789012345678901", "email": "a@example.com",
                "first_name": "A", "last_name": "Example", "is_active": true, "suspended": false, "archived": false}]})).unwrap()
    }

    fn normalize_request(tenant_id: Uuid, apply: bool) -> NormalizeRequest {
        NormalizeRequest {
            tenant_id,
            provider: "google".into(),
            domain: "example.com".into(),
            emails: vec![],
            apply,
        }
    }

    fn existing(email: &str, username: &str) -> ExistingUser {
        ExistingUser {
            id: Uuid::new_v4(),
            email: email.into(),
            username: username.into(),
            auth_mode: "federated".into(),
            auth_provider_id: Some(Uuid::new_v4()),
            is_active: true,
            deleted: false,
        }
    }

    #[test]
    fn short_import_username_checks_case_insensitive_collisions() {
        let req = request();
        let provider = provider();
        let report = plan(&req, &provider, &[], &[]);
        assert_eq!(report.rows[0].username, "a");
        let reserved = existing("someone@other.com", "A");
        assert_eq!(plan(&req, &provider, &[reserved], &[]).conflicts, 1);
        let mut reserved = existing("someone@other.com", "A");
        reserved.deleted = true;
        assert_eq!(plan(&req, &provider, &[reserved], &[]).conflicts, 0);
        let mut same_email = existing("a@example.com", "old-name");
        same_email.deleted = true;
        assert_eq!(plan(&req, &provider, &[same_email], &[]).conflicts, 1);
    }

    #[test]
    fn rename_plan_preserves_custom_names_and_rejects_collisions() {
        let req = normalize_request(Uuid::nil(), false);
        let candidates = [
            existing("user.one@example.com", "user.one@example.com"),
            existing("user@example.com", "user"),
        ];
        let plan = rename_plan(&req, &candidates, &[]);
        assert_eq!(plan.rename, 1);
        assert_eq!(plan.skip, 1);
        assert_eq!(plan.rows[0].new_username, "user.one");
        assert_eq!(plan.rows[1].new_username, "user");
        let reserved = existing("other@example.com", "USER.ONE");
        assert_eq!(rename_plan(&req, &candidates, &[reserved]).conflicts, 1);
        let mut reserved = existing("other@example.com", "USER.ONE");
        reserved.deleted = true;
        assert_eq!(rename_plan(&req, &candidates, &[reserved]).conflicts, 0);
        let duplicates = [
            existing("same@example.com", "same@example.com"),
            existing("SAME@example.com", "SAME@example.com"),
        ];
        assert_eq!(rename_plan(&req, &duplicates, &[]).conflicts, 2);
        let mut req = normalize_request(Uuid::nil(), false);
        req.emails.push("user@example.com".into());
        assert_eq!(rename_plan(&req, &candidates, &[]).rename, 0);
    }

    fn provider() -> Provider {
        Provider {
            id: Uuid::new_v4(),
            issuer: "https://accounts.google.com".into(),
            hd_domain: None,
        }
    }

    #[test]
    fn preview_defaults_and_inactive_selection() {
        let mut req = request();
        validate(&mut req).unwrap();
        assert!(!req.apply && !req.approve);
        let report = plan(&req, &provider(), &[], &[]);
        assert_eq!(report.create, 1);
        assert_eq!(report.approval_status, "pending");
        req.users[0].suspended = true;
        assert!(validate(&mut req).is_err());
        req.users[0].is_active = false;
        validate(&mut req).unwrap();
        assert_eq!(plan(&req, &provider(), &[], &[]).skip, 1);
        req.emails.push("missing@example.com".into());
        assert!(validate(&mut req).is_err());
    }

    #[test]
    fn rejects_duplicate_and_foreign_records() {
        let mut req = request();
        req.users[0].email = "A@EXAMPLE.COM".into();
        validate(&mut req).unwrap();
        assert_eq!(req.users[0].email, "a@example.com");
        req.users.push(DirectoryUser {
            google_id: "456".into(),
            email: "a@example.com".into(),
            first_name: "".into(),
            last_name: "".into(),
            is_active: true,
            suspended: false,
            archived: false,
        });
        assert!(validate(&mut req).is_err());
        req.users.pop();
        req.users[0].email = "a@other.com".into();
        assert!(validate(&mut req).is_err());
        req.users[0].email = "a@example.com".into();
        req.users[0].google_id = "1e20".into();
        assert!(validate(&mut req).is_err());
    }

    #[test]
    fn never_converts_or_approves_existing_accounts() {
        let req = request();
        let provider = provider();
        let mut existing = ExistingUser {
            id: Uuid::new_v4(),
            email: "a@example.com".into(),
            username: "a".into(),
            auth_mode: "local".into(),
            auth_provider_id: None,
            is_active: true,
            deleted: false,
        };
        assert_eq!(plan(&req, &provider, &[existing], &[]).conflicts, 1);
        existing = ExistingUser {
            id: Uuid::new_v4(),
            email: "a@example.com".into(),
            username: "a".into(),
            auth_mode: "federated".into(),
            auth_provider_id: Some(provider.id),
            is_active: true,
            deleted: false,
        };
        let identity = Identity {
            user_id: existing.id,
            idp_id: provider.id,
            issuer: provider.issuer.clone(),
            subject: req.users[0].google_id.clone(),
            approval_status: "pending".into(),
        };
        let report = plan(&req, &provider, &[existing], &[identity]);
        assert_eq!(report.skip, 1);
        assert!(report.rows[0].detail.contains("pending"));
    }

    #[test]
    fn rejects_subject_owned_by_another_user() {
        let req = request();
        let provider = provider();
        let identity = Identity {
            user_id: Uuid::new_v4(),
            idp_id: provider.id,
            issuer: provider.issuer.clone(),
            subject: req.users[0].google_id.clone(),
            approval_status: "approved".into(),
        };
        assert_eq!(plan(&req, &provider, &[], &[identity]).conflicts, 1);
    }
}
