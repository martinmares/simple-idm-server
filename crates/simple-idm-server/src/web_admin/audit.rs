use super::*;
use sqlx::{Postgres, QueryBuilder};

const PAGE_SIZE: i64 = 50;
const EXPORT_LIMIT: i64 = 10_000;

#[derive(Debug, Default, Deserialize)]
pub(super) struct AuditQuery {
    message: Option<String>,
    error: Option<String>,
    action: Option<String>,
    resource_type: Option<String>,
    outcome: Option<String>,
    q: Option<String>,
    range: Option<String>,
    from: Option<String>,
    to: Option<String>,
    actor: Option<String>,
    client: Option<String>,
    target: Option<String>,
    snapshot: Option<String>,
    before: Option<String>,
    after: Option<String>,
    format: Option<String>,
}

#[derive(Clone)]
struct Filters {
    action: String,
    resource_type: String,
    outcome: String,
    q: String,
    range: String,
    actor: String,
    client: String,
    target: String,
    from: Option<DateTime<Utc>>,
    to: DateTime<Utc>,
    snapshot: DateTime<Utc>,
}

fn date(raw: &str) -> Result<DateTime<Utc>, &'static str> {
    DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .or_else(|_| {
            NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S%.f").map(|value| value.and_utc())
        })
        .or_else(|_| {
            NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M").map(|value| value.and_utc())
        })
        .map_err(|_| "Invalid date. Use an ISO date and time; dates without an offset are UTC.")
}

fn text_filter(raw: &Option<String>) -> String {
    raw.as_deref().unwrap_or_default().trim().to_string()
}

impl Filters {
    fn new(query: &AuditQuery) -> Result<Self, &'static str> {
        let now = Utc::now();
        let snapshot = query
            .snapshot
            .as_deref()
            .filter(|v| !v.is_empty())
            .map(date)
            .transpose()?
            .unwrap_or(now)
            .min(now);
        let range = query.range.as_deref().unwrap_or("24h");
        let duration = match range {
            "1h" => Some(chrono::Duration::hours(1)),
            "24h" => Some(chrono::Duration::hours(24)),
            "7d" => Some(chrono::Duration::days(7)),
            "30d" => Some(chrono::Duration::days(30)),
            "all" | "custom" => None,
            _ => return Err("Invalid time range."),
        };
        let from_raw = text_filter(&query.from);
        let to_raw = text_filter(&query.to);
        let custom = !from_raw.is_empty() || !to_raw.is_empty() || range == "custom";
        let from = if custom {
            if from_raw.is_empty() {
                None
            } else {
                Some(date(&from_raw)?)
            }
        } else {
            duration.map(|duration| snapshot - duration)
        };
        let to = if custom && !to_raw.is_empty() {
            date(&to_raw)?.min(snapshot)
        } else {
            snapshot
        };
        if from.is_some_and(|from| from > to) {
            return Err("From must be earlier than or equal to To (UTC).");
        }
        let outcome = text_filter(&query.outcome);
        if !matches!(outcome.as_str(), "" | "success" | "failure") {
            return Err("Invalid outcome.");
        }
        Ok(Self {
            action: text_filter(&query.action),
            resource_type: text_filter(&query.resource_type),
            outcome,
            q: text_filter(&query.q),
            range: if custom {
                "custom".into()
            } else {
                range.into()
            },
            actor: text_filter(&query.actor),
            client: text_filter(&query.client),
            target: text_filter(&query.target),
            from,
            to,
            snapshot,
        })
    }

    fn predicates(&self, sql: &mut QueryBuilder<Postgres>) {
        sql.push(" WHERE created_at <= ").push_bind(self.to);
        if let Some(from) = self.from {
            sql.push(" AND created_at >= ").push_bind(from);
        }
        for (column, value) in [
            ("action", &self.action),
            ("resource_type", &self.resource_type),
            ("actor_sub", &self.actor),
            ("actor_client_id", &self.client),
            ("resource_id::text", &self.target),
        ] {
            if !value.is_empty() {
                sql.push(" AND ")
                    .push(column)
                    .push(" ILIKE ")
                    .push_bind(lists::literal_pattern(value));
            }
        }
        if !self.outcome.is_empty() {
            sql.push(" AND outcome = ").push_bind(self.outcome.clone());
        }
        if !self.q.is_empty() {
            sql.push(" AND (");
            for (i, column) in [
                "action",
                "resource_type",
                "resource_id::text",
                "actor_sub",
                "actor_client_id",
                "details::text",
            ]
            .iter()
            .enumerate()
            {
                if i > 0 {
                    sql.push(" OR ");
                }
                sql.push(*column)
                    .push(" ILIKE ")
                    .push_bind(lists::literal_pattern(&self.q));
            }
            sql.push(")");
        }
    }

    fn url(&self, path: &str, extra: Option<(&str, String)>) -> String {
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        // Freeze rolling time ranges while paging or exporting.
        params
            .append_pair("range", "custom")
            .append_pair("to", &self.to.to_rfc3339())
            .append_pair("snapshot", &self.snapshot.to_rfc3339());
        if let Some(from) = self.from {
            params.append_pair("from", &from.to_rfc3339());
        }
        for (key, value) in [
            ("action", &self.action),
            ("resource_type", &self.resource_type),
            ("outcome", &self.outcome),
            ("q", &self.q),
            ("actor", &self.actor),
            ("client", &self.client),
            ("target", &self.target),
        ] {
            if !value.is_empty() {
                params.append_pair(key, value);
            }
        }
        if let Some((key, value)) = extra {
            params.append_pair(key, &value);
        }
        format!("{path}?{}", params.finish())
    }
}

#[derive(Debug, Clone, FromRow)]
struct Event {
    id: Uuid,
    created_at: DateTime<Utc>,
    action: String,
    resource_type: String,
    resource_id: Option<Uuid>,
    outcome: String,
    actor_sub: Option<String>,
    actor_client_id: Option<String>,
    details: Option<serde_json::Value>,
}

impl Event {
    fn cursor(&self) -> String {
        format!("{}|{}", self.created_at.to_rfc3339(), self.id)
    }
    fn time(&self) -> String {
        self.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }
    fn actor_label(&self) -> &'static str {
        match self.actor_kind() {
            "recorded" => "Recorded actor",
            "root_token" => "Root token",
            _ => "Unknown actor",
        }
    }
    fn actor_kind(&self) -> &'static str {
        if self.actor_sub.is_some() || self.actor_client_id.is_some() {
            "recorded"
        } else if self
            .details
            .as_ref()
            .and_then(|d| d.get("actor_kind"))
            .and_then(|v| v.as_str())
            == Some("root_token")
        {
            "root_token"
        } else {
            "unknown"
        }
    }
    fn description(&self) -> String {
        match self.action.as_str() {
            "auth.login" => "Password sign-in".into(),
            "auth.login.federated" => "Federated sign-in".into(),
            "auth.passkey.login" => "Passkey sign-in".into(),
            "auth.mfa.verify" => "MFA verification".into(),
            "auth.mfa.required" => "MFA challenge required".into(),
            "auth.mfa.enroll" => "MFA enrollment".into(),
            "oauth.token.issue" => "Access token issued".into(),
            "oauth.token.refresh" => "Access token refreshed".into(),
            "auth.device.approve" => "Device sign-in approved".into(),
            _ => self
                .action
                .trim_start_matches("admin.")
                .replace(['.', '_'], " "),
        }
    }
    fn details_display(&self) -> String {
        // Exports intentionally omit details; redact obvious credential keys in the UI too.
        fn redact(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::Object(fields) => {
                    for (key, value) in fields {
                        let key = key.to_ascii_lowercase();
                        if [
                            "password",
                            "secret",
                            "token",
                            "authorization",
                            "cookie",
                            "private_key",
                            "recovery_code",
                        ]
                        .iter()
                        .any(|word| key.contains(word))
                            && key != "actor_kind"
                        {
                            *value = json!("[redacted]");
                        } else {
                            redact(value);
                        }
                    }
                }
                serde_json::Value::Array(values) => {
                    for value in values {
                        redact(value);
                    }
                }
                _ => {}
            }
        }
        let mut details = self.details.clone().unwrap_or(serde_json::Value::Null);
        redact(&mut details);
        serde_json::to_string_pretty(&details).unwrap_or_default()
    }
}

#[derive(Default, FromRow)]
struct Summary {
    total: i64,
    succeeded: i64,
    failed: i64,
    unknown: i64,
}

#[derive(FromRow)]
struct ActionCount {
    action: String,
    count: i64,
}

#[derive(Template)]
#[template(path = "admin/audit.html")]
struct AuditTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<Event>,
    filters: Filters,
    summary: Summary,
    actions: Vec<ActionCount>,
    newer: String,
    older: String,
    csv_url: String,
    json_url: String,
    from_input: String,
    to_input: String,
    range_label: String,
}

fn cursor(raw: &str) -> Result<(DateTime<Utc>, Uuid), &'static str> {
    let (time, id) = raw.split_once('|').ok_or("Invalid audit cursor.")?;
    Ok((
        date(time)?,
        Uuid::parse_str(id).map_err(|_| "Invalid audit cursor.")?,
    ))
}

pub(super) async fn page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let filters = match Filters::new(&query) {
        Ok(filters) => filters,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    let boundary = match (&query.before, &query.after) {
        (Some(_), Some(_)) => {
            return (StatusCode::BAD_REQUEST, "Use one paging direction.").into_response();
        }
        (Some(raw), None) | (None, Some(raw)) => match cursor(raw) {
            Ok(value) => Some(value),
            Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
        },
        _ => None,
    };
    let result = load_page(&state.db_pool, &filters, boundary, query.after.is_some()).await;
    let (rows, summary, actions, more) = match result {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, "Could not load audit");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not load audit events.",
            )
                .into_response();
        }
    };
    let newer = if (query.before.is_some() || (query.after.is_some() && more)) && !rows.is_empty() {
        filters.url("/admin/ui/audit", Some(("after", rows[0].cursor())))
    } else {
        String::new()
    };
    let older = if (query.after.is_some() || more) && !rows.is_empty() {
        filters.url(
            "/admin/ui/audit",
            Some(("before", rows.last().unwrap().cursor())),
        )
    } else {
        String::new()
    };
    let from_input = filters
        .from
        .map(|v| v.format("%Y-%m-%dT%H:%M:%S%.6f").to_string())
        .unwrap_or_default();
    let to_input = filters.to.format("%Y-%m-%dT%H:%M:%S%.6f").to_string();
    let range_label = format!(
        "{} → {}",
        filters
            .from
            .map(|v| v.to_rfc3339())
            .unwrap_or("Beginning of history".into()),
        filters.to.to_rfc3339()
    );
    let csv_url = filters.url("/admin/ui/audit/export", Some(("format", "csv".into())));
    let json_url = filters.url("/admin/ui/audit/export", Some(("format", "json".into())));
    render_template(AuditTemplate {
        sections: nav_items(AdminSection::Audit),
        message: query.message,
        error: query.error,
        rows,
        filters,
        summary,
        actions,
        newer,
        older,
        csv_url,
        json_url,
        from_input,
        to_input,
        range_label,
    })
}

#[cfg(test)]
pub(super) fn fixture() -> String {
    let filters = Filters::new(&AuditQuery::default()).unwrap();
    let rows = vec![
        Event {
            id: Uuid::from_u128(101),
            created_at: filters.to,
            action: "auth.login".into(),
            resource_type: "user".into(),
            resource_id: Some(Uuid::from_u128(10)),
            outcome: "failure".into(),
            actor_sub: None,
            actor_client_id: None,
            details: Some(json!({"reason":"Invalid credentials", "password":"must-not-appear"})),
        },
        Event {
            id: Uuid::from_u128(102),
            created_at: filters.to,
            action: "user.archive".into(),
            resource_type: "user".into(),
            resource_id: Some(Uuid::from_u128(11)),
            outcome: "success".into(),
            actor_sub: None,
            actor_client_id: None,
            details: Some(json!({"actor_kind":"root_token"})),
        },
        Event {
            id: Uuid::from_u128(103),
            created_at: filters.to,
            action: "auth.mfa.verify".into(),
            resource_type: "user".into(),
            resource_id: Some(Uuid::from_u128(10)),
            outcome: "success".into(),
            actor_sub: Some("verified-subject".into()),
            actor_client_id: Some("cli-tools".into()),
            details: None,
        },
    ];
    AuditTemplate {
        sections: nav_items(AdminSection::Audit),
        message: None,
        error: None,
        csv_url: filters.url("/admin/ui/audit/export", Some(("format", "csv".into()))),
        json_url: filters.url("/admin/ui/audit/export", Some(("format", "json".into()))),
        rows,
        summary: Summary {
            total: 203,
            succeeded: 201,
            failed: 2,
            unknown: 1,
        },
        actions: vec![ActionCount {
            action: "auth.login".into(),
            count: 100,
        }],
        newer: String::new(),
        older: filters.url(
            "/admin/ui/audit",
            Some((
                "before",
                format!("{}|{}", filters.to.to_rfc3339(), Uuid::from_u128(103)),
            )),
        ),
        from_input: filters
            .from
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string(),
        to_input: filters.to.format("%Y-%m-%dT%H:%M:%S").to_string(),
        range_label: "Fixture time range (UTC)".into(),
        filters,
    }
    .render()
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_cursors_and_spreadsheet_cells() {
        assert_eq!(
            date("2026-10-14T10:00:00+02:00").unwrap(),
            date("2026-10-14T08:00").unwrap()
        );
        assert!(date("yesterday").is_err());
        assert!(cursor("broken").is_err());
        assert!(
            Filters::new(&AuditQuery {
                from: Some("2026-01-02T00:00".into()),
                to: Some("2026-01-01T00:00".into()),
                ..Default::default()
            })
            .is_err()
        );
        for dangerous in ["=HYPERLINK(\"example\")", "  +2", "\t@SUM(1)", "\r-1"] {
            assert!(csv_cell(dangerous).starts_with('\''));
        }
        assert_eq!(csv_cell("user.archive"), "user.archive");
    }

    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "sidm_admin_session=test-session".parse().unwrap(),
        );
        headers
    }

    async fn body(response: Response) -> String {
        String::from_utf8(
            axum::body::to_bytes(response.into_body(), 10_000_000)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }

    #[tokio::test]
    #[ignore = "requires disposable ADMIN_UI_TEST_DATABASE_URL"]
    async fn audit_range_cursor_summary_and_safe_exports() {
        let pool = DbPool::connect(&std::env::var("ADMIN_UI_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        simple_idm_core::db::run_migrations(&pool).await.unwrap();
        let state = super::super::ui_database_tests::state(pool.clone()).await;
        let prefix = format!("audit-{}", Uuid::new_v4());
        let time = Utc::now() - chrono::Duration::minutes(10);
        let target = Uuid::new_v4();
        let mut ids = vec![];
        for n in 0..205 {
            let id = Uuid::new_v4();
            ids.push(id);
            sqlx::query("INSERT INTO audit_events (id,created_at,action,resource_type,resource_id,outcome,actor_sub,actor_client_id,details) VALUES ($1,$2,$3,'user',$4,$5,$6,$7,$8)")
                .bind(id).bind(time).bind(&prefix).bind(target).bind(if n % 2 == 0 { "success" } else { "failure" })
                .bind(if n % 2 == 0 { Some("=actor-formula") } else { None }).bind(if n % 2 == 0 { Some("cli-tools") } else { None })
                .bind(json!({"password":"SECRET-PASSWORD", "nested":{"access_token":"SECRET-TOKEN"},"marker":"literal%_marker"}))
                .execute(&pool).await.unwrap();
        }
        ids.sort_by(|a, b| b.cmp(a));
        let query = AuditQuery {
            range: Some("all".into()),
            action: Some(prefix.clone()),
            ..Default::default()
        };
        let filters = Filters::new(&query).unwrap();
        let (rows, summary, _, more) = load_page(&pool, &filters, None, false).await.unwrap();
        assert!(more);
        assert_eq!(rows.len(), 50);
        assert_eq!(summary.total, 205);
        assert_eq!(summary.succeeded, 103);
        assert_eq!(summary.failed, 102);
        assert_eq!(summary.unknown, 102);
        assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), ids[..50]);
        let mut seen = vec![];
        let mut boundary = None;
        loop {
            let (page, total, _, more) = load_page(&pool, &filters, boundary, false).await.unwrap();
            assert_eq!(total.total, 205);
            boundary = page.last().map(|r| (r.created_at, r.id));
            seen.extend(page.iter().map(|r| r.id));
            if !more {
                break;
            }
        }
        assert_eq!(seen, ids); // Every event, including those beyond the former 200-event limit.
        let (newer, _, _, more) = load_page(&pool, &filters, Some((time, ids[50])), true)
            .await
            .unwrap();
        assert!(!more);
        assert_eq!(newer.iter().map(|r| r.id).collect::<Vec<_>>(), ids[..50]);
        sqlx::query(
            "INSERT INTO audit_events (action,resource_type,outcome) VALUES ($1,'user','success')",
        )
        .bind(&prefix)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            load_page(&pool, &filters, None, false)
                .await
                .unwrap()
                .1
                .total,
            205
        );

        let html = body(page(State(state.clone()), headers(), Query(query)).await).await;
        assert!(html.contains("data-audit-total=\"206\""));
        assert!(html.contains("Unknown actor"));
        assert!(!html.contains("SECRET-PASSWORD"));
        assert!(!html.contains("SECRET-TOKEN"));
        let filtered = Filters::new(&AuditQuery {
            action: Some(prefix.clone()),
            actor: Some("=actor-formula".into()),
            client: Some("cli-tools".into()),
            target: Some(target.to_string()),
            q: Some("literal%_marker".into()),
            range: Some("all".into()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            load_page(&pool, &filtered, None, false)
                .await
                .unwrap()
                .1
                .total,
            103
        );
        let frozen_url = filters.url("/admin/ui/audit/export", Some(("format", "json".into())));
        let parsed: AuditQuery =
            serde_urlencoded::from_str(frozen_url.split_once('?').unwrap().1).unwrap();
        let response = export(State(state.clone()), headers(), Query(parsed)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let json_text = body(response).await;
        let json: serde_json::Value = serde_json::from_str(&json_text).unwrap();
        assert_eq!(json["count"], 205);
        assert_eq!(json["events"].as_array().unwrap().len(), 205);
        assert!(!json_text.contains("SECRET-"));
        assert!(!json_text.contains("literal%_marker"));
        let csv_query = AuditQuery {
            action: Some(prefix.clone()),
            range: Some("all".into()),
            format: Some("csv".into()),
            ..Default::default()
        };
        let csv = body(export(State(state.clone()), headers(), Query(csv_query)).await).await;
        let records: Vec<_> = csv::Reader::from_reader(csv.as_bytes())
            .records()
            .map(Result::unwrap)
            .collect();
        assert_eq!(records.len(), 206);
        let root_action = format!("{prefix}-root");
        simple_idm_core::audit::emit_event_as(
            &pool,
            &simple_idm_core::audit::Actor {
                root_token: true,
                ..Default::default()
            },
            &root_action,
            "user",
            Some(target),
            "success",
            Some(json!({"password":"SECRET-ROOT"})),
        )
        .await;
        let root_json = body(
            export(
                State(state.clone()),
                headers(),
                Query(AuditQuery {
                    action: Some(root_action),
                    range: Some("all".into()),
                    format: Some("json".into()),
                    ..Default::default()
                }),
            )
            .await,
        )
        .await;
        let root: serde_json::Value = serde_json::from_str(&root_json).unwrap();
        assert_eq!(root["events"][0]["actor_kind"], "root_token");
        assert!(root["events"][0]["actor_sub"].is_null());
        assert!(!root_json.contains("SECRET-ROOT"));
        assert!(
            records
                .iter()
                .any(|row| row.get(6) == Some("'=actor-formula"))
        );
        assert_eq!(
            export(
                State(state.clone()),
                HeaderMap::new(),
                Query(AuditQuery::default())
            )
            .await
            .status(),
            StatusCode::SEE_OTHER
        );
        assert_eq!(
            page(
                State(state.clone()),
                headers(),
                Query(AuditQuery {
                    before: Some("invalid".into()),
                    ..Default::default()
                })
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        sqlx::query("INSERT INTO audit_events (action,resource_type,outcome) SELECT $1,'user','success' FROM generate_series(1,10001)").bind(format!("{prefix}-oversize")).execute(&pool).await.unwrap();
        let response = export(
            State(state),
            headers(),
            Query(AuditQuery {
                action: Some(format!("{prefix}-oversize")),
                range: Some("all".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        sqlx::query("DELETE FROM audit_events WHERE action LIKE $1")
            .bind(format!("{prefix}%"))
            .execute(&pool)
            .await
            .unwrap();
    }
}

async fn load_page(
    pool: &DbPool,
    filters: &Filters,
    boundary: Option<(DateTime<Utc>, Uuid)>,
    ascending: bool,
) -> Result<(Vec<Event>, Summary, Vec<ActionCount>, bool), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let mut sql = QueryBuilder::new(
        "SELECT count(*) AS total, count(*) FILTER (WHERE outcome='success') AS succeeded, count(*) FILTER (WHERE outcome='failure') AS failed, count(*) FILTER (WHERE actor_sub IS NULL AND actor_client_id IS NULL AND COALESCE(details->>'actor_kind','') <> 'root_token') AS unknown FROM audit_events",
    );
    filters.predicates(&mut sql);
    let summary = sql.build_query_as::<Summary>().fetch_one(&mut *tx).await?;
    let mut sql = QueryBuilder::new("SELECT action, count(*) AS count FROM audit_events");
    filters.predicates(&mut sql);
    sql.push(" GROUP BY action ORDER BY count DESC, action LIMIT 5");
    let actions = sql
        .build_query_as::<ActionCount>()
        .fetch_all(&mut *tx)
        .await?;
    let mut sql = QueryBuilder::new(
        "SELECT id,created_at,action,resource_type,resource_id,outcome,actor_sub,actor_client_id,details FROM audit_events",
    );
    filters.predicates(&mut sql);
    if let Some((time, id)) = boundary {
        sql.push(if ascending {
            " AND (created_at,id) > ("
        } else {
            " AND (created_at,id) < ("
        })
        .push_bind(time)
        .push(",")
        .push_bind(id)
        .push(")");
    }
    sql.push(if ascending {
        " ORDER BY created_at ASC,id ASC"
    } else {
        " ORDER BY created_at DESC,id DESC"
    })
    .push(" LIMIT ")
    .push_bind(PAGE_SIZE + 1);
    let mut rows = sql.build_query_as::<Event>().fetch_all(&mut *tx).await?;
    let more = rows.len() > PAGE_SIZE as usize;
    rows.truncate(PAGE_SIZE as usize);
    if ascending {
        rows.reverse();
    }
    tx.commit().await?;
    Ok((rows, summary, actions, more))
}

fn csv_cell(value: &str) -> String {
    // Neutralize formulas even when preceded by whitespace/control characters.
    if value
        .trim_start_matches(|c: char| c.is_whitespace() || c.is_control())
        .starts_with(['=', '+', '-', '@'])
        || value.starts_with(['\t', '\r', '\n'])
    {
        format!("'{value}")
    } else {
        value.into()
    }
}

pub(super) async fn export(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let format = query.format.as_deref().unwrap_or("csv");
    if !matches!(format, "csv" | "json") {
        return (StatusCode::BAD_REQUEST, "Choose CSV or JSON.").into_response();
    }
    let filters = match Filters::new(&query) {
        Ok(filters) => filters,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    let mut sql = QueryBuilder::new(
        "SELECT id,created_at,action,resource_type,resource_id,outcome,actor_sub,actor_client_id,CASE WHEN details->>'actor_kind'='root_token' THEN '{\"actor_kind\":\"root_token\"}'::jsonb ELSE NULL::jsonb END AS details FROM audit_events",
    );
    filters.predicates(&mut sql);
    sql.push(" ORDER BY created_at DESC,id DESC LIMIT ")
        .push_bind(EXPORT_LIMIT + 1);
    let rows = match sql
        .build_query_as::<Event>()
        .fetch_all(&state.db_pool)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(%error, "Could not export audit");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not export audit events.",
            )
                .into_response();
        }
    };
    if rows.len() > EXPORT_LIMIT as usize {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Export exceeds 10,000 events. Narrow the filters; no partial export was created.",
        )
            .into_response();
    }
    let body = if format == "json" {
        serde_json::to_vec_pretty(&json!({"from": filters.from, "to": filters.to, "timezone": "UTC", "count": rows.len(), "details_included": false,
            "filters": {"action":filters.action,"resource_type":filters.resource_type,"outcome":filters.outcome,"actor":filters.actor,"client":filters.client,"target":filters.target,"q":filters.q},
            "events": rows.iter().map(|r| json!({"id":r.id,"created_at":r.created_at,"action":r.action,"resource_type":r.resource_type,"resource_id":r.resource_id,"outcome":r.outcome,"actor_sub":r.actor_sub,"actor_client_id":r.actor_client_id,"actor_kind":r.actor_kind()})).collect::<Vec<_>>() })).unwrap()
    } else {
        let mut writer = csv::Writer::from_writer(Vec::new());
        writer
            .write_record([
                "event_id",
                "created_at_utc",
                "action",
                "resource_type",
                "resource_id",
                "outcome",
                "actor_sub",
                "actor_client_id",
                "actor_kind",
            ])
            .unwrap();
        for r in &rows {
            writer
                .write_record([
                    r.id.to_string(),
                    r.created_at.to_rfc3339(),
                    csv_cell(&r.action),
                    csv_cell(&r.resource_type),
                    r.resource_id.map(|id| id.to_string()).unwrap_or_default(),
                    csv_cell(&r.outcome),
                    csv_cell(r.actor_sub.as_deref().unwrap_or_default()),
                    csv_cell(r.actor_client_id.as_deref().unwrap_or_default()),
                    r.actor_kind().to_string(),
                ])
                .unwrap();
        }
        writer.into_inner().unwrap()
    };
    (
        [
            (
                header::CONTENT_TYPE,
                if format == "json" {
                    "application/json"
                } else {
                    "text/csv; charset=utf-8"
                }
                .to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename=\"audit-{}.{}\"",
                    filters.to.format("%Y%m%dT%H%M%SZ"),
                    format
                ),
            ),
            (header::CACHE_CONTROL, "no-store".into()),
        ],
        body,
    )
        .into_response()
}
