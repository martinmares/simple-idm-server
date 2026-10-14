use super::*;
use std::collections::HashSet;

pub(super) const MAX_BATCH: usize = 100;

#[derive(Debug, Deserialize)]
pub(super) struct BulkForm {
    pub(super) ids: String,
    pub(super) action: String,
    pub(super) group_id: Option<Uuid>,
}

impl BulkForm {
    fn audit_action(&self, users: bool) -> &'static str {
        if self.action == "add_group" {
            "user.group.assign"
        } else if users {
            "user.archive"
        } else {
            "group.archive"
        }
    }
}

fn parse_ids(raw: &str) -> Result<Vec<Uuid>, &'static str> {
    let parts: Vec<_> = raw.split(',').collect();
    if parts.is_empty() || parts.len() > MAX_BATCH {
        return Err("Select between 1 and 100 objects.");
    }
    let mut seen = HashSet::new();
    let mut ids = Vec::new();
    for part in parts {
        let id = Uuid::parse_str(part.trim()).map_err(|_| "Invalid object ID.")?;
        if seen.insert(id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

struct BatchAudit<'a> {
    id: Uuid,
    actor_sub: Option<&'a str>,
    actor_client: Option<&'a str>,
}

impl BatchAudit<'_> {
    async fn record_failure(
        &self,
        pool: &DbPool,
        form: &BulkForm,
        users: bool,
        id: Uuid,
        reason: &str,
    ) {
        let event = sqlx::query("INSERT INTO audit_events (action, resource_type, resource_id, outcome, actor_sub, actor_client_id, details) VALUES ($1,$2,$3,'failure',$4,$5,$6)")
            .bind(form.audit_action(users)).bind(if users { "user" } else { "group" })
            .bind(id).bind(self.actor_sub).bind(self.actor_client)
            .bind(json!({"batch_id": self.id, "changed": false, "reason": reason, "group_id": form.group_id,
                "actor_kind": if self.actor_sub.is_some() { "oauth" } else { "root_token" }}))
            .execute(pool).await;
        if let Err(error) = event {
            tracing::warn!(batch_id=%self.id, %id, %error, "Could not audit failed bulk action");
        }
    }
}

struct BatchRow {
    id: Uuid,
    name: String,
    status: &'static str,
    reason: &'static str,
}

#[derive(Template)]
#[template(path = "admin/bulk_result.html")]
struct BatchTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    batch_id: Uuid,
    rows: Vec<BatchRow>,
    succeeded: usize,
    skipped: usize,
    failed: usize,
    return_path: String,
}

pub(super) async fn users_bulk(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<BulkForm>,
) -> Response {
    handle(state, headers, form, true).await
}

pub(super) async fn groups_bulk(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<BulkForm>,
) -> Response {
    handle(state, headers, form, false).await
}

async fn handle(state: WebAdminState, headers: HeaderMap, form: BulkForm, users: bool) -> Response {
    let token = match require_admin_token(&state, &headers).await {
        Ok(token) => token,
        Err(redirect) => return redirect.into_response(),
    };
    let path = if users {
        users_return_path_from_referer(&headers)
    } else {
        q_return_path_from_referer(&headers, "/admin/ui/groups", "/admin/ui/groups")
    };
    if form.action != "archive" && !(users && form.action == "add_group" && form.group_id.is_some())
    {
        return redirect_with(&path, "error", "Invalid bulk action").into_response();
    }
    let ids = match parse_ids(&form.ids) {
        Ok(ids) => ids,
        Err(error) => return redirect_with(&path, "error", error).into_response(),
    };
    // A configured root token has no user subject. Never invent one or store the token.
    let Some(actor) = state.admin_auth.audit_actor(&token) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let actor_sub = actor.subject.as_deref();
    let actor_client = actor.client_id.as_deref();
    let batch_id = Uuid::new_v4();
    let audit = BatchAudit {
        id: batch_id,
        actor_sub,
        actor_client,
    };
    let mut rows = Vec::new();
    for id in ids {
        // A previous object may have removed this actor's permissions. Recheck before each write.
        if !validate_admin_token(&state, &token).await {
            audit
                .record_failure(&state.db_pool, &form, users, id, "authorization_expired")
                .await;
            rows.push(BatchRow {
                id,
                name: id.to_string(),
                status: "Skipped",
                reason: "Admin authorization is no longer valid.",
            });
            continue;
        }
        let result = apply_one(
            &state.db_pool,
            default_tenant_id(),
            id,
            users,
            &form,
            &audit,
        )
        .await;
        rows.push(match result {
            Ok(row) => row,
            Err(error) => {
                tracing::warn!(%batch_id, %id, %error, "Bulk action failed");
                // The mutation transaction has rolled back. Record the failed attempt separately.
                audit
                    .record_failure(&state.db_pool, &form, users, id, "transaction_failed")
                    .await;
                BatchRow {
                    id,
                    name: id.to_string(),
                    status: "Failed",
                    reason: "Change was rolled back. Check server logs using the batch ID.",
                }
            }
        });
    }
    render_template(BatchTemplate {
        sections: nav_items(if users {
            AdminSection::Users
        } else {
            AdminSection::Groups
        }),
        message: None,
        error: None,
        batch_id,
        succeeded: rows.iter().filter(|row| row.status == "Success").count(),
        skipped: rows.iter().filter(|row| row.status == "Skipped").count(),
        failed: rows.iter().filter(|row| row.status == "Failed").count(),
        rows,
        return_path: path,
    })
}

// Each object and its audit event commit together. Other objects may still succeed.
async fn apply_one(
    pool: &DbPool,
    tenant: Uuid,
    id: Uuid,
    users: bool,
    form: &BulkForm,
    audit: &BatchAudit<'_>,
) -> Result<BatchRow, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let query = if users {
        "SELECT username FROM users WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL FOR UPDATE"
    } else {
        "SELECT name FROM groups WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL FOR UPDATE"
    };
    let name = sqlx::query_scalar::<_, String>(query)
        .bind(id)
        .bind(tenant)
        .fetch_optional(&mut *tx)
        .await?;
    let exists = name.is_some();
    let mut reason = "Change saved and audited.";
    let affected = if !exists {
        reason = "Object is archived, missing, or outside this tenant.";
        0
    } else if form.action == "add_group" {
        let group = sqlx::query_scalar::<_, Uuid>("SELECT id FROM groups WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL FOR SHARE")
            .bind(form.group_id).bind(tenant).fetch_optional(&mut *tx).await?;
        if let Some(group) = group {
            sqlx::query("INSERT INTO user_groups (tenant_id, user_id, group_id) VALUES ($1, $2, $3) ON CONFLICT (user_id, group_id) DO NOTHING")
                .bind(tenant).bind(id).bind(group).execute(&mut *tx).await?.rows_affected()
        } else {
            reason = "Selected group is archived, missing, or outside this tenant.";
            0
        }
    } else {
        let query = if users {
            "UPDATE users SET is_active = false, deleted_at = NOW(), updated_at = NOW() WHERE id = $1"
        } else {
            "UPDATE groups SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1"
        };
        sqlx::query(query)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected()
    };
    if affected == 0 && exists && reason == "Change saved and audited." {
        reason = "User already belongs directly to this group.";
    }
    sqlx::query("INSERT INTO audit_events (action, resource_type, resource_id, outcome, actor_sub, actor_client_id, details) VALUES ($1,$2,$3,'success',$4,$5,$6)")
        .bind(form.audit_action(users))
        .bind(if users { "user" } else { "group" }).bind(id).bind(audit.actor_sub).bind(audit.actor_client)
        .bind(json!({"batch_id": audit.id, "changed": affected > 0, "reason": reason, "group_id": form.group_id,
            "actor_kind": if audit.actor_sub.is_some() { "oauth" } else { "root_token" }}))
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(BatchRow {
        id,
        name: name.unwrap_or_else(|| id.to_string()),
        status: if affected > 0 { "Success" } else { "Skipped" },
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires disposable ADMIN_UI_TEST_DATABASE_URL"]
    async fn bulk_changes_preserve_links_and_commit_with_actor_audit() {
        let pool = DbPool::connect(&std::env::var("ADMIN_UI_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        simple_idm_core::db::run_migrations(&pool).await.unwrap();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let group = Uuid::new_v4();
        let other_tenant = Uuid::new_v4();
        for id in [tenant, other_tenant] {
            sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1,$2,'Bulk tests')")
                .bind(id)
                .bind(id.to_string())
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO users (id, tenant_id, username, email, password_hash) VALUES ($1,$2,$3,$4,'test-only')")
            .bind(user).bind(tenant).bind(user.to_string()).bind(format!("{user}@example.test")).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO groups (id, tenant_id, name, is_virtual) VALUES ($1,$2,$3,true)")
            .bind(group)
            .bind(tenant)
            .bind(group.to_string())
            .execute(&pool)
            .await
            .unwrap();
        let child = Uuid::new_v4();
        sqlx::query("INSERT INTO groups (id, tenant_id, name) VALUES ($1,$2,$3)")
            .bind(child)
            .bind(tenant)
            .bind(child.to_string())
            .execute(&pool)
            .await
            .unwrap();
        simple_idm_core::db::groups::set_members(&pool, group, &[child])
            .await
            .unwrap();
        let audit = BatchAudit {
            id: Uuid::new_v4(),
            actor_sub: Some("actual-admin"),
            actor_client: Some("cli-tools"),
        };
        let assign = BulkForm {
            ids: user.to_string(),
            action: "add_group".into(),
            group_id: Some(group),
        };
        assert_eq!(
            apply_one(&pool, other_tenant, user, true, &assign, &audit)
                .await
                .unwrap()
                .status,
            "Skipped"
        );
        assert_eq!(
            apply_one(&pool, tenant, user, true, &assign, &audit)
                .await
                .unwrap()
                .status,
            "Success"
        );
        assert_eq!(
            apply_one(&pool, tenant, user, true, &assign, &audit)
                .await
                .unwrap()
                .reason,
            "User already belongs directly to this group."
        );
        let archive = BulkForm {
            ids: group.to_string(),
            action: "archive".into(),
            group_id: None,
        };
        assert!(
            simple_idm_core::auth::get_effective_user_groups(&pool, user)
                .await
                .unwrap()
                .contains(&child)
        );
        assert_eq!(
            apply_one(&pool, tenant, group, false, &archive, &audit)
                .await
                .unwrap()
                .status,
            "Success"
        );
        assert_eq!(
            apply_one(&pool, tenant, group, false, &archive, &audit)
                .await
                .unwrap()
                .status,
            "Skipped"
        );
        assert!(
            simple_idm_core::auth::get_effective_user_groups(&pool, user)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM group_groups WHERE parent_group_id=$1 AND child_group_id=$2"
            )
            .bind(group)
            .bind(child)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM user_groups WHERE user_id=$1 AND group_id=$2"
            )
            .bind(user)
            .bind(group)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        let records: Vec<(String, String, serde_json::Value)> = sqlx::query_as("SELECT actor_sub, actor_client_id, details FROM audit_events WHERE details->>'batch_id'=$1")
            .bind(audit.id.to_string()).fetch_all(&pool).await.unwrap();
        assert_eq!(records.len(), 5);
        assert!(
            records
                .iter()
                .all(|(actor, client, _)| actor == "actual-admin" && client == "cli-tools")
        );
        assert_eq!(
            records
                .iter()
                .filter(|(_, _, details)| details["changed"] == true)
                .count(),
            2
        );

        // Force just this batch's audit insert to fail. The user archive must roll back.
        let failing = BatchAudit {
            id: Uuid::from_u128(u128::MAX),
            ..audit
        };
        sqlx::query("ALTER TABLE audit_events ADD CONSTRAINT bulk_test_failure CHECK (details->>'batch_id' IS DISTINCT FROM 'ffffffff-ffff-ffff-ffff-ffffffffffff')").execute(&pool).await.unwrap();
        let failed = apply_one(&pool, tenant, user, true, &archive, &failing).await;
        sqlx::query("ALTER TABLE audit_events DROP CONSTRAINT bulk_test_failure")
            .execute(&pool)
            .await
            .unwrap();
        assert!(failed.is_err());
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT is_active AND deleted_at IS NULL FROM users WHERE id=$1"
            )
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap()
        );
        assert_eq!(
            apply_one(&pool, tenant, user, true, &archive, &audit)
                .await
                .unwrap()
                .status,
            "Success"
        );
    }

    #[test]
    fn selection_is_strict_bounded_and_deduplicated() {
        let id = Uuid::new_v4();
        assert_eq!(parse_ids(&format!("{id},{id}")).unwrap(), vec![id]);
        assert!(parse_ids("").is_err());
        assert!(parse_ids(&format!("{id},bad")).is_err());
        assert!(parse_ids(&vec![id.to_string(); 101].join(",")).is_err());
    }
}
