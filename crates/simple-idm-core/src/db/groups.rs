//! Shared group membership writes for the Admin UI and API.
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum MembershipError {
    #[error("Group not found, archived, or belongs to another tenant")]
    InvalidGroup,
    #[error("A group cannot contain itself or create a membership cycle")]
    Cycle,
    #[error("This group membership already exists")]
    AlreadyExists,
    #[error(
        "Only virtual bundles can contain groups. Remove legacy members or explicitly change the group type first."
    )]
    PhysicalParent,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

pub async fn add_member(pool: &PgPool, parent: Uuid, child: Uuid) -> Result<(), MembershipError> {
    write_members(pool, parent, &[child], false).await
}

pub async fn set_members(
    pool: &PgPool,
    parent: Uuid,
    children: &[Uuid],
) -> Result<(), MembershipError> {
    write_members(pool, parent, children, true).await
}

async fn write_members(
    pool: &PgPool,
    parent: Uuid,
    children: &[Uuid],
    replace: bool,
) -> Result<(), MembershipError> {
    let mut tx = pool.begin().await?;
    // Serialize graph mutations before checking reachability, including concurrent API writes.
    sqlx::query("LOCK TABLE group_groups IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    let (tenant, is_virtual) = sqlx::query_as::<_, (Uuid, bool)>(
        "SELECT tenant_id, is_virtual FROM groups WHERE id=$1 AND deleted_at IS NULL",
    )
    .bind(parent)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(MembershipError::InvalidGroup)?;
    let children: std::collections::BTreeSet<_> = children.iter().copied().collect();
    let existing: Vec<Uuid> =
        sqlx::query_scalar("SELECT child_group_id FROM group_groups WHERE parent_group_id=$1")
            .bind(parent)
            .fetch_all(&mut *tx)
            .await?;
    if !is_virtual && (!replace || children.iter().any(|id| !existing.contains(id))) {
        return Err(MembershipError::PhysicalParent);
    }
    for child in &children {
        let valid = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM groups WHERE id=$1 AND tenant_id=$2 AND deleted_at IS NULL)")
            .bind(child).bind(tenant).fetch_one(&mut *tx).await?;
        if !valid {
            // Keep an existing archived reference when explicitly selected. Never add a new one.
            let archived = replace && existing.contains(child) && sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM groups WHERE id=$1 AND tenant_id=$2 AND deleted_at IS NOT NULL)",
            ).bind(child).bind(tenant).fetch_one(&mut *tx).await?;
            if archived {
                continue;
            }
            return Err(MembershipError::InvalidGroup);
        }
        let cycle = sqlx::query_scalar::<_, bool>("WITH RECURSIVE reachable(id) AS (SELECT $1::uuid UNION SELECT gg.child_group_id FROM group_groups gg JOIN reachable r ON gg.parent_group_id=r.id) SELECT EXISTS(SELECT 1 FROM reachable WHERE id=$2)")
            .bind(child).bind(parent).fetch_one(&mut *tx).await?;
        if cycle {
            return Err(MembershipError::Cycle);
        }
    }
    if replace {
        // Replace this bundle's contents only; other bundles keep their references.
        sqlx::query(
            "DELETE FROM group_groups WHERE parent_group_id=$1 AND NOT (child_group_id = ANY($2))",
        )
        .bind(parent)
        .bind(children.iter().copied().collect::<Vec<_>>())
        .execute(&mut *tx)
        .await?;
    }
    for child in children {
        if replace && existing.contains(&child) {
            continue;
        }
        let result = sqlx::query("INSERT INTO group_groups (tenant_id,parent_group_id,child_group_id) VALUES ($1,$2,$3) ON CONFLICT (parent_group_id,child_group_id) DO NOTHING")
            .bind(tenant).bind(parent).bind(child).execute(&mut *tx).await?;
        if !replace && result.rows_affected() == 0 {
            return Err(MembershipError::AlreadyExists);
        }
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json,
        extract::{Path, State},
        http::StatusCode,
        response::IntoResponse,
    };

    #[tokio::test]
    #[ignore = "requires disposable DATABASE_URL; run scripts/test-postgres.sh"]
    async fn shared_bundles_preserve_memberships_permissions_and_reject_cycles() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        let tenant = Uuid::new_v4();
        sqlx::query("INSERT INTO tenants (id,slug,name) VALUES ($1,$2,'Shared group tests')")
            .bind(tenant)
            .bind(tenant.to_string())
            .execute(&pool)
            .await
            .unwrap();
        let all = Uuid::new_v4();
        let selected = Uuid::new_v4();
        let gitlab = Uuid::new_v4();
        let grafana = Uuid::new_v4();
        let registry = Uuid::new_v4();
        for (id, name, virtual_group) in [
            (all, "admin:all", true),
            (selected, "admin:selected", true),
            (gitlab, "gitlab-admins", false),
            (grafana, "grafana-admins", false),
            (registry, "registry:admin", false),
        ] {
            sqlx::query("INSERT INTO groups (id,tenant_id,name,is_virtual) VALUES ($1,$2,$3,$4)")
                .bind(id)
                .bind(tenant)
                .bind(name)
                .bind(virtual_group)
                .execute(&pool)
                .await
                .unwrap();
        }
        set_members(&pool, all, &[gitlab, grafana, registry])
            .await
            .unwrap();
        // Existing API adds references without removing another bundle's references.
        let response = crate::admin::handlers::add_child_group(
            State(pool.clone()),
            Path(selected),
            Json(crate::admin::handlers::AddChildGroupRequest {
                child_group_id: gitlab,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        add_member(&pool, selected, grafana).await.unwrap();
        assert!(matches!(
            add_member(&pool, selected, grafana).await,
            Err(MembershipError::AlreadyExists)
        ));
        let user = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id,tenant_id,username,email,password_hash) VALUES ($1,$2,'shared-user','shared@example.test','unused')").bind(user).bind(tenant).execute(&pool).await.unwrap();
        for group in [selected, grafana] {
            sqlx::query("INSERT INTO user_groups (tenant_id,user_id,group_id) VALUES ($1,$2,$3)")
                .bind(tenant)
                .bind(user)
                .bind(group)
                .execute(&pool)
                .await
                .unwrap();
        }
        assert_eq!(
            crate::auth::get_user_group_names(&pool, user, true)
                .await
                .unwrap(),
            vec!["gitlab-admins", "grafana-admins"]
        );
        let ids = crate::auth::get_effective_user_groups(&pool, user)
            .await
            .unwrap();
        assert_eq!(ids.len(), 3);
        assert!(!ids.contains(&all));
        assert!(!ids.contains(&registry));
        // Replace only selected's members, deduplicating input and retaining all's full bundle.
        set_members(&pool, selected, &[gitlab, gitlab])
            .await
            .unwrap();
        let all_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM group_groups WHERE parent_group_id=$1")
                .bind(all)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(all_count, 3);
        assert!(matches!(
            set_members(&pool, selected, &[selected]).await,
            Err(MembershipError::Cycle)
        ));
        assert!(matches!(
            add_member(&pool, gitlab, selected).await,
            Err(MembershipError::PhysicalParent)
        ));
        let foreign = Uuid::new_v4();
        sqlx::query("INSERT INTO groups (id,name) VALUES ($1,$2)")
            .bind(foreign)
            .bind(foreign.to_string())
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            set_members(&pool, selected, &[foreign]).await,
            Err(MembershipError::InvalidGroup)
        ));
        assert!(matches!(
            set_members(&pool, selected, &[Uuid::new_v4()]).await,
            Err(MembershipError::InvalidGroup)
        ));
        let members: Vec<Uuid> =
            sqlx::query_scalar("SELECT child_group_id FROM group_groups WHERE parent_group_id=$1")
                .bind(selected)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(members, vec![gitlab]); // Failed edits are atomic.
        // A nested bundle grants only descendants, never ancestors or sibling bundles.
        set_members(&pool, selected, &[all]).await.unwrap();
        assert!(matches!(
            add_member(&pool, registry, selected).await,
            Err(MembershipError::PhysicalParent)
        ));
        set_members(&pool, selected, &[]).await.unwrap();
        // Concurrent opposing additions cannot both pass cycle validation.
        let (first, second) = tokio::join!(
            add_member(&pool, selected, all),
            add_member(&pool, all, selected)
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert!(
            matches!(first, Err(MembershipError::Cycle))
                || matches!(second, Err(MembershipError::Cycle))
        );
    }
    #[tokio::test]
    #[ignore = "requires disposable DATABASE_URL; run scripts/test-postgres.sh"]
    async fn virtual_contract_keeps_internal_claims_and_publishes_only_leaves() {
        use crate::auth::claims::user_authorization_claims;
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        let tenant = Uuid::new_v4();
        sqlx::query("INSERT INTO tenants(id,slug,name) VALUES ($1,$2,'Contract tests')")
            .bind(tenant)
            .bind(tenant.to_string())
            .execute(&pool)
            .await
            .unwrap();
        let all = Uuid::new_v4();
        let monitoring = Uuid::new_v4();
        let selected = Uuid::new_v4();
        let grafana = Uuid::new_v4();
        let prometheus = Uuid::new_v4();
        for (id, name, is_virtual) in [
            (all, "admin:all", true),
            (monitoring, "admin:monitoring", true),
            (selected, "admin:selected", true),
            (grafana, "grafana-admins", false),
            (prometheus, "prometheus-admins", false),
        ] {
            sqlx::query("INSERT INTO groups(id,tenant_id,name,is_virtual) VALUES($1,$2,$3,$4)")
                .bind(id)
                .bind(tenant)
                .bind(name)
                .bind(is_virtual)
                .execute(&pool)
                .await
                .unwrap();
        }
        set_members(&pool, all, &[monitoring, selected])
            .await
            .unwrap();
        set_members(&pool, monitoring, &[grafana]).await.unwrap();
        set_members(&pool, selected, &[grafana]).await.unwrap();
        let user = Uuid::new_v4();
        let leaf_user = Uuid::new_v4();
        for id in [user, leaf_user] {
            sqlx::query("INSERT INTO users(id,tenant_id,username,email,password_hash) VALUES($1,$2,$3,$4,'unused')")
                .bind(id).bind(tenant).bind(id.to_string()).bind(format!("{id}@example.test")).execute(&pool).await.unwrap();
        }
        for (u, g) in [(user, all), (user, grafana), (leaf_user, grafana)] {
            sqlx::query("INSERT INTO user_groups(tenant_id,user_id,group_id) VALUES($1,$2,$3)")
                .bind(tenant)
                .bind(u)
                .bind(g)
                .execute(&pool)
                .await
                .unwrap();
        }
        let client_id = Uuid::new_v4();
        sqlx::query("INSERT INTO oauth_clients(id,tenant_id,client_id,name,redirect_uris,grant_types,scope,is_public,ignore_virtual_groups) VALUES($1,$2,$3,'Contract client','{}','{}','',true,false)")
            .bind(client_id).bind(tenant).bind(client_id.to_string()).execute(&pool).await.unwrap();
        // UUID and pattern sources must see the same internal membership.
        sqlx::query("INSERT INTO claim_maps(client_id,group_id,claim_name,claim_value) VALUES($1,$2,'role','monitoring-admin')")
            .bind(client_id).bind(monitoring).execute(&pool).await.unwrap();
        let map_id = Uuid::new_v4();
        sqlx::query("INSERT INTO claim_maps(id,client_id,claim_name,claim_value) VALUES($1,$2,'bundle','monitoring')")
            .bind(map_id).bind(client_id).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO claim_map_patterns(claim_map_id,pattern,is_include,priority) VALUES($1,'admin:monitoring',true,1)")
            .bind(map_id).execute(&pool).await.unwrap();
        async fn load(pool: &PgPool, id: Uuid) -> crate::db::models::OAuthClient {
            sqlx::query_as("SELECT * FROM oauth_clients WHERE id=$1")
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap()
        }
        let mut client = load(&pool, client_id).await;
        let (groups, claims) = user_authorization_claims(&pool, user, &client)
            .await
            .unwrap();
        assert_eq!(groups, vec!["grafana-admins"]);
        assert_eq!(claims["role"], "monitoring-admin");
        assert_eq!(claims["bundle"], "monitoring");
        assert_eq!(
            crate::auth::get_user_group_names(&pool, user, false)
                .await
                .unwrap(),
            groups
        );
        let (_, leaf_claims) = user_authorization_claims(&pool, leaf_user, &client)
            .await
            .unwrap();
        assert!(!leaf_claims.contains_key("role"));
        assert!(!leaf_claims.contains_key("bundle"));
        add_member(&pool, monitoring, prometheus).await.unwrap();
        let (groups, _) = user_authorization_claims(&pool, user, &client)
            .await
            .unwrap();
        assert_eq!(groups, vec!["grafana-admins", "prometheus-admins"]);
        for mode in ["direct", "none"] {
            client.groups_claim_mode = mode.into();
            let (groups, claims) = user_authorization_claims(&pool, user, &client)
                .await
                .unwrap();
            assert_eq!(
                groups,
                if mode == "direct" {
                    vec!["grafana-admins"]
                } else {
                    vec![]
                }
            );
            assert_eq!(claims["role"], "monitoring-admin");
            assert_eq!(claims["bundle"], "monitoring");
        }
        client.groups_claim_mode = "effective".into();
        sqlx::query("INSERT INTO oauth_client_group_patterns(client_id,pattern,is_include,priority) VALUES($1,'grafana-admins',true,1)")
            .bind(client_id).execute(&pool).await.unwrap();
        let (groups, claims) = user_authorization_claims(&pool, user, &client)
            .await
            .unwrap();
        assert_eq!(groups, vec!["grafana-admins"]);
        assert_eq!(claims["bundle"], "monitoring");
        client.include_claim_maps = false;
        assert!(
            user_authorization_claims(&pool, user, &client)
                .await
                .unwrap()
                .1
                .is_empty()
        );
        client.include_claim_maps = true;
        // Archived intermediate bundle interrupts inheritance; direct and alternate grants survive.
        sqlx::query("UPDATE groups SET deleted_at=now() WHERE id=$1")
            .bind(monitoring)
            .execute(&pool)
            .await
            .unwrap();
        set_members(&pool, all, &[monitoring, selected])
            .await
            .unwrap();
        let retained: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_groups WHERE parent_group_id=$1 AND child_group_id=$2)")
            .bind(all).bind(monitoring).fetch_one(&pool).await.unwrap();
        assert!(retained); // A normal save must not remove an archived reference.
        assert!(matches!(
            set_members(&pool, selected, &[monitoring]).await,
            Err(MembershipError::InvalidGroup)
        ));
        set_members(&pool, all, &[selected]).await.unwrap(); // Explicit uncheck removes the reference.
        assert!(!sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM group_groups WHERE parent_group_id=$1 AND child_group_id=$2)")
            .bind(all).bind(monitoring).fetch_one(&pool).await.unwrap());
        // Restore reference after restoring the group below.
        let ids = crate::auth::get_effective_user_groups(&pool, user)
            .await
            .unwrap();
        assert!(ids.contains(&grafana));
        assert!(!ids.contains(&prometheus));
        assert!(!ids.contains(&monitoring));
        assert!(
            user_authorization_claims(&pool, user, &client)
                .await
                .unwrap()
                .1
                .is_empty()
        );
        sqlx::query("UPDATE groups SET deleted_at=NULL WHERE id=$1")
            .bind(monitoring)
            .execute(&pool)
            .await
            .unwrap();
        set_members(&pool, all, &[monitoring, selected])
            .await
            .unwrap();
        assert_eq!(
            user_authorization_claims(&pool, user, &client)
                .await
                .unwrap()
                .1["role"],
            "monitoring-admin"
        );
        // Empty virtual bundle retains its explicit claim maps.
        set_members(&pool, monitoring, &[]).await.unwrap();
        assert_eq!(
            user_authorization_claims(&pool, user, &client)
                .await
                .unwrap()
                .1["role"],
            "monitoring-admin"
        );
        // DB writes and helper writes both enforce leaf semantics.
        assert!(matches!(
            add_member(&pool, grafana, prometheus).await,
            Err(MembershipError::PhysicalParent)
        ));
        assert!(sqlx::query("INSERT INTO group_groups(tenant_id,parent_group_id,child_group_id) VALUES($1,$2,$3)")
            .bind(tenant).bind(grafana).bind(prometheus).execute(&pool).await.is_err());
        assert!(
            sqlx::query("UPDATE groups SET is_virtual=false WHERE id=$1")
                .bind(all)
                .execute(&pool)
                .await
                .is_err()
        );
        // Concurrent type conversion and membership addition must never leave a physical parent.
        let empty = Uuid::new_v4();
        sqlx::query("INSERT INTO groups(id,tenant_id,name,is_virtual) VALUES($1,$2,'empty',true)")
            .bind(empty)
            .bind(tenant)
            .execute(&pool)
            .await
            .unwrap();
        let (edge, kind) = tokio::join!(
            add_member(&pool, empty, prometheus),
            sqlx::query("UPDATE groups SET is_virtual=false WHERE id=$1")
                .bind(empty)
                .execute(&pool)
        );
        assert_eq!(usize::from(edge.is_ok()) + usize::from(kind.is_ok()), 1);
        let invalid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM groups g JOIN group_groups gg ON gg.parent_group_id=g.id WHERE g.id=$1 AND NOT g.is_virtual)")
            .bind(empty).fetch_one(&pool).await.unwrap();
        assert!(!invalid);
        // Simulate pre-migration legacy data: readable, reported, and removable without adding edges.
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("ALTER TABLE group_groups DISABLE TRIGGER virtual_group_parent")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO group_groups(tenant_id,parent_group_id,child_group_id) VALUES($1,$2,$3)",
        )
        .bind(tenant)
        .bind(grafana)
        .bind(prometheus)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("ALTER TABLE group_groups ENABLE TRIGGER virtual_group_parent")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(
            crate::auth::get_effective_user_groups(&pool, leaf_user)
                .await
                .unwrap()
                .contains(&prometheus)
        );
        set_members(&pool, grafana, &[prometheus]).await.unwrap();
        set_members(&pool, grafana, &[]).await.unwrap();
        assert!(
            !crate::auth::get_effective_user_groups(&pool, leaf_user)
                .await
                .unwrap()
                .contains(&prometheus)
        );
    }
}
