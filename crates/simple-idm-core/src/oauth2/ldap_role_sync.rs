use crate::db::models::User;
use crate::oauth2::client_credentials::OAuth2State;
use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use simple_idm_ldap_sync::{apply_role_mappings, ExternalRoleMapping, MappingMode, MappingTarget, SyncInput};
use sqlx::Row;
use std::collections::HashSet;
use std::time::Duration as StdDuration;
use tokio::time::timeout;
use tracing::{info, warn};

const SOURCE_AD: &str = "ad";

pub async fn sync_ldap_roles_if_stale(
    state: &OAuth2State,
    user: &User,
    login: &str,
) -> Result<()> {
    sync_ldap_roles_internal(state, user, login, false).await
}

pub async fn sync_ldap_roles_force(
    state: &OAuth2State,
    user: &User,
    login: &str,
) -> Result<()> {
    sync_ldap_roles_internal(state, user, login, true).await
}

async fn sync_ldap_roles_internal(
    state: &OAuth2State,
    user: &User,
    login: &str,
    force: bool,
) -> Result<()> {
    if !state.ldap_role_sync_enabled {
        return Ok(());
    }
    let cfg = match &state.ldap_auth {
        Some(v) => v,
        None => return Ok(()),
    };
    let ttl = Duration::seconds(state.ldap_role_sync_ttl_seconds as i64);

    let row = sqlx::query(
        "SELECT last_synced_at FROM user_external_role_sync_state WHERE user_id = $1 AND source = $2",
    )
    .bind(user.id)
    .bind(SOURCE_AD)
    .fetch_optional(&state.db_pool)
    .await?;

    if !force {
        if let Some(r) = row {
            let last_synced_at = r.try_get::<Option<chrono::DateTime<Utc>>, _>("last_synced_at")?;
            if let Some(ts) = last_synced_at {
                if Utc::now() - ts < ttl {
                    return Ok(());
                }
            }
        }
    }

    let ldap_data = match timeout(
        StdDuration::from_secs(state.ldap_role_sync_timeout_seconds),
        simple_idm_ad_auth::fetch_ldap_user_data(cfg, login),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            persist_sync_error(&state.db_pool, user.id, format!("LDAP role fetch failed: {e}")).await?;
            return Err(anyhow!("LDAP role fetch failed: {e}"));
        }
        Err(_) => {
            persist_sync_error(&state.db_pool, user.id, "LDAP role fetch timeout".to_string()).await?;
            return Err(anyhow!("LDAP role fetch timeout"));
        }
    };

    let roles_set: HashSet<String> = ldap_data.roles.into_iter().collect();
    let mut tx = state.db_pool.begin().await?;

    sqlx::query("DELETE FROM user_external_roles WHERE user_id = $1 AND source = $2")
        .bind(user.id)
        .bind(SOURCE_AD)
        .execute(&mut *tx)
        .await?;

    for role in &roles_set {
        sqlx::query(
            "INSERT INTO user_external_roles (user_id, source, role_name, synced_at) VALUES ($1, $2, $3, NOW())",
        )
        .bind(user.id)
        .bind(SOURCE_AD)
        .bind(role)
        .execute(&mut *tx)
        .await?;
    }

    let mapping_rows = sqlx::query(
        r#"
        SELECT external_role, group_id::text as group_id, mode, priority
        FROM external_role_mappings
        WHERE tenant_id = $1
          AND source = $2
          AND is_active = true
          AND deleted_at IS NULL
        ORDER BY priority ASC
        "#,
    )
    .bind(user.tenant_id)
    .bind(SOURCE_AD)
    .fetch_all(&mut *tx)
    .await?;

    let mut mappings: Vec<ExternalRoleMapping> = Vec::with_capacity(mapping_rows.len());
    let mut managed_targets: HashSet<String> = HashSet::new();
    for row in mapping_rows {
        let mode_str = row.try_get::<String, _>("mode")?;
        let mode = if mode_str.eq_ignore_ascii_case("remove") {
            MappingMode::Remove
        } else {
            MappingMode::Add
        };
        let group_id = row.try_get::<String, _>("group_id")?;
        managed_targets.insert(group_id.clone());
        mappings.push(ExternalRoleMapping {
            external_role: row.try_get::<String, _>("external_role")?,
            target: MappingTarget::Group(group_id),
            mode,
            priority: row.try_get::<i32, _>("priority")?,
            is_active: true,
        });
    }

    let current_group_rows =
        sqlx::query("SELECT group_id::text as group_id FROM user_groups WHERE user_id = $1")
            .bind(user.id)
            .fetch_all(&mut *tx)
            .await?;
    let current_groups: HashSet<String> = current_group_rows
        .iter()
        .filter_map(|r| r.try_get::<String, _>("group_id").ok())
        .collect();
    let managed_current: Vec<String> = current_groups
        .iter()
        .filter(|g| managed_targets.contains(*g))
        .cloned()
        .collect();

    let sync_input = SyncInput {
        external_roles: roles_set.iter().cloned().collect(),
        current_groups: managed_current.clone(),
        mappings,
    };
    let sync_out = apply_role_mappings(&sync_input);
    let desired_managed: HashSet<String> = sync_out.effective_groups.into_iter().collect();
    let current_managed: HashSet<String> = managed_current.into_iter().collect();

    for group_id in desired_managed.difference(&current_managed) {
        sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2::uuid) ON CONFLICT DO NOTHING")
            .bind(user.id)
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
    }

    let first_name = ldap_data.profile.first_name.as_deref();
    let last_name = ldap_data.profile.last_name.as_deref();
    let recovery_email = ldap_data.profile.recovery_email.as_deref();
    let phone_e164 = ldap_data.profile.phone_e164.as_deref();

    sqlx::query(
        r#"
        UPDATE users
        SET
            first_name = COALESCE($2, first_name),
            last_name = COALESCE($3, last_name),
            recovery_email = COALESCE($4, recovery_email),
            phone_e164 = COALESCE($5, phone_e164),
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(user.id)
    .bind(first_name)
    .bind(last_name)
    .bind(recovery_email)
    .bind(phone_e164)
    .execute(&mut *tx)
    .await?;

    let external_user_id = ldap_data
        .identity
        .external_user_id
        .clone()
        .unwrap_or_else(|| login.to_string());
    let external_user_id_type = ldap_data
        .identity
        .external_user_id_type
        .clone()
        .unwrap_or_else(|| "login_name".to_string());
    let login_name = ldap_data
        .identity
        .login_name
        .clone()
        .or_else(|| Some(login.to_string()));
    let upn = ldap_data.identity.upn.clone();

    sqlx::query(
        r#"
        INSERT INTO user_external_identities
          (tenant_id, user_id, source, external_user_id, external_user_id_type, login_name, upn, last_seen_at, updated_at)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        ON CONFLICT (tenant_id, source, external_user_id)
        WHERE deleted_at IS NULL
        DO UPDATE SET
          user_id = EXCLUDED.user_id,
          external_user_id_type = EXCLUDED.external_user_id_type,
          login_name = EXCLUDED.login_name,
          upn = EXCLUDED.upn,
          last_seen_at = NOW(),
          updated_at = NOW()
        "#,
    )
    .bind(user.tenant_id)
    .bind(user.id)
    .bind(SOURCE_AD)
    .bind(external_user_id)
    .bind(external_user_id_type)
    .bind(login_name)
    .bind(upn)
    .execute(&mut *tx)
    .await?;

    for group_id in current_managed.difference(&desired_managed) {
        sqlx::query("DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2::uuid")
            .bind(user.id)
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
    }

    sqlx::query(
        r#"
        INSERT INTO user_external_role_sync_state (user_id, source, last_synced_at, last_error, updated_at)
        VALUES ($1, $2, NOW(), NULL, NOW())
        ON CONFLICT (user_id, source)
        DO UPDATE SET last_synced_at = EXCLUDED.last_synced_at, last_error = NULL, updated_at = NOW()
        "#,
    )
    .bind(user.id)
    .bind(SOURCE_AD)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    info!(
        user_id = %user.id,
        username = %user.username,
        external_roles = roles_set.len(),
        "AD role sync completed"
    );

    Ok(())
}

async fn persist_sync_error(
    db: &sqlx::PgPool,
    user_id: uuid::Uuid,
    err: String,
) -> Result<()> {
    warn!(user_id = %user_id, "AD role sync failed: {}", err);
    sqlx::query(
        r#"
        INSERT INTO user_external_role_sync_state (user_id, source, last_synced_at, last_error, updated_at)
        VALUES ($1, $2, NULL, $3, NOW())
        ON CONFLICT (user_id, source)
        DO UPDATE SET last_error = EXCLUDED.last_error, updated_at = NOW()
        "#,
    )
    .bind(user_id)
    .bind(SOURCE_AD)
    .bind(err)
    .execute(db)
    .await?;
    Ok(())
}
