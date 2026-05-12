use sqlx::PgPool;

/// Hard-purge entities that have been soft-deleted longer than `retention_days`.
///
/// Deletion order is intentionally FK-safe (relations first, roots last).
pub async fn purge_soft_deleted(pool: &PgPool, retention_days: i64) {
    let retention_days = retention_days.max(1);
    let mut total_deleted: u64 = 0;

    let statements: [(&str, &str); 11] = [
        (
            "user_groups",
            r#"
            DELETE FROM user_groups
            WHERE user_id IN (
                SELECT id FROM users
                WHERE deleted_at IS NOT NULL
                  AND deleted_at < NOW() - ($1 * INTERVAL '1 day')
            )
               OR group_id IN (
                SELECT id FROM groups
                WHERE deleted_at IS NOT NULL
                  AND deleted_at < NOW() - ($1 * INTERVAL '1 day')
            )
            "#,
        ),
        (
            "group_groups",
            r#"
            DELETE FROM group_groups
            WHERE parent_group_id IN (
                SELECT id FROM groups
                WHERE deleted_at IS NOT NULL
                  AND deleted_at < NOW() - ($1 * INTERVAL '1 day')
            )
               OR child_group_id IN (
                SELECT id FROM groups
                WHERE deleted_at IS NOT NULL
                  AND deleted_at < NOW() - ($1 * INTERVAL '1 day')
            )
            "#,
        ),
        (
            "user_group_patterns",
            r#"
            DELETE FROM user_group_patterns
            WHERE deleted_at IS NOT NULL
              AND deleted_at < NOW() - ($1 * INTERVAL '1 day')
            "#,
        ),
        (
            "oauth_client_group_patterns",
            r#"
            DELETE FROM oauth_client_group_patterns
            WHERE deleted_at IS NOT NULL
              AND deleted_at < NOW() - ($1 * INTERVAL '1 day')
            "#,
        ),
        (
            "claim_map_patterns",
            r#"
            DELETE FROM claim_map_patterns
            WHERE deleted_at IS NOT NULL
              AND deleted_at < NOW() - ($1 * INTERVAL '1 day')
            "#,
        ),
        (
            "claim_maps",
            r#"
            DELETE FROM claim_maps
            WHERE deleted_at IS NOT NULL
              AND deleted_at < NOW() - ($1 * INTERVAL '1 day')
            "#,
        ),
        (
            "tenant_domains",
            r#"
            DELETE FROM tenant_domains
            WHERE deleted_at IS NOT NULL
              AND deleted_at < NOW() - ($1 * INTERVAL '1 day')
            "#,
        ),
        (
            "oauth_clients",
            r#"
            DELETE FROM oauth_clients
            WHERE deleted_at IS NOT NULL
              AND deleted_at < NOW() - ($1 * INTERVAL '1 day')
            "#,
        ),
        (
            "groups",
            r#"
            DELETE FROM groups
            WHERE deleted_at IS NOT NULL
              AND deleted_at < NOW() - ($1 * INTERVAL '1 day')
            "#,
        ),
        (
            "users",
            r#"
            DELETE FROM users
            WHERE deleted_at IS NOT NULL
              AND deleted_at < NOW() - ($1 * INTERVAL '1 day')
            "#,
        ),
        (
            "tenants",
            r#"
            DELETE FROM tenants
            WHERE deleted_at IS NOT NULL
              AND deleted_at < NOW() - ($1 * INTERVAL '1 day')
            "#,
        ),
    ];

    for (name, statement) in statements {
        match sqlx::query(statement)
            .bind(retention_days)
            .execute(pool)
            .await
        {
            Ok(result) => {
                let affected = result.rows_affected();
                total_deleted += affected;
                if affected > 0 {
                    tracing::info!(
                        "Soft-delete purge removed {} row(s) from {}",
                        affected,
                        name
                    );
                }
            }
            Err(error) => {
                tracing::warn!("Soft-delete purge failed on table {}: {}", name, error);
            }
        }
    }

    tracing::info!(
        "Soft-delete purge finished (retention={} day(s), total_deleted={})",
        retention_days,
        total_deleted
    );
}
