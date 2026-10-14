use super::DbPool;
use uuid::Uuid;

pub fn is_username_conflict(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|error| {
        error.is_unique_violation() && error.constraint() == Some("uq_users_tenant_username_active")
    })
}

/// Restore the original identity without activating it or changing its bindings.
/// The unique index atomically rejects restoration if its name has been reused.
pub async fn restore(pool: &DbPool, user_id: Uuid) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE users SET deleted_at = NULL, updated_at = NOW() WHERE id = $1 AND deleted_at IS NOT NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?
    .rows_affected()
        > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::handlers::{CreateUserRequest, create_user, delete_user};
    use crate::db::models::User;
    use axum::{
        Json,
        extract::{Path, State},
        http::StatusCode,
        response::IntoResponse,
    };

    #[tokio::test]
    #[ignore = "requires disposable USER_ARCHIVE_TEST_DATABASE_URL"]
    async fn archived_username_can_be_reused_without_transferring_identity() {
        let pool = DbPool::connect(&std::env::var("USER_ARCHIVE_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let migrations = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        sqlx::migrate::Migrator::new(migrations)
            .await
            .unwrap()
            .run(&pool)
            .await
            .unwrap();
        let tenant = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("mares-{suffix}");
        let old_email = format!("mares-{suffix}@datalite.test");
        let new_email = format!("martin.mares-{suffix}@seznam.test");
        let provider: Uuid = sqlx::query_scalar("INSERT INTO identity_providers (tenant_id, slug, provider_type, issuer, client_id, client_secret_encrypted) VALUES ($1,$2,'google','https://accounts.google.com',$2,'test') RETURNING id")
            .bind(tenant).bind(format!("google-{suffix}")).fetch_one(&pool).await.unwrap();
        let old: Uuid = sqlx::query_scalar("INSERT INTO users (tenant_id,username,email,auth_mode,auth_provider_id,password_disabled) VALUES ($1,$2,$3,'federated',$4,true) RETURNING id")
            .bind(tenant).bind(&username).bind(&old_email).bind(provider).fetch_one(&pool).await.unwrap();
        sqlx::query("INSERT INTO user_identities (tenant_id,user_id,idp_id,issuer,subject) VALUES ($1,$2,$3,'https://accounts.google.com',$4)")
            .bind(tenant).bind(old).bind(provider).bind(&suffix).execute(&pool).await.unwrap();
        let group: Uuid =
            sqlx::query_scalar("INSERT INTO groups (tenant_id,name) VALUES ($1,$2) RETURNING id")
                .bind(tenant)
                .bind(format!("old-access-{suffix}"))
                .fetch_one(&pool)
                .await
                .unwrap();
        sqlx::query("INSERT INTO user_groups (user_id,group_id) VALUES ($1,$2)")
            .bind(old)
            .bind(group)
            .execute(&pool)
            .await
            .unwrap();

        // Disabling an account does not free its username.
        sqlx::query("UPDATE users SET is_active=false WHERE id=$1")
            .bind(old)
            .execute(&pool)
            .await
            .unwrap();
        let conflict =
            sqlx::query("INSERT INTO users (tenant_id,username,email) VALUES ($1,$2,$3)")
                .bind(tenant)
                .bind(&username)
                .bind(&new_email)
                .execute(&pool)
                .await
                .unwrap_err();
        assert!(is_username_conflict(&conflict));

        // The admin API archives the old UUID and can then create a new local user.
        assert_eq!(
            delete_user(
                State(pool.clone()),
                axum::Extension(crate::audit::Actor::default()),
                Path(old)
            )
            .await
            .into_response()
            .status(),
            StatusCode::OK
        );
        let response = create_user(
            State(pool.clone()),
            axum::Extension(crate::audit::Actor::default()),
            Json(CreateUserRequest {
                username: username.clone(),
                email: new_email.clone(),
                password: "test-only-local-password".into(),
                is_active: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let new = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
        assert_ne!(old, new);
        let login: User = sqlx::query_as("SELECT * FROM users WHERE tenant_id=$1 AND username=$2 AND is_active AND deleted_at IS NULL")
            .bind(tenant).bind(&username).fetch_one(&pool).await.unwrap();
        assert_eq!(login.id, new);
        assert_eq!(login.email, new_email);
        assert_eq!(login.auth_mode, "local");
        assert!(login.auth_provider_id.is_none());
        assert!(!login.password_disabled);
        assert!(login.password_hash.is_some());
        let archived: User = sqlx::query_as("SELECT * FROM users WHERE id=$1")
            .bind(old)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(archived.deleted_at.is_some());
        assert_eq!(archived.username, username);
        assert_eq!(archived.email, old_email);
        assert_eq!(archived.auth_provider_id, Some(provider));
        let bindings: Vec<Uuid> =
            sqlx::query_scalar("SELECT user_id FROM user_identities WHERE idp_id=$1")
                .bind(provider)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(bindings, [old]);
        let memberships: Vec<Uuid> =
            sqlx::query_scalar("SELECT user_id FROM user_groups WHERE group_id=$1")
                .bind(group)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(memberships, [old]);
        let audit_user: Uuid = sqlx::query_scalar("SELECT resource_id FROM audit_events WHERE action='admin.user.delete' AND resource_id=$1")
            .bind(old).fetch_one(&pool).await.unwrap();
        assert_eq!(audit_user, old);

        // A second live account and restoring the old account both conflict.
        let conflict =
            sqlx::query("INSERT INTO users (tenant_id,username,email) VALUES ($1,$2,$3)")
                .bind(tenant)
                .bind(&username)
                .bind(format!("third-{suffix}@example.test"))
                .execute(&pool)
                .await
                .unwrap_err();
        assert!(is_username_conflict(&conflict));
        let conflict = restore(&pool, old).await.unwrap_err();
        assert!(is_username_conflict(&conflict));
        let still_archived: bool =
            sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM users WHERE id=$1")
                .bind(old)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(still_archived);

        // Reuse is tenant-scoped; email remains reserved by the archived UUID.
        let foreign = Uuid::new_v4();
        sqlx::query("INSERT INTO tenants (id,slug,name) VALUES ($1,$2,'Archive test')")
            .bind(foreign)
            .bind(foreign.to_string())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (tenant_id,username,email) VALUES ($1,$2,$3)")
            .bind(foreign)
            .bind(&username)
            .bind(&new_email)
            .execute(&pool)
            .await
            .unwrap();
        let email_conflict =
            sqlx::query("INSERT INTO users (tenant_id,username,email) VALUES ($1,$2,$3)")
                .bind(tenant)
                .bind(format!("fresh-{suffix}"))
                .bind(&old_email)
                .execute(&pool)
                .await
                .unwrap_err();
        assert_eq!(
            email_conflict.as_database_error().unwrap().constraint(),
            Some("uq_users_tenant_email")
        );

        assert_eq!(
            delete_user(
                State(pool.clone()),
                axum::Extension(crate::audit::Actor::default()),
                Path(new)
            )
            .await
            .into_response()
            .status(),
            StatusCode::OK
        );
        assert!(restore(&pool, old).await.unwrap());
        assert!(!restore(&pool, old).await.unwrap());
        assert!(!restore(&pool, Uuid::new_v4()).await.unwrap());
        let restored: User = sqlx::query_as("SELECT * FROM users WHERE id=$1")
            .bind(old)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(restored.deleted_at.is_none());
        assert!(!restored.is_active);
        assert_eq!(restored.auth_provider_id, Some(provider));
    }
}
