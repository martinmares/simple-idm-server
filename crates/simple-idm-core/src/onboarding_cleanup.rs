use crate::db::DbPool;

pub async fn cleanup_onboarding_tokens(pool: &DbPool) {
    match sqlx::query(
        r#"
        DELETE FROM ad_onboarding_tokens
        WHERE expires_at < NOW()
           OR used_at IS NOT NULL
        "#,
    )
    .execute(pool)
    .await
    {
        Ok(result) => {
            let count = result.rows_affected();
            if count > 0 {
                tracing::info!("Cleaned up {count} AD onboarding tokens");
            }
        }
        Err(err) => {
            tracing::warn!("Failed to clean up AD onboarding tokens: {err}");
        }
    }

    match sqlx::query(
        r#"
        DELETE FROM federated_invitation_tokens
        WHERE expires_at < NOW()
           OR used_at IS NOT NULL
        "#,
    )
    .execute(pool)
    .await
    {
        Ok(result) => {
            let count = result.rows_affected();
            if count > 0 {
                tracing::info!("Cleaned up {count} federated invitation tokens");
            }
        }
        Err(err) => {
            tracing::warn!("Failed to clean up federated invitation tokens: {err}");
        }
    }
}
