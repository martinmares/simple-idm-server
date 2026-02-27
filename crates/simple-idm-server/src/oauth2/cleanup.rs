use crate::db::DbPool;
use sqlx;

pub async fn cleanup_refresh_tokens(pool: &DbPool) {
    let _ = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < NOW()")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM used_refresh_tokens WHERE expires_at < NOW()")
        .execute(pool)
        .await;
}

pub async fn cleanup_device_codes(pool: &DbPool) {
    // Smaž expirované device codes
    let device_result = sqlx::query("DELETE FROM device_codes WHERE expires_at < NOW()")
        .execute(pool)
        .await;

    if let Ok(res) = device_result {
        let count = res.rows_affected();
        if count > 0 {
            tracing::info!("Cleaned up {} expired device codes", count);
        }
    }

    // Smaž staré verification attempts (starší než 1 hodinu)
    let attempts_result = sqlx::query(
        "DELETE FROM device_verification_attempts WHERE failed_at < NOW() - INTERVAL '1 hour'"
    )
    .execute(pool)
    .await;

    if let Ok(res) = attempts_result {
        let count = res.rows_affected();
        if count > 0 {
            tracing::info!("Cleaned up {} old device verification attempts", count);
        }
    }
}
