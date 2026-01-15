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
