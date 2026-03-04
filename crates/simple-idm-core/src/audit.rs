use crate::db::DbPool;
use serde_json::Value;
use uuid::Uuid;

pub async fn emit_event(
    db_pool: &DbPool,
    action: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
    outcome: &str,
    details: Option<Value>,
) {
    if let Err(err) = sqlx::query(
        r#"
        INSERT INTO audit_events (action, resource_type, resource_id, outcome, details)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(outcome)
    .bind(details)
    .execute(db_pool)
    .await
    {
        tracing::warn!("Failed to write audit event '{}': {}", action, err);
    }
}
