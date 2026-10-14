use crate::db::DbPool;
use serde_json::Value;
use uuid::Uuid;

/// Trusted request identity, supplied after authentication. Never derive it from a target ID.
#[derive(Debug, Clone, Default)]
pub struct Actor {
    pub subject: Option<String>,
    pub client_id: Option<String>,
    pub root_token: bool,
}

pub async fn emit_event(
    db_pool: &DbPool,
    action: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
    outcome: &str,
    details: Option<Value>,
) {
    emit_event_as(
        db_pool,
        &Actor::default(),
        action,
        resource_type,
        resource_id,
        outcome,
        details,
    )
    .await;
}

pub async fn emit_event_as(
    db_pool: &DbPool,
    actor: &Actor,
    action: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
    outcome: &str,
    mut details: Option<Value>,
) {
    if actor.root_token {
        let value = details.get_or_insert_with(|| serde_json::json!({}));
        if let Some(object) = value.as_object_mut() {
            object.insert("actor_kind".into(), Value::String("root_token".into()));
        }
    }
    if let Err(err) = sqlx::query(
        r#"
        INSERT INTO audit_events (action, resource_type, resource_id, outcome, details, actor_sub, actor_client_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(outcome)
    .bind(details)
    .bind(&actor.subject)
    .bind(&actor.client_id)
    .execute(db_pool)
    .await
    {
        tracing::warn!("Failed to write audit event '{}': {}", action, err);
    }
}
