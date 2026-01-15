use crate::db::{models::ClaimMap, DbPool};
use serde_json::Value;
use sqlx;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ClaimMapError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
}

/// Načte custom claim mapy pro daného klienta a vrátí HashMap s custom claims
/// Tato funkce implementuje feature podobný Kanidm "group mapping"
pub async fn build_custom_claims(
    pool: &DbPool,
    client_id: Uuid,
    user_groups: &[Uuid],
) -> Result<HashMap<String, Value>, ClaimMapError> {
    if user_groups.is_empty() {
        return Ok(HashMap::new());
    }

    // Načti claim mapy pro tohoto klienta a skupiny uživatele
    let claim_maps = sqlx::query_as::<_, ClaimMap>(
        r#"
        SELECT id, client_id, group_id, claim_name
        FROM claim_maps
        WHERE client_id = $1 AND group_id = ANY($2)
        "#,
    )
    .bind(client_id)
    .bind(user_groups)
    .fetch_all(pool)
    .await?;

    let mut custom_claims: HashMap<String, Value> = HashMap::new();

    // Seskup claim_names podle stejného jména (některé skupiny mohou mít stejný claim_name)
    for map in claim_maps {
        let value = match map.claim_value.as_deref() {
            Some(v) if !v.trim().is_empty() => Value::String(v.to_string()),
            _ => Value::Bool(true),
        };
        custom_claims.entry(map.claim_name.clone()).or_insert(value);
    }

    Ok(custom_claims)
}

/// Načte skupiny uživatele
pub async fn get_user_groups(
    pool: &DbPool,
    user_id: Uuid,
) -> Result<Vec<Uuid>, ClaimMapError> {
    let group_ids = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT group_id FROM user_groups WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(group_ids)
}

/// Načte názvy skupin pro JWT (standardní claims)
pub async fn get_user_group_names(
    pool: &DbPool,
    user_id: Uuid,
) -> Result<Vec<String>, ClaimMapError> {
    let group_names = sqlx::query_scalar::<_, String>(
        r#"
        SELECT g.name
        FROM groups g
        INNER JOIN user_groups ug ON g.id = ug.group_id
        WHERE ug.user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(group_names)
}
