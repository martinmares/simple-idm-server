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
/// Podporuje jak single string values tak array values
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
        SELECT id, client_id, group_id, claim_name, claim_value, claim_value_kind, claim_value_json
        FROM claim_maps
        WHERE client_id = $1 AND group_id = ANY($2)
        ORDER BY claim_name, group_id
        "#,
    )
    .bind(client_id)
    .bind(user_groups)
    .fetch_all(pool)
    .await?;

    // Group by claim_name
    let mut claims_by_name: std::collections::HashMap<String, Vec<ClaimMap>> = std::collections::HashMap::new();
    for map in claim_maps {
        claims_by_name.entry(map.claim_name.clone()).or_default().push(map);
    }

    let mut custom_claims: HashMap<String, Value> = HashMap::new();

    // Process each claim_name
    for (claim_name, maps) in claims_by_name {
        // Check if any map has array kind
        let has_array = maps.iter().any(|m| m.claim_value_kind == "array");

        if has_array {
            // Output as array - collect all values
            let mut all_values: Vec<String> = Vec::new();

            for map in maps {
                if map.claim_value_kind == "array" {
                    // Parse JSON array
                    if let Some(json_str) = &map.claim_value_json {
                        if let Ok(arr) = serde_json::from_str::<Vec<String>>(json_str) {
                            all_values.extend(arr);
                        }
                    }
                } else {
                    // Single value - add to array
                    if let Some(v) = &map.claim_value {
                        if !v.trim().is_empty() {
                            all_values.push(v.clone());
                        }
                    }
                }
            }

            // Deduplicate and sort
            all_values.sort();
            all_values.dedup();

            custom_claims.insert(claim_name.clone(), Value::Array(
                all_values.into_iter().map(Value::String).collect()
            ));
        } else {
            // Output as single string - take first value (deterministic due to ORDER BY)
            if let Some(first_map) = maps.first() {
                let value = match first_map.claim_value.as_deref() {
                    Some(v) if !v.trim().is_empty() => Value::String(v.to_string()),
                    _ => Value::Bool(true),
                };

                // Warn if there are multiple different single values
                if maps.len() > 1 {
                    let unique_values: std::collections::HashSet<_> = maps.iter()
                        .filter_map(|m| m.claim_value.as_ref())
                        .collect();
                    if unique_values.len() > 1 {
                        tracing::warn!(
                            "Multiple different single values for claim '{}': {:?}. Using first value deterministically.",
                            claim_name,
                            unique_values
                        );
                    }
                }

                custom_claims.insert(claim_name, value);
            }
        }
    }

    Ok(custom_claims)
}

/// Načte přímé skupiny uživatele (bez rozbalení nested groups)
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

/// Rozbalí nested groups tranzitivně
/// Vrací všechny transitive child groups pro danou skupinu
async fn expand_nested_groups(
    pool: &DbPool,
    group_id: Uuid,
) -> Result<Vec<Uuid>, ClaimMapError> {
    let mut all_groups = std::collections::HashSet::new();
    let mut stack = vec![group_id];
    let mut visited = std::collections::HashSet::new();

    while let Some(current) = stack.pop() {
        if visited.contains(&current) {
            continue;
        }
        visited.insert(current);
        all_groups.insert(current);

        // Načti child groups
        let children = sqlx::query_scalar::<_, Uuid>(
            "SELECT child_group_id FROM group_groups WHERE parent_group_id = $1"
        )
        .bind(current)
        .fetch_all(pool)
        .await?;

        stack.extend(children);
    }

    Ok(all_groups.into_iter().collect())
}

/// Načte všechny effective groups uživatele (včetně rozbalených nested groups)
pub async fn get_effective_user_groups(
    pool: &DbPool,
    user_id: Uuid,
) -> Result<Vec<Uuid>, ClaimMapError> {
    // Načti přímé skupiny uživatele
    let direct_groups = get_user_groups(pool, user_id).await?;

    // Rozbal nested groups pro každou přímou skupinu
    let mut all_effective_groups = std::collections::HashSet::new();

    for group_id in direct_groups {
        let expanded = expand_nested_groups(pool, group_id).await?;
        all_effective_groups.extend(expanded);
    }

    Ok(all_effective_groups.into_iter().collect())
}

/// Načte názvy skupin pro JWT (standardní claims)
/// Vrací effective groups (včetně rozbalených nested groups), seřazené alfabeticky
pub async fn get_user_group_names(
    pool: &DbPool,
    user_id: Uuid,
) -> Result<Vec<String>, ClaimMapError> {
    // Získej effective group IDs (včetně nested)
    let effective_group_ids = get_effective_user_groups(pool, user_id).await?;

    if effective_group_ids.is_empty() {
        return Ok(vec![]);
    }

    // Načti názvy pro všechny effective groups
    let group_names = sqlx::query_scalar::<_, String>(
        r#"
        SELECT name
        FROM groups
        WHERE id = ANY($1)
        ORDER BY name
        "#,
    )
    .bind(&effective_group_ids)
    .fetch_all(pool)
    .await?;

    Ok(group_names)
}
