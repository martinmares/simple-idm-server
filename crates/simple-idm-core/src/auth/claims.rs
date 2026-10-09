use crate::claim_map_patterns::evaluate_claim_map_patterns;
use crate::db::{
    DbPool,
    models::{ClaimMap, ClaimMapPattern},
};
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
///
/// Hybridní model:
/// - Claim map může mít group_id (přímý match)
/// - Claim map může mít patterns (dynamický match na group_names)
/// - Může mít obojí současně (union)
pub async fn build_custom_claims(
    pool: &DbPool,
    client_id: Uuid,
    user_groups: &[Uuid],
    user_group_names: &[String],
) -> Result<HashMap<String, Value>, ClaimMapError> {
    // Načti všechny claim mapy pro tohoto klienta
    let all_claim_maps = sqlx::query_as::<_, ClaimMap>(
        r#"
        SELECT id, client_id, group_id, claim_name, claim_value, claim_value_kind, claim_value_json, updated_at
        FROM claim_maps
        WHERE client_id = $1
          AND deleted_at IS NULL
        ORDER BY claim_name
        "#,
    )
    .bind(client_id)
    .fetch_all(pool)
    .await?;

    if all_claim_maps.is_empty() {
        return Ok(HashMap::new());
    }

    // Pro každý claim map: evaluuj jestli se aplikuje
    let mut applicable_claim_maps = Vec::new();

    for claim_map in all_claim_maps {
        let mut applies = false;

        // Check 1: Direct group_id match
        if let Some(group_id) = claim_map.group_id {
            if user_groups.contains(&group_id) {
                applies = true;
            }
        }

        // Check 2: Pattern-based match
        if !applies {
            // Načti patterns pro tento claim map
            let patterns = sqlx::query_as::<_, ClaimMapPattern>(
                r#"
                SELECT id, claim_map_id, pattern, is_include, priority, created_at
                FROM claim_map_patterns
                WHERE claim_map_id = $1
                  AND deleted_at IS NULL
                ORDER BY priority ASC
                "#,
            )
            .bind(claim_map.id)
            .fetch_all(pool)
            .await?;

            if !patterns.is_empty() && evaluate_claim_map_patterns(user_group_names, &patterns) {
                applies = true;
            }
        }

        if applies {
            applicable_claim_maps.push(claim_map);
        }
    }

    // Group applicable claim maps by claim_name
    let mut claims_by_name: std::collections::HashMap<String, Vec<ClaimMap>> =
        std::collections::HashMap::new();
    for map in applicable_claim_maps {
        if is_reserved_claim(&map.claim_name) {
            return Err(
                sqlx::Error::Protocol("Reserved JWT claim name in claim map".into()).into(),
            );
        }
        claims_by_name
            .entry(map.claim_name.clone())
            .or_default()
            .push(map);
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

            custom_claims.insert(
                claim_name.clone(),
                Value::Array(all_values.into_iter().map(Value::String).collect()),
            );
        } else {
            // Output as single string - take first value (deterministic due to ORDER BY)
            if let Some(first_map) = maps.first() {
                let value = match first_map.claim_value.as_deref() {
                    Some(v) if !v.trim().is_empty() => Value::String(v.to_string()),
                    _ => Value::Bool(true),
                };

                // Warn if there are multiple different single values
                if maps.len() > 1 {
                    let unique_values: std::collections::HashSet<_> =
                        maps.iter().filter_map(|m| m.claim_value.as_ref()).collect();
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
pub async fn get_user_groups(pool: &DbPool, user_id: Uuid) -> Result<Vec<Uuid>, ClaimMapError> {
    let group_ids = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT g.id FROM user_groups ug JOIN users u ON u.id=ug.user_id AND u.deleted_at IS NULL JOIN groups g ON g.id=ug.group_id AND g.tenant_id=u.tenant_id AND g.deleted_at IS NULL WHERE ug.user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(group_ids)
}

/// Internal membership includes virtual bundles; archived nodes interrupt inheritance.
pub async fn get_effective_user_groups(
    pool: &DbPool,
    user_id: Uuid,
) -> Result<Vec<Uuid>, ClaimMapError> {
    Ok(sqlx::query_scalar::<_, Uuid>(
        r#"
        WITH RECURSIVE effective(id, tenant_id) AS (
            SELECT g.id, g.tenant_id FROM user_groups ug
            JOIN users u ON u.id=ug.user_id AND u.deleted_at IS NULL
            JOIN groups g ON g.id=ug.group_id AND g.tenant_id=u.tenant_id
            WHERE ug.user_id=$1 AND g.deleted_at IS NULL
            UNION
            SELECT g.id, g.tenant_id FROM effective e
            JOIN group_groups gg ON gg.parent_group_id=e.id
            JOIN groups g ON g.id=gg.child_group_id AND g.tenant_id=e.tenant_id
            WHERE g.deleted_at IS NULL
        ) SELECT id FROM effective ORDER BY id
    "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

/// Načte názvy skupin pro JWT (standardní claims)
/// Returns only regular names. The legacy ignore_virtual argument is ignored.
pub async fn get_user_group_names(
    pool: &DbPool,
    user_id: Uuid,
    _ignore_virtual: bool,
) -> Result<Vec<String>, ClaimMapError> {
    // Získej effective group IDs (včetně nested)
    let effective_group_ids = get_effective_user_groups(pool, user_id).await?;

    if effective_group_ids.is_empty() {
        return Ok(vec![]);
    }

    // Načti názvy pro všechny effective groups
    let group_names = sqlx::query_scalar::<_, String>(
        "SELECT name FROM groups WHERE id=ANY($1) AND NOT is_virtual AND deleted_at IS NULL ORDER BY name",
    ).bind(&effective_group_ids).fetch_all(pool).await?;

    Ok(group_names)
}

/// Načte názvy přímých skupin uživatele (bez nested groups), seřazené alfabeticky
pub async fn get_direct_user_group_names(
    pool: &DbPool,
    user_id: Uuid,
    _ignore_virtual: bool,
) -> Result<Vec<String>, ClaimMapError> {
    let direct_group_ids = get_user_groups(pool, user_id).await?;

    if direct_group_ids.is_empty() {
        return Ok(vec![]);
    }

    let group_names = sqlx::query_scalar::<_, String>(
        "SELECT name FROM groups WHERE id=ANY($1) AND NOT is_virtual AND deleted_at IS NULL ORDER BY name",
    ).bind(&direct_group_ids).fetch_all(pool).await?;

    Ok(group_names)
}

pub fn is_reserved_claim(name: &str) -> bool {
    matches!(
        name,
        "iss"
            | "sub"
            | "aud"
            | "exp"
            | "iat"
            | "nbf"
            | "jti"
            | "nonce"
            | "scope"
            | "groups"
            | "amr"
            | "acr"
            | "credential_version"
            | "tenant_id"
            | "email"
            | "preferred_username"
            | "azp"
            | "auth_time"
            | "at_hash"
            | "c_hash"
    )
}

/// Publication filters affect `groups` only. Claim maps have their own client-specific rules.
pub async fn user_authorization_claims(
    pool: &DbPool,
    user_id: Uuid,
    client: &crate::db::models::OAuthClient,
) -> Result<(Vec<String>, HashMap<String, Value>), ClaimMapError> {
    let ids = get_effective_user_groups(pool, user_id).await?;
    let internal_names = sqlx::query_scalar::<_, String>(
        "SELECT name FROM groups WHERE id=ANY($1) AND deleted_at IS NULL ORDER BY name",
    )
    .bind(&ids)
    .fetch_all(pool)
    .await?;
    let names = match client.groups_claim_mode.as_str() {
        "none" => Vec::new(),
        "direct" => get_direct_user_group_names(pool, user_id, true).await?,
        _ => get_user_group_names(pool, user_id, true).await?,
    };
    let patterns = sqlx::query_as::<_, crate::db::models::OAuthClientGroupPattern>(
        "SELECT id, client_id, pattern, is_include, priority, created_at FROM oauth_client_group_patterns WHERE client_id=$1 AND deleted_at IS NULL ORDER BY priority",
    ).bind(client.id).fetch_all(pool).await?;
    let published = if patterns.is_empty() {
        names
    } else {
        crate::client_group_filters::apply_client_group_filters(&names, &patterns)
    };
    let claims = if client.include_claim_maps {
        build_custom_claims(pool, client.id, &ids, &internal_names).await?
    } else {
        HashMap::new()
    };
    Ok((published, claims))
}
