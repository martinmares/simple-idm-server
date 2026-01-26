use crate::db::{models::{Group, UserGroupPattern}, DbPool};
use std::collections::HashSet;
use uuid::Uuid;

/// Check if a pattern matches a group name
/// Supports wildcard matching with '*'
///
/// Examples:
/// - pattern "ssh:*" matches "ssh:role:admin", "ssh:principal:alice"
/// - pattern "ssh:role:*" matches "ssh:role:admin" but not "ssh:principal:alice"
/// - pattern "exact-match" matches only "exact-match"
pub fn pattern_matches(pattern: &str, group_name: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if !pattern.contains('*') {
        return pattern == group_name;
    }

    // Handle wildcard matching
    let pattern_parts: Vec<&str> = pattern.split('*').collect();

    if pattern_parts.len() == 2 {
        let prefix = pattern_parts[0];
        let suffix = pattern_parts[1];

        if suffix.is_empty() {
            // Pattern like "ssh:*"
            return group_name.starts_with(prefix);
        } else if prefix.is_empty() {
            // Pattern like "*:admin"
            return group_name.ends_with(suffix);
        } else {
            // Pattern like "ssh:*:admin"
            return group_name.starts_with(prefix) && group_name.ends_with(suffix);
        }
    }

    // Multiple wildcards - simple implementation
    // Could be improved with proper glob matching if needed
    false
}

/// Evaluate which groups a user should be assigned to based on their patterns
/// Returns tuple of (groups_to_add, groups_to_remove)
pub fn evaluate_patterns(
    patterns: &[UserGroupPattern],
    all_groups: &[Group],
) -> (HashSet<Uuid>, HashSet<Uuid>) {
    let mut groups_to_include: HashSet<Uuid> = HashSet::new();
    let mut groups_to_exclude: HashSet<Uuid> = HashSet::new();

    // Sort patterns by priority (highest first)
    let mut sorted_patterns = patterns.to_vec();
    sorted_patterns.sort_by(|a, b| b.priority.cmp(&a.priority));

    // For each group, find the first matching pattern (highest priority)
    for group in all_groups {
        for pattern in &sorted_patterns {
            if pattern_matches(&pattern.pattern, &group.name) {
                if pattern.is_include {
                    groups_to_include.insert(group.id);
                } else {
                    groups_to_exclude.insert(group.id);
                }
                break; // First match wins due to priority
            }
        }
    }

    // Remove excluded groups from included set
    for excluded_id in &groups_to_exclude {
        groups_to_include.remove(excluded_id);
    }

    (groups_to_include, groups_to_exclude)
}

/// Background job to evaluate and synchronize user group assignments based on patterns
pub async fn evaluate_and_sync_patterns(pool: &DbPool) {
    tracing::debug!("Starting group patterns evaluation");

    // Fetch all users who have patterns
    let users_with_patterns = match sqlx::query!(
        r#"
        SELECT DISTINCT user_id FROM user_group_patterns
        "#
    )
    .fetch_all(pool)
    .await
    {
        Ok(users) => users,
        Err(e) => {
            tracing::error!("Failed to fetch users with patterns: {:?}", e);
            return;
        }
    };

    if users_with_patterns.is_empty() {
        tracing::debug!("No users with group patterns found");
        return;
    }

    // Fetch all groups
    let all_groups = match sqlx::query_as!(
        Group,
        r#"SELECT id, name, description, is_virtual, created_at, updated_at FROM groups"#
    )
    .fetch_all(pool)
    .await
    {
        Ok(groups) => groups,
        Err(e) => {
            tracing::error!("Failed to fetch groups: {:?}", e);
            return;
        }
    };

    let mut total_added = 0;
    let mut total_removed = 0;

    // Process each user
    for user_row in users_with_patterns {
        let user_id = user_row.user_id;

        // Fetch patterns for this user
        let patterns = match sqlx::query_as!(
            UserGroupPattern,
            r#"
            SELECT id, user_id, pattern, is_include, priority, created_at
            FROM user_group_patterns
            WHERE user_id = $1
            ORDER BY priority DESC
            "#,
            user_id
        )
        .fetch_all(pool)
        .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to fetch patterns for user {}: {:?}", user_id, e);
                continue;
            }
        };

        // Evaluate which groups should be assigned
        let (groups_to_include, _) = evaluate_patterns(&patterns, &all_groups);

        // Fetch current group assignments
        let current_groups = match sqlx::query!(
            r#"SELECT group_id FROM user_groups WHERE user_id = $1"#,
            user_id
        )
        .fetch_all(pool)
        .await
        {
            Ok(rows) => rows.into_iter().map(|r| r.group_id).collect::<HashSet<_>>(),
            Err(e) => {
                tracing::error!("Failed to fetch current groups for user {}: {:?}", user_id, e);
                continue;
            }
        };

        // Find groups to add (in groups_to_include but not in current_groups)
        let to_add: Vec<_> = groups_to_include.difference(&current_groups).collect();

        // Find groups to remove (in current_groups but not in groups_to_include)
        // BUT: Only remove groups that match some pattern
        // Don't remove manually assigned groups that don't match any pattern
        let matching_group_ids: HashSet<Uuid> = all_groups
            .iter()
            .filter(|g| {
                patterns
                    .iter()
                    .any(|p| pattern_matches(&p.pattern, &g.name))
            })
            .map(|g| g.id)
            .collect();

        let to_remove: Vec<_> = current_groups
            .iter()
            .filter(|gid| matching_group_ids.contains(gid) && !groups_to_include.contains(gid))
            .collect();

        // Add missing groups
        for group_id in to_add {
            match sqlx::query!(
                "INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                user_id,
                group_id
            )
            .execute(pool)
            .await
            {
                Ok(_) => {
                    total_added += 1;
                    tracing::debug!("Added user {} to group {}", user_id, group_id);
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to add user {} to group {}: {:?}",
                        user_id,
                        group_id,
                        e
                    );
                }
            }
        }

        // Remove excluded groups
        for group_id in to_remove {
            match sqlx::query!(
                "DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2",
                user_id,
                group_id
            )
            .execute(pool)
            .await
            {
                Ok(_) => {
                    total_removed += 1;
                    tracing::debug!("Removed user {} from group {}", user_id, group_id);
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to remove user {} from group {}: {:?}",
                        user_id,
                        group_id,
                        e
                    );
                }
            }
        }
    }

    if total_added > 0 || total_removed > 0 {
        tracing::info!(
            "Group patterns sync completed: {} assignments added, {} removed",
            total_added,
            total_removed
        );
    } else {
        tracing::debug!("Group patterns sync completed: no changes");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(pattern_matches("ssh:role:admin", "ssh:role:admin"));
        assert!(!pattern_matches("ssh:role:admin", "ssh:role:user"));
    }

    #[test]
    fn test_wildcard_prefix() {
        assert!(pattern_matches("ssh:*", "ssh:role:admin"));
        assert!(pattern_matches("ssh:*", "ssh:principal:alice"));
        assert!(!pattern_matches("ssh:*", "ldap:role:admin"));
    }

    #[test]
    fn test_wildcard_suffix() {
        assert!(pattern_matches("*:admin", "ssh:role:admin"));
        assert!(pattern_matches("*:admin", "ldap:role:admin"));
        assert!(!pattern_matches("*:admin", "ssh:role:user"));
    }

    #[test]
    fn test_wildcard_middle() {
        assert!(pattern_matches("ssh:*:admin", "ssh:role:admin"));
        assert!(pattern_matches("ssh:*:admin", "ssh:principal:admin"));
        assert!(!pattern_matches("ssh:*:admin", "ssh:role:user"));
    }

    #[test]
    fn test_match_all() {
        assert!(pattern_matches("*", "anything"));
        assert!(pattern_matches("*", "ssh:role:admin"));
    }
}
