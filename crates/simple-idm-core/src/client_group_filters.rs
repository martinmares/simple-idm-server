use crate::db::models::OAuthClientGroupPattern;
use crate::group_patterns::pattern_matches;

/// Apply client group filtering patterns to a list of group names
///
/// Patterns are applied sequentially by priority (lower number = higher priority).
/// Include patterns add groups to the result, exclude patterns remove them.
///
/// This is a runtime operation (no database writes) that filters which groups
/// appear in JWT tokens based on client needs.
///
/// # Examples
///
/// ```
/// // Client only needs Grafana groups
/// patterns = [
///   { pattern: "grafana:*", is_include: true, priority: 1 },
///   { pattern: "*", is_include: false, priority: 2 }
/// ]
///
/// input: ["ssh:role:admin", "grafana:role:viewer", "gitlab:role:dev"]
/// output: ["grafana:role:viewer"]
/// ```
pub fn apply_client_group_filters(
    group_names: &[String],
    patterns: &[OAuthClientGroupPattern],
) -> Vec<String> {
    if patterns.is_empty() {
        // No filtering - return all groups
        return group_names.to_vec();
    }

    // Sort patterns by priority (lowest number = first to apply)
    let mut sorted_patterns = patterns.to_vec();
    sorted_patterns.sort_by_key(|p| p.priority);

    // Track which groups are included
    let mut included_groups = std::collections::HashSet::new();

    // Apply patterns sequentially
    for pattern in &sorted_patterns {
        for group_name in group_names {
            if pattern_matches(&pattern.pattern, group_name) {
                if pattern.is_include {
                    // Include: add to result
                    included_groups.insert(group_name.clone());
                } else {
                    // Exclude: remove from result
                    included_groups.remove(group_name);
                }
            }
        }
    }

    // Convert back to Vec and sort for deterministic output
    let mut result: Vec<String> = included_groups.into_iter().collect();
    result.sort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_pattern(pattern: &str, is_include: bool, priority: i32) -> OAuthClientGroupPattern {
        OAuthClientGroupPattern {
            id: Uuid::new_v4(),
            client_id: Uuid::new_v4(),
            pattern: pattern.to_string(),
            is_include,
            priority,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_no_patterns_returns_all() {
        let groups = vec![
            "ssh:role:admin".to_string(),
            "grafana:role:viewer".to_string(),
        ];
        let patterns = vec![];

        let result = apply_client_group_filters(&groups, &patterns);

        assert_eq!(result.len(), 2);
        assert!(result.contains(&"ssh:role:admin".to_string()));
        assert!(result.contains(&"grafana:role:viewer".to_string()));
    }

    #[test]
    fn test_include_only_grafana() {
        let groups = vec![
            "ssh:role:admin".to_string(),
            "grafana:role:viewer".to_string(),
            "gitlab:role:developer".to_string(),
        ];

        // Only include grafana groups - no exclude pattern needed
        // (groups not explicitly included are excluded by default)
        let patterns = vec![
            make_pattern("grafana:*", true, 1),
        ];

        let result = apply_client_group_filters(&groups, &patterns);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "grafana:role:viewer");
    }

    #[test]
    fn test_exclude_specific_group() {
        let groups = vec![
            "ssh:role:admin".to_string(),
            "ssh:role:devops".to_string(),
            "ssh:role:monitoring".to_string(),
        ];

        let patterns = vec![
            make_pattern("ssh:*", true, 1),
            make_pattern("ssh:role:admin", false, 2),
        ];

        let result = apply_client_group_filters(&groups, &patterns);

        assert_eq!(result.len(), 2);
        assert!(result.contains(&"ssh:role:devops".to_string()));
        assert!(result.contains(&"ssh:role:monitoring".to_string()));
        assert!(!result.contains(&"ssh:role:admin".to_string()));
    }

    #[test]
    fn test_sequential_application() {
        let groups = vec![
            "ssh:role:admin".to_string(),
            "ssh:role:devops".to_string(),
            "grafana:role:admin".to_string(),
        ];

        // Add all ssh groups, then remove admin groups
        let patterns = vec![
            make_pattern("ssh:*", true, 1),
            make_pattern("*:admin", false, 2),
        ];

        let result = apply_client_group_filters(&groups, &patterns);

        // ssh:role:admin added by pattern 1, removed by pattern 2
        // grafana:role:admin never added (no matching include), so pattern 2 doesn't affect it
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "ssh:role:devops");
    }

    #[test]
    fn test_priority_ordering() {
        let groups = vec![
            "test:group".to_string(),
        ];

        // Higher priority (lower number) should apply first
        let patterns = vec![
            make_pattern("*", false, 10), // Apply second: exclude all
            make_pattern("test:*", true, 1), // Apply first: include test:*
        ];

        let result = apply_client_group_filters(&groups, &patterns);

        // Pattern 1 includes test:group, pattern 10 excludes it
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_empty_groups() {
        let groups: Vec<String> = vec![];
        let patterns = vec![
            make_pattern("ssh:*", true, 1),
        ];

        let result = apply_client_group_filters(&groups, &patterns);

        assert_eq!(result.len(), 0);
    }
}
