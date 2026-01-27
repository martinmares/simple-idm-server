//! Claim Map Pattern evaluation module.
//!
//! This module provides pattern matching for claim maps, allowing dynamic
//! claim assignment based on user's group names.

use crate::db::models::ClaimMapPattern;

/// Check if a group name matches a pattern
/// Supports wildcards:
/// - `ssh:*` matches `ssh:server1`, `ssh:server2`, etc.
/// - `*:admin` matches `ssh:admin`, `http:admin`, etc.
/// - `ssh:*:admin` matches `ssh:server1:admin`, `ssh:server2:admin`, etc.
/// - `ssh:test*` matches `ssh:test1`, `ssh:test2`, etc. (prefix matching)
/// - `ssh:*admin` matches `ssh:localadmin`, `ssh:sysadmin`, etc. (suffix matching)
fn pattern_matches(pattern: &str, group_name: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split(':').collect();
    let group_parts: Vec<&str> = group_name.split(':').collect();

    if pattern_parts.len() != group_parts.len() {
        return false;
    }

    for (pattern_part, group_part) in pattern_parts.iter().zip(group_parts.iter()) {
        // Exact wildcard match
        if *pattern_part == "*" {
            continue;
        }

        // Check for prefix/suffix wildcards
        if pattern_part.contains('*') {
            if pattern_part.starts_with('*') && pattern_part.ends_with('*') {
                // *substring* - contains match
                let substring = &pattern_part[1..pattern_part.len() - 1];
                if !group_part.contains(substring) {
                    return false;
                }
            } else if let Some(suffix) = pattern_part.strip_prefix('*') {
                // *suffix - suffix match
                if !group_part.ends_with(suffix) {
                    return false;
                }
            } else if let Some(prefix) = pattern_part.strip_suffix('*') {
                // prefix* - prefix match
                if !group_part.starts_with(prefix) {
                    return false;
                }
            } else {
                // Wildcard in middle (not supported)
                return false;
            }
        } else {
            // Exact match required
            if *pattern_part != *group_part {
                return false;
            }
        }
    }

    true
}

/// Evaluate if claim map patterns match any of the user's groups
///
/// Returns true if patterns match (claim should be applied), false otherwise
///
/// # Logic
/// - If patterns is empty, return true (no patterns = always match)
/// - Patterns are applied sequentially by priority (ASC: 1, 2, 3...)
/// - Include patterns add to match set, exclude patterns remove from match set
/// - Final result: true if any group remains in match set
///
/// # Example
/// ```
/// let patterns = vec![
///     ClaimMapPattern { pattern: "ssh:*", is_include: true, priority: 1, ... },
///     ClaimMapPattern { pattern: "ssh:test*", is_include: false, priority: 2, ... },
/// ];
/// let groups = vec!["ssh:prod".to_string(), "ssh:test1".to_string()];
///
/// // Result: true (ssh:prod matches, ssh:test1 excluded)
/// ```
pub fn evaluate_claim_map_patterns(
    group_names: &[String],
    patterns: &[ClaimMapPattern],
) -> bool {
    // No patterns = always match (backward compatibility)
    if patterns.is_empty() {
        return true;
    }

    // Sort patterns by priority (ASC)
    let mut sorted_patterns = patterns.to_vec();
    sorted_patterns.sort_by_key(|p| p.priority);

    // Track which groups match
    let mut matched_groups = std::collections::HashSet::new();

    // Apply patterns sequentially
    for pattern in &sorted_patterns {
        for group_name in group_names {
            if pattern_matches(&pattern.pattern, group_name) {
                if pattern.is_include {
                    matched_groups.insert(group_name.clone());
                } else {
                    matched_groups.remove(group_name);
                }
            }
        }
    }

    // Return true if any groups matched
    !matched_groups.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_pattern(pattern: &str, is_include: bool, priority: i32) -> ClaimMapPattern {
        ClaimMapPattern {
            id: Uuid::new_v4(),
            claim_map_id: Uuid::new_v4(),
            pattern: pattern.to_string(),
            is_include,
            priority,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_pattern_matches_exact() {
        assert!(pattern_matches("ssh:server1", "ssh:server1"));
        assert!(!pattern_matches("ssh:server1", "ssh:server2"));
    }

    #[test]
    fn test_pattern_matches_wildcard() {
        assert!(pattern_matches("ssh:*", "ssh:server1"));
        assert!(pattern_matches("ssh:*", "ssh:server2"));
        assert!(!pattern_matches("ssh:*", "http:server1"));

        assert!(pattern_matches("*:admin", "ssh:admin"));
        assert!(pattern_matches("*:admin", "http:admin"));
        assert!(!pattern_matches("*:admin", "ssh:user"));
    }

    #[test]
    fn test_pattern_matches_multiple_wildcards() {
        assert!(pattern_matches("ssh:*:admin", "ssh:server1:admin"));
        assert!(pattern_matches("ssh:*:admin", "ssh:server2:admin"));
        assert!(!pattern_matches("ssh:*:admin", "ssh:server1:user"));
        assert!(!pattern_matches("ssh:*:admin", "http:server1:admin"));
    }

    #[test]
    fn test_pattern_matches_length_mismatch() {
        assert!(!pattern_matches("ssh:*", "ssh:server1:admin"));
        assert!(!pattern_matches("ssh:*:admin", "ssh:server1"));
    }

    #[test]
    fn test_pattern_matches_prefix_wildcard() {
        assert!(pattern_matches("ssh:test*", "ssh:test1"));
        assert!(pattern_matches("ssh:test*", "ssh:test2"));
        assert!(pattern_matches("ssh:test*", "ssh:testing"));
        assert!(!pattern_matches("ssh:test*", "ssh:prod1"));
    }

    #[test]
    fn test_pattern_matches_suffix_wildcard() {
        assert!(pattern_matches("ssh:*admin", "ssh:localadmin"));
        assert!(pattern_matches("ssh:*admin", "ssh:sysadmin"));
        assert!(pattern_matches("ssh:*admin", "ssh:admin"));
        assert!(!pattern_matches("ssh:*admin", "ssh:user"));
    }

    #[test]
    fn test_pattern_matches_contains_wildcard() {
        assert!(pattern_matches("ssh:*prod*", "ssh:production"));
        assert!(pattern_matches("ssh:*prod*", "ssh:preprod"));
        assert!(pattern_matches("ssh:*prod*", "ssh:prod"));
        assert!(!pattern_matches("ssh:*prod*", "ssh:staging"));
    }

    #[test]
    fn test_evaluate_empty_patterns() {
        let groups = vec!["ssh:server1".to_string(), "http:admin".to_string()];
        let patterns = vec![];

        assert!(evaluate_claim_map_patterns(&groups, &patterns));
    }

    #[test]
    fn test_evaluate_simple_include() {
        let groups = vec!["ssh:server1".to_string(), "http:admin".to_string()];
        let patterns = vec![make_pattern("ssh:*", true, 1)];

        assert!(evaluate_claim_map_patterns(&groups, &patterns));
    }

    #[test]
    fn test_evaluate_no_match() {
        let groups = vec!["ssh:server1".to_string(), "http:admin".to_string()];
        let patterns = vec![make_pattern("ftp:*", true, 1)];

        assert!(!evaluate_claim_map_patterns(&groups, &patterns));
    }

    #[test]
    fn test_evaluate_include_then_exclude() {
        let groups = vec![
            "ssh:prod".to_string(),
            "ssh:test1".to_string(),
            "ssh:test2".to_string(),
        ];
        let patterns = vec![
            make_pattern("ssh:*", true, 1),      // Include all ssh:*
            make_pattern("ssh:test*", false, 2), // Exclude ssh:test*
        ];

        // ssh:prod should match (included, not excluded)
        assert!(evaluate_claim_map_patterns(&groups, &patterns));
    }

    #[test]
    fn test_evaluate_all_excluded() {
        let groups = vec!["ssh:test1".to_string(), "ssh:test2".to_string()];
        let patterns = vec![
            make_pattern("ssh:*", true, 1),      // Include all ssh:*
            make_pattern("ssh:test*", false, 2), // Exclude ssh:test*
        ];

        // All groups excluded = no match
        assert!(!evaluate_claim_map_patterns(&groups, &patterns));
    }

    #[test]
    fn test_evaluate_priority_matters() {
        let groups = vec!["ssh:admin".to_string()];

        // Priority 1 (exclude) then 2 (include) = should match
        let patterns1 = vec![
            make_pattern("ssh:*", false, 1), // Exclude first
            make_pattern("*:admin", true, 2), // Include after
        ];
        assert!(evaluate_claim_map_patterns(&groups, &patterns1));

        // Priority 1 (include) then 2 (exclude) = should not match
        let patterns2 = vec![
            make_pattern("*:admin", true, 1),  // Include first
            make_pattern("ssh:*", false, 2),   // Exclude after
        ];
        assert!(!evaluate_claim_map_patterns(&groups, &patterns2));
    }

    #[test]
    fn test_evaluate_multiple_groups_partial_match() {
        let groups = vec![
            "ssh:server1".to_string(),
            "http:admin".to_string(),
            "ftp:user".to_string(),
        ];
        let patterns = vec![make_pattern("*:admin", true, 1)];

        // http:admin matches
        assert!(evaluate_claim_map_patterns(&groups, &patterns));
    }
}
