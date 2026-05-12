use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum MappingTarget {
    Group(String),
    ClaimMap(String),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum MappingMode {
    Add,
    Remove,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExternalRoleMapping {
    pub external_role: String,
    pub target: MappingTarget,
    pub mode: MappingMode,
    pub priority: i32,
    pub is_active: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SyncInput {
    pub external_roles: Vec<String>,
    pub current_groups: Vec<String>,
    pub mappings: Vec<ExternalRoleMapping>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SyncResult {
    pub effective_groups: Vec<String>,
    pub added_groups: Vec<String>,
    pub removed_groups: Vec<String>,
    pub matched_external_roles: Vec<String>,
}

pub fn apply_role_mappings(input: &SyncInput) -> SyncResult {
    let mut current: HashSet<String> = input.current_groups.iter().cloned().collect();
    let mut matched_roles: HashSet<String> = HashSet::new();

    let external_set: HashSet<String> = input.external_roles.iter().cloned().collect();

    let mut mappings: Vec<&ExternalRoleMapping> =
        input.mappings.iter().filter(|m| m.is_active).collect();

    // Lower number = higher priority.
    mappings.sort_by_key(|m| m.priority);

    // Collisions are resolved by first (highest priority) mapping for each target.
    let mut decided_targets: HashMap<String, MappingMode> = HashMap::new();

    for mapping in mappings {
        if !external_set.contains(&mapping.external_role) {
            continue;
        }
        matched_roles.insert(mapping.external_role.clone());

        let target_group = match &mapping.target {
            MappingTarget::Group(group_id) => group_id,
            MappingTarget::ClaimMap(_) => {
                // Claim maps are handled outside this function.
                continue;
            }
        };

        if decided_targets.contains_key(target_group) {
            continue;
        }

        decided_targets.insert(target_group.clone(), mapping.mode.clone());
    }

    let before = current.clone();

    for (group_id, mode) in decided_targets {
        match mode {
            MappingMode::Add => {
                current.insert(group_id);
            }
            MappingMode::Remove => {
                current.remove(&group_id);
            }
        }
    }

    let mut effective_groups: Vec<String> = current.iter().cloned().collect();
    effective_groups.sort();

    let mut added_groups: Vec<String> = current.difference(&before).cloned().collect();
    added_groups.sort();

    let mut removed_groups: Vec<String> = before.difference(&current).cloned().collect();
    removed_groups.sort();

    let mut matched_external_roles: Vec<String> = matched_roles.into_iter().collect();
    matched_external_roles.sort();

    SyncResult {
        effective_groups,
        added_groups,
        removed_groups,
        matched_external_roles,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn applies_add_and_remove_with_priority() {
        let input = SyncInput {
            external_roles: vec!["ad:devops".to_string()],
            current_groups: vec!["users".to_string()],
            mappings: vec![
                ExternalRoleMapping {
                    external_role: "ad:devops".to_string(),
                    target: MappingTarget::Group("team:devops".to_string()),
                    mode: MappingMode::Add,
                    priority: 10,
                    is_active: true,
                },
                ExternalRoleMapping {
                    external_role: "ad:devops".to_string(),
                    target: MappingTarget::Group("team:devops".to_string()),
                    mode: MappingMode::Remove,
                    priority: 20,
                    is_active: true,
                },
            ],
        };

        let out = apply_role_mappings(&input);
        assert_eq!(
            out.effective_groups,
            vec!["team:devops".to_string(), "users".to_string()]
        );
        assert_eq!(out.added_groups, vec!["team:devops".to_string()]);
        assert_eq!(out.removed_groups, Vec::<String>::new());
        assert_eq!(out.matched_external_roles, vec!["ad:devops".to_string()]);
    }
}
