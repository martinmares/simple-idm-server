-- Read-only. Run before deployment and retain the report with the release record.
-- psql "$DATABASE_URL" -f scripts/group-contract-audit.sql
SELECT g.tenant_id, g.id AS physical_parent_uuid, g.name AS physical_parent,
       c.id AS child_uuid, c.name AS child, g.deleted_at AS parent_archived_at,
       cm.id AS claim_map_uuid, oc.client_id, cm.claim_name
FROM groups g JOIN group_groups gg ON gg.parent_group_id=g.id
JOIN groups c ON c.id=gg.child_group_id
LEFT JOIN claim_maps cm ON cm.group_id=g.id AND cm.deleted_at IS NULL
LEFT JOIN oauth_clients oc ON oc.id=cm.client_id
WHERE NOT g.is_virtual ORDER BY g.tenant_id, g.name, c.name;

-- Potential virtual-export dependencies; inspect the applications too.
SELECT tenant_id, id AS client_uuid, client_id, groups_claim_mode,
       include_claim_maps, ignore_virtual_groups
FROM oauth_clients WHERE deleted_at IS NULL AND NOT ignore_virtual_groups
ORDER BY tenant_id, client_id;

-- Patterns now see effective internal names regardless of groups publication.
SELECT oc.tenant_id, oc.client_id, cm.id AS claim_map_uuid, cm.claim_name,
       p.pattern, p.is_include, p.priority
FROM claim_map_patterns p JOIN claim_maps cm ON cm.id=p.claim_map_id
JOIN oauth_clients oc ON oc.id=cm.client_id
WHERE p.deleted_at IS NULL AND cm.deleted_at IS NULL AND oc.deleted_at IS NULL
ORDER BY oc.client_id, cm.claim_name, p.priority;

-- Potentially conflicting scalar mappings; actual overlap depends on membership.
SELECT client_id, claim_name, array_agg(DISTINCT claim_value) AS values
FROM claim_maps WHERE deleted_at IS NULL AND claim_value_kind='single'
GROUP BY client_id, claim_name HAVING COUNT(DISTINCT claim_value)>1;
