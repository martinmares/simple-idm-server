-- Enforce strict tree semantics for group hierarchy:
-- each child group can have at most one parent.

-- Deduplicate possible historical multi-parent rows:
-- keep oldest relation per child, delete the rest.
WITH ranked AS (
    SELECT
        ctid,
        ROW_NUMBER() OVER (
            PARTITION BY child_group_id
            ORDER BY created_at ASC, parent_group_id ASC
        ) AS rn
    FROM group_groups
)
DELETE FROM group_groups gg
USING ranked r
WHERE gg.ctid = r.ctid
  AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS uq_group_groups_single_parent
    ON group_groups(child_group_id);
