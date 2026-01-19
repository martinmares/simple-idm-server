-- Add support for nested groups (groups can contain other groups)
-- This allows creating "bundles" like team:devops that contains multiple app-specific groups

CREATE TABLE IF NOT EXISTS group_groups (
    parent_group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    child_group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (parent_group_id, child_group_id),
    -- Prevent self-loops (group cannot contain itself)
    CONSTRAINT no_self_loop CHECK (parent_group_id != child_group_id)
);

-- Index for efficient child lookup (find all parents of a group)
CREATE INDEX idx_group_groups_child ON group_groups(child_group_id);

-- Index for efficient parent lookup (find all children of a group)
CREATE INDEX idx_group_groups_parent ON group_groups(parent_group_id);

-- Note: Cycle detection is handled in application code before insert
