-- Add pattern support to claim maps
-- This enables dynamic claim mapping based on group patterns instead of fixed group_id

-- First, make group_id optional in claim_maps (allow pattern-based claim maps)
ALTER TABLE claim_maps
ALTER COLUMN group_id DROP NOT NULL;

-- Create claim_map_patterns table
CREATE TABLE claim_map_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_map_id UUID NOT NULL REFERENCES claim_maps(id) ON DELETE CASCADE,
    pattern TEXT NOT NULL,
    is_include BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for efficient querying
CREATE INDEX idx_claim_map_patterns_claim_map_id ON claim_map_patterns(claim_map_id);
CREATE INDEX idx_claim_map_patterns_priority ON claim_map_patterns(claim_map_id, priority ASC);

-- Comments
COMMENT ON TABLE claim_map_patterns IS 'Patterns for dynamic claim mapping based on group names';
COMMENT ON COLUMN claim_map_patterns.pattern IS 'Wildcard pattern like "ssh:*" or "*:admin"';
COMMENT ON COLUMN claim_map_patterns.is_include IS 'true = include matching groups, false = exclude';
COMMENT ON COLUMN claim_map_patterns.priority IS 'Lower number = higher priority, patterns applied sequentially';
