-- User Group Patterns table
-- Allows automatic assignment of users to groups matching wildcard patterns
-- Example: pattern "ssh:*" with is_include=true assigns user to all groups starting with "ssh:"
-- Higher priority patterns override lower priority ones

CREATE TABLE user_group_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    pattern TEXT NOT NULL,
    is_include BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for efficient lookups by user
CREATE INDEX idx_user_group_patterns_user_id ON user_group_patterns(user_id);

-- Index for sorting by priority during evaluation
CREATE INDEX idx_user_group_patterns_priority ON user_group_patterns(priority DESC);
