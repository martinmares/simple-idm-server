-- OAuth Client Group Patterns table
-- Allows runtime filtering of groups in JWT tokens based on client needs
-- Example: client "Grafana" with pattern "grafana:*" receives only Grafana-related groups
-- Patterns are applied sequentially by priority (lower number = higher priority)
-- Include patterns add groups, exclude patterns remove them

CREATE TABLE oauth_client_group_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    pattern TEXT NOT NULL,
    is_include BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for efficient lookups by client
CREATE INDEX idx_oauth_client_group_patterns_client_id ON oauth_client_group_patterns(client_id);

-- Index for sorting by priority during evaluation (ASC for sequential application)
CREATE INDEX idx_oauth_client_group_patterns_priority ON oauth_client_group_patterns(client_id, priority ASC);
