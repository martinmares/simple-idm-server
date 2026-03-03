CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    actor_sub TEXT NULL,
    actor_client_id TEXT NULL,
    details JSONB NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
    ON audit_events(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_action
    ON audit_events(action);

CREATE INDEX IF NOT EXISTS idx_audit_events_resource
    ON audit_events(resource_type, resource_id);
