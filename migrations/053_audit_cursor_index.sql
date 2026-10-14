CREATE INDEX IF NOT EXISTS idx_audit_events_cursor
    ON audit_events (created_at DESC, id DESC);
