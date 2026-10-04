CREATE TABLE IF NOT EXISTS sessions (
 session_id TEXT PRIMARY KEY, bastion_id TEXT NOT NULL,
 issuer TEXT, subject TEXT, tenant TEXT, username TEXT,
 host_id TEXT NOT NULL, address TEXT, port INTEGER, linux_user TEXT NOT NULL,
 client_ip TEXT NOT NULL, requested_at INTEGER NOT NULL,
 connected_at INTEGER, ended_at INTEGER, reconciled_at INTEGER,
 duration_ms INTEGER, result TEXT NOT NULL, end_reason TEXT, exit_status INTEGER,
 certificate_id TEXT
);
CREATE INDEX IF NOT EXISTS sessions_requested ON sessions(requested_at);
CREATE INDEX IF NOT EXISTS sessions_subject ON sessions(subject, requested_at);
CREATE INDEX IF NOT EXISTS sessions_host ON sessions(host_id, requested_at);
PRAGMA user_version = 1;
