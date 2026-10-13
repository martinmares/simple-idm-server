ALTER TABLE sessions ADD COLUMN session_kind TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE sessions ADD COLUMN sudo_readonly INTEGER NOT NULL DEFAULT 0 CHECK (sudo_readonly IN (0,1));
PRAGMA user_version = 2;
