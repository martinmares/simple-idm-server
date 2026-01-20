-- Add virtual group flag and per-client ignore flag

ALTER TABLE groups
ADD COLUMN IF NOT EXISTS is_virtual BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE oauth_clients
ADD COLUMN IF NOT EXISTS ignore_virtual_groups BOOLEAN NOT NULL DEFAULT false;
