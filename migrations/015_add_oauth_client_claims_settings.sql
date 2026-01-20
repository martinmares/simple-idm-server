-- Add per-client group/claim map settings

ALTER TABLE oauth_clients
ADD COLUMN IF NOT EXISTS groups_claim_mode TEXT NOT NULL DEFAULT 'effective';

ALTER TABLE oauth_clients
ADD COLUMN IF NOT EXISTS include_claim_maps BOOLEAN NOT NULL DEFAULT true;
