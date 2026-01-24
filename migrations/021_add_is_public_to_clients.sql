-- Add is_public flag to oauth_clients for public clients (PKCE-only, no secret)
-- Default is false (confidential client with secret required)

ALTER TABLE oauth_clients
  ADD COLUMN is_public BOOLEAN NOT NULL DEFAULT false;

-- Add comment for clarity
COMMENT ON COLUMN oauth_clients.is_public IS
  'true for public clients (e.g., browser/mobile apps using PKCE), false for confidential clients requiring client_secret';

-- Add constraint: public clients must have NULL client_secret_hash
ALTER TABLE oauth_clients
  ADD CONSTRAINT check_public_client_no_secret
  CHECK (
    (is_public = true AND client_secret_hash IS NULL) OR
    (is_public = false AND client_secret_hash IS NOT NULL)
  );
