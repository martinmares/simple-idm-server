-- Make client_secret_hash nullable to support public clients
-- Public clients (like simple-idm-ssh-login) don't need a secret

ALTER TABLE oauth_clients
  ALTER COLUMN client_secret_hash DROP NOT NULL;

-- Add comment for clarity
COMMENT ON COLUMN oauth_clients.client_secret_hash IS
  'Optional: NULL for public clients (e.g., PKCE-only flows), hashed secret for confidential clients';
