-- Add nonce to authorization_codes for OIDC ID token validation
ALTER TABLE authorization_codes
ADD COLUMN IF NOT EXISTS nonce TEXT;
