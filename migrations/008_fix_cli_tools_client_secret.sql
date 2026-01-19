-- Fix cli-tools client to use empty client_secret for public client
-- Hash for empty string "" generated with argon2
-- This allows PKCE flow without requiring client secret
UPDATE oauth_clients
SET client_secret_hash = '$argon2id$v=19$m=19456,t=2,p=1$cmFuZG9tc2FsdDEyMzQ1Njc4$XuNHV8S+FPZGCjrD8bqRHT5rCREu9xqhvWqmCFKaRRA'
WHERE client_id = 'cli-tools';
