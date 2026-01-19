# Changes from Claude Code

This file summarizes the changes made by Claude Code agent after the ChatGPT work.

## OAuth2/OIDC behavior & security
- Implemented JWT `kid` (Key ID) support in JWT header and JWKS for key rotation strategy.
- Added configurable `kid` via `JWT_KEY_ID` environment variable (default: `default-key-2025`).
- JWT tokens now include `kid` in header for proper key identification.
- JWKS endpoint returns configured `kid` instead of hardcoded value.

## Rate limiting
- Implemented per-endpoint rate limiting with stricter limits for `/oauth2/token` endpoint.
- Added environment variables for token endpoint rate limiting configuration:
  - `RATE_LIMIT_TOKEN_ENDPOINT_REQUESTS_PER_SECOND` (default: 2)
  - `RATE_LIMIT_TOKEN_ENDPOINT_BURST_SIZE` (default: 5)
- Token endpoint now has separate, stricter rate limiting to prevent brute-force attacks.
- Improved startup logging to show both global and per-endpoint rate limits.

## CLI Tool (simple-idm-ctl)
- Implemented OAuth2/OIDC login flow with authorization code + PKCE.
- Added `login` command for browser-based authentication:
  - Opens browser automatically for user login.
  - Runs local callback server on port 8888 (configurable via `--port`).
  - Supports PKCE (Proof Key for Code Exchange) for security.
  - Displays authorization URL if browser doesn't open automatically.
- Added `logout` command for session termination.
- Added `status` command for session information display:
  - Shows login status and token expiration.
  - Displays server URL and session creation time.
  - Warns when token is expired.
- Session persistence in `~/.config/simple-idm-ctl/session`:
  - Stores access_token, refresh_token, expires_at, base_url, created_at.
  - File permissions set to 0600 on Unix systems for security.
- Automatic token refresh before expiration:
  - Refreshes when token expires in less than 5 minutes.
  - Silent refresh during normal command execution.
- Maintained backward compatibility with `--token` parameter:
  - `--token` flag takes priority over session (legacy mode).
  - `--base-url` and `--insecure` flags still supported.
- Created OAuth2 client for simple-idm-ctl in database (migration 005):
  - Client ID: `simple-idm-ctl`.
  - Redirect URIs: `http://localhost:8888/callback`, `http://127.0.0.1:8888/callback`.
  - Grant types: `authorization_code`, `refresh_token`.
  - Scope: `openid profile email`.

## Documentation
- Updated README.md with new Configuration section documenting all environment variables.
- Added documentation for JWT kid support and its purpose.
- Added documentation for per-endpoint rate limiting configuration.
- Updated .env.example with new configuration options.
- Marked completed TODO items in README.md (kid support and per-endpoint rate limiting).
