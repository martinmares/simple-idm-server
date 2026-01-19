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

## CLI Tool (simple-idm-ctl) - Contract 2026-01-19.01
- **Changed from application-based to user-based authentication**:
  - CLI now authenticates as a user (not as an application client).
  - Users must be members of `simple-idm:role:admin` group to use CLI.
  - Authorization checked via group membership in JWT token.
- **OAuth2 client changed from `simple-idm-ctl` to `cli-tools`** (migrations 005, 007):
  - Client ID: `cli-tools` (for CLI tools and custom integrations).
  - Redirect URIs: `http://localhost:8888/callback`, `http://127.0.0.1:8888/callback`.
  - Grant types: `authorization_code`, `refresh_token`.
  - Scope: `openid profile email groups`.
  - Public client with PKCE (no client_secret validation when code_verifier present).
- **Created `simple-idm:role:admin` group and seed admin user** (migration 006):
  - Group naming convention: `app:role:level` (e.g., `simple-idm:role:admin`).
  - Seed user: username `admin`, email `admin@localhost`.
  - Admin user automatically assigned to admin group.
- **Updated authorization middleware** (src/admin/middleware.rs):
  - Checks for `simple-idm:role:admin` group membership in JWT groups claim.
  - Backward compatibility with deprecated `admin` group (with warning).
- **OAuth2/OIDC login flow with PKCE**:
  - Added `login --url <SERVER_URL>` command (required parameter, no defaults).
  - Opens browser automatically for user login.
  - Runs local callback server on port 8888 (configurable via `--port`).
  - Supports PKCE (Proof Key for Code Exchange) for public client security.
  - Displays authorization URL if browser doesn't open automatically.
- **Multi-server session management**:
  - Sessions stored in `~/.config/simple-idm-ctl/sessions.json`.
  - Support for multiple named servers (default server name: "default").
  - Added `sessions list` and `sessions use <SERVER>` commands.
  - File permissions set to 0600 on Unix systems for security.
- **Session lifecycle**:
  - Added `logout` command (with optional `--server` or `--all` flags).
  - Added `status` command showing login status, token expiration, server URL.
  - Automatic token refresh when expires in less than 5 minutes.
  - Silent refresh during normal command execution.
- **Removed legacy authentication**:
  - Removed `--token` parameter (OAuth login required).
  - Removed `--base-url` parameter (URL stored in session).
  - No hardcoded server defaults (explicit `--url` required for login).
- **PKCE flow without client_secret** (src/oauth2/authorization_code.rs):
  - Skip client_secret validation when `code_verifier` is present.
  - Allows public clients (CLI tools) to use authorization code flow securely.

## Documentation
- Updated README.md with new Configuration section documenting all environment variables.
- Added documentation for JWT kid support and its purpose.
- Added documentation for per-endpoint rate limiting configuration.
- Updated .env.example with new configuration options.
- Marked completed TODO items in README.md (kid support and per-endpoint rate limiting).
