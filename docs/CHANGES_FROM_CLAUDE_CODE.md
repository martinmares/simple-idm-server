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

## Documentation
- Updated README.md with new Configuration section documenting all environment variables.
- Added documentation for JWT kid support and its purpose.
- Added documentation for per-endpoint rate limiting configuration.
- Updated .env.example with new configuration options.
- Marked completed TODO items in README.md (kid support and per-endpoint rate limiting).
