# Changes from ChatGPT work

This file summarizes the changes made after the repository was handed over from the original "Claude code" baseline.

## Documentation
- Fixed OAuth2 docs inconsistencies and corrected admin endpoint guidance.
- Added Czech integration guides for Grafana, GitLab, and Elasticsearch plus a Czech blueprint for client expectations.
- Updated TODO priorities and marked completed items.
- Clarified GitLab claim-maps usage (optional) and login flow behavior.

## OAuth2/OIDC behavior & security
- Improved OAuth2 token request parsing and form-encoded handling.
- Hardened PKCE handling (ignore empty fields) and verified redirect/client checks.
- Added claim values support in custom claims (claim maps).
- Introduced stable `sub` plus `preferred_username` claim behavior for provider compatibility.
- Added login by email or username with UI/flow alignment.
- Enforced `userinfo` scope validation and JWT `aud` checks.
- Added refresh token rotation, configurable expiry, introspection and revocation endpoints.
- Scheduled refresh-token cleanup with logging and redaction of DB credentials in logs.

## Rate limiting
- Added configurable rate limiting with smart IP extractor and startup logging.

## Admin CLI and TUI
- Added an admin CLI (`simple-idm-ctl`) with JSON/table output and command expansion.
- Added an admin TUI with CRUD workflows, pickers, selectors, and improved editing UX.
- Implemented relationship views for user/group mappings, plus aggregated list views.
- Added claim-map TUI editing, selectors, and improved error rendering.
- Improved keyboard shortcuts (Ctrl+G/Ctrl+U) to avoid input conflicts.

## Auth UI
- Refined OAuth2 login/reset/error pages and background styling.
- Added password reset flow and UI messaging.

## Tests & tooling
- Added and split authorization-code integration tests (including refresh token rotation).
- Improved Docker-based test readiness checks and SQLX offline metadata refresh.

## Miscellaneous
- Cleaned up `.gitignore` and local settings tracking.
- Minor TUI layout and help text refinements (including client list column sizing).
