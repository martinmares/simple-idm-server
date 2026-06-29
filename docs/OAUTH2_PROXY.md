# simple-idm-oauth2-proxy

`simple-idm-oauth2-proxy` protects applications that do not implement OAuth2/OIDC
login themselves. It handles browser login against `simple-idm-server` and exposes
the authenticated identity to the upstream application through trusted headers.

Typical deployment with an external ingress/proxy:

```text
browser
  -> nginx / ingress / OpenShift Route
  -> simple-idm-oauth2-proxy
  -> upstream application
```

Small/simple deployment without nginx:

```text
browser
  -> simple-idm-oauth2-proxy
  -> upstream application
```

`simple-idm-oauth2-proxy` is not intended to replace nginx, Traefik, HAProxy, or
OpenShift Route as a general edge proxy. It is a focused OIDC adapter for
applications that should not embed their own OAuth2/OIDC login flow.

## Modes

### `auth_request`

Use this mode when nginx/ingress performs reverse proxying and calls
`simple-idm-oauth2-proxy` only for authentication decisions.

```toml
mode = "auth_request"
listen_addr = "127.0.0.1:4180"
public_base_url = "https://app.example.com/oauth2"
```

The proxy exposes:

- `/auth` for nginx `auth_request`
- `/start` for login start
- `/callback` for OIDC callback
- `/logout` for logout
- `/healthz` for process health checks

### `reverse_proxy`

Use this mode when you want to avoid nginx for simple internal WebUI services.

```toml
mode = "reverse_proxy"
listen_addr = "127.0.0.1:4180"
public_base_url = "https://app.example.com"
upstream_url = "http://127.0.0.1:3000"
protected_prefixes = ["/"]
public_prefixes = ["/healthz", "/static"]
upstream_timeout_secs = 300
```

In this mode the proxy:

- owns the OIDC login flow,
- validates the session cookie,
- strips client-supplied `X-Auth-*` headers,
- injects trusted `X-Auth-*` headers,
- forwards HTTP/1.1 traffic to one configured upstream,
- forwards WebSocket upgrade traffic to the same upstream.

TLS termination is intentionally out of scope for this proxy. Put nginx,
Traefik, HAProxy, or OpenShift Route in front when TLS termination, edge
hardening, buffering, rate limiting, or more complex routing is required.

This is the preferred mode for simple internal WebUI services when the public
edge already handles TLS. The edge forwards all application traffic to
`simple-idm-oauth2-proxy`, and the proxy forwards authenticated traffic to the
upstream application.

```text
browser
  -> nginx with wildcard TLS certificate
  -> simple-idm-oauth2-proxy on 127.0.0.1:4180
  -> upstream application on 127.0.0.1:8181
```

Example reverse proxy config:

```toml
mode = "reverse_proxy"
listen_addr = "127.0.0.1:4180"
public_base_url = "https://registry.example.com"
upstream_url = "http://127.0.0.1:8181"
protected_prefixes = ["/"]
public_prefixes = ["/health", "/healthz", "/static"]
upstream_timeout_secs = 300

cookie_name = "_oauth2_proxy"
cookie_secret = "CHANGE-ME-TO-RANDOM-32-PLUS-CHARS"
cookie_secure = true
cookie_httponly = true
cookie_samesite = "lax"

session_max_age = 3600
session_backend = "memory"

oidc_issuer = "https://sso.example.com"
client_id = "example-app"
client_secret = "CHANGE-ME"
redirect_path = "/callback"
scopes = ["openid", "profile", "email", "groups"]

groups_claim = "groups"
username_claims = ["preferred_username", "email", "sub"]
email_claim = "email"

pass_token_header = false
groups_header_name = "X-Auth-Groups"
groups_header_format = "csv"
```

The OIDC client must allow this redirect URI:

```text
https://registry.example.com/callback
```

For public WebUI clients, prefer confidential clients with a generated
`client_secret`. Public clients are appropriate for CLI/native flows, not for a
server-side proxy that can safely hold a secret.

## Systemd

Recommended layout:

```text
/usr/local/bin/simple-idm-oauth2-proxy
/etc/simple-idm-oauth2-proxy/config.toml
```

Example unit:

```ini
[Unit]
Description=Simple IDM OAuth2 proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=simple-idm-oauth2-proxy
Group=simple-idm-oauth2-proxy
Environment=RUST_LOG=info
Environment=OAUTH2_PROXY_CONFIG=/etc/simple-idm-oauth2-proxy/config.toml
ExecStart=/usr/local/bin/simple-idm-oauth2-proxy
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/simple-idm-oauth2-proxy

[Install]
WantedBy=multi-user.target
```

If `session_backend = "memory"`, `/var/lib/simple-idm-oauth2-proxy` is not
required. If `session_backend = "sqlite"`, set `session_sqlite_path` under that
directory and keep the `ReadWritePaths` entry.

## Nginx TLS Edge for Reverse Proxy Mode

Use this when nginx owns TLS and certificates, but authentication is handled by
`simple-idm-oauth2-proxy`.

```nginx
upstream app_oauth2_proxy {
    server 127.0.0.1:4180;
}

server {
    listen 443 ssl http2;
    server_name registry.example.com;

    # include TLS/certificate settings here

    location / {
        client_max_body_size 2g;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Never allow callers to spoof identity headers.
        proxy_set_header X-Auth-Subject "";
        proxy_set_header X-Auth-User    "";
        proxy_set_header X-Auth-Email   "";
        proxy_set_header X-Auth-Groups  "";

        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;

        proxy_connect_timeout 30s;
        proxy_send_timeout    300s;
        proxy_read_timeout    300s;

        proxy_pass http://app_oauth2_proxy;
    }
}
```

The upstream application should be reachable only from the proxy boundary. Do
not expose the upstream application directly when it trusts `X-Auth-*` headers.

## Logout

`GET /logout` and `POST /logout` clear the proxy session cookie. The response is
a small static logout page.

Logout from the proxy does not necessarily log the user out from the upstream
OIDC provider. If the browser still has an active SSO session at
`simple-idm-server`, the next visit may immediately create a new proxy session
without asking for credentials again. This is expected SSO behavior.

Application logout buttons should link to `/logout` when the UI is protected by
`simple-idm-oauth2-proxy`. Application-local login pages should either be
disabled for UI users or reserved for non-browser/API flows.

## Trusted Header Contract

The upstream application may trust these headers only when it is reachable
exclusively through the trusted proxy boundary.

The public edge must strip client-supplied `X-Auth-*` headers before forwarding
the request.

Headers emitted by the proxy:

```http
X-Auth-Subject: 97173b5f-6277-4aa7-b15e-a6c0b03cf0fd
X-Auth-User: mares
X-Auth-Email: mares@example.com
X-Auth-Groups: app:role:admin,app:tenant:o2
```

`X-Auth-Subject` is the stable OIDC `sub` claim and should be preferred for audit
and durable identity. `X-Auth-User` is display/login oriented and may change.

`X-Auth-Groups` is CSV by default. Base64url-encoded JSON array output is
available through `groups_header_format = "jsonb64"`.

## Configuration Notes

Relevant options:

```toml
groups_claim = "groups"
username_claims = ["preferred_username", "sub"]
email_claim = "email"

groups_header_name = "X-Auth-Groups"
groups_header_format = "csv"
```

The proxy always emits:

- `X-Auth-Subject`
- `X-Auth-User`
- `X-Auth-Groups`

It emits `X-Auth-Email` when the claim is available.
