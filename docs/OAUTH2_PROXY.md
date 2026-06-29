# simple-idm-oauth2-proxy

`simple-idm-oauth2-proxy` protects applications that do not implement OAuth2/OIDC
login themselves. It handles browser login against `simple-idm-server` and exposes
the authenticated identity to the upstream application through trusted headers.

Typical deployment with an external ingress/proxy:

```text
browser
  -> nginx / ingress
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
