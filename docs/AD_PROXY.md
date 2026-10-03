# simple-idm-ad-proxy

`simple-idm-ad-proxy` is a small AD/LDAP login adapter for applications that
can trust reverse-proxy headers but do not implement OIDC.

It is intentionally simpler than `simple-idm-oauth2-proxy`:

- no database,
- no OAuth2/OIDC flow,
- in-memory sessions,
- LDAP/AD password verification,
- AD `memberOf` to application role/group mapping,
- nginx `auth_request` integration.

## Flow

```text
browser
  -> nginx TLS edge
    -> simple-idm-ad-proxy /auth
      -> backend on 127.0.0.1
```

Unauthenticated users are redirected to `/login`. After successful AD login the
proxy stores an in-memory session and emits trusted identity headers for nginx.

## Configuration

See `examples/config.example.ad-proxy.toml`.

The LDAP backend supports two explicit authentication modes:

```toml
[ldap]
mode = "service_account"
bind_dn = "CN=svc-auth,OU=Service Accounts,DC=example,DC=cz"
bind_password = "..."
```

`service_account` is the default mode. The proxy binds with a technical account,
finds the user with `user_filter`, verifies the submitted password by binding as
that user, then reads profile attributes and `memberOf` through the technical
account.

Multiple proxy instances on one host can share the service-account identity
without duplicating it in every TOML file:

```toml
[ldap]
mode = "service_account"
host = "ad.example.cz"
port = 636
base_dn_file = "shared/base-dn"
bind_dn_file = "shared/bind-dn"
bind_password_file = "shared/bind-password"
```

Relative paths are resolved against the directory containing the proxy TOML
file. Every value supports either its inline form (`base_dn`, `bind_dn`,
`bind_password`) or its `_file` form, never both. Files must contain one UTF-8
line; one trailing LF or CRLF is removed. Restrict the password file to the
service account, for example with `chmod 600 shared/bind-password`. Values are
loaded only at process startup, so changing a file requires restarting the
proxy instance. `AD_PROXY_LDAP_BIND_PASSWORD` counts as the inline password and
therefore must not be combined with `bind_password_file`.

When no technical account is available, use direct user bind:

```toml
[ldap]
mode = "bind_as_user"
user_bind_format = "{login}@AD.EXAMPLE"
```

In `bind_as_user` mode the proxy binds directly with the submitted username and
password, then reads the same user's profile attributes and `memberOf` through
that LDAP connection. This requires AD/LDAP to allow users to read their own
group membership. For AD, useful `user_bind_format` values are usually
`{login}@AD.EXAMPLE` or `AD\\{login}`.

The proxy supports mapping either full AD group DNs or only their CN:

```toml
[[role_mappings]]
ad_group_cn = "Icinga_Grafana_Viewer"
emit_group = "grafana_viewer"
emit_header_role = "Viewer"

[[role_mappings]]
ad_group_dn = "CN=OCP_PROD_TSM_ADMIN,OU=OCP,OU=Resources,OU=grp,DC=ad,DC=example"
emit_group = "ocp_tsm_admin"
```

Only mapped groups are emitted. Raw AD `memberOf` values are not forwarded to
upstream applications.

## Headers

Canonical headers (enabled by default):

```text
X-Auth-Subject: <AD objectGUID or fallback identity>
X-Auth-User: <sAMAccountName or UPN>
X-Auth-Email: <mail/otherMailbox when available>
X-Auth-Groups: grafana_viewer,ocp_tsm_admin
X-Auth-Role: Viewer
```

Optional WEBAUTH compatibility aliases (`emit_webauth = true`):

```text
X-WEBAUTH-USER: <username>
X-WEBAUTH-EMAIL: <email>
X-WEBAUTH-GROUPS: grafana_viewer
X-WEBAUTH-ROLE: Viewer
```

Applications in the Simple IDM stack should consume only the canonical
`X-Auth-*` contract. Keep WEBAUTH aliases disabled unless an upstream product
requires them. For Grafana, nginx can map the canonical response headers to
Grafana's configured `X-WEBAUTH-*` names at the final proxy boundary.

## nginx `auth_request`

```nginx
upstream ad_proxy {
    server 127.0.0.1:4181;
}

upstream app_backend {
    server 127.0.0.1:3000;
}

server {
    listen 443 ssl http2;
    server_name app.example.cz;

    location /login {
        proxy_pass http://ad_proxy;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /logout {
        proxy_pass http://ad_proxy;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location = /auth {
        internal;
        proxy_pass http://ad_proxy/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        auth_request /auth;
        auth_request_set $auth_user $upstream_http_x_auth_user;
        auth_request_set $auth_subject $upstream_http_x_auth_subject;
        auth_request_set $auth_email $upstream_http_x_auth_email;
        auth_request_set $auth_groups $upstream_http_x_auth_groups;
        auth_request_set $auth_role $upstream_http_x_auth_role;
        auth_request_set $auth_login $upstream_http_x_auth_login;

        error_page 401 =302 $auth_login;

        proxy_set_header X-Auth-User "";
        proxy_set_header X-Auth-Subject "";
        proxy_set_header X-Auth-Email "";
        proxy_set_header X-Auth-Groups "";
        proxy_set_header X-Auth-Role "";

        proxy_set_header X-Auth-User $auth_user;
        proxy_set_header X-Auth-Subject $auth_subject;
        proxy_set_header X-Auth-Email $auth_email;
        proxy_set_header X-Auth-Groups $auth_groups;
        proxy_set_header X-Auth-Role $auth_role;

        proxy_pass http://app_backend;
    }
}
```

## Grafana

Grafana can use auth proxy headers directly.

Example:

```ini
[auth.proxy]
enabled = true
header_name = X-WEBAUTH-USER
header_property = username
auto_sign_up = true
sync_ttl = 15
whitelist = 127.0.0.1
headers = Email:X-WEBAUTH-EMAIL Role:X-WEBAUTH-ROLE Groups:X-WEBAUTH-GROUPS
```

The recommended nginx integration reads `X-Auth-*` from the AD proxy
`auth_request` response and sets the Grafana-specific `X-WEBAUTH-*` request
headers only when proxying to Grafana. Set `emit_webauth = true` only when
Grafana receives the AD proxy response headers directly.
