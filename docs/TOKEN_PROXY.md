# simple-idm-token-proxy

`simple-idm-token-proxy` provides two explicit modes:

- `serve` runs a localhost reverse proxy for workloads that need to call a
  protected HTTP API without embedding token handling in the application.
- `fetch` downloads authenticated runtime assets into a shared volume and exits.

In `serve` mode, every proxied request reads the current token from a required file and
sends it upstream as:

```http
Authorization: Bearer <token>
```

The token is read on every request, so projected Kubernetes/OpenShift
ServiceAccount token rotation is picked up without restarting the workload.

The proxy does not validate the token and does not implement login or policy.
The upstream service remains responsible for JWT validation and authorization.

## Proxy mode

New configurations should declare all context headers explicitly and disable
automatic release mappings with `--no-release-headers`. The automatic mappings
remain available only for backward compatibility and are planned for removal
in a future version.

```bash
simple-idm-token-proxy serve \
  --listen 127.0.0.1:9999 \
  --upstream https://config.example.com/simple-config-server \
  --token-file /var/run/secrets/workload-identity/simple-config/token \
  --ca-file /var/run/certs/internal-ca.pem \
  --no-release-headers \
  --env-header RELEASE_ID=X-Config-Release-ID \
  --env-header CUSTOMER_RELEASE_ID=X-Config-Customer-Release-ID \
  --env-header APP_TENANT=X-Tenant
```

The token file is intentionally mandatory; there is no implicit default path.

Equivalent environment variables:

```env
SIMPLE_IDM_TOKEN_PROXY_LISTEN=127.0.0.1:9999
SIMPLE_IDM_TOKEN_PROXY_UPSTREAM=https://config.example.com/simple-config-server
SIMPLE_IDM_TOKEN_PROXY_TOKEN_FILE=/var/run/secrets/workload-identity/simple-config/token
SIMPLE_IDM_TOKEN_PROXY_CA_FILE=/var/run/certs/internal-ca.pem
SIMPLE_IDM_TOKEN_PROXY_NO_RELEASE_HEADERS=true
SIMPLE_IDM_TOKEN_PROXY_ENV_HEADERS=RELEASE_ID=X-Config-Release-ID,CUSTOMER_RELEASE_ID=X-Config-Customer-Release-ID,APP_TENANT=X-Tenant
```

For configuration requests, `kube-build-app` injects `RELEASE_ID` and optional
`CUSTOMER_RELEASE_ID` into the proxy container using stable ConfigMap references.
With the explicit mappings above, the proxy sends these as
`X-Config-Release-ID` and `X-Config-Customer-Release-ID`, respectively. It
discards both headers supplied by the caller. In this explicit mode the proxy
validates HTTP field values; release relationships and permissions must be
validated by the upstream service. Example container environment for a customer release:

```yaml
env:
  - name: SIMPLE_IDM_TOKEN_PROXY_NO_RELEASE_HEADERS
    value: "true"
  - name: SIMPLE_IDM_TOKEN_PROXY_ENV_HEADERS
    value: "RELEASE_ID=X-Config-Release-ID,CUSTOMER_RELEASE_ID=X-Config-Customer-Release-ID,APP_TENANT=X-Tenant"
  - name: APP_TENANT
    value: default
  - name: RELEASE_ID
    valueFrom:
      configMapKeyRef:
        name: release-context-dev
        key: RELEASE_ID
  - name: CUSTOMER_RELEASE_ID
    valueFrom:
      configMapKeyRef:
        name: release-context-dev
        key: CUSTOMER_RELEASE_ID
        optional: true
```

The customer reference remains in the Pod template on development builds;
when the ConfigMap has no customer key, the variable is absent and the proxy
omits the customer release header. The proxy reads these values once at startup.
To use custom variable names, change the left-hand sides of the declared
mappings. Missing or empty values omit the corresponding headers.
`X-Config-Release-ID` previously carried the customer release name; it now
carries the image release ID from the release manifest. This is a deliberate
breaking change while the integration is in development. Existing sidecar
definitions must replace `CUSTOMER_RELEASE_NAME` sourced from the old
`cloud-app.cz/customer-release-name` annotation with the ConfigMap mapping above.
The upstream config server must still validate that the requested release is
authorized for the workload; the header alone is not an authorization grant.

## General environment-to-header mapping (0.13.1)

Both `serve` and `fetch` accept repeatable `--env-header ENV_NAME=X-Header`
arguments. The left side is the **name** of an environment variable, not its
value; the right side declares the upstream HTTP header. For example:

```bash
export APP_TENANT='default'
export APP_ENVIRONMENT='dev'
export APP_NAME='order-api'

simple-idm-token-proxy serve \
  --upstream https://config.example.com/simple-config-server \
  --token-file /var/run/secrets/workload-identity/simple-config/token \
  --no-release-headers \
  --env-header APP_TENANT=X-Tenant \
  --env-header APP_ENVIRONMENT=X-Environment \
  --env-header APP_NAME=X-Application
```

The resulting upstream headers include:

```http
X-Tenant: default
X-Environment: dev
X-Application: order-api
Authorization: Bearer <current token file contents>
```

For a Pod, use one comma-separated configuration variable instead of CLI flags:

```yaml
env:
  - name: APP_TENANT
    value: default
  - name: APP_ENVIRONMENT
    value: dev
  - name: APP_NAME
    value: order-api
  - name: SIMPLE_IDM_TOKEN_PROXY_ENV_HEADERS
    value: "APP_TENANT=X-Tenant,APP_ENVIRONMENT=X-Environment,APP_NAME=X-Application"
  - name: SIMPLE_IDM_TOKEN_PROXY_NO_RELEASE_HEADERS
    value: "true"
```

These variables must be injected into the proxy container (or the fetch init
container), not only into the application container. The normal upstream and
token-file settings remain required. CLI mappings replace the environment list
when both are supplied; repeated CLI mappings are combined. A single CLI flag
also accepts a comma-separated list.

Mapping behavior:

- Only declared variables are read. Values are read once at startup and passed
  as-is, without interpolation or trimming; restart the container to pick up
  changed environment values. Token file contents are still read per proxied
  request.
- An unset or empty variable omits its header. In `serve`, client-supplied
  values for **all declared headers** are stripped, even if the mapped variable
  is absent or empty. The managed value is sent at most once.
- Environment names use `[A-Za-z_][A-Za-z0-9_]*`. Header names must be valid
  `X-*` names and are case-insensitive. A duplicate destination fails startup;
  one variable can supply multiple distinct headers.
- Invalid HTTP field values, including CR/LF injection, fail startup. Generic
  values need not be Kubernetes label values. Values are not logged, and
  validation errors identify the variable without printing its contents.
- For backward compatibility, automatic release headers remain active in
  `serve` unless disabled. An explicit
  mapping to `X-Config-Release-ID` or `X-Config-Customer-Release-ID` overrides
  the respective default source and uses generic HTTP value validation.
  The customer-requires-image-release check remains active.
- For a completely generic proxy, `serve --no-release-headers` (or
  `SIMPLE_IDM_TOKEN_PROXY_NO_RELEASE_HEADERS=true`) disables the automatic
  release mappings and their dependency check. Explicit mappings still apply.
  The two existing release headers supplied by clients remain stripped.
- `fetch` has no automatic release mappings, preserving its existing behavior;
  use `--env-header` to declare any needed context headers explicitly.

### Compatibility and planned removal

An existing `serve` deployment without new flags still automatically maps
`RELEASE_ID` and `CUSTOMER_RELEASE_ID`. This compatibility mode also retains
the Kubernetes label value checks and the customer-requires-image-release
check. The old `--release-id-env-name` and `--customer-release-id-env-name`
flags and their corresponding environment settings remain supported.

For migration, keep the same source variables and destination header names,
declare both mappings explicitly, and enable `--no-release-headers`. Restart
the proxy container after changing its configuration. The destination headers
stay the same, but release-specific proxy validation is disabled: confirm that
the upstream enforces any required release relationships and permissions.

Removal checklist (planned; no removal version assigned yet):

- [x] Provide explicit environment-to-header mapping and a compatibility mode.
- [x] Use explicit mappings in recommended examples and document migration.
- [ ] Migrate deployed sidecars and relevant kube-build-app examples/templates
  to explicit mappings; preserve ConfigMap sources and optional customer IDs.
- [ ] Verify development and customer-release requests against the upstream,
  including its release validation and unchanged bearer authorization.
- [ ] In an announced breaking release, remove automatic release mapping,
  the old release-source flags/settings and their proxy-specific validation.
- [ ] Decide how long to accept `--no-release-headers` and its ENV setting as
  compatibility no-ops, so already migrated deployments do not fail startup.
- [ ] Keep spoof protection for every declared header and cover the final
  migration with tests and release notes.

Headers provide request context. The upstream still determines authorization
from the verified token and its policy; merely supplying a context header does
not grant access.

To verify a deployed proxy without changing the config server, temporarily set
`RUST_LOG=simple_idm_token_proxy=debug` on one proxy sidecar. After that Pod starts
and a client makes a configuration request, its logs include `forwarded managed
headers` with the names of the headers actually attached to the outgoing
request. Header values and the bearer token are not logged. The message is
emitted after the upstream responds. Disable debug logging after the check. The
`proxy_overrides_client_release_header` test also verifies both headers against
a local upstream and checks that caller-supplied values are discarded.

If the upstream URL includes a path prefix, the proxy accepts both a request
with that prefix and a request without it. This lets an application call the
localhost proxy using its normal upstream-relative paths.

## Fetch mode

`fetch` is intended for Kubernetes/OpenShift init containers. It reads the same
projected token, downloads all declared files sequentially, stages them below
`--output-dir`, and publishes them only after every download and optional
SHA-256 check succeeds.

```bash
simple-idm-token-proxy fetch \
  --upstream https://config.example.com/simple-config-server \
  --token-file /var/run/secrets/workload-identity/simple-config/token \
  --ca-file /var/run/certs/internal-ca.pem \
  --output-dir /app/runtime-config \
  --files-json '[
    {
      "source": "/api/v1/tenants/default/envs/test/assets/files/ssl/client-keystore.jks",
      "target": "client-keystore.jks",
      "mode": "0440",
      "sha256": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    },
    {
      "source": "/api/v1/tenants/default/envs/test/assets/files/ssl/client-truststore.jks",
      "target": "client-truststore.jks",
      "mode": "0440"
    }
  ]'
```

Fetch targets must be relative paths below `--output-dir`. Absolute paths,
empty path segments, `.` and `..` are rejected. Modes use four octal digits.
Redirects are intentionally disabled and any non-success HTTP status fails the
command.

Use `--ca-file` or `SIMPLE_IDM_TOKEN_PROXY_CA_FILE` for an internal certificate
authority. The PEM file may contain multiple certificates; they are added to
the normal trust roots rather than replacing them.

For a controlled sandbox, TLS verification can instead be disabled explicitly
with `--insecure-upstream-tls`. It cannot be combined with `--ca-file`. Do not
use insecure TLS in production.

## Container image

Build the Linux binary from the repository root:

```bash
just release-linux-token-proxy
```

The Docker build context must be the repository root because the local Linux
binary is under `target/`. From the repository root:

```bash
just image-token-proxy
```

The image entrypoint is the binary itself, so container arguments must begin
with either `serve` or `fetch`.
