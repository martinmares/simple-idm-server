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

```bash
simple-idm-token-proxy serve \
  --listen 127.0.0.1:9999 \
  --upstream https://config.example.com/simple-config-server \
  --token-file /var/run/secrets/workload-identity/simple-config/token \
  --ca-file /var/run/certs/internal-ca.pem
```

The token file is intentionally mandatory; there is no implicit default path.

Equivalent environment variables:

```env
SIMPLE_IDM_TOKEN_PROXY_LISTEN=127.0.0.1:9999
SIMPLE_IDM_TOKEN_PROXY_UPSTREAM=https://config.example.com/simple-config-server
SIMPLE_IDM_TOKEN_PROXY_TOKEN_FILE=/var/run/secrets/workload-identity/simple-config/token
SIMPLE_IDM_TOKEN_PROXY_CA_FILE=/var/run/certs/internal-ca.pem
```

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
