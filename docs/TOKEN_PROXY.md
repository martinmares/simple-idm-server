# simple-idm-token-proxy

`simple-idm-token-proxy` is a small localhost reverse proxy for workloads that
need to call a protected HTTP API without embedding token handling in the
application.

For every proxied request it reads the current token from a required file and
sends it upstream as:

```http
Authorization: Bearer <token>
```

The token is read on every request, so projected Kubernetes/OpenShift
ServiceAccount token rotation is picked up without restarting the workload.

The proxy does not validate the token and does not implement login or policy.
The upstream service remains responsible for JWT validation and authorization.

## Example

```bash
simple-idm-token-proxy \
  --listen 127.0.0.1:9999 \
  --upstream https://config.example.com/simple-config-server \
  --token-file /var/run/secrets/workload-identity/simple-config
```

The token file is intentionally mandatory; there is no implicit default path.

Equivalent environment variables:

```env
SIMPLE_IDM_TOKEN_PROXY_LISTEN=127.0.0.1:9999
SIMPLE_IDM_TOKEN_PROXY_UPSTREAM=https://config.example.com/simple-config-server
SIMPLE_IDM_TOKEN_PROXY_TOKEN_FILE=/var/run/secrets/workload-identity/simple-config
```

If the upstream URL includes a path prefix, the proxy accepts both a request
with that prefix and a request without it. This lets an application call the
localhost proxy using its normal upstream-relative paths.

For a controlled sandbox with an internal CA, TLS verification can be disabled
explicitly with `--insecure-upstream-tls`. Do not use that flag in production.

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

Or, when standing in the directory containing the Dockerfile:

```bash
cd crates/simple-idm-token-proxy
docker build -f Dockerfile -t simple-idm-token-proxy:local ../..
```
