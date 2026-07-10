# simple-idm-oidc-metadata-proxy

`simple-idm-oidc-metadata-proxy` is a small read-only proxy for OIDC discovery
and JWKS metadata.

It is intended for cases where workloads receive JWTs from an issuer that is
not directly reachable from a validating service. A typical example is an
OpenShift/Kubernetes ServiceAccount token consumed by a service running outside
the cluster.

The proxy deliberately exposes only public verification metadata:

- `/.well-known/openid-configuration`
- `/openid/v1/jwks`
- `/health`
- `/healthz`

All other paths return `404`.

It does not implement login, sessions, token validation, or authorization. The
consumer service still validates JWT issuer, signature, audience, expiry, and
application policy.

## OpenShift Example

```text
Java workload in OKD
  -> projected ServiceAccount token
  -> simple-config-token-proxy
  -> simple-config-server on Linux
  -> validates token using JWKS exposed by simple-idm-oidc-metadata-proxy
```

Deploy `simple-idm-oidc-metadata-proxy` inside the cluster, give it access to
the internal issuer metadata, and expose it through a Route:

```text
https://jwks-metadata.apps.example.com/.well-known/openid-configuration
https://jwks-metadata.apps.example.com/openid/v1/jwks
```

The validator outside the cluster should normally keep `issuer` configured to
the exact `iss` value found in the token, and use the public `jwks_url` from the
Route.

## Configuration

See `examples/config.example.oidc-metadata-proxy.env`.

Minimal environment:

```env
SIMPLE_IDM_OIDC_METADATA_PROXY_LISTEN=0.0.0.0:8080
SIMPLE_IDM_OIDC_METADATA_PROXY_UPSTREAM_BASE_URL=https://kubernetes.default.svc
SIMPLE_IDM_OIDC_METADATA_PROXY_UPSTREAM_JWKS_URL=https://api.example.com:6443/openid/v1/jwks
SIMPLE_IDM_OIDC_METADATA_PROXY_PUBLIC_BASE_URL=https://jwks-metadata.apps.example.com
SIMPLE_IDM_OIDC_METADATA_PROXY_UPSTREAM_CA_FILE=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
SIMPLE_IDM_OIDC_METADATA_PROXY_UPSTREAM_BEARER_TOKEN_FILE=/var/run/secrets/kubernetes.io/serviceaccount/token
```

Run:

```bash
simple-idm-oidc-metadata-proxy
```

Equivalent CLI flags are available:

```bash
simple-idm-oidc-metadata-proxy \
  --listen 0.0.0.0:8080 \
  --upstream-base-url https://kubernetes.default.svc \
  --upstream-jwks-url https://api.example.com:6443/openid/v1/jwks \
  --public-base-url https://jwks-metadata.apps.example.com \
  --upstream-ca-file /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  --upstream-bearer-token-file /var/run/secrets/kubernetes.io/serviceaccount/token
```

Some Kubernetes/OpenShift installations allow unauthenticated access to
discovery metadata but require an authenticated request for JWKS. In that case
bind the proxy ServiceAccount to a `ClusterRole` with `get` permission for the
non-resource URLs `/.well-known/openid-configuration` and `/openid/v1/jwks`.

## Discovery Rewriting

The proxy rewrites only `jwks_uri` by default:

```json
{
  "jwks_uri": "https://jwks-metadata.apps.example.com/openid/v1/jwks"
}
```

It intentionally keeps `issuer` unchanged, because JWT validation requires the
configured issuer to match the token `iss` claim.

Use `SIMPLE_IDM_OIDC_METADATA_PROXY_ISSUER_OVERRIDE` only when you explicitly
want discovery issuer rewriting and know that downstream validators expect that
value.

## Safety Rules

- expose only the two OIDC metadata endpoints,
- do not proxy arbitrary paths,
- do not log tokens,
- do not add authentication here,
- keep authorization in the consuming service.
