# Kubernetes workload tokens for Config Server

This optional endpoint exchanges a short-lived, Pod-bound Kubernetes ServiceAccount
JWT for an IDM access token. It does not log in a human, create an OAuth client or
grant application permissions from an annotation. No database migration is needed.

The feature is **disabled by default**. Set `WORKLOAD_IDENTITY_CONFIG_FILE` to an
administrator-controlled JSON file and restart IDM. The file must not be writable
by applications. Use the same trust configuration and signing keys on all replicas.

```json
{
  "jwks_ca_file": "/etc/simple-idm/kubernetes-ca.pem",
  "issuers": [
    {
      "name": "development-cluster",
      "issuer": "https://kubernetes.example.com",
      "jwks_url": "https://kubernetes.example.com/openid/v1/jwks",
      "subject_audience": "simple-idm-workload",
      "grants": [
        {
          "namespace": "orders-test",
          "service_account": "scs-calendar",
          "service_account_uid": "c0ec7a83-6652-43e4-b27c-a20a8fa95034",
          "application": "calendar"
        }
      ]
    }
  ]
}
```

Use the actual issuer from cluster discovery and actual ServiceAccount UID. The
optional CA bundle is only needed for private certificate authorities. HTTPS is
required except for numeric loopback HTTP endpoints used in local tests. Redirects
are rejected. JWKS documents are size-limited and cached for 60 seconds; unknown
signing keys may be rejected until that cache expires. CA and policy changes need
an IDM restart. Issuer names and issuer URLs must be unique.

Only a named, explicitly granted ServiceAccount can exchange a token. `default`
accounts and ambiguous grants are rejected. Recreating an account changes its UID
and requires updating the grant; reusing its name is insufficient.

## Protocol and issued permissions

POST `/oauth2/workload/token` with `application/x-www-form-urlencoded`:

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token_type=urn:ietf:params:oauth:token-type:jwt
subject_token=<projected token, audience simple-idm-workload>
requested_token_type=urn:ietf:params:oauth:token-type:access_token
audience=simple-config-server
scope=config:read
```

`requested_token_type` and `scope` may be omitted; no other token type, target or
scope is supported by this first increment. This is the workload endpoint, not a
new grant on the existing human `/oauth2/token` endpoint. Requests are subject to
the token endpoint rate limiter and a 48 KiB body limit. Unknown fields, including
caller-selected tenant/application, are rejected.

Verification accepts RS256 with an RSA key or ES256 with a P-256 key from the
configured cluster JWKS. Header algorithm, JWK algorithm (when present), key type
and curve must agree; HMAC and other algorithms are rejected. IDM output tokens
remain RS256. Verification requires a configured issuer and audience, expiration, issued
time, not-before, matching subject/namespace/ServiceAccount claims, exact granted
account UID and Pod-bound claims. Input lifetime is at most one hour. The endpoint
does not consult caller-supplied discovery URLs or trust an unverified claim to
choose anything other than a preconfigured issuer.

The output is an RS256 IDM access token with the normal IDM issuer and key ID:

```text
sub: workload:development-cluster:orders-test:scs-calendar:<account UID>
aud: simple-config-server
scope: config:read
groups:
  - simple-config:tenant:orders-test
  - simple-config:env:default
  - simple-config:app:calendar
amr: [workload]
```

Tenant equals the complete Kubernetes namespace. Environment is `default`.
Application comes from the administrator's grant. Tokens have no human/admin
groups, refresh token or user email. Lifetime is at most 300 seconds and never
longer than the remaining subject-token lifetime. A successful response includes
`issued_token_type`, `token_type`, `expires_in` and `scope`. Responses and handler
errors are `no-store`; form/limit errors are covered by the route middleware.

Token issuance and rejection reasons are logged without credential bodies.
Successful logs identify the configured cluster, namespace, account UID,
application and Pod. This is node-local structured logging, not a new persistent
database audit subsystem.

## Security and operational boundaries

- This verifies signatures, not Kubernetes TokenReview. Pod/account deletion is
  not checked live. Previously issued credentials remain usable until expiry;
  removing a file, annotation or account is not instant revocation of all tokens.
- The operator must mount the projected token only in the proxy, with dedicated
  audience `simple-idm-workload`; the application needs only its localhost URL.
- Anyone who can alter workloads or run code under the granted account must be
  trusted for that identity. The exchange is not isolation from a cluster admin.
- SCS must verify the IDM issuer/audience and enforce application/tenant/environment
  permissions. Catalog and OpenBao access are separate authorization boundaries;
  this token is not intended for either of them.
- No discovery metadata, existing human client, role or production configuration
  is changed automatically when this code is built.

## Verification

```sh
cargo test --locked -p simple-idm-core workload_identity
```

An opt-in test uses the production IDM handler/signing service, a real Go proxy
binary and real SCS, entirely on loopback with disposable keys. It needs no IDM
database and does not start the full IDM daemon or operator:

```sh
SIMPLE_TOKEN_PROXY_E2E_BIN=/absolute/path/simple-token-proxy \
SIMPLE_CONFIG_SERVER_E2E_BIN=/absolute/path/simple-config-server \
  cargo test --locked -p simple-idm-core \
  workload_identity::tests::real_go_proxy_and_scs_accept_only_idm_issued_identity \
  -- --ignored
```

The test covers accepted application reads, rejection of the original Kubernetes
token by SCS, cross-application denial despite spoofed headers, account UID mismatch
and recovery after subject-token replacement. This is not a cluster deployment or
qualification of human SSO, PostgreSQL, HA or admission injection.
