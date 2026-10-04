# Bastion V1

V1 provides browser SSO, a local host picker, an interactive SSH terminal and
durable access audit. The client connects to the bastion over HTTPS/WSS; only
the bastion generates the per-session SSH private key and obtains the user
certificate. The CA private key stays on the signer. Linux/macOS clients and a
Unix bastion with OpenSSH are supported. File transfer, forwarding, session
recording and reconnection are outside V1.

## Client

Copy [the profile example](../examples/config.example.bastions.toml) to
`~/Library/Application Support/simple-idm-ssh-login/bastions.toml` on macOS;
on Linux use `$XDG_CONFIG_HOME/simple-idm-ssh-login/bastions.toml`
(default `~/.config/simple-idm-ssh-login/bastions.toml`). This file is
separate from existing direct SSH `config.toml` profiles. Set `url`, `issuer`,
`client_id`, optional tenant **slug** and scopes for your deployment.

```sh
simple-idm-ssh-login bastion.example.com
# Explicit form if a hostname conflicts with an existing subcommand:
simple-idm-ssh-login bastion bastion.example.com
```

The browser performs OIDC login with PKCE and the IDM's MFA policy. The picker
shows permitted hosts and Linux accounts, initially focused on the list.
Press `/` to edit the filter, then Enter to apply it and return to the list.
Use arrow keys to select, Enter in the list to connect, and Esc to leave.
Esc while editing cancels the edit; Ctrl-U clears the filter. Multiple accounts produce an account
picker. `exit` returns to the host list. Ctrl-C in the shell reaches the remote
program; terminal resizing is forwarded. After an authentication error the
client can renew login before a new connection. No local SSH key or certificate
is needed in bastion mode. Existing direct SSH commands remain available.

Client 0.11.0 uses Ratatui for a bordered filter and host table with selection,
row counts and a scrollbar when the list exceeds the viewport. PageUp/PageDown
and Home/End navigate larger lists. The header shows server-verified identity,
tenant, bastion ID, endpoint and the connected TLS endpoint IP (the proxy IP
when nginx terminates TLS). Daemon 0.1.1 provides identity and host addresses;
it resolves only authorized hosts, with a one-second DNS timeout. Old daemon
catalogs remain compatible but lack this metadata. Mouse capture is disabled
so native terminal text selection works. Screen updates follow input/resize,
without continuous repainting.

## Adding hosts with the CLI (0.2.0)

Run the text wizard as the configuration owner:

```sh
simple-idm-bastion --config ~/.config/simple-idm-bastion/config.toml add-host
```

It collects host ID, display name, address, port, environment, description,
IDM groups, Linux accounts and optional certificate principals. It previews
and validates the addition before confirmation. Existing comments and file
permissions survive; unique `.bak-UUID` backups are retained. Duplicate IDs
are rejected. All fields can also be supplied as arguments (`add-host --help`),
with `--dry-run` for a preview or `--yes` to save non-interactively.

An optional independently verified `--host-key-fingerprint SHA256:...` pins
an ED25519 host key only after a successful comparison. The wizard can prompt
for that fingerprint too. Obtain it **on the target** with
`sudo ssh-keygen -E sha256 -lf /etc/ssh/ssh_host_ed25519_key.pub`.
Without a fingerprint, known_hosts remains unchanged and must be managed
separately. Target Linux accounts and user-CA trust are not modified.
Files are replaced atomically, each with its own backup. known_hosts is saved
first, so its verified key may remain added if the subsequent config save fails.
The command never restarts the daemon. Restart it manually and reopen the
client list to load the new catalog; restart ends active sessions.

## Identity and delegated signing

Register a public OIDC client with client ID `simple-idm-bastion`, browser
loopback callback/PKCE support and `bastion:connect` scope. Match the audience
in the daemon and signer. The API receives an **access token**, not the browser
ID token. Tokens must include the authoritative `tenant_id` UUID and the
`bastion:connect` scope. Pin the actual tenant UUID in both services. A client
tenant slug is only a login hint. The daemon filters the catalog by verified
groups and rechecks the selected host/account on every new connection.

Add this section to the existing signer configuration:

```toml
[bastion]
expected_audience = "simple-idm-bastion"
tenant_id = "11111111-1111-4111-8111-111111111111" # replace with actual UUID
service_key_env = "BASTION_SERVICE_KEY"
required_scope = "bastion:connect"
```

Provide the same random service secret of at least 32 bytes to both services
through their service environments. The configured names may differ, but the
values must match. Keep environment files private and rotate both services
together. Do not put the secret in client profiles, source control or URLs.

The delegated request is `POST /ssh/sign/bastion` with
`Authorization: Bearer <user-access-token>` and `X-Bastion-Key: <service-secret>`:

```json
{
  "public_key": "ssh-ed25519 ...",
  "requested_principals": ["alice"],
  "ttl_seconds": 3600,
  "session_id": "22222222-2222-4222-8222-222222222222"
}
```

`requested_principals` is optional. An explicit list narrows principals derived
from verified identity/groups; it cannot grant a new principal. The signer
returns `certificate`, `valid_after`, `valid_before` and `principals`. The
certificate key ID is `simple-idm-cert:bastion:<session_uuid>` and its extensions
allow only PTY. The existing `/ssh/sign` endpoint retains the direct login
contract. Catalog membership alone does not authorize a signer principal.
For example, catalog group `infra-admins` is distinct from signer group
`ssh:role:infra-admins`, which maps to principal `role:infra-admins` when signer
role mapping is enabled. The target account must authorize that principal.

## Daemon and target deployment

Use [the daemon config](../examples/config.example.bastion.toml). `signer_url`
is the **full** delegated URL, including `/ssh/sign/bastion`. V1 accepts only a
loopback HTTP `bind`; expose it through a TLS reverse proxy. Issuer and signer
URLs require HTTPS except explicit loopback fixtures. Unknown configuration
fields fail validation. Each host has `allowed_groups` and a `logins` list.
`{username}` uses validated, verified
`preferred_username`; fixed accounts such as `postgres` preserve the actual
IDM identity in audit. Optional `principals` narrows certificate authorization.

Create a dedicated `simple-idm-bastion` service account, install the executable
as `/usr/local/bin/simple-idm-bastion`, and copy the daemon example to
`/etc/simple-idm-bastion/config.toml`, matching the unit's explicit `--config`
path (the binary's default path is `bastion.toml`). Install verified host keys
under `/etc/simple-idm-bastion`. Give the service account read access to config
and `known_hosts`; keep them administrator-owned. Install the service secret
as a root-owned mode-0600 `/etc/simple-idm-bastion/bastion.env`:

```text
BASTION_SERVICE_KEY=<random-secret-at-least-32-bytes>
```

The [systemd unit](../examples/systemd/simple-idm-bastion.service) supplies
private state/runtime directories, a restrictive umask, restart policy and
whole-process-group shutdown. Its command ends in the required `serve`
subcommand. Run `simple-idm-bastion --config /etc/simple-idm-bastion/config.toml check-config`
before enabling it, then run `systemctl daemon-reload` and enable
the service. The systemd fixture is a Linux deployment example; no deployment
is performed by the smoke harness. Leave PTY devices available: outbound SSH
requires `/dev/ptmx`. The service needs DNS/network access to IDM, signer and
catalog targets. Do not run it as root.

Install only the SSH CA **public** key on targets. Use the
[target sshd example](../examples/systemd/bastion-target-sshd.conf), create the
managed Linux accounts, and create root-owned
`/etc/ssh/simple-idm-principals/<linux-account>` files containing allowed
certificate principals, one per line. For `alice`, this might contain `alice`;
for a shared account, authorize an explicit signer-derived principal according
to your policy. Validate the full effective sshd configuration with `sshd -t`
and `sshd -T -C user=postgres,host=target,addr=<bastion-ip>` before reload.
Keep a separately reviewed recovery path during rollout. Limit SSH ingress
to bastion addresses where appropriate.

Provision target host public keys in the daemon's `known_hosts` from an
independently verified source; for a nonstandard port use
`[hostname]:port ssh-ed25519 ...`. `ssh-keyscan` alone does not authenticate a
host. Unknown or changed host keys must fail. Review key rotation and update
the managed file before retrying; never disable strict host-key verification.

## nginx and terminal transport

The [nginx example](../examples/nginx/bastion.conf) belongs inside `http {}`.
Replace DNS/TLS paths and validate with `nginx -t`. It forwards WebSocket
upgrade headers and the bearer authorization header, disables buffering, and
sets long transport timeouts. These are transport timeouts, not session TTL.
Keepalive traffic keeps a healthy silent terminal connected. Restrict direct
access to the loopback listener and trust only the actual proxy IPs in
`trusted_proxies`. nginx overwrites forwarded client IP headers; it must not
trust arbitrary caller-supplied addresses.

The client uses `/api/v1/hosts` and `/api/v1/terminal`. Terminal parameters are
`host_id`, `login`, `cols`, `rows`, `term`; credentials belong in headers.
V1 uses binary WebSocket frames for terminal bytes and JSON text controls:
`ready` with version/session ID, `resize` with version 1/cols/rows, `error`
with a message, and `exit` with a required integer `status`. V1 has no reconnect ticket.

## Expiration and revocation

Certificate TTL, normally 3600 seconds and bounded by signer policy, determines
when SSH authentication may **start**. An established shell continues after
certificate expiration. A fresh SSH authentication using that same expired
certificate is denied. Expiration of the access token also does not terminate
an already authorized terminal. V1 does not impose an inactivity/session-age
lock or an hourly disconnect.

Every new bastion connection revalidates its token and host/account permission.
Groups are token claims: group changes take effect when a new token carries
the change, subject to token lifetime/validation skew. V1 does not promise
immediate revocation or termination of an existing shell. Keepalive detects
a lost transport; it is not an inactivity timer. Disconnecting SSH does not
guarantee termination of detached programs such as `tmux` or `nohup`.

## Audit and operations

The daemon owns a durable SQLite audit DB and permits a single active instance
per database. Records correlate bastion/session, issuer/subject/tenant,
username, target host/address/port, Linux account, client IP, UTC timestamps,
certificate ID, result/end reason and exit status. `duration_ms` measures
connected time using a monotonic clock. Audit initialization precedes shell
release; unavailable audit storage must deny new sessions. End writes are
idempotent and retried. Restart reconciliation marks incomplete records
`interrupted` / `restart_unknown_end` with a reconciliation timestamp;
unknown end time and duration remain null. Audit records connection access,
not shell contents; never store bearer tokens or private keys in audit.

Configure `retention_days` (example: 90) according to your policy; stop the daemon
and run `simple-idm-bastion --config /etc/simple-idm-bastion/config.toml retain`
to prune completed/reconciled records. Retention is an explicit maintenance
command, not a background scheduler. Restrict DB,
WAL, backups and exports to approved operators. Use SQLite's online backup
mechanism for a running service, or stop it before copying the database and
associated files. Test restoration into an isolated instance before relying
on a backup. Monitor disk availability, signer/JWKS errors and audit-end-write
errors. Exact CLI audit filter/export invocations are described by the built
daemon's `audit --help`; filters use subject, username, host, result and UTC
Unix epoch milliseconds for `since`/`until`. JSON/CSV exports contain identity
and access metadata and deserve the same protection as the database.

```sh
simple-idm-bastion --config /etc/simple-idm-bastion/config.toml audit --username alice --format json
simple-idm-bastion --config /etc/simple-idm-bastion/config.toml audit --host grafana --format csv
```

## Isolated verification

Run from the repository root. Build the disposable target image explicitly;
the harness requires an existing image and never silently pulls/builds one:

```sh
docker build -t simple-idm-bastion-smoke:local -f scripts/bastion-smoke.Dockerfile scripts
python3 scripts/bastion-smoke.py
cargo build -p simple-idm-ssh-signer
python3 scripts/bastion-smoke.py --signer-bin target/debug/simple-idm-ssh-signer
cargo build -p simple-idm-bastion
python3 scripts/bastion-smoke.py --signer-bin target/debug/simple-idm-ssh-signer --bastion-bin target/debug/simple-idm-bastion
```

The Python standard-library harness creates its own loopback-bound sshd,
temporary CA/host/user/RSA issuer keys and HTTP discovery/JWKS mock. It disables
ambient HTTP proxies, SSH agent and connection multiplexing. Only the fixture
target's host key/config and public CA are mounted into the container. It does
not use production hostnames, accounts, services or existing SSH config. The
real-signer mode tests both direct and delegated signing, token/tenant/scope
and service-secret denial, principal narrowing and PTY-only cert extensions.
Both modes prove a connected PTY continues after expiration while a new
authentication with the expired cert fails, plus account/host-key denial and
remote exit status. Cleanup removes only owned processes/container/temp files.
The full `--bastion-bin` mode adds catalog/terminal authorization, real SSH through
WSS with a private TLS fixture proxy and validated certificate trust, binary
UTF-8, PTY resize/Ctrl-C, terminal continuation after certificate expiry, and
audit-before-shell/exit/duration. It checks concurrent identities sharing a
Linux account, disconnect, changed host key, an unavailable audit writer,
restart with unknown end time, audit filters/CSV export, and session-key cleanup.
The TLS fixture is not nginx; validate the deployment nginx config separately.
`--keep` preserves private fixture artifacts for debugging; protect and remove
them after use. Exit zero means the selected mode passed, never that an
unselected browser/TUI flow passed.

Manually verify browser SSO/MFA and the TUI against an isolated test tenant:
check filtering, account choice, `vim`/`top`, UTF-8, resize, Ctrl-C/EOF, return
to the picker after `exit`, terminal restoration after an error, and audit
identity/target/duration. Also verify denied host/account, changed host key,
two distinct users, disconnect, restart reconciliation and audit-storage
failure. The JWKS mock intentionally does not implement a browser login UI.
Do not point these tests at live infrastructure.

Verified on 2026-10-03 with Docker Desktop, OpenSSH 10.3 client and an Alpine
OpenSSH 10.0 target: standalone, real signer and full daemon/WSS/audit modes
passed. The full mode used the real `simple-idm-bastion` and
`simple-idm-ssh-signer` binaries. Browser SSO/TUI and Linux systemd activation
were not part of that automated run.
Both example TOML files parsed, the daemon example passed `check-config`, and
the nginx example passed `nginx -t` with substituted fixture TLS paths.

### Configuration discovery (0.2.1)

`--config <FILE>` overrides automatic discovery. Without it, the CLI checks
`simple-idm-bastion/config.toml`, then `simple-idm-bastion/bastion.toml` in the
OS user configuration directory, followed by `/etc/simple-idm-bastion/config.toml`
and `/etc/simple-idm-bastion/bastion.toml`. Linux uses `$XDG_CONFIG_HOME` or
`~/.config`; macOS uses `~/Library/Application Support`. Missing files produce
a Clap usage error listing searched paths. An invalid explicit path never falls
back to another file. Help, version and examples work without a configuration.
For the existing user-service setup, `simple-idm-bastion add-host` is sufficient.
