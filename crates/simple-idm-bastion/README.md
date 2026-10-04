# Simple IDM Bastion V1

Linux/macOS daemon using the existing core `JwtValidator`, delegated SSH
certificates, external OpenSSH and `portable-pty`. Build from the parent workspace:

```sh
cargo build -p simple-idm-bastion --locked
cargo test -p simple-idm-bastion --locked
./target/debug/simple-idm-bastion examples
./target/debug/simple-idm-bastion --config crates/simple-idm-bastion/examples/bastion.toml check-config
```

Copy [bastion.toml](examples/bastion.toml) to your deployment. `examples` prints
usage without reading any configuration or accessing the network. `check-config`
checks syntax and policy; startup additionally checks files, permissions, service
key, single-instance ownership and OIDC discovery. See the parent
[deployment guide](../../docs/BASTION.md) and [Czech guide](../../docs/BASTION.cs.md).

## Deployment and authorization

Install `/usr/bin/ssh` and `/usr/bin/ssh-keygen`. Bind only loopback
HTTP; nginx supplies external HTTPS/WSS and must support WebSocket upgrade and
keepalive. Provision a managed `known_hosts` with verified host keys or `@cert-authority`
entries. Unknown/changed host keys fail; no local acceptance/password prompts,
user SSH configuration, agent credentials, multiplexing, escape commands, agent,
X11, or port forwarding are enabled. Targets trust the signer's user CA and map
principals to existing Linux accounts using `AuthorizedPrincipalsFile`/Command.

`tenant_id` is mandatory and matches the immutable claim exactly. Configure
`expected_audience` to the same **public OIDC client ID** used by the login client
and delegated signer. V1 fixes the required scope to `bastion:connect`; a token
must include that whitespace-delimited scope and have no nonce. ID tokens are
rejected. The JWT validator handles signature, issuer, audience and expiry;
RS256 is the supported deployment algorithm. Group membership comes from the
verified access token and changes become effective with fresh tokens, not
immediately. Existing sessions continue after token/certificate expiration.

Each host requires at least one matching `allowed_groups` entry. `logins` lists
fixed accounts or `{username}`. The latter uses only verified `preferred_username`
matching `[a-z][a-z0-9_-]{0,31}`. Invalid mappings are omitted. Host `principals`
is an optional nonempty list (colon is allowed, e.g. `role:ops`) that narrows
signer-derived principals. If omitted, the signer uses its complete mapped allowed
set; Linux login authorization is still checked against the host catalog. A
principal need not equal a Linux login when target account mapping is configured.

Set `BASTION_SERVICE_KEY` (or the configured `bastion_key_env`) to a shared secret
of at least 32 bytes. The daemon sends the user's access token in Authorization
and the service secret in `X-Bastion-Key` to exactly `signer_url`; signer redirects
are refused. HTTPS is required for service URLs except loopback fixtures.

```json
POST /ssh/sign/bastion
{"public_key":"ssh-ed25519 ...","requested_principals":["role:ops"],"ttl_seconds":3600,"session_id":"UUID"}
```

`requested_principals` is omitted when not configured. The existing response
`{certificate, valid_after, valid_before, principals}` is used. The daemon rejects
widened principal metadata, expired/future/overlong validity, non-user certificates,
principals inconsistent with the actual certificate, and a certificate not matching
the ephemeral key. `ssh-keygen` parses/fingerprints the certificate; audit stores
its actual key ID and serial. Signer policy must issue PTY-only certificates with
all forwarding extensions disabled and include the session UUID in its key ID.

## API and wire protocol

Native clients send `Authorization: Bearer ACCESS_TOKEN`, never a URL token.

* `GET /api/v1/hosts` returns `{hosts:[{id,name,environment,description,logins}]}`.
* `GET /api/v1/terminal?host_id=grafana&login=alice&cols=80&rows=24&term=xterm-256color`
  upgrades to WebSocket after repeating authorization. External transport is WSS.

Binary messages in both directions carry unchanged terminal bytes (including
Ctrl-C/EOF). JSON text messages are controls:

```json
{"type":"ready","version":1,"session_id":"UUID"}
{"type":"resize","version":1,"cols":120,"rows":40}
{"type":"error","version":1,"message":"..."}
{"type":"exit","version":1,"status":0}
```

Client resize requires version 1 and dimensions 1..1000. Default dimensions are
80x24; default TERM is `xterm-256color`. TERM permits 1..64 ASCII letters/digits and
`_-+.` only. Sending terminal input before ready fails. WebSocket messages are
limited to 64 KiB; PTY queues are bounded, slow peers time out, and ping/pong
keepalive detects lost connections. There is no idle/session/certificate lifetime
termination policy. Reconnection and file transfer are outside V1.

A private Unix socket in the session's mode-0700 directory carries a random
LocalCommand marker; terminal output cannot spoof readiness. OpenSSH invokes it
only after authentication. The helper waits until the daemon durably records
`connected_at` before releasing OpenSSH. OpenSSH first captures normal remote terminal modes, then enters local raw
mode; the daemon waits for that transition before sending ready or exposing
terminal data/input. This marker proves SSH
authentication; remote PTY/shell request failure immediately afterward is still a
session error/exit, since OpenSSH LocalCommand is not a remote-shell acknowledgment.
Per-session keys are removed on exit/error/disconnect; leftover generated session
directories are removed on daemon restart while the instance lock is held.

## Durable audit

Create the database parent directory owned by the daemon with mode 0700. Initial
database and persistent `.bastion.lock` sidecar files are mode 0600. Use a dedicated
private `session_dir`. Keep this local SQLite database on a filesystem with reliable
SQLite/flock semantics; all daemon instances must share the same canonical database
path. Never remove/replace the lock sidecar while an instance is running. V1 allows
one instance; audit reads can run concurrently, retention requires it stopped.

SQLite WAL with FULL synchronous commits stores session requests before signing
or shell exposure, verified identity, denied attempts (including missing token and
hidden host), target details, certificate ID, authenticated connection time, end
reason/status and monotonic connected duration in milliseconds. Unknown identity
fields remain null. Tokens, service secrets, keys and terminal contents are absent.

End writes retry three times with visible operational errors. Persistent failure
refuses subsequent terminal sessions until restart. Restart marks unfinished rows
`interrupted` with `reconciled_at`; actual `ended_at` and duration remain unknown.
The command `retain` deletes only finished/reconciled rows older than `retention_days`
(default 90); schedule this administrative task during service downtime. To back up,
use SQLite's online backup API or stop the daemon and back up the DB together with
WAL/SHM as appropriate; copying only a live WAL database can lose recent sessions.

```sh
simple-idm-bastion --config /etc/simple-idm-bastion/bastion.toml audit --host grafana --username alice --since 1790985600000 --format json
simple-idm-bastion --config /etc/simple-idm-bastion/bastion.toml audit --subject USER_UUID --result failed --format csv
simple-idm-bastion --config /etc/simple-idm-bastion/bastion.toml retain
```

`--since` is inclusive and `--until` exclusive, both UTC epoch milliseconds.
Only configured trusted proxy IPs can supply one `X-Real-IP`; other peers and
all `X-Forwarded-For` headers are ignored. nginx must overwrite that header.
Disconnecting closes the SSH transport but cannot guarantee that remote `tmux`,
`nohup` or detached processes terminate. Audit measures terminal connection time.

## Isolated live transport verification

Use the parent smoke entry point for the disposable OpenSSH target, real signer
and daemon. Build the binaries and fixture image first:

```sh
cargo build -p simple-idm-bastion -p simple-idm-ssh-signer --locked
docker build -t simple-idm-bastion-smoke:local -f scripts/bastion-smoke.Dockerfile scripts
python3 scripts/bastion-smoke.py --signer-bin target/debug/simple-idm-ssh-signer --bastion-bin target/debug/simple-idm-bastion
```

It creates only disposable loopback services and a dedicated Docker target.
It checks signer authentication/authorization, daemon catalog, connected audit
before readiness, real remote PTY resizing, binary bytes, Ctrl-C, a shell surviving
certificate expiry, exact exit status, durable duration, disconnect, and key cleanup.
The normal run removes fixture artifacts; `--keep` retains private keys/logs only
for debugging. Browser SSO and TUI are exercised by the client separately.

### Configuration discovery (0.2.1)

`--config <FILE>` overrides automatic discovery. Without it, the CLI checks
`simple-idm-bastion/config.toml`, then `simple-idm-bastion/bastion.toml` in the
OS user configuration directory, followed by `/etc/simple-idm-bastion/config.toml`
and `/etc/simple-idm-bastion/bastion.toml`. Linux uses `$XDG_CONFIG_HOME` or
`~/.config`; macOS uses `~/Library/Application Support`. Missing files produce
a Clap usage error listing searched paths. An invalid explicit path never falls
back to another file. Help, version and examples work without a configuration.
For the existing user-service setup, `simple-idm-bastion add-host` is sufficient.
