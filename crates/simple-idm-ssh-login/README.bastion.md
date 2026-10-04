# Bastion client V1

Copy `examples/bastions.toml` to the OS configuration directory alongside `config.toml`: on macOS
`~/Library/Application Support/simple-idm-ssh-login/bastions.toml`, on Linux
`$XDG_CONFIG_HOME/simple-idm-ssh-login/bastions.toml` (default
`~/.config/simple-idm-ssh-login/bastions.toml`)
and configure the bastion URL, OIDC issuer and public client ID. This is separate
from the existing SSH certificate `config.toml`. Register the public OIDC client
with PKCE and loopback callback URLs with dynamic ports. The client always requests `openid` and `bastion:connect` in addition to configured
scopes. The expected access-token audience is this dedicated public client ID
(IDM issues `aud = client_id`); no API resource parameter is needed. the client sends the access
token, not the ID token. Tokens stay in memory and never appear in terminal URLs.

```sh
simple-idm-ssh-login examples
simple-idm-ssh-login bastion bastion.datalite.cz
simple-idm-ssh-login bastion.datalite.cz
simple-idm-ssh-login bastion bastion.datalite.cz --device
simple-idm-ssh-login bastion.datalite.cz --device
```

The local browser opens by default (`--browser`). On a headless VPS use
`--device` (client 0.12.0): it prints URL/code without opening a browser or
starting a loopback callback. Complete login and MFA on another device; approval
opens the TUI. The bastion OAuth client must additionally allow
`urn:ietf:params:oauth:grant-type:device_code`, preserving its current scopes.
IDM decides whether MFA is required. Reauthentication keeps the chosen mode.
Both modes return API access tokens and require a local bastions.toml profile.
 Focus starts in the host list.
Press `/` to edit the filter by host ID, name,
environment, description, hostname, resolved IP or login; multiple words must
all match. Enter applies the filter and returns focus to the list without
connecting; Enter in the list connects. Esc during editing restores the previous
filter; Ctrl-U clears it. The cursor is visible only while editing the filter.
The Ratatui screen shows the server-verified user, tenant, bastion ID,
HTTPS endpoint and connected TLS endpoint IP. The bordered host table includes
hostname, IP, Linux account and environment; the environment column is omitted
below 100 columns. A scrollbar appears only when rows exceed the viewport.
Arrow keys select; PageUp/PageDown and Home/End navigate larger lists, Enter
connects and `q` quits the host list (or returns from the account picker).
Esc remains available for going back/cancelling. While editing the filter,
`q` is an ordinary character. Mouse capture stays disabled for native text selection.
Daemon 0.1.1 adds identity and destination metadata; older daemons are accepted
but cannot provide these fields. Destination IPs are resolved on the bastion,
with a one-second timeout; they describe DNS results, not a pinned SSH address. Hosts with multiple Linux accounts open
an account picker. Esc cancels an in-progress connection. Errors and shell exit
statuses return to the host list, preserving its filter, selected row and scroll
position (client 0.11.2). In the remote shell, Ctrl-C is sent unchanged
to the remote program; use `exit` or Ctrl-D to return to the list. V1 does not
reconnect dropped sessions, transfer files or forward ports.

Raw byte transport supports Linux/macOS terminals, including escape sequences,
UTF-8, Ctrl-C and interactive applications. Resize is polled every 100 ms.
WebSocket pings detect connection loss without imposing a session-duration or
inactivity limit. Terminal restoration uses a scope guard on normal exit,
errors and unwinding; SIGKILL or process abort cannot run cleanup. Configuration
allows HTTPS/WSS and explicit loopback HTTP/WS fixtures only. HTTP redirects are
disabled for the catalog so credentials cannot be redirected to another host.

The client uses `GET /api/v1/hosts` and `GET /api/v1/terminal` with a Bearer
header. Terminal frames are binary bytes; JSON text carries `resize` from the
client and `ready`, `error`, `exit` from the server. API paths are rooted at the
configured origin. `ready` and `resize` include `version: 1`; the client requires a V1 ready
event before sending any terminal input. HTTP 401 on a new connection repeats
browser authentication and reloads the authorized catalog.

The `examples` command prints static guidance before loading either config file;
it performs no authentication, key resolution or network access. See
`docs/BASTION.md` for deployment instructions.

Tests: `cargo test -p simple-idm-ssh-login` and
`cargo test -p simple-idm-core --lib browser_flow_tests`.
For a real PTY fixture, build the client tests with `cargo test -p
simple-idm-ssh-login --no-run`, then run `python3
crates/simple-idm-ssh-login/examples/verify-terminal.py <test-binary>`. This checks
filtering and selection, raw Ctrl-C/UTF-8/arrow bytes, versioned resize, shell
exit, server error, cancellation before ready, return to the list and cleanup.
It creates only an isolated loopback WebSocket endpoint.
