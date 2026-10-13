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
connects, f/F2 opens the file manager, and `q` quits the host list (or returns from the account picker).
Esc remains available for going back/cancelling. While editing the filter,
`q` is an ordinary character. Mouse capture stays disabled for native text selection.
Daemon 0.1.1 adds identity and destination metadata; older daemons are accepted
but cannot provide these fields. Destination IPs are resolved on the bastion,
with a one-second timeout; they describe DNS results, not a pinned SSH address. Hosts with multiple Linux accounts open
an account picker. Esc cancels an in-progress connection. Errors and shell exit
statuses return to the host list, preserving its filter, selected row and scroll
position (client 0.11.2). In the remote shell, Ctrl-C is sent unchanged
to the remote program; use `exit` or Ctrl-D to return to the list. V1 does not
reconnect dropped sessions or forward ports. File sessions are described below.

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

## File manager (0.14.0)

Select an authorized host and press **f** or **F2**. The same account picker and browser/device
login apply. Upgrade both `simple-idm-ssh-login` and `simple-idm-bastion` to 0.14.0.
The left panel starts in the local working directory; the right panel starts in
the remote account's home directory. Tab switches panels, arrows/PageUp/PageDown/
Home/End select entries, Enter opens directories and Backspace goes to the parent.
`/` edits the active panel's filter; Enter applies it, Esc restores the previous
filter. Letters, including q, are ordinary text while editing.

| Action | Letter | Function key |
| --- | --- | --- |
| Copy from active panel to the other panel | c or s | F5 |
| Rename in the active panel | r | F6 |
| Create directory | n | F7 |
| Delete file or empty directory | d | F8 |
| Refresh panels | u | F4 |
| Return to host list | q / Esc | — |

Copy prompts for the destination filename. Existing destinations require a
separate overwrite confirmation; enter a different name or Esc to skip. Delete
always requires confirmation. Transfers run in a background worker with bounded
buffers, byte progress and speed. Esc cancels an active copy and removes its
partial file when the connection remains usable. Cancellation does not undo an
already published file. Ctrl-C exits; abrupt termination or a lost connection can
leave a `.simple-idm-*.part` file for manual cleanup.

The first version copies one regular file at a time. Recursive/multiple-file copy,
symlink traversal, editing and resume are not supported. Permissions
and timestamps are not preserved. Remote filenames use the SFTP library's UTF-8
representation. Local names retain their original OS representation for source
operations; editable destination names are Unicode.

Files are first written to a unique temporary file in the destination directory.
Remote overwrite uses a temporary backup because standard SFTP v3 rename does not
replace an existing destination. The original is restored if publishing fails
while the connection is usable. This overwrite is not crash-atomic: a connection
loss can leave a `.simple-idm-*.backup` holding the original. Existing directories
and symlinks are not overwritten. Remote filesystem permissions still apply; the
file manager does not elevate privileges.

The client speaks SFTP through a separate authenticated `/api/v1/files` WebSocket.
The bastion runs OpenSSH's SFTP subsystem without a PTY, retaining session keys and
certificates on the bastion. No direct client SSH connection is made to the target.
The target sshd must enable `Subsystem sftp internal-sftp` or an equivalent SFTP
server; existing certificate/principal authentication remains in effect.

Transport integration (requires an installed local OpenSSH sftp-server):

```sh
cargo test -p simple-idm-ssh-login websocket_sftp_roundtrip_collisions_and_cancel -- --ignored
```

Controlling-terminal integration for letter shortcuts and terminal restoration:

```sh
cargo test -p simple-idm-ssh-login --no-run
python3 crates/simple-idm-ssh-login/examples/verify-files.py <client-test-binary>
```

## SHA-256 and preview (0.14.1)

`h` computes SHA-256 of the selected regular file, on either panel, and shows the
full digest. Remote bytes are read through the existing SFTP/WebSocket session;
no remote shell command is executed. Hashing streams the complete file with
bounded buffers and can be cancelled with Esc.

`v` or F3 opens a read-only preview of the first 64 KiB. Valid UTF-8 text without
binary control characters is displayed as text; other content uses a hexadecimal
view with offsets and an ASCII column. A truncated preview is explicitly marked.
Arrows, PageUp/PageDown and Home/End scroll vertically, Left/Right scroll
horizontally, and q/Esc/Enter closes the viewer without leaving the file manager.

`/` activates the current panel's case-insensitive substring filter. Results
change while typing; Enter returns focus to the list, Esc restores the previous
filter and Ctrl-U clears it. SHA/preview require only the updated client; the
bastion 0.14.0 file transport remains compatible.

### Wrap toggle (0.14.2)

Press `w` in the viewer to toggle line wrapping. The title shows wrap ON/OFF.
Wrapping preserves indentation; vertical scrolling and End use the rendered row
count. Horizontal scrolling applies only with wrapping off. Switching modes returns
to the top and resets horizontal scrolling. The default is wrap OFF.

## Root read-only panel (0.14.4)

`e` toggles the remote panel between its configured Linux account and root read-only.
The target must have the narrowly scoped NOPASSWD SFTP rule and the bastion host
must opt in. Both client and daemon need 0.14.4. A failed switch preserves the old
session; no password is requested. Root mode supports downloads, preview and SHA-256,
not remote writes. For setup and audit migration see
[the deployment guide](../../docs/BASTION.md#optional-root-read-only-files-0144).

### Directory navigation (0.14.5)

Each panel remembers the filter, selected filename and scroll position of visited
directories. Returning with Backspace or `../` selects the directory just exited
and restores the parent's previous view. Selection follows the filename if the
listing changes order; refresh also retains the selected filename when possible.

## Local web UI (0.15.0)

```sh
simple-idm-ssh-login bastion bastion.cloud-app.cz --web
# The hostname shortcut works too, including device authentication:
simple-idm-ssh-login bastion.cloud-app.cz --web --device
```

After the usual browser/device authentication, the client opens a local browser
UI with the authorized hosts, an xterm.js terminal and a two-panel file manager.
Only the client needs updating for `--web`; the existing bastion terminal/files
endpoints are reused. Root read-only requires the previously documented bastion
and target configuration.

The local panel is the filesystem of the computer running the CLI, under its OS
account. The remote panel uses SFTP through the bastion. Copy, rename, mkdir,
delete, case-insensitive filtering, SHA-256, text/hex preview (first 64 KiB), wrap,
progress/cancel and root read-only use the same file operations as the TUI.
Letters/function keys match the TUI where applicable. Use buttons or Enter to
confirm name/overwrite/delete dialogs; the terminal receives its own keystrokes.
Only individual regular files are copied; permissions/timestamps are not preserved.

The HTTP listener binds exclusively to `127.0.0.1` on an ephemeral port. All
assets are bundled into the binary; Node.js, CDN access and a public web service
are unnecessary. An unguessable, one-use URL fragment establishes an HttpOnly,
SameSite=Strict local session; the fragment is immediately removed from the URL.
The API checks Host, Origin and the local session; WebSocket upgrades also require
the exact local Origin. The IDM token remains in Rust memory and is never sent
to browser JavaScript or put into localStorage. Treat the launch link as a secret.

This is a local desktop UI, not a remotely exposed bastion web portal. Do not
reverse-proxy or port-forward the listener. `--device` changes IDM authentication,
not the loopback-only listener. On a headless machine, use the TUI or run the client
on the computer with the browser. When an access token expires, restart the CLI
to authenticate again; web mode currently does not reauthenticate automatically.
Closing the browser tab leaves the CLI running. **Stop client** or Ctrl-C closes it.
Abrupt shutdown can leave partial transfer files as described above.

Developer checks:

```sh
cargo test -p simple-idm-ssh-login
cargo test -p simple-idm-ssh-login web_operations_and_readonly_enforcement -- --ignored
```

An isolated browser fixture uses the installed OpenSSH `sftp-server`, including
its `-R` mode, and an echo terminal over the bastion WebSocket protocol:

```sh
WEB_FIXTURE_ROOT=/tmp/your-fixture-dir WEB_FIXTURE_INFO=/tmp/bastion-web.json \
  cargo test -p simple-idm-ssh-login web_browser_fixture -- --ignored --nocapture
```

Open the `url` from the JSON file. **Stop client** ends the fixture.
For the browser regression script, prepare a fresh fixture directory containing
`hello.txt` (with the text `Hello from Bastion`), `binary.dat` (binary content),
`folder/inside.txt` and an empty `downloads/` directory. After opening the fixture
URL with Playwright CLI, run:

```sh
playwright-cli run-code --filename=crates/simple-idm-ssh-login/examples/verify-web.js
```

The script verifies navigation/selection, filtering, previews, copy/overwrite,
rename/mkdir/delete, Enter/Escape in dialogs, root read-only, terminal input and
resize, and then stops the fixture. Screenshots go to `output/playwright/`.

Vendored xterm.js 5.5.0 is MIT licensed; its license is included under `web/vendor/`.

### Browser selection and terminal sizing (0.15.1)

```sh
simple-idm-ssh-login bastion bastion.cloud-app.cz --web --web-browser firefox
simple-idm-ssh-login bastion.cloud-app.cz --web --web-browser firefox --device
```

`--web-browser` requires `--web` and chooses the application used to open the
local UI. Without it, the OS default browser is used. Device flow still prints
the IDM authorization URL/code; it does not select a local UI browser. Browser
selection also applies to the IDM browser login (0.15.2); with `--device` no
authentication browser is opened.
On macOS this uses the named application (e.g. Firefox); on Linux it uses the
browser executable. If opening the requested browser fails, the client prints
a one-use local launch link rather than switching to the default browser.

Terminal dimensions use the bundled MIT-licensed xterm Fit addon 0.10.0 and
actual rendered cell sizes, including scrollbar space, instead of fixed row-height
estimates. The terminal mount excludes the panel's border and padding, so the
last screen row remains visible even after resizing or scrolling to the bottom.

### Bundled terminal icons (0.15.3)

The web terminal bundles JetBrains Mono NL Nerd Font Mono Regular from Nerd Fonts
v3.4.0. Its Linux/home/clock/Powerline and other Nerd Font icons are available
without installing fonts on the client computer or changing the remote shell.
The browser loads the local font before creating and measuring the terminal.
Regular glyphs and icons use fixed-width terminal cells; bold is synthesized by
the browser. The original SIL Open Font License is included under `web/vendor/`.
The font adds approximately 2.4 MB to the client binary; it is served exclusively
by the local client, with no CDN requests.
