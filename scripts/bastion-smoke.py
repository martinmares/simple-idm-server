#!/usr/bin/env python3
"""Isolated bastion/OpenSSH fixtures. Python 3.9+, OpenSSL and OpenSSH required.

Never accepts a target URL or existing service: every service is owned by this run.
Run --help for modes. No Python packages, host sshd edits, or global SSH config.
"""

import argparse
import base64
import contextlib
import http.server
import hashlib
import json
import os
from pathlib import Path
import secrets
import selectors
import signal
import shutil
import socket
import socketserver
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import urllib.parse
import uuid

TENANT = "11111111-1111-4111-8111-111111111111"


def run(*argv, input=None, check=True, timeout=60):
    result = subprocess.run([str(v) for v in argv], input=input,
                            capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{argv[0]} failed ({result.returncode}): "
                           + result.stderr.decode(errors="replace"))
    return result


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http_json(url, token=None, data=None, headers=None):
    # No ambient proxies, redirects, or destinations outside our loopback fixture.
    if not url.startswith("http://127.0.0.1:"):
        raise ValueError("fixture HTTP requests must use literal loopback")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    request_headers = {"Content-Type": "application/json", **(headers or {})}
    if token:
        request_headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=request_headers,
                                 data=None if data is None else json.dumps(data).encode())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=5) as response:
            payload = response.read()
            return response.status, json.loads(payload) if payload.startswith((b"{", b"[")) else payload
    except urllib.error.HTTPError as error:
        return error.code, error.read()


class Issuer:
    """RS256 discovery/JWKS fixture. Signing is performed by OpenSSL."""
    def __init__(self, root):
        self.key = root / "issuer.pem"
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
            "-pkeyopt", "rsa_keygen_pubexp:65537", "-out", self.key)
        self.key.chmod(0o600)
        modulus = run("openssl", "rsa", "-in", self.key, "-noout", "-modulus").stdout
        self.jwks = {"keys": [{"kid": "fixture-rsa", "kty": "RSA", "alg": "RS256", "use": "sig",
                               "n": b64(bytes.fromhex(modulus.decode().strip().split("=")[1])),
                               "e": "AQAB"}]}
        fixture = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/.well-known/openid-configuration":
                    payload = {"issuer": fixture.url, "jwks_uri": fixture.url + "/jwks",
                               "authorization_endpoint": fixture.url + "/authorize",
                               "token_endpoint": fixture.url + "/token",
                               "response_types_supported": ["code"],
                               "subject_types_supported": ["public"],
                               "id_token_signing_alg_values_supported": ["RS256"]}
                elif self.path == "/jwks":
                    payload = fixture.jwks
                else:
                    self.send_error(404)
                    return
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def token(self, **overrides):
        now = int(time.time())
        claims = {"iss": self.url, "sub": "fixture-user", "aud": ["fixture-login"],
                  "iat": now, "exp": now + 300, "preferred_username": "fixture",
                  "groups": ["infra-admins", "ssh:principal:fixture"],
                  "scope": "openid profile groups bastion:connect", "tenant_id": TENANT}
        claims.update(overrides)
        signing = (b64(json.dumps({"alg": "RS256", "kid": "fixture-rsa", "typ": "JWT"}).encode())
                   + "." + b64(json.dumps(claims).encode())).encode()
        signature = run("openssl", "dgst", "-sha256", "-sign", self.key, input=signing).stdout
        return signing.decode() + "." + b64(signature)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class Fixtures:
    def __init__(self, root, image):
        self.root, self.image = root, image
        self.container = "bastion-smoke-" + secrets.token_hex(6)
        self.processes, self.logs = [], []
        self.proxies = []
        self.issuer = None

    def start(self):
        for key in ("ca", "host", "user", "wrong-host"):
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.root / key)
        target = self.root / "target"
        target.mkdir()
        # Only target host private key and CA public key are mounted into sshd.
        shutil.copyfile(self.root / "host", target / "host")
        shutil.copyfile(self.root / "ca.pub", target / "ca.pub")
        (target / "host").chmod(0o600)
        (target / "sshd_config").write_text("""Port 22
ListenAddress 0.0.0.0
HostKey /fixture/host
TrustedUserCAKeys /fixture/ca.pub
PubkeyAuthentication yes
AuthorizedKeysFile none
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers fixture
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitUserRC no
LogLevel VERBOSE
Subsystem sftp internal-sftp
PidFile /tmp/fixture-sshd.pid
""")
        # Docker chooses an unused loopback port; never expose this on the LAN.
        run("docker", "run", "--detach", "--name", self.container,
            "--label", "simple-idm.fixture=bastion-smoke", "--network", "bridge",
            "--publish", "127.0.0.1::22", "--mount", f"type=bind,src={target},dst=/fixture,readonly",
            self.image)
        mapping = run("docker", "port", self.container, "22/tcp").stdout.decode().strip()
        if not mapping.startswith("127.0.0.1:") or "\n" in mapping:
            raise RuntimeError("unexpected non-loopback Docker port mapping")
        self.port = int(mapping.rsplit(":", 1)[1])
        pub = (self.root / "host.pub").read_text().split()
        self.known_hosts = self.root / "known_hosts"
        self.known_hosts.write_text(f"[127.0.0.1]:{self.port} {pub[0]} {pub[1]}\n")
        self.bad_known_hosts = self.root / "wrong_known_hosts"
        wrong = (self.root / "wrong-host.pub").read_text().split()
        self.bad_known_hosts.write_text(f"[127.0.0.1]:{self.port} {wrong[0]} {wrong[1]}\n")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1) as sock:
                    if sock.recv(256).startswith(b"SSH-"):
                        break
            except OSError:
                pass
            time.sleep(0.2)
        else:
            raise RuntimeError("fixture sshd did not become ready")
        self.issuer = Issuer(self.root)

    def spawn(self, binary, config, name, extra=(), env_extra=None):
        log = (self.root / (name + ".log")).open("wb")
        self.logs.append(log)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.root),
               "TMPDIR": str(self.root), "XDG_CONFIG_HOME": str(self.root / "config"),
               "RUST_LOG": "info", "NO_PROXY": "*", **(env_extra or {})}
        process = subprocess.Popen([str(binary), "--config", str(config), *extra],
                                   cwd=self.root, env=env, stdout=log, stderr=log,
                                   start_new_session=True)
        self.processes.append(process)
        return process

    def ready(self, url, process):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("fixture daemon exited; inspect its fixture log")
            try:
                if http_json(url)[0] in (200, 401):
                    return
            except OSError:
                pass
            time.sleep(0.2)
        raise RuntimeError("fixture daemon startup timed out")

    def ssh(self, known_hosts=None, user="fixture", cert=True, tty=False):
        args = ["ssh", "-F", "/dev/null", "-p", str(self.port), "-i", str(self.root / "user"),
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "UserKnownHostsFile=" + str(known_hosts or self.known_hosts),
                "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=5",
                "-o", "PreferredAuthentications=publickey", "-o", "LogLevel=ERROR"]
        if cert:
            args += ["-o", "CertificateFile=" + str(self.root / "user-cert.pub")]
        else:
            args += ["-o", "CertificateFile=none"]
        if tty:
            args.append("-tt")
        args.append(user + "@127.0.0.1")
        return args

    def close(self):
        for proxy in self.proxies:
            proxy.close()
        for process in reversed(self.processes):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
        for log in self.logs:
            log.close()
        if self.issuer:
            self.issuer.close()
        result = run("docker", "logs", self.container, check=False, timeout=10)
        (self.root / "sshd.log").write_bytes(result.stdout + result.stderr)
        result = run("docker", "rm", "--force", self.container, check=False, timeout=15)
        if result.returncode and b"No such container" not in result.stderr:
            raise RuntimeError("could not remove owned fixture container " + self.container)


class Stream:
    def __init__(self, process):
        self.process = process
        self.buffer = b""
        self.selector = selectors.DefaultSelector()
        self.selector.register(process.stdout, selectors.EVENT_READ)

    def until(self, marker, timeout=15):
        deadline = time.monotonic() + timeout
        while marker not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"terminal did not produce {marker!r}: {self.buffer!r}")
            for key, _ in self.selector.select(remaining):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    raise AssertionError(f"terminal closed before {marker!r}: {self.buffer!r}")
                self.buffer += chunk
        before, self.buffer = self.buffer.split(marker, 1)
        return before

    def close(self):
        self.selector.close()


class UpgradeDenied(Exception):
    def __init__(self, status):
        self.status = status


class TLSProxy:
    """Loopback-only TLS terminator for fixture WSS; no nginx claim is made."""
    def __init__(self, root, backend_port):
        cert, key = root / "tls.crt", root / "tls.key"
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", key, "-out", cert)
        key.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        self.client_context = ssl.create_default_context(cafile=str(cert))
        owner = self
        self.connections = []
        self.lock = threading.Lock()

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    client = context.wrap_socket(self.request, server_side=True)
                except (ssl.SSLError, OSError):
                    return
                with client, socket.create_connection(("127.0.0.1", backend_port), timeout=5) as backend:
                    client.settimeout(90)
                    backend.settimeout(90)
                    with owner.lock:
                        owner.connections.extend((client, backend))
                    def copy(source, destination):
                        try:
                            while True:
                                block = source.recv(16384)
                                if not block:
                                    break
                                destination.sendall(block)
                        except OSError:
                            pass
                        finally:
                            with contextlib.suppress(OSError):
                                destination.shutdown(socket.SHUT_RDWR)
                    upstream = threading.Thread(target=copy, args=(client, backend), daemon=True)
                    upstream.start()
                    copy(backend, client)
                    upstream.join(timeout=2)
        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        with self.lock:
            for connection in self.connections:
                with contextlib.suppress(OSError):
                    connection.shutdown(socket.SHUT_RDWR)
                connection.close()
        self.server.server_close()
        self.thread.join(timeout=2)


class WebSocket:
    """Small bounded RFC6455 fixture client; literal loopback, no TLS/proxy.

    Optional TLS uses the fixture's certificate trust store and hostname checks.
    """
    def __init__(self, port, token, host="fixture", login="fixture", tls_context=None, endpoint="/api/v1/terminal", **query):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=15)
        if tls_context:
            try:
                self.sock = tls_context.wrap_socket(self.sock, server_hostname="127.0.0.1")
            except BaseException:
                self.sock.close()
                raise
        self.buffer = b""
        self.output = b""
        self.controls = []
        key = base64.b64encode(os.urandom(16)).decode()
        params = {"host_id": host, "login": login, "cols": 80, "rows": 24,
                  "term": "xterm-256color", **query}
        request = ("GET " + endpoint + "?" + urllib.parse.urlencode(params) + " HTTP/1.1\r\n"
                   + f"Host: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   + f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                   + (f"Authorization: Bearer {token}\r\n" if token else "") + "\r\n")
        self.sock.sendall(request.encode())
        try:
            while b"\r\n\r\n" not in self.buffer:
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise EOFError("WebSocket upgrade connection closed")
                self.buffer += chunk
                if len(self.buffer) > 65536:
                    raise RuntimeError("invalid WebSocket upgrade response")
            headers, self.buffer = self.buffer.split(b"\r\n\r\n", 1)
            status = int(headers.split(b" ", 2)[1])
            if status != 101:
                raise UpgradeDenied(status)
            fields = dict(line.split(b":", 1) for line in headers.lower().split(b"\r\n")[1:])
            # Header names are case-insensitive; the base64 value is case-sensitive.
            accept = next(line.split(b":", 1)[1].strip() for line in headers.split(b"\r\n")[1:]
                          if line.lower().startswith(b"sec-websocket-accept:"))
            expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
            if accept != expected or fields.get(b"upgrade", b"").strip() != b"websocket":
                raise RuntimeError("invalid WebSocket handshake")
        except BaseException:
            self.sock.close()
            raise

    def read(self, length):
        while len(self.buffer) < length:
            chunk = self.sock.recv(max(4096, length - len(self.buffer)))
            if not chunk:
                raise EOFError("WebSocket closed")
            self.buffer += chunk
        result, self.buffer = self.buffer[:length], self.buffer[length:]
        return result

    def send(self, opcode, payload):
        if len(payload) > 65536:
            raise ValueError("fixture frame too large")
        mask = os.urandom(4)
        header = bytes([0x80 | opcode])
        size = len(payload)
        header += (bytes([0x80 | size]) if size < 126 else
                   bytes([0x80 | 126]) + struct.pack("!H", size) if size < 65536 else
                   bytes([0x80 | 127]) + struct.pack("!Q", size))
        self.sock.sendall(header + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(payload)))

    def binary(self, payload):
        self.send(2, payload)

    def control(self, payload):
        self.send(1, json.dumps(payload).encode())

    def message(self, timeout=15):
        self.sock.settimeout(timeout)
        chunks, kind = [], None
        total = 0
        while True:
            first, second = self.read(2)
            final, opcode = bool(first & 0x80), first & 15
            if first & 0x70 or second & 0x80:
                raise RuntimeError("unexpected server masking/extensions")
            length = second & 127
            if length == 126:
                length = struct.unpack("!H", self.read(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self.read(8))[0]
            if length > 65536:
                raise RuntimeError("oversized fixture WebSocket frame")
            payload = self.read(length)
            if opcode == 8:
                raise EOFError("WebSocket close frame")
            if opcode == 9:
                self.send(10, payload)
                continue
            if opcode == 10:
                continue
            if opcode in (1, 2) and kind is None:
                kind = opcode
            elif opcode != 0 or kind is None:
                raise RuntimeError("invalid WebSocket fragmentation")
            chunks.append(payload)
            total += length
            if total > 1048576:
                raise RuntimeError("oversized fixture WebSocket message")
            if final:
                return kind, b"".join(chunks)

    def pump(self, timeout=15):
        opcode, payload = self.message(timeout)
        if opcode == 1:
            control = json.loads(payload)
            self.controls.append(control)
            return control
        self.output += payload
        if len(self.output) > 1048576:
            raise RuntimeError("fixture terminal output limit exceeded")
        return None

    def expect_control(self, kind, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                control = self.pump(max(0.01, deadline - time.monotonic()))
            except TimeoutError as error:
                raise AssertionError(f"terminal timeout awaiting control {kind!r}: {self.output!r}") from error
            if control and control.get("type") == kind:
                return control
            if control and control.get("type") == "error":
                raise AssertionError("unexpected daemon error: " + control.get("message", ""))
        raise AssertionError("missing WebSocket control " + kind)

    def until(self, marker, timeout=15):
        deadline = time.monotonic() + timeout
        while marker not in self.output:
            if time.monotonic() >= deadline:
                raise AssertionError(f"missing terminal marker {marker!r}: {self.output!r}")
            control = self.pump(max(0.01, deadline - time.monotonic()))
            if control and control.get("type") in ("error", "exit"):
                raise AssertionError("terminal ended before marker: " + str(control))
        before, self.output = self.output.split(marker, 1)
        return before

    def close(self):
        with contextlib.suppress(OSError):
            self.send(8, struct.pack("!H", 1000))
        self.sock.close()


def check(condition, label):
    if not condition:
        raise AssertionError(label)
    print("PASS " + label, flush=True)


def ssh_checks(fixture, valid_before):
    # Reject fallback to the raw public key: target has no authorized_keys.
    check(run(*fixture.ssh(cert=False), "true", check=False).returncode == 255,
          "raw key denied (certificate authentication is required)")
    check(run(*fixture.ssh(user="root"), "true", check=False).returncode == 255,
          "unapproved Linux account denied")
    check(run(*fixture.ssh(known_hosts=fixture.bad_known_hosts), "true", check=False).returncode == 255,
          "mismatched host key denied")
    # No multiplexing: the post-expiry check must perform a fresh authentication.
    process = subprocess.Popen(fixture.ssh(tty=True) + [
        "stty -echo; printf 'READY\\n'; while IFS= read -r line; do "
        "case \"$line\" in probe) printf 'ALIVE_AFTER_EXPIRY\\n';; quit) exit 7;; esac; done"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True)
    fixture.processes.append(process)
    stream = Stream(process)
    try:
        stream.until(b"READY\r\n")
        check(process.poll() is None, "certificate opens a live PTY session")
        # Wait on the returned boundary, never alter the system clock.
        while time.time() < valid_before + 2:
            time.sleep(min(0.2, valid_before + 2 - time.time()))
        process.stdin.write(b"probe\n")
        process.stdin.flush()
        stream.until(b"ALIVE_AFTER_EXPIRY\r\n")
        check(process.poll() is None, "existing shell continues after certificate expiration")
        denied = run(*fixture.ssh(), "true", check=False)
        check(denied.returncode == 255 and b"Permission denied" in denied.stderr,
              "fresh authentication using the same expired certificate is denied")
        process.stdin.write(b"quit\n")
        process.stdin.flush()
        check(process.wait(timeout=5) == 7, "remote exit status preserved")
    finally:
        stream.close()


def signer_checks(fixture, binary):
    port = free_port()
    config = fixture.root / "signer.toml"
    config.write_text(f'''listen_addr = "127.0.0.1:{port}"
oidc_issuer = "{fixture.issuer.url}"
expected_audience = "fixture-login"
ca_private_key_path = {json.dumps(str(fixture.root / 'ca'))}
default_ttl_seconds = 12
max_ttl_seconds = 12
clock_skew_seconds = 1
require_explicit_ssh_principal = true
allow_ssh_role_principals = false
[bastion]
expected_audience = "simple-idm-bastion"
tenant_id = "{TENANT}"
service_key_env = "BASTION_SERVICE_KEY"
required_scope = "bastion:connect"
''')
    fixture.service_key = secrets.token_hex(32)
    process = fixture.spawn(binary, config, "signer", env_extra={"BASTION_SERVICE_KEY": fixture.service_key})
    url = f"http://127.0.0.1:{port}"
    fixture.ready(url + "/healthz", process)
    request = {"public_key": (fixture.root / "user.pub").read_text(),
               "requested_principals": ["fixture"], "ttl_seconds": 12}
    for label, token, expected in (
        ("missing JWT", None, 401),
        ("wrong audience", fixture.issuer.token(aud=["wrong"]), 401),
        ("wrong issuer", fixture.issuer.token(iss="http://invalid.fixture"), 401),
        # Older than JWT library leeway.
        ("expired JWT", fixture.issuer.token(exp=int(time.time()) - 3600), 401),
        ("missing SSH principal", fixture.issuer.token(groups=["infra-admins"]), 403),
    ):
        status, _ = http_json(url + "/ssh/sign", token, request)
        check(status == expected, "signer rejects " + label)
    token = fixture.issuer.token()
    head, body, signature = token.split(".")
    invalid = head + "." + body + "." + b64(b"\x00" * 256)
    check(http_json(url + "/ssh/sign", invalid, request)[0] == 401,
          "signer rejects invalid signature")
    status, result = http_json(url + "/ssh/sign", token, request)
    check(status == 200 and result["principals"] == ["fixture"], "real signer issues fixture principal")
    session_id = str(uuid.uuid4())
    delegated = {**request, "session_id": session_id}
    fixture.signer_url = url
    fixture.access_token = fixture.issuer.token(aud=["simple-idm-bastion"])
    headers = {"X-Bastion-Key": fixture.service_key}
    endpoint = url + "/ssh/sign/bastion"
    for label, overrides in (
        ("wrong tenant", {"tenant_id": str(uuid.uuid4())}),
        ("missing tenant", {"tenant_id": None}),
        ("missing scope", {"scope": None}),
        ("scope substring", {"scope": "bastion:connect-extra"}),
        ("ID token", {"nonce": "fixture-nonce"}),
        ("wrong audience", {"aud": ["fixture-login"]}),
        ("expired token", {"exp": int(time.time()) - 3600}),
    ):
        status, _ = http_json(endpoint, fixture.issuer.token(aud=["simple-idm-bastion"], **overrides)
                              if "aud" not in overrides else fixture.issuer.token(**overrides), delegated, headers)
        check(status in (401, 403), "delegated signer rejects " + label)
    for label, supplied_headers in (("missing service key", {}),
                                     ("incorrect service key", {"X-Bastion-Key": "x" * 64})):
        check(http_json(endpoint, fixture.access_token, delegated, supplied_headers)[0] in (401, 403),
              "delegated signer rejects " + label)
    check(http_json(endpoint, fixture.access_token,
                    {**delegated, "requested_principals": ["root"]}, headers)[0] == 403,
          "delegated signer rejects principal escalation")
    check(http_json(endpoint, fixture.access_token,
                    {**delegated, "session_id": "not-a-uuid"}, headers)[0] in (400, 422),
          "delegated signer rejects invalid session UUID")
    status, result = http_json(endpoint, fixture.access_token, delegated, headers)
    check(status == 200 and result["principals"] == ["fixture"],
          "delegated signer issues only authorized requested principal")
    (fixture.root / "user-cert.pub").write_text(result["certificate"] + "\n")
    details = run("ssh-keygen", "-L", "-f", fixture.root / "user-cert.pub").stdout.decode()
    check("simple-idm-cert:bastion:" + session_id in details, "certificate key ID correlates session UUID")
    extension_section = details.split("Extensions:", 1)[1].strip().splitlines()
    check([line.strip() for line in extension_section] == ["permit-pty"],
          "bastion certificate grants PTY only")
    check(result["valid_before"] <= int(time.time()) + 12, "signer enforces short test TTL")
    return result["valid_before"]


def audit_rows(config, binary, **filters):
    args = [str(binary), "--config", str(config), "audit", "--format", "json"]
    for name, value in filters.items():
        args += ["--" + name, str(value)]
    return json.loads(run(*args).stdout)


def wait_audit(config, binary, session, result):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        for record in audit_rows(config, binary):
            if record["session_id"] == session and record["result"] == result:
                return record
        time.sleep(0.1)
    raise AssertionError(f"session {session} did not reach audit result {result}")


def denied_upgrade(port, token, expected, **params):
    try:
        socket = WebSocket(port, token, **params)
    except UpgradeDenied as denial:
        label = str(params) if params else "missing token" if not token else "default host/account request"
        check(denial.status == expected, f"terminal rejects {label} (HTTP {expected})")
    else:
        socket.close()
        raise AssertionError("unauthorized terminal upgraded")



def sftp_checks(port, token, config, binary, readonly=False):
    """Real target SFTP over the daemon's WS relay, without a terminal or shell."""
    def string(value):
        return struct.pack("!I", len(value)) + value
    with contextlib.closing(WebSocket(port, token, endpoint="/api/v1/files", **({"sudo_readonly":"true"} if readonly else {}))) as ws:
        ready = ws.expect_control("ready")
        check(ready.get("sudo_readonly",False) == readonly, "SFTP ready confirms requested mode")
        record = wait_audit(config, binary, ready["session_id"], "connected")
        check(record["sudo_readonly"] == readonly and record["session_kind"] == "sftp", "SFTP audit records login identity and elevation mode")
        check(record["connected_at"] is not None, "SFTP audit is durable before protocol input")
        buffered = bytearray()
        request_id = 0
        def exchange(payload):
            wire = struct.pack("!I", len(payload)) + payload
            # Message boundaries must not become SFTP packet boundaries.
            for offset in range(0, len(wire), 511):
                ws.binary(wire[offset:offset+511])
            while len(buffered) < 4 or len(buffered) < 4 + struct.unpack("!I", buffered[:4])[0]:
                opcode, data = ws.message(15)
                if opcode != 2:
                    raise AssertionError("unexpected SFTP control: " + repr(data))
                buffered.extend(data)
            length = struct.unpack("!I", buffered[:4])[0]
            result = bytes(buffered[4:4+length])
            del buffered[:4+length]
            return result
        def request(kind, payload=b"", expected=101):
            nonlocal request_id
            request_id += 1
            reply = exchange(bytes([kind]) + struct.pack("!I", request_id) + payload)
            assert reply[0] == expected and struct.unpack("!I",reply[1:5])[0] == request_id, repr(reply)
            if expected == 101:
                assert struct.unpack("!I", reply[5:9])[0] == 0, repr(reply)
            return reply
        version = exchange(b"\x01" + struct.pack("!I", 3))
        check(version[0] == 2 and struct.unpack("!I", version[1:5])[0] == 3, "SFTP subsystem negotiates v3 through WS without PTY")
        if readonly:
            protected=b"/root/bastion-proof.txt"
            handle_reply=request(3,string(protected)+struct.pack("!II",1,0),102)
            handle=handle_reply[9:9+struct.unpack("!I",handle_reply[5:9])[0]]
            reply=request(5,string(handle)+struct.pack("!QI",0,4096),103)
            check(b"root-only-fixture" in reply,"Root read-only SFTP reads a root-owned 0600 file without password")
            request(4,string(handle))
            for kind,payload in [(3,string(protected)+struct.pack("!II",2,0)),(13,string(protected)),(14,string(b"/root/not-created")+struct.pack("!I",0)),(18,string(protected)+string(b"/root/not-renamed"))]:
                request_id += 1
                reply=exchange(bytes([kind])+struct.pack("!I",request_id)+payload)
                check(reply[0]==101 and struct.unpack("!I",reply[5:9])[0]!=0,"Root read-only SFTP refuses write operation " + str(kind))
            return
        # Ordinary SFTP cannot access the same protected file.
        request_id+=1
        denied=exchange(bytes([3])+struct.pack("!I",request_id)+string(b"/root/bastion-proof.txt")+struct.pack("!II",1,0))
        check(denied[0]==101 and struct.unpack("!I",denied[5:9])[0]!=0,"Ordinary SFTP cannot read root-owned file")
        directory = ("/home/fixture/files-" + secrets.token_hex(6)).encode()
        request(14, string(directory) + struct.pack("!I",0))
        path = directory + "/žluťoučký.bin".encode()
        handle_reply = request(3,string(path) + struct.pack("!II", 2|8|32,0),102)
        handle = handle_reply[9:9+struct.unpack("!I",handle_reply[5:9])[0]]
        data = bytes(range(256)) * 1024
        for offset in range(0,len(data),16384):
            request(6,string(handle) + struct.pack("!Q",offset) + string(data[offset:offset+16384]))
        request(4,string(handle))
        handle_reply = request(3,string(path) + struct.pack("!II",1,0),102)
        handle = handle_reply[9:9+struct.unpack("!I",handle_reply[5:9])[0]]
        downloaded = bytearray()
        while len(downloaded) < len(data):
            reply=request(5,string(handle) + struct.pack("!QI",len(downloaded),32768),103)
            downloaded.extend(reply[9:9+struct.unpack("!I",reply[5:9])[0]])
        request(4,string(handle))
        check(bytes(downloaded)==data, "SFTP upload/download preserves binary bytes and Unicode paths")
        handle_reply=request(11,string(directory),102)
        handle=handle_reply[9:9+struct.unpack("!I",handle_reply[5:9])[0]]
        entries=request(12,string(handle),104)
        check("žluťoučký.bin".encode() in entries,"SFTP directory listing")
        request(4,string(handle))
        renamed=directory+b"/renamed.bin"
        request(18,string(path)+string(renamed))
        request(13,string(renamed))
        request(15,string(directory))
        check(True,"SFTP mkdir, rename, delete and rmdir")
        session_id=ready["session_id"]
    ended=wait_audit(config,binary,session_id,"disconnected")
    check(ended["ended_at"] is not None,"SFTP disconnect is durably audited")

def daemon_checks(fixture, binary):
    port = free_port()
    config = fixture.root / "bastion.toml"
    # Use localhost as a separately catalogued target with an untrusted key.
    wrong = (fixture.root / "wrong-host.pub").read_text().split()
    with fixture.known_hosts.open("a") as hosts:
        hosts.write(f"[localhost]:{fixture.port} {wrong[0]} {wrong[1]}\n")
    config.write_text(f'''bind = "127.0.0.1:{port}"
bastion_id = "fixture-bastion"
tenant_id = "{TENANT}"
issuer = "{fixture.issuer.url}"
expected_audience = "simple-idm-bastion"
signer_url = "{fixture.signer_url}/ssh/sign/bastion"
bastion_key_env = "BASTION_SERVICE_KEY"
known_hosts = {json.dumps(str(fixture.known_hosts))}
audit_db = {json.dumps(str(fixture.root / 'audit.db'))}
session_dir = {json.dumps(str(fixture.root / 'sessions'))}
ttl_seconds = 12
retention_days = 1
max_sessions = 8
trusted_proxies = []

[[hosts]]
id = "fixture"
name = "Fixture"
address = "127.0.0.1"
port = {fixture.port}
environment = "test"
description = "Disposable Docker target"
allowed_groups = ["infra-admins"]
logins = ["fixture"]
principals = ["fixture"]
sftp_sudo_readonly = true
sftp_server = "/usr/lib/ssh/sftp-server"

[[hosts]]
id = "hidden"
name = "Hidden"
address = "127.0.0.1"
port = {fixture.port}
environment = "test"
allowed_groups = ["other-admins"]
logins = ["fixture"]
principals = ["fixture"]

[[hosts]]
id = "wrong-key"
name = "Wrong host key"
address = "localhost"
port = {fixture.port}
environment = "test"
allowed_groups = ["infra-admins"]
logins = ["fixture"]
principals = ["fixture"]

[[hosts]]
id = "sudo-denied"
name = "Sudo denied"
address = "127.0.0.1"
port = {fixture.port}
environment = "test"
allowed_groups = ["infra-admins"]
logins = ["fixture"]
principals = ["fixture"]
sftp_sudo_readonly = true
sftp_server = "/usr/bin/false"
''')
    run(binary, "--config", config, "check-config")
    env = {"BASTION_SERVICE_KEY": fixture.service_key}
    daemon = fixture.spawn(binary, config, "bastion", extra=("serve",), env_extra=env)
    fixture.ready(f"http://127.0.0.1:{port}/api/v1/hosts", daemon)
    token = fixture.access_token
    catalog_url = f"http://127.0.0.1:{port}/api/v1/hosts"
    status, catalog = http_json(catalog_url, token)
    check(status == 200 and {h["id"] for h in catalog["hosts"]} == {"fixture", "wrong-key", "sudo-denied"},
          "daemon catalog filters hidden host")
    for label, supplied, expected in (
        ("missing access token", None, 401),
        ("wrong tenant", fixture.issuer.token(aud=["simple-idm-bastion"], tenant_id=str(uuid.uuid4())), 403),
        ("missing access scope", fixture.issuer.token(aud=["simple-idm-bastion"], scope=None), 403),
        ("expired access token", fixture.issuer.token(aud=["simple-idm-bastion"], exp=int(time.time()) - 3600), 401),
        ("wrong audience", fixture.issuer.token(aud=["wrong"]), 401),
    ):
        check(http_json(catalog_url, supplied)[0] == expected, "catalog rejects " + label)
    outsider = fixture.issuer.token(aud=["simple-idm-bastion"], groups=["ssh:principal:fixture"])
    check(http_json(catalog_url, outsider)[1]["hosts"] == [], "unapproved group sees empty catalog")
    denied_upgrade(port, None, 401)
    denied_upgrade(port, token, 403, host="hidden")
    denied_upgrade(port, token, 403, login="root")
    denied_upgrade(port, outsider, 403)
    denied_upgrade(port, token, 400, cols=0)
    denied_upgrade(port, token, 403, host="127.0.0.1")
    denied_upgrade(port, None, 401, endpoint="/api/v1/files")
    denied_upgrade(port, token, 403, endpoint="/api/v1/files", host="hidden")
    denied_upgrade(port, token, 403, endpoint="/api/v1/files", login="root")
    with contextlib.closing(WebSocket(port, token, host="wrong-key", endpoint="/api/v1/files")) as ws:
        ws.expect_control("error")
        check(not any(c["type"] == "ready" for c in ws.controls), "SFTP denies changed host key before ready")
    denied_upgrade(port, token, 403, endpoint="/api/v1/files", host="hidden", sudo_readonly="true")
    denied_upgrade(port, token, 403, endpoint="/api/v1/files", host="wrong-key", sudo_readonly="true")
    denied_upgrade(port, token, 403, endpoint="/api/v1/terminal", sudo_readonly="true")
    with contextlib.closing(WebSocket(port, token, endpoint="/api/v1/files", host="sudo-denied", sudo_readonly="true")) as ws:
        ready=ws.expect_control("ready")
        check(ws.expect_control("exit")["status"] != 0, "sudo -n rejects an unapproved command without a password prompt")
        failed=wait_audit(config,binary,ready["session_id"],"failed")
        check(failed["sudo_readonly"] and failed["linux_user"]=="fixture", "Failed sudo elevation retains original identity in audit")
    sftp_checks(port, token, config, binary)
    sftp_checks(port, token, config, binary, readonly=True)
    with contextlib.closing(WebSocket(port, token, host="wrong-key")) as ws:
        error = ws.expect_control("error")
        check(error["version"] == 1 and not any(c["type"] == "ready" for c in ws.controls),
              "daemon denies changed SSH host key before shell ready")
    proxy = TLSProxy(fixture.root, port)
    fixture.proxies.append(proxy)
    try:
        untrusted = WebSocket(proxy.port, token, tls_context=ssl.create_default_context())
    except ssl.SSLCertVerificationError:
        check(True, "WSS rejects untrusted fixture TLS certificate")
    else:
        untrusted.close()
        raise AssertionError("untrusted TLS certificate accepted")
    with contextlib.closing(WebSocket(proxy.port, token, tls_context=proxy.client_context)) as ws:
        ready = ws.expect_control("ready")
        check(ready["version"] == 1 and str(uuid.UUID(ready["session_id"])) == ready["session_id"],
              "trusted WSS authenticates real SSH and returns V1 session UUID")
        record = wait_audit(config, binary, ready["session_id"], "connected")
        check(record["connected_at"] is not None and record["subject"] == "fixture-user",
              "connected audit is durable before shell input")
        ws.binary(b"stty -echo; printf '__%s__\\n' READY\n")
        ws.until(b"__READY__\r\n")
        ws.binary("printf '__UTF8__žluťoučký\\n'\n".encode())
        ws.until("__UTF8__žluťoučký\r\n".encode())
        check(True, "binary terminal transport preserves UTF-8")
        ws.control({"type": "resize", "version": 1, "cols": 111, "rows": 37})
        ws.binary(b"sleep 1; stty size; printf '__%s__\\n' SIZE\n")
        check(b"37 111" in ws.until(b"__SIZE__\r\n"), "resize reaches remote PTY")
        ws.binary(b"sleep 30\n")
        time.sleep(0.5)
        ws.binary(b"\x03")
        ws.binary(b"printf '__%s__\\n' INTERRUPTED\n")
        ws.until(b"__INTERRUPTED__\r\n")
        check(True, "Ctrl-C interrupts remote command without closing terminal")
        # The signer used a 12-second certificate. Probe after its latest possible expiry.
        boundary = record["connected_at"] / 1000 + 14
        while time.time() < boundary:
            time.sleep(min(0.2, boundary - time.time()))
        ws.binary(b"printf '__%s__\\n' DAEMON_AFTER_EXPIRY\n")
        ws.until(b"__DAEMON_AFTER_EXPIRY__\r\n")
        check(True, "bastion terminal continues after its certificate expires")
        ws.binary(b"exit 7\n")
        check(ws.expect_control("exit")["status"] == 7, "daemon relays remote exit status")
    record = wait_audit(config, binary, ready["session_id"], "exited")
    check(record["exit_status"] == 7 and record["duration_ms"] >= 12000
          and record["ended_at"] >= record["connected_at"]
          and record["tenant"] == TENANT and record["linux_user"] == "fixture"
          and ready["session_id"] in record["certificate_id"],
          "audit records identity, target, certificate, exit and connected duration")
    # Concurrent identities share only the Linux account, never a session/key/audit ID.
    other = fixture.issuer.token(aud=["simple-idm-bastion"], sub="fixture-user-two", preferred_username="bob")
    with contextlib.closing(WebSocket(port, token)) as first, contextlib.closing(WebSocket(port, other)) as second:
        one, two = first.expect_control("ready"), second.expect_control("ready")
        check(one["session_id"] != two["session_id"], "concurrent identities have isolated sessions")
        first.binary(b"exit 0\n")
        second.binary(b"exit 0\n")
        first.expect_control("exit")
        second.expect_control("exit")
    one_record = wait_audit(config, binary, one["session_id"], "exited")
    two_record = wait_audit(config, binary, two["session_id"], "exited")
    check(one_record["subject"] == "fixture-user" and two_record["subject"] == "fixture-user-two"
          and two_record["username"] == "bob" and one_record["certificate_id"] != two_record["certificate_id"],
          "shared Linux account retains distinct audited IDM identities")
    with contextlib.closing(WebSocket(port, token)) as disconnected:
        disconnected_id = disconnected.expect_control("ready")["session_id"]
    wait_audit(config, binary, disconnected_id, "disconnected")
    check(True, "client disconnect closes and audits the terminal")
    # Hold only our fixture DB's writer lock: the daemon must refuse shell startup.
    with sqlite3.connect(fixture.root / "audit.db", timeout=1) as db:
        db.execute("BEGIN IMMEDIATE")
        denied_upgrade(port, token, 503)
        db.rollback()
    check(True, "unavailable audit writer fails closed before terminal upgrade")
    with contextlib.closing(WebSocket(port, token)) as interrupted:
        interrupted_id = interrupted.expect_control("ready")["session_id"]
        os.killpg(daemon.pid, signal.SIGKILL)
        daemon.wait(timeout=5)
    daemon = fixture.spawn(binary, config, "bastion-restart", extra=("serve",), env_extra=env)
    fixture.ready(catalog_url, daemon)
    recovered = wait_audit(config, binary, interrupted_id, "interrupted")
    check(recovered["ended_at"] is None and recovered["duration_ms"] is None
          and recovered["reconciled_at"] is not None and recovered["end_reason"] == "restart_unknown_end",
          "restart reconciles interrupted session without inventing end time/duration")
    records = audit_rows(config, binary)
    check(any(r["result"] == "denied" for r in records) and any(r["result"] == "failed" for r in records),
          "audit includes denied attempts and SSH connection failures")
    check(audit_rows(config, binary, subject="fixture-user-two")[0]["subject"] == "fixture-user-two",
          "audit CLI subject filter")
    exported = run(binary, "--config", config, "audit", "--format", "csv").stdout.decode()
    check("session_id,bastion_id" in exported and interrupted_id in exported, "audit CLI CSV export")
    sensitive = (fixture.service_key, fixture.access_token, "BEGIN OPENSSH PRIVATE KEY")
    check(not any(value in json.dumps(records) or value in exported for value in sensitive),
          "audit exports contain no service key, bearer token or private key")
    check(not list((fixture.root / "sessions").iterdir()), "session keys cleaned after exit/disconnect/restart")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="simple-idm-bastion-smoke:local",
                        help="prebuilt disposable sshd image; harness never pulls or builds")
    parser.add_argument("--signer-bin", type=Path,
                        help="use the real locally built signer instead of ssh-keygen")
    parser.add_argument("--bastion-bin", type=Path,
                        help="run full catalog/WS/SSH/audit flow; requires --signer-bin")
    parser.add_argument("--keep", action="store_true", help="retain private fixture logs/keys for debugging")
    args = parser.parse_args()
    if args.signer_bin:
        args.signer_bin = args.signer_bin.resolve(strict=True)
    if args.bastion_bin:
        if not args.signer_bin:
            parser.error("--bastion-bin requires --signer-bin")
        args.bastion_bin = args.bastion_bin.resolve(strict=True)
    for binary in ("docker", "ssh", "ssh-keygen", "openssl"):
        if not shutil.which(binary):
            parser.error("missing dependency: " + binary)
    docker_endpoint = os.environ.get("DOCKER_HOST")
    if not docker_endpoint:
        context = json.loads(run("docker", "context", "inspect").stdout)
        docker_endpoint = context[0]["Endpoints"]["docker"]["Host"]
    if not docker_endpoint.startswith(("unix://", "npipe://")):
        parser.error("fixture requires a local Docker socket; remote Docker engines are refused")
    run("docker", "image", "inspect", args.image)
    root = Path(tempfile.mkdtemp(prefix="idm-bastion-", dir="/private/tmp" if sys.platform == "darwin" else "/tmp"))
    root.chmod(0o700)
    fixture = Fixtures(root, args.image)
    try:
        fixture.start()
        check(http_json(fixture.issuer.url + "/jwks")[1] == fixture.issuer.jwks,
              "isolated OIDC discovery/JWKS issuer ready")
        if args.signer_bin:
            valid_before = signer_checks(fixture, args.signer_bin)
        else:
            run("ssh-keygen", "-q", "-s", root / "ca", "-I", "fixture-expiration",
                "-n", "fixture", "-V", "-1s:+12s", "-O", "clear", "-O", "permit-pty", root / "user.pub")
            # ssh-keygen uses second resolution, so add an extra second here.
            valid_before = int(time.time()) + 13
        ssh_checks(fixture, valid_before)
        if args.bastion_bin:
            daemon_checks(fixture, args.bastion_bin)
        print("PASS fixture smoke complete (browser SSO/TUI are not exercised)", flush=True)
    finally:
        try:
            fixture.close()
        finally:
            if args.keep:
                print("Private fixture artifacts retained at " + str(root), file=sys.stderr)
            else:
                shutil.rmtree(root)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print("FAIL " + str(error), file=sys.stderr)
        sys.exit(1)
