#!/usr/bin/env python3
"""Run the ignored terminal fixture on a controlling PTY (Linux/macOS).
Usage: python3 examples/verify-terminal.py /path/to/simple_idm_ssh_login-test-binary
The Rust test binary is produced by cargo test -p simple-idm-ssh-login --no-run.
"""
import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import time

for mode in ("success", "error", "cancel", "panic"):
    pid, master = pty.fork()
    if pid == 0:
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        os.environ["BASTION_FIXTURE_MODE"] = mode
        os.execv(sys.argv[1], [sys.argv[1], "raw_terminal_fixture", "--ignored", "--nocapture"])
    output = bytearray()
    original_flags = termios.tcgetattr(master)[3]
    sent = False
    selected = False
    filter_applied_at = None
    connected = False
    returned = False
    returned_at = None
    settled_draws = None
    deadline = time.monotonic() + 20
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break
                if not data:
                    break
                output.extend(data)
                # Ratatui preserves cursor position when clearing/resizing. A real
                # terminal answers DSR; this PTY harness must provide the same reply.
                for _ in range(data.count(b"\x1b[6n")):
                    os.write(master, b"\x1b[1;1R")
            if not selected and b"FIXTURE_HOST_LIST" in output:
                os.write(master, b"ignored/production\r")
                filter_applied_at = time.monotonic()
                selected = True
            if filter_applied_at is not None and time.monotonic() - filter_applied_at > 0.3 and not connected:
                # Enter in the filter applies it; it must not open the shell.
                for marker in (b"FIXTURE_SHELL_READY", b"FIXTURE_WAITING_READY", b"FIXTURE_RETURNED_LIST", b"FIXTURE_EXPECTED_PANIC"):
                    assert marker not in output, "filter Enter opened a session"
                os.write(master, b"\x1b[F\r")  # End selects the last filtered host.
                connected = True
            if not returned and b"FIXTURE_RETURNED_LIST" in output:
                returned = True
                returned_at = time.monotonic()
                # A mouse report must not cause continuous redraws or filter changes.
                os.write(master, b"\x1b[<0;10;5M\x1b[<0;10;5m")
            if returned_at is not None and time.monotonic() - returned_at > 0.15 and settled_draws is None:
                # One queued SIGWINCH from the preceding shell is legitimate.
                settled_draws = output.count(b"FIXTURE_RETURNED_LIST")
            if returned_at is not None and time.monotonic() - returned_at > 0.4:
                assert output.count(b"FIXTURE_RETURNED_LIST") == settled_draws, output.decode(errors="replace")
                os.write(master, b"\x1b" if mode == "error" else b"q")
                returned_at = None
            if not sent and mode == "success" and b"FIXTURE_SHELL_READY" in output:
                fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 35, 100, 0, 0))
                os.write(master, b"\x03\xc3\xa9\x1b[A")
                sent = True
            if not sent and mode == "cancel" and b"FIXTURE_WAITING_READY" in output:
                os.write(master, b"\x1b")
                sent = True
        else:
            raise AssertionError("PTY fixture timed out")
        _, status = os.waitpid(pid, 0)
        if mode == "panic":
            assert os.waitstatus_to_exitcode(status) == 101, output.decode(errors="replace")
            restored = termios.tcgetattr(master)[3]
            mask = termios.ICANON | termios.ECHO | termios.ISIG
            assert restored & mask == original_flags & mask, "panic left terminal in raw mode"
            assert b"FIXTURE_EXPECTED_PANIC" in output, output.decode(errors="replace")
            assert output.index(b"FIXTURE_EXPECTED_PANIC") > output.rfind(b"\x1b[?1049l"), "panic hidden in alternate screen"
            print("panic: terminal restored and diagnostic visible")
            continue
        assert os.waitstatus_to_exitcode(status) == 0, output.decode(errors="replace")
        assert b"FIXTURE_RESTORED" in output, output.decode(errors="replace")
        print(f"{mode}: terminal fixture passed")
    except BaseException:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        raise
    finally:
        os.close(master)
