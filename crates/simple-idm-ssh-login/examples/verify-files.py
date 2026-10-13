#!/usr/bin/env python3
"""Exercise file-manager letter shortcuts/filter on a controlling PTY.
Usage: python3 verify-files.py /path/to/simple_idm_ssh_login-test-binary
Requires a local OpenSSH sftp-server. All mutations target a temporary directory.
"""
import fcntl
import os
from pathlib import Path
import pty
import select
import signal
import struct
import sys
import tempfile
import termios
import time

with tempfile.TemporaryDirectory(prefix="idm-files-tui-") as directory:
    root = Path(directory)
    (root / "preview.txt").write_bytes(b"abc")
    pid, master = pty.fork()
    if pid == 0:
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        os.environ["FILES_FIXTURE_ROOT"] = directory
        os.execv(sys.argv[1], [sys.argv[1], "file_manager_terminal_fixture", "--ignored", "--nocapture"])
    output = bytearray()
    flags = termios.tcgetattr(master)[3]
    stage = 0
    next_action = time.monotonic() + 0.6
    deadline = time.monotonic() + 20
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.05)[0]:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break
                if not data:
                    break
                output.extend(data)
                for _ in range(data.count(b"\x1b[6n")):
                    os.write(master, b"\x1b[1;1R")
            if time.monotonic() < next_action:
                continue
            if stage == 0 and b"REMOTE" in output:
                os.write(master, b"\tn\x15scratch\r")
                stage = 1
                next_action = time.monotonic() + 0.4
            elif stage == 1 and (root / "scratch").is_dir():
                # Filter Enter applies the filter, then 'r' opens rename.
                os.write(master, b"/scratch\rr\x15renamed\r")
                stage = 2
                next_action = time.monotonic() + 0.4
            elif stage == 2 and (root / "renamed").is_dir():
                os.write(master, b"/\x15renamed\rd\r")
                stage = 3
                next_action = time.monotonic() + 0.4
            elif stage == 3 and not (root / "renamed").exists():
                # Uppercase filter matches a lowercase filename. Enter applies it.
                os.write(master, b"/\x15PREVIEW\rv")
                stage = 4
                next_action = time.monotonic() + 0.4
            elif stage == 4 and b"Text" in output:
                os.write(master, b"wwqh")
                stage = 5
                next_action = time.monotonic() + 0.4
            elif stage == 5 and b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in output:
                os.write(master, b"qe")
                stage = 6
                next_action = time.monotonic() + 0.4
            elif stage == 6 and b"ROOT READ ONLY" in output:
                # Mutations on the remote panel must be blocked before dialogs.
                os.write(master, b"nd")
                stage = 7
                next_action = time.monotonic() + 0.4
            elif stage == 7:
                assert {p.name for p in root.iterdir()} == {"preview.txt"}
                os.write(master, b"e")
                stage = 8
                next_action = time.monotonic() + 0.6
            elif stage == 8:
                os.write(master, b"/q\x1b")
                stage = 9
                next_action = time.monotonic() + 0.4
            elif stage == 9:
                os.write(master, b"q")
                stage = 10
        else:
            raise AssertionError("file TUI fixture timed out: " + output.decode(errors="replace"))
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0, output.decode(errors="replace")
        assert stage == 10 and b"FIXTURE_FILES_DONE" in output, output.decode(errors="replace")
        mask = termios.ICANON | termios.ECHO | termios.ISIG
        assert termios.tcgetattr(master)[3] & mask == flags & mask, "terminal mode not restored"
        assert {p.name for p in root.iterdir()} == {"preview.txt"}, "fixture files were not removed"
        print("PASS file TUI: Tab, n/mkdir, case-insensitive /filter, r/rename, d/delete, v/view, w/wrap toggle, h/SHA256, e/root read-only and back, blocked mutations, q/back and terminal restoration")
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.close(master)
