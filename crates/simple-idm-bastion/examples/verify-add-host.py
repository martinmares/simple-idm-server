#!/usr/bin/env python3
"""Isolated CLI checks; no daemon, network scan or system service changes.
Usage: python3 verify-add-host.py /path/to/simple-idm-bastion
"""
import os
import pty
import select
import time
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
example = Path(__file__).with_name('bastion.toml').read_text()
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    config = root / 'config.toml'
    known = root / 'known_hosts'
    known.write_text('# managed keys\n')
    import re
    original = re.sub(r'^known_hosts = .*$', f'known_hosts = "{known}"', example, flags=re.M)
    config.write_text(original)
    config.chmod(0o600)
    args = [binary, '--config', str(config), 'add-host', '--id', 'nuc-new',
            '--name', 'Intel NUC "new"', '--address', 'nuc-new.cluster',
            '--environment', 'infra', '--group', 'ssh:principal:mares',
            '--login', 'mares', '--principal', 'mares']

    def run(command, success=True, env=None):
        result = subprocess.run(command, text=True, capture_output=True, env=env)
        assert (result.returncode == 0) == success, result.stdout + result.stderr
        return result

    run(args + ['--dry-run'])
    assert config.read_text() == original and not list(root.glob('*.bak-*'))
    run(args + ['--yes'])
    updated = config.read_text()
    assert updated.startswith(original.rstrip('\n')) and 'nuc-new' in updated
    assert config.stat().st_mode & 0o777 == 0o600
    backups = list(root.glob('config.toml.bak-*'))
    assert len(backups) == 1 and backups[0].read_text() == original
    run([binary, '--config', str(config), 'check-config'])
    run(args + ['--yes'], success=False)  # duplicate ID
    assert config.read_text() == updated
    run([binary, '--config', str(config), 'add-host', '--yes'], success=False)
    assert config.read_text() == updated

    # Generate a real key; stub keyscan in this subprocess's PATH to avoid network.
    key = root / 'key'
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)])
    fingerprint = run(['ssh-keygen', '-E', 'sha256', '-lf', str(key) + '.pub']).stdout.split()[1]
    pub = Path(str(key) + '.pub').read_text().split()
    scanner = root / 'ssh-keyscan'
    scanner.write_text('#!/bin/sh\nprintf "%s\\n" "nuc-pin.cluster ' + pub[0] + ' ' + pub[1] + '"\n')
    scanner.chmod(0o700)
    env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'])
    pin_args = args.copy()
    pin_args[pin_args.index('nuc-new')] = 'nuc-pin'
    pin_args[pin_args.index('nuc-new.cluster')] = 'nuc-pin.cluster'
    run(pin_args + ['--yes', '--host-key-fingerprint', 'SHA256:wrong'], success=False, env=env)
    assert config.read_text() == updated and known.read_text() == '# managed keys\n'
    run(pin_args + ['--yes', '--host-key-fingerprint', fingerprint], env=env)
    assert 'nuc-pin.cluster ssh-ed25519' in known.read_text()
    assert list(root.glob('known_hosts.bak-*'))[0].read_text() == '# managed keys\n'
    run([binary, '--config', str(config), 'check-config'])
    print('add-host: preview, atomic save/backup, permissions, duplicate/missing-field rejection, fingerprint mismatch and verified key pinning passed')

    # Real TTY wizard, including cancellation before any configuration writes.
    for answer, expected_count in [('no', 0), ('yes', 1)]:
        wizard_config = root / ('wizard-' + answer + '.toml')
        wizard_config.write_text(original)
        master, slave = pty.openpty()
        proc = subprocess.Popen([binary, '--config', str(wizard_config), 'add-host'],
                                stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        try:
            os.write(master, ('wizard-host\nWizard host\nwizard.cluster\n\ninfra\n\nssh:principal:mares\nmares\n\n\n' + answer + '\n').encode())
            output = bytearray()
            deadline = time.monotonic() + 10
            while proc.poll() is None and time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        break
            assert proc.wait(timeout=2) == 0, output.decode(errors='replace')
            assert len(list(root.glob(wizard_config.name + '.bak-*'))) == expected_count
            if answer == 'no':
                assert wizard_config.read_text() == original
            else:
                run([binary, '--config', str(wizard_config), 'check-config'])
                assert 'wizard-host' in wizard_config.read_text()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            os.close(master)
    print('add-host: interactive TTY wizard save/cancel passed')

    user_home = root / 'home'
    xdg = root / 'xdg'
    user_config_dir = (user_home / 'Library' / 'Application Support') if sys.platform == 'darwin' else xdg
    user_config = user_config_dir / 'simple-idm-bastion' / 'config.toml'
    user_config.parent.mkdir(parents=True)
    user_config.write_text(original)
    auto_env = dict(os.environ, HOME=str(user_home), XDG_CONFIG_HOME=str(xdg))
    run([binary, 'check-config'], env=auto_env)
    run([binary] + args[3:] + ['--dry-run'], env=auto_env)
    assert user_config.read_text() == original
    missing = run([binary, '--config', str(root / 'missing.toml'), 'check-config'], success=False, env=auto_env)
    assert missing.returncode == 2 and 'never falls back' in missing.stderr
    fields = run([binary, 'add-host', '--yes'], success=False, env=auto_env)
    assert fields.returncode == 2 and '--address' in fields.stderr
    run([binary, '--config', str(root / 'missing.toml'), 'examples'], env=auto_env)
    print('config discovery: OS user config, explicit missing path without fallback, Clap required arguments and config-free examples passed')
