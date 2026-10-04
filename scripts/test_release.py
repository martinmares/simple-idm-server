"""Exercise release invariants in isolated workspaces, without publishing."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.patch = patch.object(release, "ROOT", self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.binaries = [
            "simple-idm-server", "simple-idm-ctl", "simple-idm-oauth2-proxy",
            "simple-idm-oidc-metadata-proxy", "simple-idm-token-proxy", "simple-idm-ad-proxy",
            "simple-idm-ssh-login", "simple-idm-ssh-signer", "simple-idm-bastion",
        ]
        members = ["crates/core"] + ["crates/" + name for name in self.binaries]
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nresolver = "2"\nmembers = ' + json.dumps(members) +
            '\n[workspace.package]\nversion = "0.12.1"\n')
        (self.root / "VERSION").write_text("0.12.1\n")
        for index, member in enumerate(members):
            folder = self.root / member
            (folder / "src").mkdir(parents=True)
            manifest = f'[package]\nname = "test-{index}"\nversion.workspace = true\nedition = "2024"\n'
            if index:
                manifest += f'[[bin]]\nname = "{self.binaries[index-1]}"\npath = "src/main.rs"\n'
                (folder / "src/main.rs").write_text("fn main() {}\n")
            else:
                (folder / "src/lib.rs").write_text("")
            (folder / "Cargo.toml").write_text(manifest)
        (self.root / "migrations").mkdir()
        (self.root / "migrations/001_init.sql").write_text("SELECT 1;\n")
        self.command("cargo", "generate-lockfile", "--offline")
        for name in ("README.md", "LICENSE"):
            (self.root / name).write_text(name + "\n")
        self.command("git", "init", "-q")
        self.command("git", "config", "user.name", "Release test")
        self.command("git", "config", "user.email", "release@example.invalid")
        self.command("git", "config", "commit.gpgSign", "false")
        self.command("git", "add", ".")
        self.command("git", "commit", "-qm", "Initial test fixture")

    def command(self, *args):
        return subprocess.run(args, cwd=self.root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_bump_updates_all_packages_without_editing_member_manifests(self):
        originals = {p: p.read_bytes() for p in release.manifests()}
        with contextlib.redirect_stdout(io.StringIO()):
            release.bump("0.13.0-rc.1")
        self.assertEqual(release.check(), "0.13.0-rc.1")
        self.assertEqual(originals, {p: p.read_bytes() for p in release.manifests()})

    def test_failed_bump_restores_all_files(self):
        files = [self.root / name for name in ("VERSION", "Cargo.toml", "Cargo.lock")]
        originals = [p.read_bytes() for p in files]
        with patch.object(release.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "cargo")):
            with self.assertRaises(subprocess.CalledProcessError):
                release.bump("0.13.0")
        self.assertEqual(originals, [p.read_bytes() for p in files])

    def test_mismatched_version_and_lock_are_rejected(self):
        (self.root / "VERSION").write_text("0.13.0\n")
        with self.assertRaisesRegex(AssertionError, "VERSION differs"):
            release.check()
        (self.root / "VERSION").write_text("0.12.1\n")
        p = self.root / "Cargo.lock"
        p.write_text(p.read_text().replace('version = "0.12.1"', 'version = "0.8.0"', 1))
        with self.assertRaisesRegex(AssertionError, "stale version"):
            release.check()

    def test_member_must_inherit_version(self):
        p = release.manifests()[0]
        p.write_text(p.read_text().replace('version.workspace = true', 'version = "0.12.1"'))
        with self.assertRaisesRegex(AssertionError, "inherit"):
            release.check()

    def test_tag_on_another_commit_is_rejected(self):
        self.command("git", "tag", "v0.12.1")
        self.assertEqual(release.check(release=True), "0.12.1")
        self.command("git", "commit", "--allow-empty", "-qm", "Another commit")
        with self.assertRaisesRegex(AssertionError, "another commit"):
            release.check(release=True)

    def test_invalid_version_is_rejected_without_changes(self):
        for version in ("01.2.3", "1.2", "v1.2.3", "1.2.3-01", "1.2.3+meta", "1.2.3\nmalicious"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.bump(version)
        self.assertEqual(release.check(), "0.12.1")

    def test_archives_contain_supported_binaries_migrations_and_build_metadata(self):
        for target in release.TARGETS:
            folder = self.root / "target" / target / "release"
            folder.mkdir(parents=True)
            suffix = ".exe" if target.endswith("msvc") else ""
            for binary in self.binaries:
                (folder / (binary + suffix)).write_bytes(b"test binary")
            with contextlib.redirect_stdout(io.StringIO()):
                release.package(target)
            base = f"simple-idm-0.12.1-{release.TARGETS[target]}"
            dist = self.root / "dist/release"
            if suffix:
                with zipfile.ZipFile(dist / (base + ".zip")) as archive:
                    names = archive.namelist()
                    metadata = archive.read(base + "/BUILD.json")
            else:
                with tarfile.open(dist / (base + ".tar.gz")) as archive:
                    names = archive.getnames()
                    metadata = archive.extractfile(base + "/BUILD.json").read()
                    self.assertEqual(archive.getmember(base + "/simple-idm-server").mode, 0o755)
            expected = [b for b in self.binaries if not (suffix and b == "simple-idm-bastion")]
            if suffix:
                self.assertNotIn(base + "/simple-idm-bastion.exe", names)
            self.assertIn(base + "/migrations/001_init.sql", names)
            for binary in expected:
                self.assertIn(base + "/" + binary + suffix, names)
            self.assertEqual(json.loads(metadata)["target"], target)
            self.assertEqual(json.loads(metadata)["binaries"], expected)
        release.checksums()
        for line in (self.root / "dist/release/SHA256SUMS").read_text().splitlines():
            checksum, name = line.split("  ")
            self.assertEqual(checksum, hashlib.sha256((self.root / "dist/release" / name).read_bytes()).hexdigest())

    def test_missing_binary_prevents_archive(self):
        with self.assertRaisesRegex(AssertionError, "Missing release binary"):
            release.package("x86_64-unknown-linux-musl")
        self.assertEqual(list((self.root / "dist/release").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
