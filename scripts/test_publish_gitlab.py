"""Exercise Linux-only publishing and retry behavior without contacting GitLab."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

PUBLISHER = Path(__file__).resolve().parent / "publish_gitlab.sh"
FAKE_CURL = r'''
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
path = Path(os.environ["GITLAB_FAKE_STATE"])
state = json.loads(path.read_text())
url = args[-1]
method = args[args.index("--request") + 1] if "--request" in args else "GET"
state["calls"].append([method, url])
status = 200
body = {}
if method == "GET":
    if url.endswith("/assets/links"):
        body = [{"id": 1, "name": "SHA256SUMS"}]
    else:
        commit = state["tag"] if "/repository/tags/" in url else state["release"]
        status = 200 if commit else 404
        body = {"commit": {"id": commit}}
else:
    if "/packages/generic/" in url:
        source = args[args.index("--upload-file") + 1]
        assert Path(source).is_file(), source
        state["uploads"].append(Path(source).name)
    if "--data-binary" in args:
        payload = json.loads(Path(args[args.index("--data-binary") + 1][1:]).read_text())
        state["payloads"].append(payload)
path.write_text(json.dumps(state))
if "--output" in args:
    Path(args[args.index("--output") + 1]).write_text(json.dumps(body))
if "--write-out" in args:
    print(status, end="")
'''


class PublishGitLabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        curl = self.bin / "curl"
        curl.write_text(f"#!{sys.executable}\n" + FAKE_CURL)
        curl.chmod(0o755)
        if not shutil.which("sha256sum"):
            sha = self.bin / "sha256sum"
            sha.write_text('#!/usr/bin/env bash\nexec shasum -a 256 "$@"\n')
            sha.chmod(0o755)
        dist = self.root / "dist"
        assets = dist / "release"
        assets.mkdir(parents=True)
        (dist / "release.env").write_text("RELEASE_VERSION=0.12.1\nRELEASE_TAG=v0.12.1\nRELEASE_COMMIT=expected-commit\n")
        (dist / "release_notes.md").write_text("Release notes\n")
        self.name = "simple-idm-0.12.1-linux-amd64.tar.gz"
        (assets / self.name).write_bytes(b"archive")
        digest = hashlib.sha256(b"archive").hexdigest()
        (assets / "SHA256SUMS").write_text(f"{digest}  {self.name}\n")
        self.state = self.root / "state.json"

    def publish(self, tag=None, release=None, corrupt=False):
        self.state.write_text(json.dumps({"tag": tag, "release": release, "calls": [], "uploads": [], "payloads": []}))
        if corrupt:
            (self.root / "dist/release" / self.name).write_bytes(b"corrupt")
        result = subprocess.run(["bash", str(PUBLISHER)], cwd=self.root, capture_output=True, text=True,
                                env={**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}",
                                     "CI_API_V4_URL": "https://gitlab.invalid/api/v4",
                                     "CI_PROJECT_ID": "42", "CI_JOB_TOKEN": "fake-token",
                                     "GITLAB_FAKE_STATE": str(self.state)})
        return result, json.loads(self.state.read_text())

    def test_new_release_uploads_linux_archive_without_windows_zip(self):
        result, state = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state["uploads"], [self.name, "SHA256SUMS"])
        payload = state["payloads"][0]
        self.assertEqual(payload["ref"], "expected-commit")
        self.assertEqual([link["name"] for link in payload["assets"]["links"]], state["uploads"])

    def test_retry_updates_release_and_repairs_links(self):
        result, state = self.publish(tag="expected-commit", release="expected-commit")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["PUT", "https://gitlab.invalid/api/v4/projects/42/releases/v0.12.1"], state["calls"])
        self.assertIn(["POST", "https://gitlab.invalid/api/v4/projects/42/releases/v0.12.1/assets/links"], state["calls"])
        self.assertIn(["PUT", "https://gitlab.invalid/api/v4/projects/42/releases/v0.12.1/assets/links/1"], state["calls"])

    def test_tag_or_release_on_another_commit_blocks_uploads(self):
        for tag, release in (("another-commit", None), ("expected-commit", "another-commit")):
            with self.subTest(tag=tag, release=release):
                result, state = self.publish(tag=tag, release=release)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(state["uploads"], [])

    def test_bad_checksum_blocks_all_api_calls(self):
        result, state = self.publish(corrupt=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state["calls"], [])


if __name__ == "__main__":
    unittest.main()
