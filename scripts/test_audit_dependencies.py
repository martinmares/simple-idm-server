import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "audit_dependencies", Path(__file__).with_name("audit-dependencies.py")
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class DependencyAuditPolicyTests(unittest.TestCase):
    def check(self, findings, status=1):
        report = {"database": {}, "vulnerabilities": {"list": findings}, "warnings": {}}
        result = SimpleNamespace(returncode=status, stdout=json.dumps(report), stderr="")
        with patch.object(audit.subprocess, "run", return_value=result):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return audit.main()

    def finding(self, advisory="RUSTSEC-2023-0071", version="0.9.10"):
        return {"advisory": {"id": advisory}, "package": {"name": "rsa", "version": version}}

    def test_only_the_reviewed_version_is_accepted(self):
        self.assertEqual(self.check([self.finding()]), 0)
        self.assertEqual(self.check([self.finding(version="0.9.11")]), 1)

    def test_additional_advisory_is_not_hidden(self):
        self.assertEqual(self.check([self.finding(), self.finding(advisory="new-advisory")]), 1)

    def test_tool_failure_without_findings_is_not_accepted(self):
        self.assertEqual(self.check([]), 1)
        self.assertEqual(self.check([], status=2), 2)

    def test_clean_report_is_accepted(self):
        self.assertEqual(self.check([], status=0), 0)
