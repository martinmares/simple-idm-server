import json
import stat
import tempfile
import unittest
from pathlib import Path

from export_google_workspace_users import api_error_hints, check_subject, fetch_users, normalize_users, write_export


class ExportTests(unittest.TestCase):
    def test_api_diagnostics_do_not_echo_secrets(self):
        error = Exception()
        error.content = json.dumps({"error": {
            "message": "secret-token-value",
            "errors": [{"reason": "forbidden"}],
            "details": [{"reason": "SERVICE_DISABLED", "metadata": {"token": "secret-token-value"}}],
        }}).encode()
        hints = api_error_hints(error)
        self.assertEqual(len(hints), 2)
        self.assertIn("Workspace", " ".join(hints))
        self.assertNotIn("secret-token-value", " ".join(hints))
        error.content = b"not JSON secret-token-value"
        self.assertEqual(api_error_hints(error), [])

    def test_pagination(self):
        class Service:
            def __init__(self):
                self.calls = []

            def users(self):
                return self

            def list(self, **kwargs):
                self.calls.append(kwargs)
                return self

            def execute(self, num_retries):
                self.assert_retries = num_retries
                if len(self.calls) == 1:
                    return {"users": [{"id": "1"}], "nextPageToken": "next"}
                return {"users": [{"id": "2"}]}

        service = Service()
        self.assertEqual(fetch_users(service, "example.com"), [{"id": "1"}, {"id": "2"}])
        self.assertIsNone(service.calls[0]["pageToken"])
        self.assertEqual(service.calls[1]["pageToken"], "next")
        self.assertEqual(service.calls[0]["domain"], "example.com")
        self.assertEqual(service.assert_retries, 3)

    def test_profile_and_inactive_accounts(self):
        users = [
            {"id": "111521075025250201000", "primaryEmail": "MARES@example.com",
             "name": {"givenName": "Martin", "familyName": "Mares"}},
            {"id": "2", "primaryEmail": "suspended@example.com", "suspended": True},
            {"id": "3", "primaryEmail": "archived@example.com", "archived": True},
        ]
        rows = normalize_users(users, "EXAMPLE.com", active_only=True)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["google_id"], "111521075025250201000")
        self.assertEqual(rows[0]["first_name"], "Martin")
        self.assertEqual(sum(row["is_active"] for row in normalize_users(users, "example.com")), 1)

    def test_rejects_invalid_or_duplicate_records(self):
        user = {"id": "1", "primaryEmail": "a@example.com"}
        for records in [
            [user, user], [{"id": 123, "primaryEmail": "a@example.com"}],
            [{"id": "1", "primaryEmail": "a@other.com"}],
            [user, {"id": "2", "primaryEmail": "A@example.com"}],
        ]:
            with self.assertRaises(ValueError):
                normalize_users(records, "example.com")

    def test_comparison_and_safe_output(self):
        rows = normalize_users([{"id": "111521075025250201000", "primaryEmail": "a@example.com"}], "example.com")
        check_subject(rows, "A@example.com", "111521075025250201000")
        with self.assertRaises(ValueError):
            check_subject(rows, "a@example.com", "wrong")
        with self.assertRaises(ValueError):
            check_subject(rows, "missing@example.com", "111521075025250201000")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "users.json"
            write_export(output, rows, "json")
            self.assertEqual(json.loads(output.read_text())[0]["google_id"], "111521075025250201000")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                write_export(output, [], "json")
            csv_output = Path(directory) / "users.csv"
            write_export(csv_output, rows, "csv")
            self.assertIn("111521075025250201000,a@example.com,,,true,false,false", csv_output.read_text())


if __name__ == "__main__":
    unittest.main()
