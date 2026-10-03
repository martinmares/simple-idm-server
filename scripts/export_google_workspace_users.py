#!/usr/bin/env python3
"""Read-only Workspace user export; never modifies Simple IDM or Google users."""

import argparse
import csv
import io
import json
import os
import sys
from pathlib import Path


SCOPES = ["https://www.googleapis.com/auth/admin.directory.user.readonly"]
FIELDS = ["google_id", "email", "first_name", "last_name", "is_active", "suspended", "archived"]


def api_error_hints(error):
    try:
        payload = json.loads(getattr(error, "content", b"{}"))
        detail = payload.get("error", {})
        entries = detail.get("errors", []) + detail.get("details", [])
        reasons = {entry.get("reason") for entry in entries if isinstance(entry, dict)}
        message = detail.get("message", "")
    except (ValueError, TypeError, AttributeError):
        return []
    hints = []
    explanations = {
        "accessNotConfigured": "Enable Admin SDK API in the project that owns this Desktop client.",
        "SERVICE_DISABLED": "Enable Admin SDK API in the project that owns this Desktop client.",
        "insufficientPermissions": "Grant the requested read-only scope during Google consent.",
        "ACCESS_TOKEN_SCOPE_INSUFFICIENT": "Grant the requested read-only scope during Google consent.",
        "forbidden": "Check the signed-in account's Workspace user-read privileges and API access policy.",
        "notAuthorized": "Check the signed-in account's Workspace user-read privileges and requested domain.",
        "domainPolicy": "Your Workspace policy blocks this API or OAuth application.",
        "rateLimitExceeded": "Google API rate limit reached; retry later.",
        "userRateLimitExceeded": "Google API user rate limit reached; retry later.",
    }
    for reason in sorted(reasons.intersection(explanations)):
        hints.append(f"Google reason: {reason}. {explanations[reason]}")
    # Only recognize known messages; never echo arbitrary OAuth response content.
    if isinstance(message, str) and "Not Authorized to access this resource/api" in message:
        hints.append("Google reports: Not authorized to access the Directory resource/API. Check Workspace admin privileges.")
    return hints


def fetch_users(service, domain):
    users = []
    page_token = None
    seen_tokens = set()
    while True:
        page = service.users().list(
            domain=domain,
            maxResults=500,
            orderBy="email",
            projection="basic",
            fields="nextPageToken,users(id,primaryEmail,name(givenName,familyName),suspended,archived)",
            pageToken=page_token,
        ).execute(num_retries=3)
        users.extend(page.get("users", []))
        print(f"Retrieved {len(users)} users...", file=sys.stderr)
        page_token = page.get("nextPageToken")
        if not page_token:
            break
        if page_token in seen_tokens:
            raise ValueError("Directory API returned a repeated pagination token")
        seen_tokens.add(page_token)
    return users


def normalize_users(users, domain, active_only=False):
    rows = []
    seen_ids = set()
    seen_emails = set()
    for user in users:
        google_id = user.get("id")
        email = user.get("primaryEmail", "")
        if not isinstance(google_id, str) or not google_id:
            raise ValueError("A Directory user has no string ID; export aborted")
        if not isinstance(email, str) or email.count("@") != 1:
            raise ValueError("A Directory user has no valid primary email; export aborted")
        if email.rsplit("@", 1)[1].casefold() != domain.casefold():
            raise ValueError("Directory API returned a user outside the requested domain")
        if google_id in seen_ids or email.casefold() in seen_emails:
            raise ValueError("Duplicate Directory ID or email; export aborted")
        seen_ids.add(google_id)
        seen_emails.add(email.casefold())
        suspended = bool(user.get("suspended", False))
        archived = bool(user.get("archived", False))
        active = not (suspended or archived)
        if active_only and not active:
            continue
        name = user.get("name", {})
        rows.append({
            "google_id": google_id,
            "email": email,
            "first_name": name.get("givenName", ""),
            "last_name": name.get("familyName", ""),
            "is_active": active,
            "suspended": suspended,
            "archived": archived,
        })
    return sorted(rows, key=lambda row: row["email"].casefold())


def check_subject(rows, email, expected_sub):
    matches = [row for row in rows if row["email"].casefold() == email.casefold()]
    if len(matches) != 1:
        raise ValueError("The comparison email was not found exactly once in the export")
    if matches[0]["google_id"] != expected_sub:
        raise ValueError("Directory ID does not match the expected OIDC sub; do not pre-link identities")
    print("Directory ID matches the supplied OIDC sub.", file=sys.stderr)


def write_export(path, rows, output_format):
    if output_format == "json":
        content = json.dumps(rows, ensure_ascii=False, indent=2) + "\n"
    else:
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: str(value).lower() if isinstance(value, bool) else value
                             for key, value in row.items()})
        content = buffer.getvalue()
    # Exclusive creation prevents overwriting existing exports or following symlinks.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as output:
        output.write(content)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", type=Path, required=True,
                        help="Google OAuth Desktop app credentials JSON (not the SSO Web client)")
    parser.add_argument("--domain", required=True, help="Primary email domain, e.g. datalite.cz")
    parser.add_argument("--output", type=Path, required=True, help="New CSV/JSON file; parent must exist")
    parser.add_argument("--format", choices=["csv", "json"], default="csv")
    parser.add_argument("--admin", help="Optional Google admin account login hint")
    parser.add_argument("--active-only", action="store_true", help="Exclude suspended and archived accounts")
    parser.add_argument("--check-email", help="Already linked IDM user's email for ID comparison")
    parser.add_argument("--expected-sub", help="That user's Google sub displayed in Simple IDM")
    args = parser.parse_args(argv)
    args.domain = args.domain.strip().lower()
    if not args.domain or any(char.isspace() for char in args.domain) or any(char in args.domain for char in "@/:"):
        parser.error("--domain must be a domain name, without @ or a URL")
    if bool(args.check_email) != bool(args.expected_sub):
        parser.error("--check-email and --expected-sub must be supplied together")
    if args.output.exists() or args.output.is_symlink():
        parser.error("Output already exists; choose a new filename")
    if not args.output.parent.is_dir():
        parser.error("Output parent directory does not exist")
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
        from google_auth_httplib2 import AuthorizedHttp
        from googleapiclient.discovery import build
        import httplib2
    except ImportError:
        print("Install dependencies: python3 -m pip install -r scripts/requirements-google-workspace-export.txt", file=sys.stderr)
        return 1
    try:
        with args.credentials.open(encoding="utf-8") as file:
            config = json.load(file)
        if "installed" not in config:
            raise ValueError("Credentials must be for an OAuth Desktop app, not a Web app or service account")
        flow = InstalledAppFlow.from_client_config(config, SCOPES)
        print("Opening Google admin sign-in in your browser (timeout: 180 seconds)...", file=sys.stderr)
        auth_options = {"access_type": "online", "prompt": "select_account"}
        if args.admin:
            auth_options["login_hint"] = args.admin
        credentials = flow.run_local_server(
            host="localhost", bind_addr="127.0.0.1", port=0,
            timeout_seconds=180, **auth_options,
        )
        http = AuthorizedHttp(credentials, http=httplib2.Http(timeout=30))
        with build("admin", "directory_v1", http=http, cache_discovery=False) as service:
            users = fetch_users(service, args.domain)
        rows = normalize_users(users, args.domain, args.active_only)
        if args.check_email:
            check_subject(rows, args.check_email, args.expected_sub)
        write_export(args.output, rows, args.format)
        print(f"Exported {len(rows)} users to {args.output}. No identities were imported.")
        return 0
    except Exception as error:
        # Avoid printing OAuth responses, credentials or tokens in diagnostics.
        if isinstance(error, (OSError, ValueError)):
            print(f"Export failed: {error}", file=sys.stderr)
        else:
            status = getattr(getattr(error, "resp", None), "status", None)
            print(f"Export failed: {type(error).__name__}" + (f" (HTTP {status})" if status else ""), file=sys.stderr)
            for hint in api_error_hints(error):
                print(hint, file=sys.stderr)
            print("Check API enablement, admin permissions, consent and network connectivity.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
