#!/usr/bin/env python3
"""Fail on RustSec findings except the reviewed, public-key-only RSA advisory."""
import json
import subprocess
import sys


def main():
    result = subprocess.run(["cargo", "audit", "--json"], capture_output=True, text=True)
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(result.stderr, file=sys.stderr)
        return result.returncode or 1
    if result.returncode not in (0, 1):
        print(result.stderr, file=sys.stderr)
        return result.returncode
    if "database" not in report or "vulnerabilities" not in report:
        print("Incomplete cargo-audit report", file=sys.stderr)
        return 1
    findings = report.get("vulnerabilities", {}).get("list", [])
    if result.returncode == 1 and not findings and not any(report.get("warnings", {}).values()):
        print(result.stderr or "cargo-audit failed without findings", file=sys.stderr)
        return 1
    unexpected = []
    for finding in findings:
        package = finding.get("package", {})
        if (finding.get("advisory", {}).get("id"), package.get("name"), package.get("version")) == (
            "RUSTSEC-2023-0071", "rsa", "0.9.10"
        ):
            print("Reviewed exception: RUSTSEC-2023-0071 / rsa 0.9.10; see docs/SECURITY_UPGRADE.md.")
        else:
            unexpected.append(finding)
    warnings = report.get("warnings", {})
    if unexpected or any(warnings.values()):
        print(json.dumps({"vulnerabilities": unexpected, "warnings": warnings}, indent=2))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
