#!/usr/bin/env bash
# Shared by GitHub CI and `just ci-check`; stop on the first failed check.
set -euo pipefail
cd "$(dirname "$0")/.."
export SQLX_OFFLINE=true

# Match release.sh: macOS may still expose Python 3.9 as python3.
ci_python=''
for interpreter in "${RELEASE_PYTHON:-python3}" python3.14 python3.13 python3.12 python3.11; do
    if command -v "$interpreter" >/dev/null 2>&1 && "$interpreter" -c 'import tomllib' >/dev/null 2>&1; then
        ci_python="$interpreter"
        break
    fi
done
if [[ -z "$ci_python" ]]; then
    echo 'CI checks require Python 3.11+ (set RELEASE_PYTHON if needed)' >&2
    exit 1
fi

audit_version=$(cargo audit --version) || {
    echo 'Install the CI audit tool: cargo install cargo-audit --locked --version 0.22.2' >&2
    exit 1
}
if [[ "${audit_version##* }" != "0.22.2" ]]; then
    echo 'CI requires cargo-audit 0.22.2. Run: cargo install cargo-audit --locked --version 0.22.2 --force' >&2
    exit 1
fi

echo 'Checking shared version'
"$ci_python" scripts/release.py check
echo 'Testing release and audit policy scripts'
"$ci_python" -m unittest discover -s scripts -p 'test_*.py'
echo 'Checking formatting'
cargo fmt --all -- --check
echo 'Testing workspace and all targets'
cargo test --locked --workspace --all-targets
echo 'Auditing dependencies with reviewed exceptions'
"$ci_python" scripts/audit-dependencies.py
