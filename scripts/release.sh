#!/usr/bin/env bash
# macOS can still have Python 3.9 as python3; select an installed Python 3.11+.
set -euo pipefail
for interpreter in "${RELEASE_PYTHON:-python3}" python3.14 python3.13 python3.12 python3.11; do
  if command -v "$interpreter" >/dev/null 2>&1 && "$interpreter" -c 'import tomllib' >/dev/null 2>&1; then
    exec "$interpreter" "$(dirname "$0")/release.py" "$@"
  fi
done
echo 'Release commands require Python 3.11+ (set RELEASE_PYTHON if needed)' >&2
exit 1
