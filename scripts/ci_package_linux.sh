#!/usr/bin/env bash
set -euo pipefail

target="x86_64-unknown-linux-musl"

bash scripts/ci_package_binaries.sh "linux-x86_64" "target/${target}/release"
