#!/usr/bin/env bash
set -euo pipefail
exec bash "$(dirname "$0")/release.sh" package x86_64-unknown-linux-musl
