#!/usr/bin/env bash
# Compatibility entry point for older local packaging commands.
set -euo pipefail
if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <platform> <release-dir> [binary-extension]" >&2
  exit 1
fi
case "$1" in
  linux-x86_64) target=x86_64-unknown-linux-musl ;;
  darwin-arm64) target=aarch64-apple-darwin ;;
  windows-x86_64) target=x86_64-pc-windows-msvc ;;
  *) echo "Unsupported platform: $1" >&2; exit 1 ;;
esac
expected="target/$target/release"
if [[ "${2%/}" != "$expected" || "${3:-}" != "$([[ "$target" == *-msvc ]] && echo .exe || true)" ]]; then
  echo "Use the default target directory: $expected (Windows extension: .exe)" >&2
  exit 1
fi
exec bash "$(dirname "$0")/release.sh" package "$target"
