#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <platform> <release-dir> [binary-extension]" >&2
  exit 1
fi

platform="$1"
release_dir="$2"
extension="${3:-}"
version="$(tr -d '[:space:]' < VERSION)"
package_dir="dist/simple-idm-${version}-${platform}"

mkdir -p "${package_dir}"

for bin in \
  simple-idm-server \
  simple-idm-ctl \
  simple-idm-oauth2-proxy \
  simple-idm-ssh-login \
  simple-idm-ssh-signer
do
  cp "${release_dir}/${bin}${extension}" "${package_dir}/"
done

tar -C dist -czf "dist/simple-idm-${version}-${platform}.tar.gz" "simple-idm-${version}-${platform}"
ls -lh "dist/simple-idm-${version}-${platform}.tar.gz"
