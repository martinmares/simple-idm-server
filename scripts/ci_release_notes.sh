#!/usr/bin/env bash
set -euo pipefail

version="$(tr -d '[:space:]' < VERSION)"
if [[ -z "${version}" ]]; then
  echo "VERSION is empty" >&2
  exit 1
fi

tag="v${version}"
mkdir -p dist

git fetch --tags --force >/dev/null 2>&1 || true

previous_tag="$(
  git tag --list 'v*' --sort=-version:refname \
    | grep -v "^${tag}$" \
    | head -n 1 || true
)"

range=""
if [[ -n "${previous_tag}" ]]; then
  range="${previous_tag}..HEAD"
else
  range="HEAD"
fi

release_date="$(date -u +%Y-%m-%d)"

{
  echo "## ${tag} - ${release_date}"
  echo
  if [[ -n "${previous_tag}" ]]; then
    echo "Changes since ${previous_tag}:"
  else
    echo "Initial release notes:"
  fi
  echo
  git log --no-merges --pretty=format:'- %s (%h)' "${range}" || true
  echo
} > dist/release_notes.md

{
  echo "# Changelog"
  echo
  cat dist/release_notes.md
  echo
  if [[ -f CHANGELOG.md ]]; then
    sed '1{/^# Changelog$/d;}' CHANGELOG.md | sed '/^All notable release changes are appended/d'
  fi
} > dist/CHANGELOG.generated.md

{
  echo "RELEASE_VERSION=${version}"
  echo "RELEASE_TAG=${tag}"
  echo "PREVIOUS_RELEASE_TAG=${previous_tag}"
} > dist/release.env

cat dist/release_notes.md
