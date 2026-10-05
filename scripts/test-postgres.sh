#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
compose=(docker compose -f docker-compose.test.yml -p "simple-idm-tests-$$")
cleanup() {
    "${compose[@]}" down --volumes --remove-orphans
}
trap cleanup EXIT

"${compose[@]}" up -d --wait --wait-timeout 60
address=$("${compose[@]}" port postgres 5432)
export DATABASE_URL="postgres://postgres:local-test-only@${address}/simple_idm_test"
export GOOGLE_IMPORT_TEST_DATABASE_URL="$DATABASE_URL"
export DOMAIN_POLICY_TEST_DATABASE_URL="$DATABASE_URL"
export DEVICE_SSO_TEST_DATABASE_URL="$DATABASE_URL"
export SQLX_OFFLINE=true

cargo sqlx migrate run --source migrations
cargo test --locked -p simple-idm-core --lib -- --ignored --test-threads=1
