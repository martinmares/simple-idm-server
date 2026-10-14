set shell := ["zsh", "-cu"]

release_target_linux := "x86_64-unknown-linux-musl"

# Install all native binaries, replacing previous local versions.
install:
    #!/usr/bin/env zsh
    set -eu
    for crate in simple-idm-server simple-idm-ctl simple-idm-oauth2-proxy \
        simple-idm-oidc-metadata-proxy simple-idm-token-proxy simple-idm-ad-proxy \
        simple-idm-ssh-login simple-idm-ssh-signer simple-idm-bastion; do
        cargo install --path "crates/$crate" --root "$HOME/.cargo" --target-dir target --force
    done

release-linux:
    cargo zigbuild --locked --release --workspace --target {{ release_target_linux }}

release-linux-server:
    cargo zigbuild --locked --release --bin simple-idm-server --target {{ release_target_linux }}

release-linux-ctl:
    cargo zigbuild --locked --release --bin simple-idm-ctl --target {{ release_target_linux }}

release-linux-oauth2-proxy:
    cargo zigbuild --locked --release --bin simple-idm-oauth2-proxy --target {{ release_target_linux }}

release-linux-oidc-metadata-proxy:
    cargo zigbuild --locked --release --bin simple-idm-oidc-metadata-proxy --target {{ release_target_linux }}

release-linux-token-proxy:
    cargo zigbuild --locked --release --bin simple-idm-token-proxy --target {{ release_target_linux }}

release-linux-ad-proxy:
    cargo zigbuild --locked --release --bin simple-idm-ad-proxy --target {{ release_target_linux }}

release-linux-ssh-login:
    cargo zigbuild --locked --release --bin simple-idm-ssh-login --target {{ release_target_linux }}

release-linux-ssh-signer:
    cargo zigbuild --locked --release --bin simple-idm-ssh-signer --target {{ release_target_linux }}

release-linux-bastion:
    cargo zigbuild --locked --release --bin simple-idm-bastion --target {{ release_target_linux }}

release-linux-bins: release-linux-server release-linux-ctl release-linux-oauth2-proxy release-linux-oidc-metadata-proxy release-linux-token-proxy release-linux-ad-proxy release-linux-ssh-login release-linux-ssh-signer release-linux-bastion

image-token-proxy tag="simple-idm-token-proxy:local":
    docker build -f Dockerfile-token-proxy -t {{ tag }} .

release-macos:
    cargo build --locked --release --workspace

reelase-macos: release-macos

# Build both Unix variants locally; Windows is built by GitHub Actions.
release-all: release-linux release-macos

# Update VERSION, the shared Cargo version and Cargo.lock together.
release-version version:
    bash scripts/release.sh bump {{ quote(version) }}

# Check all crate versions before building or releasing.
check-version:
    bash scripts/release.sh check

# Same check script and audit tool version as GitHub CI.
ci-check:
    bash scripts/ci-check.sh

# Run database integration tests locally in an isolated Compose project.
test-postgres:
    bash scripts/test-postgres.sh
