set shell := ["zsh", "-cu"]

release_target_linux := "x86_64-unknown-linux-musl"
release_target_windows := "x86_64-pc-windows-msvc"

release-linux:
    cargo zigbuild --release --workspace --target {{ release_target_linux }}

release-linux-server:
    cargo zigbuild --release --bin simple-idm-server --target {{ release_target_linux }}

release-linux-ctl:
    cargo zigbuild --release --bin simple-idm-ctl --target {{ release_target_linux }}

release-linux-oauth2-proxy:
    cargo zigbuild --release --bin simple-idm-oauth2-proxy --target {{ release_target_linux }}

release-linux-oidc-metadata-proxy:
    cargo zigbuild --release --bin simple-idm-oidc-metadata-proxy --target {{ release_target_linux }}

release-linux-token-proxy:
    cargo zigbuild --release --bin simple-idm-token-proxy --target {{ release_target_linux }}

release-linux-ad-proxy:
    cargo zigbuild --release --bin simple-idm-ad-proxy --target {{ release_target_linux }}

release-linux-ssh-login:
    cargo zigbuild --release --bin simple-idm-ssh-login --target {{ release_target_linux }}

release-linux-ssh-signer:
    cargo zigbuild --release --bin simple-idm-ssh-signer --target {{ release_target_linux }}

release-linux-bins: release-linux-server release-linux-ctl release-linux-oauth2-proxy release-linux-oidc-metadata-proxy release-linux-token-proxy release-linux-ad-proxy release-linux-ssh-login release-linux-ssh-signer

image-token-proxy tag="simple-idm-token-proxy:local":
    docker build -f Dockerfile-token-proxy -t {{ tag }} .

release-macos:
    cargo build --release --workspace

reelase-macos: release-macos

release-windows:
    cargo xwin build --release --workspace --target {{ release_target_windows }}

release-all: release-linux release-macos release-windows
