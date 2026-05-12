set shell := ["zsh", "-cu"]

release_target_linux := "x86_64-unknown-linux-musl"
release_target_windows := "x86_64-pc-windows-msvc"

release-linux:
    cargo zigbuild --release --workspace --target {{ release_target_linux }}

release-macos:
    cargo build --release --workspace

reelase-macos: release-macos

release-windows:
    cargo xwin build --release --workspace --target {{ release_target_windows }}

release-all: release-linux release-macos release-windows
