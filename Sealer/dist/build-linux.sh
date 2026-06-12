#!/usr/bin/env bash
# Build a fully static x86_64 Linux release of the Sealer (musl), in Docker,
# and pack a deployable tarball. Works from any host with Docker (on Apple
# Silicon this runs under amd64 emulation — slow but correct).
set -euo pipefail
cd "$(dirname "$0")/.."

docker run --rm --platform linux/amd64 -v "$PWD":/src -w /src rust:1-bookworm sh -c '
    set -e
    apt-get update -qq && apt-get install -y -qq musl-tools >/dev/null
    rustup target add x86_64-unknown-linux-musl
    CC_x86_64_unknown_linux_musl=musl-gcc \
        cargo build --release --target x86_64-unknown-linux-musl \
        -p sealer-cli -p sealerd --target-dir target/linux
'

OUT=dist/splitkey-sealer-x86_64-linux
rm -rf "$OUT" && mkdir -p "$OUT"
cp target/linux/x86_64-unknown-linux-musl/release/{sks,sealer,sealerd} "$OUT/"
cp dist/systemd/sealerd.service "$OUT/"
cp dist/sealer.example.toml "$OUT/"
cp dist/INSTALL.md "$OUT/"
tar -czf "$OUT.tar.gz" -C dist "$(basename "$OUT")"
echo "built: $OUT.tar.gz"
file "$OUT/sealerd"
