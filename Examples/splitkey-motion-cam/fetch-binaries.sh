#!/usr/bin/env bash
# Populate ./bin/ with the static x86_64-linux sealer binaries.
#
# These are deliberately NOT committed — during development every rebuild
# would bloat git history with a new 14 MB set. Run this once after building
# them (and again whenever you rebuild). Once GitHub release builds exist,
# this will fetch a pinned release instead of the local build.
set -euo pipefail
cd "$(dirname "$0")"

# Produced by Sealer/dist/build-linux.sh (musl static-pie).
SRC="../../Sealer/dist/splitkey-sealer-x86_64-linux"

if [ ! -x "$SRC/sealerd" ]; then
  cat >&2 <<EOF
error: built binaries not found at $SRC

Build them first (static x86_64-linux, runs in Docker):
    ( cd ../../Sealer && ./dist/build-linux.sh )

Then re-run ./fetch-binaries.sh
EOF
  exit 1
fi

mkdir -p bin
install -m755 "$SRC"/sealerd "$SRC"/sealer "$SRC"/sks bin/
echo "populated ./bin/ from $SRC"
ls -l bin/
