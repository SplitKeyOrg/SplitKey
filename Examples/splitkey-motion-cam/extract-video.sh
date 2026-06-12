#!/usr/bin/env bash
# Extract (decrypt) sealed footage from the archive — SIM shortcut using the
# on-box crk.secret in place of a real keyholder quorum release.
#
#   ./extract-video.sh [SUBPATH]
#
# SUBPATH is optional, relative to ./archive (a sub-tree or a single .sks).
# Default: the whole archive. Decrypted clips land in ./extracted/<seq>.mkv.
#
# How it works (mirrors `demo-usbcam.sh` step 5, per-segment):
#   sks inspect  → window_index (and skip chain-event records)
#   sks release  → derive that window's key from crk.secret  (cached per window)
#   sks unseal   → .sks + window key → plaintext .mkv
set -euo pipefail
cd "$(dirname "$0")"

SUB="${1:-.}"
mkdir -p extracted

docker compose run --rm -T \
  -v "$PWD/extracted:/out:z" \
  -e SUB="$SUB" \
  --entrypoint bash sealer -c '
    set -euo pipefail
    root="/archive/$SUB"
    [ -e "$root" ] || { echo "not found in archive: $SUB" >&2; exit 1; }

    n=0
    for f in $(find "$root" -name "*.sks" | sort); do
      meta=$(sks inspect "$f" --json)
      # skip hash-chain bookkeeping records — only footage has a container
      echo "$meta" | grep -q "\"kind\": \"chain-event\"" && continue

      win=$(echo "$meta" | grep "\"window_index\"" | grep -oE "[0-9]+" | head -1)
      wk="/tmp/wk-$win.key"
      [ -f "$wk" ] || sks release --crk /config/ceremony/crk.secret --window "$win" --out "$wk"

      base=$(basename "$f" .sks)
      sks unseal "$f" --window-key "$wk" --out "/out/$base.mkv"
      echo "  $base  (window $win)"
      n=$((n+1))
    done
    echo "extracted $n footage segment(s) -> ./extracted/"
'
echo
echo "Play with:  ffplay extracted/<seq>.mkv   (or open in VLC)"
