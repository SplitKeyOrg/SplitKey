#!/usr/bin/env bash
# SplitKey Sealer — live USB camera demo (macOS, pipe mode).
#
# USB cam → ffmpeg (avfoundation, hardware H.264) → pipe → sealerd
# Plaintext footage exists ONLY in RAM; sealed .sks segments land in a
# local archive, then we verify the chain and perform a simulated quorum
# release of the current day's window to play the footage back.
#
# Env overrides:
#   CAM_INDEX (default 0)        avfoundation device index
#   CAM_SIZE  (default 1920x1080)
#   CAM_FPS   (default 30.000030 — many UVC cams use this exact rate;
#              run `ffmpeg -f avfoundation -framerate 1000 -i "N:none"`
#              to list your camera's modes)
#   DURATION  (default 20)       seconds to record
set -euo pipefail
cd "$(dirname "$0")"

CAM_INDEX=${CAM_INDEX:-0}
CAM_SIZE=${CAM_SIZE:-1920x1080}
CAM_FPS=${CAM_FPS:-30.000030}
DURATION=${DURATION:-20}

# Pick up a rustup/cargo install that login-only shells put on PATH.
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

command -v ffmpeg >/dev/null || { echo "ffmpeg required: brew install ffmpeg"; exit 1; }
command -v cargo  >/dev/null || { echo "cargo required: install Rust from https://rustup.rs"; exit 1; }
echo "Building sealer-cli + sealerd (release)…"
cargo build --release -p sealer-cli -p sealerd
BIN=target/release

VCODEC="h264_videotoolbox -realtime true"
ffmpeg -hide_banner -encoders 2>/dev/null | grep -q h264_videotoolbox || VCODEC="libx264 -preset veryfast -tune zerolatency"

#D=$(mktemp -d)
#trap 'rm -rf "$D"' EXIT
D=./tmp
say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

say "1. Key ceremony (simulated): daily windows, 3-of-5"
$BIN/sks ceremony-sim --community usbcam-demo --window-secs 86400 --windows 540 \
    --threshold 3-of-5 --out "$D/ceremony"

say "2. Configure + enroll this MacBook as a camera"
cat > "$D/sealer.toml" <<EOF
[community]
id = "usbcam-demo"
manifest = "$D/ceremony/manifest.skm"
admin_pubkey = "$D/ceremony/admin.pub"

[device]
camera_id = "macbook-usbcam"
state_dir = "$D/state"

[source]
mode = "pipe"

[source.pipe]
format  = "mpegts"
command = "ffmpeg -hide_banner -loglevel error -f avfoundation -framerate $CAM_FPS -video_size $CAM_SIZE -pixel_format nv12 -i ${CAM_INDEX}:none -c:v $VCODEC -g 30 -f mpegts -"

[sealing]
segment_max_secs  = 5
segment_max_bytes = "16MB"

[chain]
heartbeat_secs = 0

[[storage]]
type = "fs"
path = "$D/archive"
EOF
$BIN/sealer --config "$D/sealer.toml" enroll

say "3. Recording ${DURATION}s from the USB camera — plaintext never touches disk"
$BIN/sealerd --config "$D/sealer.toml" &
SEALERD=$!
sleep "$DURATION"
kill -INT $SEALERD
wait $SEALERD || true

say "4. Keyless verification of the sealed archive"
$BIN/sks verify "$D/archive" --device-pub "$D/state/device.pub"

say "5. Simulated quorum release of today's window → playback"
SEG=$(find "$D/archive" -name '*.sks' | sort | sed -n 2p)   # first footage segment (0 is the boot event)
WINDOW=$($BIN/sks inspect "$SEG" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["window_index"])')
$BIN/sks release --crk "$D/ceremony/crk.secret" --window "$WINDOW" --out "$D/wk.key"

OUT=/tmp/splitkey-released
mkdir -p "$OUT"
i=0
for seg in $(find "$D/archive" -name '*.sks' | sort); do
    # skip chain events (tiny CBOR bodies); footage is the .ts segments
    kind=$($BIN/sks inspect "$seg" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["content_meta"].get("kind",""))')
    [ "$kind" = "chain-event" ] && continue
    $BIN/sks unseal "$seg" --window-key "$D/wk.key" --out "$OUT/part-$(printf %03d $i).ts" 2>/dev/null
    i=$((i+1))
done
cat "$OUT"/part-*.ts > "$OUT/released.ts"
echo
echo "Released $i sealed segments → $OUT/released.ts"
echo "Watch it:  ffplay $OUT/released.ts    (or open with VLC)"
