#!/usr/bin/env bash
# Full SplitKey release-loop drill, end to end on one machine:
#
#   ceremony (booklets, CRK destroyed)
#     → camera enrolls + seals into MinIO (S3, watcher mode)
#       → three keyholders combine paper shares
#         → keeper releases exactly one window, verified, playback-ready
#
# Needs: docker, rust toolchain. Self-contained (own MinIO on port 19002);
# safe to run alongside the Sealer/sim compose.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

PORT=19002
NET=skdrill
MINIO=skdrill-minio
WORK=$(mktemp -d /tmp/splitkey-drill.XXXXXX)

cleanup() {
    docker rm -f "$MINIO" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    [ -n "${SEALERD_PID:-}" ] && kill "$SEALERD_PID" 2>/dev/null || true
}
trap cleanup EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "build (sealerd + ceremony + keeper)"
(cd Sealer && cargo build -q -p sealerd)
cargo build -q -p ceremony-cli -p keeper-cli
SEALERD=Sealer/target/debug/sealerd
SEALER=Sealer/target/debug/sealer
CEREMONY=target/debug/ceremony
KEEPER=target/debug/keeper

step "MinIO up (S3 on 127.0.0.1:$PORT)"
docker network create "$NET" >/dev/null 2>&1 || true
docker run -d --rm --name "$MINIO" --network "$NET" -p "127.0.0.1:$PORT:9000" \
    minio/minio server /data >/dev/null
docker run --rm --network "$NET" --entrypoint sh minio/mc -c \
    "until mc alias set m http://$MINIO:9000 minioadmin minioadmin >/dev/null 2>&1; do sleep 1; done && mc mb m/footage" \
    >/dev/null
echo "bucket 'footage' ready"

step "key ceremony: 3-of-5, booklets printed, CRK destroyed"
START=$(date -u -v-2d +%F 2>/dev/null || date -u -d "2 days ago" +%F)
"$CEREMONY" new --community drill --epoch 1 --start "$START" --windows 10 \
    --threshold 3-of-5 \
    --keyholder alice --keyholder bob --keyholder carol \
    --keyholder dave --keyholder erin \
    --out "$WORK/epoch1"
head -5 "$WORK/epoch1/booklets/alice.txt"; echo "..."

step "camera: enroll + seal three clips into the bucket"
mkdir -p "$WORK/ingest"
cat > "$WORK/sealer.toml" <<EOF
[community]
id           = "drill"
manifest     = "$WORK/epoch1/manifest.skm"
admin_pubkey = "$WORK/epoch1/admin.pub"

[device]
camera_id = "drill-cam"
state_dir = "$WORK/state"

[source]
mode = "watch"

[source.watch]
path        = "$WORK/ingest"
ready_glob  = "*.ts"
stable_secs = 1
poll_ms     = 250
after_seal  = "delete"

[[storage]]
type       = "s3"
endpoint   = "http://127.0.0.1:$PORT"
bucket     = "footage"
credential = "env:SEALER_S3_CRED"
EOF
export SEALER_S3_CRED="minioadmin:minioadmin"
"$SEALER" --config "$WORK/sealer.toml" enroll
"$SEALERD" --config "$WORK/sealer.toml" &
SEALERD_PID=$!
sleep 1
for i in 1 2 3; do printf 'DRILL-FOOTAGE-%s|' "$i" > "$WORK/ingest/clip$i.ts"; done

export AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin
WINDOW=$(( $(date -u +%s) / 86400 ))
LISTARGS=(--manifest "$WORK/epoch1/manifest.skm" --admin-pub "$WORK/epoch1/admin.pub")
for _ in $(seq 1 30); do
    "$KEEPER" list "${LISTARGS[@]}" --store s3://footage --endpoint "http://127.0.0.1:$PORT" \
        2>/dev/null | grep -q "4 records" && break
    sleep 1
done
kill "$SEALERD_PID" && wait "$SEALERD_PID" 2>/dev/null || true
SEALERD_PID=""

step "anyone can browse existence (no key needed)"
"$KEEPER" list "${LISTARGS[@]}" --store s3://footage --endpoint "http://127.0.0.1:$PORT"

step "keyholders alice + carol + erin combine today's shares"
"$KEEPER" combine "${LISTARGS[@]}" --window "$WINDOW" \
    --out "$WORK/window.key" \
    "$WORK/epoch1/booklets/alice.txt" \
    "$WORK/epoch1/booklets/carol.txt" \
    "$WORK/epoch1/booklets/erin.txt"

step "release window $WINDOW from the bucket"
"$KEEPER" release "${LISTARGS[@]}" --window "$WINDOW" \
    --window-key "$WORK/window.key" \
    --store s3://footage --endpoint "http://127.0.0.1:$PORT" \
    --device-pub "$WORK/state/device.pub" \
    --out "$WORK/released"

step "released plaintext"
cat "$WORK/released/drill-cam/footage.ts"; echo
echo
echo "report: $WORK/released/report.txt"
echo "drill artifacts kept in: $WORK"
