#!/usr/bin/env bash
# Supervises motion + sealerd as one unit. motion writes event clips to a
# tmpfs (the container's /dev/shm — RAM only); sealerd watch-mode seals them
# and deletes the plaintext. If either dies, tear the container down so the
# compose restart policy brings the whole pipeline back cleanly.
set -euo pipefail

CLIPS=/dev/shm/splitkey-clips
mkdir -p "$CLIPS"

if [ ! -f /config/state/device.key ]; then
  echo "FATAL: device not enrolled (/config/state/device.key missing)." >&2
  echo "Run the one-time init first:  docker compose run --rm init" >&2
  exit 1
fi

MOTION="" ; SEALERD=""
shutdown() {
  echo "entrypoint: shutting down…" >&2
  [ -n "$SEALERD" ] && kill -INT  "$SEALERD" 2>/dev/null || true
  [ -n "$MOTION"  ] && kill -TERM "$MOTION"  2>/dev/null || true
}
trap shutdown TERM INT

# motion -n = foreground (no daemonize); logs to stderr.
motion -n -c /config/motion.conf &
MOTION=$!

sealerd --config /config/sealer.toml &
SEALERD=$!

# Whichever exits first, tear the rest down and fail so we get restarted.
wait -n
echo "entrypoint: a supervised process exited — tearing down." >&2
shutdown
wait || true
exit 1
