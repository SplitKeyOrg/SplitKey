#!/bin/sh
# Synthetic camera: writes a ~200 KB "clip" every INTERVAL seconds.
# Writes to a dot-file first, then renames — like a real recorder.
set -eu
INTERVAL="${INTERVAL:-10}"
echo "camera-sim: one clip every ${INTERVAL}s"
while true; do
    name="clip-$(date +%s).mp4"
    dd if=/dev/urandom of="/clips/.$name" bs=1024 count=200 2>/dev/null
    mv "/clips/.$name" "/clips/$name"
    echo "camera-sim: recorded $name"
    sleep "$INTERVAL"
done
