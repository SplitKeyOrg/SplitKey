#!/bin/sh
# Wait for ceremony artifacts, enroll once, then run the daemon.
set -eu
while [ ! -f /community/manifest.skm ]; do
    echo "sealerd: waiting for ceremony..."
    sleep 1
done
if [ ! -f /state/device.key ]; then
    sealer --config /etc/splitkey/sealer.toml enroll
fi
exec sealerd --config /etc/splitkey/sealer.toml
