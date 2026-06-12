#!/bin/sh
# Continuous auditor: keyless chain verification over the fs archive.
# Exits nonzero (container goes red) the moment the chain stops verifying.
set -eu
while [ ! -f /state/device.pub ]; do
    echo "verifier: waiting for enrollment..."
    sleep 2
done
echo "verifier: watching /archive"
while true; do
    if find /archive -name '*.sks' | grep -q .; then
        sks verify /archive --device-pub /state/device.pub || {
            echo "verifier: CHAIN VERIFICATION FAILED"
            exit 1
        }
    fi
    sleep 15
done
