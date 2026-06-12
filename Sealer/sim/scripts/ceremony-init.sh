#!/bin/sh
# One-shot: generate the simulated community if absent.
set -eu
if [ -f /community/manifest.skm ]; then
    echo "ceremony: community already exists"
    exit 0
fi
sks ceremony-sim --community sim-community --window-secs 86400 --windows 540 \
    --threshold 3-of-5 --out /community
echo "ceremony: generated manifest + admin key (+ crk.secret, SIMULATION ONLY)"
