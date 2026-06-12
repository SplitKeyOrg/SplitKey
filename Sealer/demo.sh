#!/usr/bin/env bash
# SplitKey Sealer — Phase 1 demo (docs/10-roadmap.md):
# seal footage, tamper with it seven ways, watch `sks verify` name each
# attack, then perform a simulated quorum release of one day's window.
#
# Usage:  ./demo.sh            (builds with cargo if needed)
set -euo pipefail
cd "$(dirname "$0")"

SKS=${SKS:-target/debug/sks}
[ -x "$SKS" ] || cargo build -p sealer-cli
D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
must_fail() { if "$@"; then echo "UNEXPECTED PASS"; exit 1; fi; }

say "1. Key ceremony (simulated): 540 daily windows, 3-of-5 threshold"
$SKS ceremony-sim --community maplecourt --window-secs 86400 \
    --start-unix 1770000000 --windows 540 --threshold 3-of-5 --out "$D/ceremony"

say "2. Enroll a camera (device signing key)"
$SKS keygen-device --out "$D/dev"

say "3. 'Record' five clips and seal them (camera holds only PUBLIC keys)"
for i in 0 1 2 3 4; do head -c 100000 /dev/urandom > "$D/clip-$i.bin"; done
$SKS seal --manifest "$D/ceremony/manifest.skm" --admin-pub "$D/ceremony/admin.pub" \
    --device-key "$D/dev/device.key" --camera-id lobby-east --out "$D/sealed" \
    "$D"/clip-*.bin
cp -R "$D/sealed" "$D/pristine"

say "4. Verify: keyless — anyone can check, no one can watch"
$SKS verify "$D/sealed" --device-pub "$D/dev/device.pub"

say "ATTACK 1: flip one byte inside a segment body"
python3 - "$D/sealed/00000002.sks" <<'EOF'
import sys
p = sys.argv[1]; b = bytearray(open(p,'rb').read()); b[len(b)//2] ^= 0xFF
open(p,'wb').write(bytes(b))
EOF
must_fail $SKS verify "$D/sealed" --device-pub "$D/dev/device.pub"
cp "$D/pristine/00000002.sks" "$D/sealed/"

say "ATTACK 2: truncate a segment (drop the tail)"
python3 - "$D/sealed/00000004.sks" <<'EOF'
import sys
p = sys.argv[1]; b = open(p,'rb').read(); open(p,'wb').write(b[:-5000])
EOF
must_fail $SKS verify "$D/sealed" --device-pub "$D/dev/device.pub"
cp "$D/pristine/00000004.sks" "$D/sealed/"

say "ATTACK 3: silently delete the middle segment"
rm "$D/sealed/00000002.sks"
must_fail $SKS verify "$D/sealed" --device-pub "$D/dev/device.pub"
cp "$D/pristine/00000002.sks" "$D/sealed/"

say "ATTACK 4: edit a header (redate/renumber a segment)"
python3 - "$D/sealed/00000001.sks" <<'EOF'
import sys
p = sys.argv[1]; b = bytearray(open(p,'rb').read()); b[12] ^= 1
open(p,'wb').write(bytes(b))
EOF
must_fail $SKS verify "$D/sealed" --device-pub "$D/dev/device.pub"
cp "$D/pristine/00000001.sks" "$D/sealed/"

say "ATTACK 5: graft one segment's body onto another's header"
python3 - "$D/sealed" <<'EOF'
import sys, os
d = sys.argv[1]
def parts(p):
    b = open(p,'rb').read()
    hl = int.from_bytes(b[4:8],'big'); pos = 8+hl+64; start = pos
    while True:
        cl = int.from_bytes(b[pos:pos+4],'big'); pos += 4
        if cl == 0: break
        pos += cl
    return b, start, pos-4
b1, s1, e1 = parts(os.path.join(d,'00000001.sks'))
b3, s3, e3 = parts(os.path.join(d,'00000003.sks'))
open(os.path.join(d,'00000001.sks'),'wb').write(b1[:s1]+b3[s3:e3]+b1[e1:])
EOF
must_fail $SKS verify "$D/sealed" --device-pub "$D/dev/device.pub"
cp "$D/pristine/00000001.sks" "$D/sealed/"

say "ATTACK 6: replace a segment with a forgery from a different device"
$SKS keygen-device --out "$D/evil-dev"
head -c 100000 /dev/urandom > "$D/evil.bin"
$SKS seal --manifest "$D/ceremony/manifest.skm" --admin-pub "$D/ceremony/admin.pub" \
    --device-key "$D/evil-dev/device.key" --camera-id lobby-east --out "$D/evil-sealed" "$D/evil.bin"
cp "$D/evil-sealed/00000000.sks" "$D/sealed/00000002.sks"
must_fail $SKS verify "$D/sealed" --device-pub "$D/dev/device.pub"
cp "$D/pristine/00000002.sks" "$D/sealed/"

say "ATTACK 7: splice in footage from another camera (same device key)"
head -c 100000 /dev/urandom > "$D/other.bin"
for _ in 1 2 3; do
  $SKS seal --manifest "$D/ceremony/manifest.skm" --admin-pub "$D/ceremony/admin.pub" \
      --device-key "$D/dev/device.key" --camera-id garage-west --out "$D/other-sealed" "$D/other.bin"
done
cp "$D/other-sealed/00000002.sks" "$D/sealed/00000002.sks"
must_fail $SKS verify "$D/sealed" --device-pub "$D/dev/device.pub"
cp "$D/pristine/00000002.sks" "$D/sealed/"

say "5. Pristine chain still verifies"
$SKS verify "$D/sealed" --device-pub "$D/dev/device.pub"

say "6. Quorum release (simulated): derive ONE day's window key, unseal"
WINDOW=$($SKS inspect "$D/sealed/00000000.sks" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["window_index"])')
$SKS release --crk "$D/ceremony/crk.secret" --window "$WINDOW" --out "$D/wk.key"
$SKS unseal "$D/sealed/00000000.sks" --window-key "$D/wk.key" --out "$D/recovered.bin"
cmp "$D/clip-0.bin" "$D/recovered.bin" && echo "recovered plaintext matches original ✔"

say "7. ...and that key opens NOTHING outside its window"
$SKS release --crk "$D/ceremony/crk.secret" --window $((WINDOW+1)) --out "$D/wk-next.key"
must_fail $SKS unseal "$D/sealed/00000000.sks" --window-key "$D/wk-next.key" --out "$D/nope.bin"

printf '\n\033[1mDemo complete: tampering is detectable, footage is write-only, release is window-scoped.\033[0m\n'
