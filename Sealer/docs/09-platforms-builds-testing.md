# 09 — Platforms, Builds & Testing

## Target matrix

| Tier | Target | Triple | Notes |
|------|--------|--------|-------|
| 1 | Raspberry Pi Zero 2 W (demo/reference) | `aarch64-unknown-linux-musl` | 512 MB RAM. AES crypto-extension availability unverified on this SKU — decided: leave the AESGCM suite **untested on this board** and mark it as such (QEMU coverage later); XChaCha default unaffected. Camera Module 3 (IMX708) via `rpicam-vid` pipe. |
| 1 | Generic Linux x86_64 (NVR sidecar, dev) | `x86_64-unknown-linux-musl` | AES-NI → AESGCM suite viable. |
| 1 | Luckfox Pico / Pico Pro / Max (RV1106/RV1103) | `armv7-unknown-linux-musleabihf` — confirmed: musl static binaries run out-of-the-box on the stock Luckfox Buildroot image | 64–256 MB DDR, Cortex-A7 + HW H.264/H.265 venc. The real-world cheap-camera reference. Memory budget: Sealer ≤ 32 MB RSS. |
| 2 | Windows x86_64 (sidecar for Blue Iris-style setups) | `x86_64-pc-windows-msvc` | Watcher mode + service wrapper. |
| 3 | OpenIPC firmwares (hisi/goke/ssc SoCs) | various musl | Postponed (decided: low priority). Ship as an OpenIPC package; pipe from majestic. |
| 3 | Axis ACAP, other vendor SDKs | per-SDK | Inline library form. |
| 3 | ESP32(-S3/-P4) | `xtensa`/`riscv32` no_std | Exploratory: only `sks-format` + `sealer-crypto` cores + a bespoke shim. RAM is the constraint (chunked sealing in ≤ 100 KB buffers); honest assessment doc before committing. |
| dev | macOS (arm64) | `aarch64-apple-darwin` | Development convenience only. |

Static musl builds everywhere on Linux: no glibc-version roulette on random
camera firmware. Binary size target: < 8 MB stripped for the
watcher+s3 feature set (feature gates per [00-architecture.md](00-architecture.md)).

## Build & release pipeline

- `cross` (or cargo-zigbuild) for cross-compilation; CI matrix builds every
  tier-1/2 target on each PR.
- **Reproducible builds** are a stated goal from day one (locked toolchain,
  `--remap-path-prefix`, vendored deps): anyone can rebuild the binary and
  match the hash — feeds the firmware-trust story
  ([04](04-tamper-evidence.md), [12](12-ideas-for-splitkey.md)).
- Release artifacts: per-target tarballs + `.deb`/`.ipk`, systemd unit,
  OpenIPC package manifest; all signed (minisign/Ed25519) with hashes in a
  signed RELEASES file.
- MSRV pinned; `cargo-deny` for license/advisory gating; `cargo-audit` in CI.

## Docker simulation environment (the primary dev loop)

`docker compose up` brings up a synthetic community — per the plan's "docker
container we can run simulations in":

```
┌─ camera-sim ──────────┐   ┌─ sealerd ───────┐   ┌─ minio (or rustfs) ─┐
│ ffmpeg testsrc → mp4  │──▶│ watcher mode    │──▶│ S3 + object lock    │
│ segments into /clips  │   │                 │   └─────────────────────┘
└───────────────────────┘   │                 │   ┌─ catalog-stub ──────┐
┌─ camera-sim-2 ────────┐   │ pipe mode       │──▶│ tiny REST recorder  │
│ ffmpeg → h264 ES pipe │──▶│                 │   └─────────────────────┘
└───────────────────────┘   └─────────────────┘   ┌─ verifier ──────────┐
┌─ rtsp-sim ────────────┐                         │ sks verify loop     │
│ mediamtx + ffmpeg     │──▶ (rtsp mode)          │ (must stay green)   │
└───────────────────────┘                         └─────────────────────┘
```

Plus a `ceremony-sim` one-shot container that generates a test community
(CRK → manifest + shares) and a `release-sim` that reconstructs a window key
from test shares and decrypts — proving the full loop end-to-end **before
any real Keyholder app exists**.

Chaos knobs (env vars): kill -9 the sealer mid-segment, drop the network,
fill the spool disk, skew the clock, corrupt random bytes in stored
segments, delete stored segments. The verifier and the test assertions must
catch every injected fault — this *is* the product's value proposition, so
fault-injection tests are tier-0, not nice-to-have.

## Test plan layers

1. **Unit**: format round-trip, chain logic, window arithmetic (DST
   irrelevance, epoch boundaries, leap seconds don't matter for
   `floor(unix/3600)` but write the test anyway), config validation.
2. **Property/fuzz**: `cargo-fuzz` on `sks-format` parser, NAL scanner, QR
   decoder, manifest parser (all parse hostile input); proptest on
   chain reconstruction (any subset/permutation of segments → verifier
   verdict matches ground truth).
3. **Crypto vectors**: published test vectors for `.sks` (known key, known
   plaintext → byte-exact output with pinned RNG) so independent
   implementations can interop; cross-check secretstream against libsodium
   reference.
4. **Integration**: the compose environment above, scripted scenarios
   (happy path, every chaos knob, manifest rotation mid-run, window
   boundary crossing, reboot recovery).
5. **Hardware-in-loop**: Pi Zero 2 W lab rig — 72 h soak, thermal, RAM
   ceiling, SD wear accounting (smartctl/blkdiscard stats), real power-pull
   tests (the only honest crash test).
6. **Performance gates**: sustained seal throughput ≥ 2× bitrate on RV1106-
   class CPU (XChaCha20 on Cortex-A7 ≈ 100+ MB/s — verify early, it sizes
   everything); RSS ceiling per target; spool drain rate.

## Telemetry for tests and ops

`/metrics` Prometheus endpoint (segments sealed/uploaded, spool depth,
chain head age, source liveness, clock confidence) — the same signals the
soak rig, the compose verifier, and real deployments all watch.
