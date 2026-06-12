# 10 — Implementation Roadmap

Phases are cumulative; each ends with something demonstrable. Estimates
assume one focused developer; adjust freely.

## Phase 0 — Decisions & spikes ✅ (mostly complete)

The blocking open questions are **decided** — see
[11-open-questions.md](11-open-questions.md): 24 h windows / paper shares,
CRK naming, libsodium backend, BLAKE2b, X25519-only v1, dumb-storage
catalog.

Remaining (non-blocking, runs in parallel with Phase 1+):

- Format review: circulate [03-segment-format.md](03-segment-format.md) for
  external cryptographic review. Cheap now, expensive later.
- Hardware perf validation of libsodium XChaCha on Pi Zero 2 W / RV1106
  (moved to Phase 3 — libsodium is chosen; this only confirms throughput).

## Phase 1 — Core: seal & verify (3–4 weeks)

The product's nucleus, no daemon yet.

- `sks-format`, `sealer-crypto`, `sealer-chain` crates.
- `sealer-keys`: manifest parse/verify; `ceremony-sim` test generator
  (throwaway stand-in for real ceremony tooling).
- `sks verify` + `sks inspect` CLI working on synthetic segments.
- Published test vectors; fuzz targets running in CI.
- **Demo: seal a file, tamper with it seven different ways, watch
  `sks verify` name each attack.** This demo is also the pitch.

## Phase 2 — Daemon MVP: watcher → S3 ✅ (core complete)

- ✅ `sealerd` pipeline with watcher source (polling), spool, S3 + fs sinks,
  signed `.skc` catalog records.
- ✅ Config file (`deny_unknown_fields`) + `sealer doctor/status/enroll`.
- ✅ Chain events (boot, heartbeat); crash-safety invariants implemented and
  tested (kill -9 → chain resumes with declared boot event).
- ✅ Docker compose simulation (`sim/`): MinIO with object lock + versioning,
  camera-sim, continuous keyless verifier; chaos drills validated manually
  (tamper → red, WORM delete denied even for storage admin).
- **Demo (validated): `docker compose up --build` in `sim/`.**
- Remaining for later phases: `source_lost/restored` events, inotify
  watcher, Prometheus `/metrics`, spool quota enforcement, per-object
  retention headers, fault injection automated in CI.

## Phase 3 — Reference hardware (2–3 weeks)

- Pi Zero 2 W: pipe mode from `rpicam-vid` (plaintext never on disk),
  aarch64-musl release build, systemd unit, install script.
- 72 h soak on the lab rig; RAM/CPU/wear numbers published.
- **Demo: physical camera on a shelf, sealing to a $5/mo bucket; the
  "stolen SD card" party trick — pull the card, show nothing readable.**

## Phase 4 — Release loop closes (2–3 weeks, coordinates with Keyholder plan)

- Catalog-as-objects: `.skc` record + per-window index writer in `sealerd`
  (no catalog service — decided, [06](06-storage.md)).
- `release-sim`: reconstruct a window key from test shares, enumerate a
  window straight from the bucket via `.skc` records, decrypt, `sks verify`
  the lot. End-to-end proof of the whole SplitKey concept with no GUI apps
  yet — **this is the milestone that makes the project real to outsiders.**

## Phase 5 — Reach (ongoing, prioritize by demand)

- RTSP source mode (`retina`), fMP4 muxing → seal ONVIF cameras.
- Windows sidecar build + service wrapper.
- SFTP/HTTP sinks, multi-sink fan-out.
- QR actions (probe + manifest-announce first).
- RFC 3161 anchoring; transparency-log anchoring.
- Luckfox/RV1106 port (musl static confirmed working on stock Buildroot).
- OpenIPC packaging + community engagement — postponed (low priority).

## Phase 6 — Hardening & evidentiary posture

- External security audit of crypto + format.
- Verification-algorithm spec doc (independent-implementer grade).
- Reproducible-build attestation; signed releases.
- TPM/secure-element device key support.
- PQ-hybrid suite design (X25519+ML-KEM) behind suite ID.

## Dependency callouts (work that lives outside Sealer but gates it)

| Dependency | Gates | Plan |
|------------|-------|------|
| Ceremony tooling (real) | Phase 4+ real deployments | `plans/community-signing.md` — Sealer defines the manifest/share formats it consumes ([02](02-key-management.md)); ceremony tool must adopt them |
| Keyholder app | Real releases | `plans/keeper-app.md` (Tauri) — consumes catalog + `.sks` + share formats |
| Catalog service | — | Not needed (decided: dumb storage, `.skc` objects in the bucket); optional HTTP service is a future optimization only |
| Portal | Nothing in Sealer | Later |
