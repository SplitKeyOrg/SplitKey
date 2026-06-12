# 05 — Ingestion (Camera → Sealer)

The Source stage answers: *how do footage bytes reach the Sealer?* Four
modes, phased; all feed the same Segmenter→Sealer pipeline.

## Mode 1 — Directory watcher (v1, the "tack-on")

Watch a directory where any existing recorder (NVR software, motion,
Frigate, vendor firmware, a dashcam's SD card mount…) writes segment files.

- **Completion detection** (a file must be *closed and done* before sealing):
  - Linux: inotify `CLOSE_WRITE`; fallback: size-stable polling (2 intervals)
    + optional lsof-style open-handle check.
  - Windows: `ReadDirectoryChangesW` + rename-pattern/stability heuristics
    (many recorders write `.tmp` then rename — support configurable
    "ready" glob).
  - macOS: FSEvents + stability polling (dev/test convenience, not a target).
- After sealing + fsync to spool: delete plaintext (configurable:
  `delete` / `truncate+delete` / `keep` for migration trials).
- **Honest caveats** (documented to users, drive the inline roadmap):
  1. Plaintext touches flash before sealing — a window of exposure, and
     deletion on wear-leveled flash is not forensic erasure.
  2. ~3× flash I/O (write plain, read plain, write sealed) — real wear cost
     on cheap SD cards.
- Crash rule: an unsealed file found at startup is sealed immediately
  (it's footage, not garbage), with a chain event noting recovery.

## Mode 2 — Pipe / stdin (v1.5, first plaintext-never-on-disk mode)

`rpicam-vid ... -o - | sealerd --source pipe` or a FIFO. The recorder
streams an H.264/H.265 elementary stream or MPEG-TS; the Segmenter cuts in
RAM. This is the Pi Zero 2 W demo path: hardware-encoded bitstream piped
straight into the Sealer; plaintext exists only in RAM.

- Segment cutting for raw ES: prefer cutting at IDR/keyframe boundaries so
  each segment is independently decodable. Requires a minimal NAL-unit
  scanner (no decoding) — small, but must be fuzzed.
- Backpressure: bounded channel; if crypto/storage stalls, policy is
  configurable: drop-oldest (favor liveness) vs block (favor completeness)
  — default block, with chain event on overflow either way.

## Mode 3 — RTSP puller (v2)

`sealerd` connects to an IP camera's RTSP URL and acts as the recorder —
seals cameras you cannot install software on (the vast majority of deployed
hardware).

- RTSP/RTP client (`retina` crate is the leading candidate), H.264/H.265,
  TCP-interleaved transport by default.
- Depacketize → optionally mux to fragmented MP4 or MPEG-TS per segment
  (decide: store raw ES + metadata vs mux on device; mux costs CPU but makes
  released footage immediately playable — leaning **fMP4 mux**, it's cheap).
- One pipeline per camera; an NVR-class box runs many.
- Note: RTSP plaintext crosses the LAN — recommend isolated camera VLAN;
  documentable, not solvable here.

## Mode 4 — Inline / SDK (v3)

`sealer-crypto` + `sks-format` as a library (C ABI shim provided) linked
into the camera's own muxer: OpenIPC's recorder (majora/OpenIPC firmware),
vendor SDKs (Axis ACAP), or our own future firmware builds. Plaintext never
exists outside the encode pipeline's RAM.

## Segmenter rules (all modes)

- Cut at: max duration (default 60 s) OR max bytes (default 16 MB) OR
  **window boundary** (always) OR source loss.
- Watcher mode: recorder's own files are usually ≤ window length; if a file
  spans a window boundary it is sealed into the window of its first byte and
  the discrepancy recorded in `content_meta` (we won't re-cut someone else's
  container in v1; flagged in open questions).
- Audio, if present in the container, is sealed as-is (it's opaque bytes).
  Whether communities *want* audio recorded is policy, not Sealer's call.

## Source health

- `source_lost`/`source_restored` chain events with reason (file activity
  stopped, RTSP teardown, pipe EOF).
- Heartbeat chain events cover motion-triggered cameras
  ([04-tamper-evidence.md](04-tamper-evidence.md)).
- Watchdog: if the source produces nothing for N× the expected cadence,
  health endpoint + optional catalog alert flips to degraded.

## Platform input notes

| Platform | Likely source |
|----------|---------------|
| Raspberry Pi Zero 2 W + Camera Module 3 | Mode 2 pipe from `rpicam-vid` (HW H.264 encode) — primary demo |
| Luckfox Pico (RV1106) | Mode 4 eventually (rkipc hook) — Mode 2 from venc sample apps first |
| OpenIPC devices | Mode 2/4 via majestic streamer output |
| Windows + existing NVR (Blue Iris etc.) | Mode 1 watcher on the clip directory |
| Generic ONVIF/IP cams | Mode 3 RTSP |
| ESP32-CAM (exploratory) | Out of pipeline scope; would be a bespoke firmware using the no_std cores |
