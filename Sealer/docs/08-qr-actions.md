# 08 — QR-Code Actions

Show a printed QR code to the camera to administer it. This is genuinely
useful — many target devices have **no accessible network/UI** (sealed
doorbells, cameras on isolated VLANs, OpenIPC boxes) and the lens is the one
input that always exists. It is also an unauthenticated, publicly reachable
input (*anyone* can stand in front of a camera), so the security model comes
first.

## Security model

**Every QR action is a signed, single-use, expiring command.**

Payload (CBOR, base45-in-QR):

```
{ ver, community_id, action, params,
  target: camera_id | "*",        # scope
  nonce: 16B random,              # replay defense (device persists seen nonces
                                  #   until expiry)
  not_before, expires,            # validity window (short: hours)
  key_id, sig }                   # Ed25519 by the community ADMIN key
                                  #   (same key that signs manifests)
```

Device verification pipeline: decode → schema check → community/target match
→ time window → nonce unseen → signature against pinned admin key chain →
execute → **always record a chain event** (`qr_action`, with payload hash,
accepted/rejected, reason). Rejected scans are rate-limited (e.g. process at
most 1 QR candidate/sec, exponential backoff on repeated failures) so QR
scanning can't be used to DoS the pipeline, and rejects are logged but
do *not* spam chain events beyond a cap.

What signing buys: a random person with a printer can't reconfigure the
camera. What it doesn't buy: secrecy (QR contents are visible to bystanders
— so **no secrets ever travel in a QR**) and admin-key custody (the admin
key signing QR actions is as powerful as the person holding it; ceremony
plan must cover its custody).

## Action catalog

| Action | Params | Risk notes |
|--------|--------|-----------|
| `manifest-announce` | URL + hash of new manifest, or chunked manifest inline (multi-QR) | The headline use: yearly key rotation without touching the device. Inline manifests need multi-frame QR (animated/sequential) — size math: ~730 × 32 B pubkeys ≈ 23 KB ≈ 10–20 QR frames; or just deliver hash+URL and fetch via network when present. |
| `probe` | none | Liveness/status check. Response channel (camera has no screen): LED blink pattern, and/or a `probe_response` chain event + catalog status update the prober checks on their phone. |
| `set-config` | whitelisted key subset only (e.g. heartbeat interval) | Storage credentials and source config are **excluded** — too dangerous via lens. |
| `pause-sealing` | duration (capped, e.g. ≤ 24 h) | Decided: included, ships **off** by default. Enabling the feature on a device requires a **keeper-threshold-signed** enable action (t-of-n keyholder signatures, not just the admin key); individual pauses remain loud chain events + catalog notices — visible, bounded, non-silent. |
| `enroll-begin` | enrollment bootstrap (install-time only) | Only honored when device is in unenrolled state. |
| `community-verify` | challenge value | See below. |

Explicitly rejected actions: key material delivery (QRs are public),
firmware update triggers (supply-chain surface), anything irreversible.

## Community verification (`community-verify`)

Purpose: let a resident confirm "this camera really runs SplitKey and seals
to *our* community keys" — countering the fake-sticker attack (a normal
surveillance camera with a SplitKey logo).

Flow sketch: resident's phone app generates a challenge QR; camera must
respond by publishing `sig(device_key, challenge ‖ chain_head ‖ manifest_hash)`
to the catalog within seconds; the phone fetches and verifies against
community records. Proves: live device, holds the registered key, currently
sealing against the expected manifest, chain head fresh. Does **not** prove
the lens you're looking at feeds *that* device (hard problem — a visual
nonce displayed/blinked by the prober and required inside the next sealed
segment gets close; v2 exploration).

## Decoder placement & cost

- QR detection runs on the device, sampling decoded frames at low rate
  (~1 fps, downscaled) — needs frame access, which exists in pipe/RTSP/inline
  modes. In pure watcher mode the Sealer never decodes video → QR actions
  unavailable unless a lightweight sampler taps the source separately
  (decode I-frames only at 1 fps; H.264 I-frame decode of a downscaled
  stream is feasible on Cortex-A7, but this is real CPU cost — feature-gated,
  off by default on watcher deployments).
- Library: `rqrr` or `quirc` binding (pure-Rust preferred); fuzz the decoder
  — it parses hostile camera input by definition.
- This is the one place the Sealer *interprets* video content; isolate it
  (own task, sandboxed parsing, never touches key store directly — submits
  verified commands over an internal channel).

## Open issues for this feature

(also mirrored in [11-open-questions.md](11-open-questions.md))

- Multi-frame QR ergonomics for full-manifest delivery (phone screen
  animation vs paper sequence).
- ~~Whether `pause-sealing` should exist~~ — decided above: included,
  off-by-default, keeper-threshold-signed enablement.
- **Temporary live stream (pinned for future design)**: installers and
  handymen legitimately need a live preview to aim a camera. Sketch: a
  one-time-use, short-lived, signed `live-preview` QR unlocks a local
  preview stream for N minutes, with a chain event + disclosure like any
  pause. Needs real design work (single-use enforcement, stream path,
  abuse) — deliberately deferred.
- Admin key custody between ceremonies (HSM? split custody? part of the
  community-signing plan).
