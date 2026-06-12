# 02 — Key Management & Time Windows

## Key hierarchy

```
Key Ceremony (offline PC, yearly)                        Device (Sealer)
─────────────────────────────────                        ───────────────
Community Root Key (CRK), epoch E
   │  HKDF(CRK, "splitkey/wk" ‖ E ‖ window_index)
   ▼
Window Key seed → X25519 keypair per window
   ├── WK_priv[w] ──▶ Shamir split t-of-n ──▶ printed shares (BIP39 words)
   │                                          one share-set per keyholder
   └── WK_pub[w]  ──▶ Pubkey Manifest (signed) ──────────▶ provisioned to
                                                           every Sealer
CRK: destroyed after manifest + shares are produced
     (decided: no escrow — redundancy comes from enrolling enough
      keyholders above the threshold, not from a master-key backup)
```

- **Community Root Key (CRK)** — Exists only on
  the air-gapped ceremony machine, only during the ceremony.
- **Window Keys** — one X25519 keypair per time window for the whole epoch,
  all derived deterministically from the CRK so the ceremony is a single
  generation pass.
- **DEKs** — per-segment, random, sealed to the current window's public key
  ([01-crypto-design.md](01-crypto-design.md)).

### Why per-window Shamir shares (not shares of the CRK)

If keyholders held shares of the CRK itself, the *first* release would
reconstruct the CRK and expose **every** window in the epoch. Instead the
ceremony derives each window's private key and Shamir-splits **each window
independently**. Releasing window `w` reveals only `WK_priv[w]`.

This matches the community-signing plan (`plans/community-signing.md`):
keyholders receive a printed booklet of per-window share codes (BIP39 word
encoding, multilingual wordlists) and "call in" only the codes for the
requested window.

**Print volume math** (drives the window-length decision):
a 32-byte share ≈ 24 BIP39 words. Plus share metadata (window ID, share
index, checksum) — call it one line per window.

| Window length | Windows/epoch (~12 mo) | Booklet size per keyholder |
|---------------|------------------------|----------------------------|
| 1 hour | ~8,760 | ~250 pages — impractical on paper |
| 12 hours | ~730 | ~20 pages — workable |
| 24 hours | ~365 | ~10 pages — comfortable |

**Decided: (a) 24 h windows with paper shares** — most practical for
communities, matches "print all days of the year." Release granularity is a
whole day per window.

Communities that genuinely need finer (e.g. 1 h) windows can opt into
**digital share storage** (Keyholder app + YubiKey), where booklet size is
no constraint — the window length is a per-community manifest parameter, so
nothing in the Sealer changes. The two-level day/hour derivation scheme is
shelved (kept in git history) unless demand resurfaces.

## Window definition (gaps, DST, time zones)

- Windows are defined in **UTC, fixed duration, no DST adjustments ever**:
  `window_index = floor(unix_seconds / window_seconds)`. The mapping is pure
  arithmetic — no calendar, no gaps, no double-counted hours.
- The *human-facing* schedule ("release Tuesday 14:00–15:00 local") is a UI
  conversion problem in the Portal/Keyholder app, never an on-device concern.
- Segments never span a window boundary: the Segmenter force-cuts at the
  boundary. A segment belongs to the window containing its first frame.
- **Multiple cameras, one community** (decided): all cameras seal to the
  same community window keys, so releasing a window releases that window
  for *all* cameras — acceptable for most communities. Communities that
  store shares digitally can adopt per-camera key derivation later (release
  tooling loads only the keys for one camera + day); the manifest format
  reserves room for this without new paper.
- **Epoch boundary**: epochs are delimited by ceremony dates recorded in the
  manifest, expressed as window indexes. Manifests cover **18 months** of
  windows (12 nominal + 6 grace) so a delayed ceremony never leaves cameras
  without keys. Key *re-use* after grace expiry is rejected by design —
  re-using window keys across years collapses the time-bounding guarantee
  (one old release would unlock the same window next year). If the manifest
  is exhausted, behavior is configurable: `fail-closed` (stop recording) or
  `seal-to-last-key` with loud alerting. Decided default: `seal-to-last-key`
  + alert, because losing footage is usually worse than coarse granularity.
  Implementation note: an exhausted-mode segment records its *true* window
  index in the header while being sealed to the *last manifest window's*
  key — release tooling must release `last_window`'s key for such segments
  (they are recognizable: `window_index > manifest.last_window`).

## Time synchronization

The window index depends on the device clock; a wrong clock seals footage to
the wrong window (release confusion, not a confidentiality break — but it
matters for evidence).

- NTP (chrony) when networked; battery RTC is a recommended BOM addition
  for offline sites (Pi Zero 2 W has no RTC).
- **No-clock operation is supported** (decided): a device with no trusted
  clock keeps sealing — the monotonic counter + `boot_id` + gap-free
  `segment_seq` still order footage irrefutably; `clock_confidence =
  unknown` is recorded honestly in every header. Window assignment falls
  back to the device's best wall-clock guess; once someone sets the clock,
  the correction appears as a `clock_step` chain event. Limited evidentiary
  utility, but footage is never dropped for lack of a clock.
- The Chainer records both wall-clock and a monotonic counter in every
  header; verifiers can detect clock steps ([04-tamper-evidence.md](04-tamper-evidence.md)).
- Clock confidence (synced / drifting / unknown) is recorded per segment so a
  court can weigh timestamp trust.
- Max acceptable skew and behavior on skew detection: configurable
  (`warn` / `hold-uploads` / `stop`).

## Ceremony interface (what the Sealer consumes)

The ceremony tooling itself is a separate plan
(`plans/community-signing.md`); the Sealer only defines the artifacts it
accepts:

1. **Pubkey Manifest** (`manifest.skm`): CBOR, Ed25519-signed by the
   community admin key. Contains: community ID, epoch number, window length,
   first/last window index, the ordered list (or a compact seed-derived
   commitment + explicit list) of `WK_pub`, admin key ID, ceremony date,
   threshold parameters (t, n — informational), successor-manifest rules.
2. **Enrollment package**: initial manifest + pinned admin verify key +
   device registration (camera ID assignment), delivered at install time via
   USB/SD/QR ([08-qr-actions.md](08-qr-actions.md)).
3. **Manifest updates**: yearly (new epoch) or emergency (key compromise →
   manifest revocation + replacement), delivered via QR, the catalog
   channel, or a file drop; always verified against the pinned admin key
   chain.

## Device-side key store

Contents (all non-secret except the device signing key):

| Item | Secret? | Purpose |
|------|---------|---------|
| Pubkey manifest(s) | No | Sealing targets per window |
| Pinned admin verify key | No (integrity-critical) | Manifest/QR verification |
| Device signing key (Ed25519) | Yes | Chain/segment signatures |
| Chain state (counter, last tag) | No (integrity-critical) | Chain continuity |

Storage: flat files in a state directory with atomic-rename updates;
device signing key in TPM2/secure element when the platform has one
(feature-gated), plain file with 0600 + optional passphrase otherwise.

## Rotation summary

| Key | Rotates | Mechanism |
|-----|---------|-----------|
| DEK | Every segment | Random |
| Window Key | Every window (1–24 h) | Pre-derived at ceremony; device just switches pubkeys |
| CRK / epoch | ~12 months (+6 mo grace) | New key ceremony; new manifest |
| Admin verify key | At ceremony, or emergency | New manifest signed by old key (chain of trust), or physical re-enrollment if old key is compromised |
| Device signing key | On compromise or device replacement | Re-registration with catalog; old key's segments remain verifiable against the catalog's key history |
