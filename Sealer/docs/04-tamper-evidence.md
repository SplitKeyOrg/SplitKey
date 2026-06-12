# 04 — Tamper Evidence & Chain of Custody

Goal: footage that is **evidentiary** — its integrity, continuity, ordering,
and timing are mathematically demonstrable, not "trust our NVR." Per-segment
AEAD already gives integrity *within* a segment nearly for free; this layer
makes the *sequence* of segments trustworthy.

## The hash chain

Each segment's authenticated, signed header carries `prev_link = hash(previous
segment's SIG block)` plus a gap-free `segment_seq`
([03-segment-format.md](03-segment-format.md)). The recording becomes a hash
chain:

```
[seg 41]◀──prev_link──[seg 42]◀──prev_link──[seg 43]◀── ...
   sig                   sig                   sig
```

What a verifier (`sks verify`, no keys needed) can prove over any run of
segments:

| Attack | Detection |
|--------|-----------|
| Modify a segment body | body AEAD tags + body_hash + SIG fail |
| Replace a segment wholesale | next segment's `prev_link` mismatches |
| Drop segments from the middle | `segment_seq` gap + broken link |
| Drop segments from the end | next-known segment (or the camera's live head, or the catalog) doesn't link back; `sks verify` reports the chain head it could reach |
| Reorder segments | seq + links disagree |
| Splice footage from another camera/time | header AAD/signature binds camera ID, window, timestamps |
| Fabricate a parallel history | requires the device signing key; even then, two conflicting chains with the same seq numbers are themselves evidence of compromise once both surface (catalog sees duplicates) |

## Chain events (making operational reality visible)

Not all discontinuities are attacks. The Chainer emits tiny **chain-event
segments** (normal `.sks` files whose body is a CBOR event record, sealed and
chained exactly like footage):

- `boot` (with new `boot_id`) — reboots are declared, not silent
- `clock_step` (NTP correction beyond threshold, with before/after)
- `source_lost` / `source_restored` (camera feed died — distinguishes
  "camera offline" from "segments deleted")
- `config_change` (hash of new config), `manifest_update`
- `heartbeat` — emitted every N minutes when no footage is being produced
  (motion-triggered cameras), so silence has a maximum credible duration.
  **A camera that records nothing still proves it was alive.**
- `window_close` — first segment after a window rollover; its plaintext
  `content_meta` pins the closed window's `min_seq`/`max_seq`/`count`, so
  truncating a past window's tail requires deleting every later window too
  ([06-storage.md](06-storage.md)).

Gap analysis then becomes precise: any time range is covered by footage,
covered by a declared event, or **unexplained** — and only the last category
is suspicious.

## Timestamps you can argue in court

Layered, weakest to strongest:

1. **Device wall clock** in every header, with `clock_confidence` and NTP
   state recorded.
2. **Monotonic counter + boot_id**: orders segments irrefutably relative to
   each other even if wall clock is wrong.
3. **External anchoring (roadmap, high value):** periodically (e.g. hourly
   and at every boot) submit the current chain head hash to:
   - an **RFC 3161 timestamp authority**, storing the token in the next
     chain-event segment → proves "this chain prefix existed by time T";
   - and/or a **transparency log** (community-run or public, sigsum-style)
     → additionally proves *to everyone* the head existed, and makes
     after-the-fact chain rewriting publicly detectable.
   Anchoring is what converts "the device claims 14:02" into "a third party
   confirms the recording existed by 14:05." It also bounds how far back a
   *fully compromised* device could rewrite history: only since its last
   anchor.

## Withholding ≠ tampering (and why the chain alone can't fix it)

The chain detects modification and *visible* gaps, but a storage provider
silently deleting blobs looks identical to "uploads never happened" unless
something independent knows the blobs existed. Defenses (see
[06-storage.md](06-storage.md) for enforcement):

- catalog records on upload (catalog and storage must not be the same
  trust domain),
- Object Lock / WORM retention on storage,
- transparency-log anchoring (above),
- optional multi-backend replication.

## Device signing key — trust scope

- The chain is only as strong as the device key's custody. Use the
  platform secure element/TPM/OP-TEE where available; record the key's
  fingerprint and enrollment date in the catalog.
- Key compromise lets an attacker forge *future* chain segments, not alter
  anchored history. Anchoring frequency is therefore a security parameter.
- Re-keying (replacement device) is an enrollment event recorded in the
  catalog; verifiers treat cross-key chain joints as explicit, audited
  splices.

## Firmware integrity (secondary project — noted, not solved here)

A tampered firmware image could leak plaintext at capture time regardless of
sealing. Out of scope for the Sealer, but the plan should grow toward:
measured/verified boot where the platform supports it (Pi: signed boot on
CM4/5; RV1106: vendor secure boot), reproducible Sealer builds, and binary
attestation in the catalog (device reports its image hash in chain events —
a lying device can lie, but a *consistent* lie across time + anchors raises
the bar). Captured in [12-ideas-for-splitkey.md](12-ideas-for-splitkey.md).

## Verifier deliverables

- `sks verify <dir|prefix>`: chain + signature + completeness report over a
  set of segments; outputs machine-readable JSON and a human report
  ("continuous 2026-06-10T00:00Z → 06-11T13:20Z; 1 reboot (declared);
  no unexplained gaps; head anchored at 13:00Z via TSA X").
- `sks inspect <file>`: dump one header/footer.
- Both must run without any key material and be boring enough for a court
  expert to read. The verification *algorithm* gets its own short spec
  document before implementation (test vectors included) so third parties
  can implement it independently.
