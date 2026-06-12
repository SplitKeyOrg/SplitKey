# 03 — Sealed Segment Format (`.sks`)

One file per segment. Designed for: streaming write (no seek-back),
incremental decrypt, partial-corruption recovery, verification without
decryption, and parsing on tiny devices.

## Layout

```
┌──────────────────────────────────────────────────────────────┐
│ MAGIC "SKS1" (4 B)                                           │
├──────────────────────────────────────────────────────────────┤
│ HEADER (CBOR, length-prefixed)             — authenticated   │
│   format_version        u8                                   │
│   suite_id              tstr   ("SKS1-XCHACHA")              │
│   community_id          tstr (≤64, e.g. "maplecourt-hoa")    │
│   camera_id             tstr (≤64, e.g. "lobby-east")        │
│   device_key_id         bstr/8  (fingerprint of Ed25519 key) │
│   epoch                 u16                                  │
│   window_index          u64                                  │
│   segment_seq           u64    (monotonic per camera, gap-   │
│                                 free; THE chain counter)     │
│   boot_id               bstr/8 (random per boot; reboots     │
│                                 visible)                     │
│   ts_wall_start/end     i64    (unix ms)                     │
│   ts_mono               u64    (monotonic ns at start)       │
│   clock_confidence      u8     (synced/drift/unknown)        │
│   prev_link             bstr/32 (hash of previous segment's  │
│                                  SIG block; zeros for        │
│                                  genesis — see 04)           │
│   content_meta          map    (container hint: "ts"/"mp4"/  │
│                                 "h264-es", recorder name,    │
│                                 optional detection labels    │
│                                 e.g. "car"/"person";         │
│                                 plaintext by design)         │
│   sealed_dek            bstr   (crypto_box_seal output:      │
│                                 DEK ‖ secretstream header)   │
├──────────────────────────────────────────────────────────────┤
│ HEADER_SIG (64 B)  Ed25519(device_key, MAGIC ‖ HEADER)       │
├──────────────────────────────────────────────────────────────┤
│ BODY: secretstream chunks                                    │
│   repeated: chunk_len u32 ‖ AEAD chunk (64 KiB default)      │
│   first chunk AAD = hash(HEADER)  → binds body to header     │
│   last chunk has secretstream FINAL tag                      │
├──────────────────────────────────────────────────────────────┤
│ FOOTER (CBOR, length-prefixed)                               │
│   body_hash      bstr/32  (BLAKE2b over BODY)                │
│   chunk_count    u32                                         │
│   body_len       u64                                         │
├──────────────────────────────────────────────────────────────┤
│ SIG block: Ed25519(device_key, HEADER_SIG ‖ FOOTER)          │
│   ── hash(SIG block) becomes next segment's prev_link        │
└──────────────────────────────────────────────────────────────┘
```

## Properties this buys

| Need | Mechanism |
|------|-----------|
| Verify without decrypting | HEADER, FOOTER, SIG, body_hash are all plaintext; `sks verify` checks signatures + chain links + body hash with zero key material. |
| Truncation detection (intra-segment) | secretstream FINAL tag. |
| Truncation/reorder detection (inter-segment) | `prev_link` chain + gap-free `segment_seq` (see [04](04-tamper-evidence.md)). |
| Replay under different identity/time | HEADER is in the body's AAD and signed; moving a body between headers fails AEAD. |
| Streaming write on-device | Header is fully known before body bytes flow; footer+sig appended at close; no seek-back. |
| Partial corruption recovery | Per-chunk tags localize damage; later chunks of a damaged segment still decrypt (secretstream state permitting) and later *segments* are unaffected. |
| Tiny parser | CBOR with a fixed schema; `sks-format` crate is no_std-capable. |

## Naming & companion files

```
<community>/<camera>/<epoch>/<window_index>/<segment_seq>.sks
<segment_seq>.sksum            # optional detached: hash + sig only, lets
                               # auditors mirror integrity data cheaply
```

Object-store key layout mirrors this path ([06-storage.md](06-storage.md)).
Names contain **no wall-clock timestamps** (metadata stays inside the
authenticated header; filenames can't be trusted anyway). Window index in the
path is what release tooling filters on.

## Catalog record (per segment)

Reported to the metadata catalog on upload; duplicates the *public* header
fields so footage can be found without touching blobs:

`{community_id, camera_id, epoch, window_index, segment_seq, ts_wall_start,
ts_wall_end, clock_confidence, sealed_dek, prev_link, sig_hash, body_len,
storage_url, upload_ts}`

The catalog knows **what exists, when, and where — never what it shows**.

## Versioning rules

- `format_version` bumps for breaking layout changes; parsers reject
  unknown major versions.
- New suite IDs (e.g. a future PQ-hybrid) are additive — old verifiers can
  still chain-verify segments whose body cipher they don't know, because
  verification never needs the cipher.
- Unknown HEADER map keys are ignored but still authenticated (CBOR bytes are
  signed as-is).

## Open format questions

(Tracked in [11-open-questions.md](11-open-questions.md))

- CBOR vs. a hand-rolled fixed layout for the smallest targets.
- ~~`content_meta` plaintext vs encrypted~~ — decided: plaintext, and
  deliberately so; labels like "car"/"person" make sealed footage
  searchable without decryption.
- Merkle-tree mode for very long recordings (efficient partial verification)
  — v2 candidate, chain is sufficient for launch.
