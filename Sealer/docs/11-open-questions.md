# 11 — Open Questions → Decision Record

Decided 2026-06-11 by project owner. Decisions are propagated into the other
docs; this file is the record. Items still genuinely open are at the bottom.

## Keys & windows

1. **Window length & share mechanics — DECIDED: 24 h paper windows.**
   Daily windows are most practical for communities. Communities that need
   finer (e.g. 1 h) windows store keeper keys digitally (Keyholder app /
   YubiKey) where booklet size is no constraint. Two-level day/hour scheme
   shelved. → [02-key-management.md](02-key-management.md)
2. **Master key name — DECIDED: "Community Root Key (CRK)".**
3. **CRK after ceremony — DECIDED: destroy, no escrow.** Redundancy comes
   from enrolling enough keyholders above the threshold (n comfortably
   larger than t), not from a master-key backup.
4. **Manifest exhaustion default — DECIDED: `seal-to-last-key` + alert.**
   Key *re-use* across epochs stays rejected (breaks time-bounding);
   exhaustion holds the last key rather than dropping footage.
5. **Leap years / calendar weirdness — structurally solved** (pure UTC
   window arithmetic; manifests carry explicit index ranges). Standing
   constraint on ceremony tooling: print "all windows in manifest range,"
   never "all days of a calendar year."
6. **Multiple cameras, one community — DECIDED: shared window keys; a
   release covers all cameras for that window.** Fine for most communities.
   Per-camera scoping arrives naturally with digital share storage (load
   only that camera + day); manifest format reserves room for per-camera
   derivation later.

## Crypto & format

7. **Crypto backend — DECIDED: libsodium** (unless a specific hardware
   target forces otherwise; pure-Rust fallback stays behind a feature flag).
8. **Chain-link hash — DECIDED: BLAKE2b** (libsodium `crypto_generichash`).
9. **PQ readiness — DECIDED: X25519-only for v1.** Suite-ID mechanism is
   the documented migration path to a hybrid X25519+ML-KEM suite later.
10. **`content_meta` — DECIDED: plaintext.** Preferable, even: optional
    detection labels ("car", "person") make sealed footage searchable
    without decryption.

## Product & policy

11. **Watcher files spanning a window boundary — DECIDED: keep it simple.**
    Seal to the first-byte window; no re-muxing of foreign containers in v1.
12. **`pause-sealing` QR — DECIDED: include, ships off.** Enabling the
    feature requires a **keeper-threshold-signed** action (not just the
    admin key). Pauses stay loud, bounded chain events.
13. **Retention default — DECIDED: keep it simple.** Per-community policy;
    docs recommend 30–90 days; no hard opinion baked into the Sealer.
14. **Audio — DECIDED: seal whatever is in the stream.** SplitKey is not
    camera software; audio capture on/off is an upstream recorder option.
    Noted in user-facing docs (wiretap-law pointer stays in
    [05-ingestion.md](05-ingestion.md) territory).
15. **Live view — PINNED (needs design, deliberately deferred).** The use
    case is cameras that *cannot* be live-monitored; dual-stream forking is
    upstream's business. Real need identified: installer/handyman alignment
    preview → sketch is a **one-time-use, short-lived, signed
    `live-preview` QR** ([08-qr-actions.md](08-qr-actions.md)). Circle back.
16. **Clock trust — DECIDED: must work with no clock.** Monotonic counter +
    boot_id + gap-free seq substitute for ordering;
    `clock_confidence = unknown` recorded honestly; utility is limited until
    someone sets the clock, and the correction lands as a `clock_step`
    chain event. → [02-key-management.md](02-key-management.md)

## Ecosystem

17. **Catalog — DECIDED: dumb storage, no SplitKey backend service.**
    Signed `.skc` records + per-window index objects written next to the
    segments; release tooling reads the bucket directly.
    → [06-storage.md](06-storage.md)
18. **OpenIPC engagement — DECIDED: postpone** (low priority; tier 3).
19. **Luckfox uclibc — RESOLVED: musl static binaries run out-of-the-box**
    on the stock Luckfox Buildroot image.
20. **Pi Zero 2 W AES extensions — DECIDED: leave AESGCM untested on this
    board and mark it as such**; QEMU coverage later. XChaCha default
    unaffected.
21. **Trademark/name check — assume safe for now.**

## Still open / deferred

- **(15) Temporary live-preview QR** — needs a real design pass
  (single-use enforcement, stream path, abuse cases) before any
  implementation.
- **External format review** — circulate
  [03-segment-format.md](03-segment-format.md) for cryptographic review
  during Phase 1 (non-blocking but scheduled).
- **Keeper-threshold-signed QR actions** (from #12) — the multi-signature
  QR payload format needs a small spec addition in
  [08-qr-actions.md](08-qr-actions.md) when QR actions are built (Phase 5).
