# 12 — Idea Suggestions for SplitKey (Project-Wide)

Augmentations surfaced while planning the Sealer. None are Sealer
commitments; they're candidates for the project backlog / OVERVIEW.

## Trust & verification

1. **Community transparency log.** A small append-only log (sigsum-style)
   per community recording: chain-head anchors from every camera, manifest
   publications, release events, disclosure notices. One artifact unifies
   "footage existed," "nothing was rewritten," and "every release was
   disclosed" — and makes *withholding* by storage or insiders publicly
   visible. Could be the same service as the catalog or deliberately
   separate.
2. **Threshold decryption (no-reconstruction releases).** Today's design
   reconstructs a window private key at release. The cryptographic upgrade:
   keyholders' devices compute partial X25519 decryptions of the sealed DEK
   and *only the DEK* ever materializes — the window key never exists
   anywhere, even transiently, and shares never leave keyholder hardware.
   Natural Keyholder-app v2; also enables remote (non-physical-meeting)
   attestations with better security than reading codes over the phone.
3. **Release watermarking.** When footage is released, the decryption tool
   stamps the output (visible overlay + steganographic ID: request ID,
   approver set, date). Leaked released footage becomes traceable to its
   release event — accountability extends past decryption.
4. **Camera co-witnessing.** Cameras within sight of each other
   periodically embed each other's chain heads (heard via the catalog) in
   their own chains — a community-scale lightweight timestamping mesh that
   makes rewriting any one camera's history require compromising several.
5. **Firmware attestation track** (the plan's "secondary project"):
   reproducible builds + signed releases (already in Sealer plan), then
   measured boot on capable platforms, then a "device passport" in the
   catalog (image hash history per camera). Honest framing: a fully
   compromised device can lie; the goal is raising cost and surfacing
   inconsistency, not perfection.

## Community & governance

6. **Release-policy engine.** Machine-readable community policy (max
   window span per request, cooldowns, who may request, mandatory delay
   before decryption "cooling-off," emergency fast-path with extra
   disclosure). Keyholder app enforces what bylaws promise; policy hash
   recorded in disclosure notices.
7. **Dead-man / succession planning.** Keyholders move away, die, lose
   booklets. Annual re-attestation ping ("do you still hold your shares?")
   via Keyholder app/Portal; below-threshold-risk alert triggers an early
   ceremony. Quietly critical for a system whose failure mode is
   "footage permanently unreadable."
8. **Practice releases.** Quarterly drill against a synthetic test window
   (ceremony pre-seals a known test clip per quarter). Communities verify
   quorum actually works *before* an incident; doubles as keyholder
   training. Cheap, enormous operational value.
9. **Victim-initiated release lane.** The OVERVIEW's stalking scenario
   implies the *subject* of footage may be the requester. Portal flow with
   advocacy-org templates, expedited summons, and policy guardrails —
   product-defining for the anti-abuse mission.
10. **Insurance/legal artifact pack.** One command exports: verification
    report, anchor receipts, disclosure log, policy hash — the bundle a
    lawyer, insurer, or court actually files. The evidentiary story is only
    real when it's a PDF someone can submit.

## Adoption & reach

11. **"SplitKey Inside" certification + visible signage.** Standardized
    sticker/plate with the community ID and a QR linking to the
    community's transparency page (cameras, keyholders count, threshold,
    release history). The deterrence value of cameras is preserved while
    advertising that no one watches alone — arguably the project's best
    marketing surface. Pairs with the `community-verify` QR flow
    ([08-qr-actions.md](08-qr-actions.md)).
12. **NVR-distro integrations.** Frigate/Scrypted/Blue Iris plugins that
    point their clip output at a Sealer watcher directory — adoption
    without new hardware. Frigate especially (open source, huge community,
    privacy-sympathetic users).
13. **Sealed snapshots for doorbells.** Low-power doorbells may not sustain
    video sealing; a stills-mode (seal a JPEG burst per event) widens the
    device floor dramatically — the `.sks` format already doesn't care
    what the bytes are.
14. **Legislation alignment doc.** `Draft Legislation Outline.rtf` exists
    at repo root — extract the technical requirements a statute would
    impose (retention bounds, disclosure timelines, audit formats) and
    check Sealer/catalog designs against them now, so the reference
    implementation *is* the compliance implementation.
15. **Hosted "community bucket" starter.** Most HOAs can't run MinIO. A
    turnkey hosted storage+catalog offering (or one-click deploy templates
    for B2/R2/S3 with object lock + IAM presets) removes the hardest
    deployment step. The trust story survives because storage is untrusted
    by design.

## Engineering

16. **`sks` as a general evidence-sealing format.** Nothing in the design
    is video-specific: bodycams, dashcams, audio recorders, document
    custody. Keeping the format spec clean and standalone
    ([03-segment-format.md](03-segment-format.md)) leaves this door open.
17. **Time-capsule mode.** Seal-to-future-window (encrypt to a window key
    whose shares are deliberately not distributed until a future ceremony)
    — community records that *cannot* be opened before a date. Niche, but
    falls out of the architecture for free and makes a great demo of the
    model's flexibility.
