# SplitKey Sealer

The **Sealer** is the on-device component of SplitKey. It runs on (or next to)
security cameras and seals footage the moment it exists: every video segment is
encrypted to keys the device itself cannot decrypt, chained together so
tampering and gaps are detectable, and shipped to storage. The camera becomes a
write-only witness — it can create evidence but can never read it back.

> Status: **planning**. These documents specify the architecture and
> implementation plan. No implementation code exists yet.

## Design pillars

1. **Write-only device.** The Sealer holds only *public* keys. Compromising the
   camera (or stealing its SD card) yields nothing readable, including the
   device's own past footage.
2. **Time-bounded release.** Footage is sealed per *time window* (e.g. 1 hour).
   The community can release one window without exposing any other.
3. **Tamper-evident by construction.** Per-segment AEAD tags are chained into a
   hash chain and signed by a device key, so continuity, ordering, and timing
   are provable — and missing footage is visible, not silent.
4. **Tack-on deployable.** Works as a sidecar next to any recorder that writes
   files to a directory; deeper integrations (pipe, RTSP, inline) come later.
5. **Small.** Rust, static binaries, runs in tens of MB of RAM on
   128 MB-class camera SoCs.

## Document index

| Doc | Contents |
|-----|----------|
| [00-architecture.md](docs/00-architecture.md) | Component breakdown, data-flow pipeline, process model, crate layout |
| [01-crypto-design.md](docs/01-crypto-design.md) | Cipher selection, streaming AEAD, envelope encryption, libraries, RNG |
| [02-key-management.md](docs/02-key-management.md) | Key hierarchy, window key derivation, ceremony interface, rotation |
| [03-segment-format.md](docs/03-segment-format.md) | The `.sks` sealed-segment container format and manifest formats |
| [04-tamper-evidence.md](docs/04-tamper-evidence.md) | Hash chain, device signatures, timestamps, gap detection |
| [05-ingestion.md](docs/05-ingestion.md) | Video inputs: directory watcher, pipe, RTSP, inline; segmentation |
| [06-storage.md](docs/06-storage.md) | Output backends, spooling, WORM/Object Lock, metadata catalog |
| [07-configuration.md](docs/07-configuration.md) | Config file, CLI, credentials handling |
| [08-qr-actions.md](docs/08-qr-actions.md) | QR-code control plane and its security model |
| [09-platforms-builds-testing.md](docs/09-platforms-builds-testing.md) | Hardware targets, cross-compilation, Docker simulation, test plan |
| [10-roadmap.md](docs/10-roadmap.md) | Implementation phases and milestones |
| [11-open-questions.md](docs/11-open-questions.md) | Unresolved design questions needing decisions |
| [12-ideas-for-splitkey.md](docs/12-ideas-for-splitkey.md) | New idea suggestions for the SplitKey project as a whole |

## Terminology used in these docs

Extends the project glossary in [`../OVERVIEW.md`](../OVERVIEW.md):

| Term | Definition |
|------|------------|
| **Community Root Key (CRK)** | The per-epoch master secret generated at the key ceremony. Never touches the device. |
| **Window Key (WK)** | Per-time-window X25519 keypair derived from the CRK. The device gets only the public half. |
| **DEK** | Data Encryption Key — random per-segment symmetric key. |
| **Segment** | One sealed unit of footage (N seconds / N MB), the granularity of encryption and chaining. |
| **Epoch** | The lifetime of one CRK (nominally 12 months + grace), bounded by key ceremonies. |
| **Pubkey Manifest** | Signed file provisioned to the device listing every window's public key for the epoch. |
| **Sealed segment (`.sks`)** | The on-disk/in-transit container holding encrypted footage + chain metadata. |
| **Spool** | Local queue of sealed segments awaiting upload. |
