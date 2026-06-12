# 00 — Architecture

## Goals and non-goals

**Goals**

- Run on anything from a low-power doorbell SoC to a 4K NVR box.
- "Tack on" to existing camera systems with zero changes to the recorder
  (directory-watch mode), while allowing deeper integration over time.
- Footage is unreadable on the device within seconds of being captured.
- Tamper-evidence, ordering, and gap-detection guarantees survive device
  compromise *after* the fact (a stolen camera can't rewrite history).
- Cross-platform: Linux first-class; Windows/macOS supported for the
  sidecar mode; exotic camera OSes via static binaries or vendor SDKs.

**Non-goals (for the Sealer itself)**

- Key reconstruction or decryption — that is the Keyholder app's job.
- Video transcoding/analytics — the Sealer treats footage as opaque bytes.
- Long-term storage — it produces sealed segments and hands them off.

## Process model

A single daemon, `sealerd`, plus a small operator CLI, `sealer`:

```
┌────────────────────────────── sealerd ───────────────────────────────┐
│                                                                      │
│  ┌────────┐   ┌───────────┐   ┌────────┐   ┌─────────┐   ┌────────┐  │
│  │ Source │──▶│ Segmenter │──▶│ Sealer │──▶│ Chainer │──▶│ Spooler│  │
│  └────────┘   └───────────┘   └────────┘   └─────────┘   └───┬────┘  │
│   (watcher,    (cut at N s /   (DEK +       (hash chain,     │       │
│    pipe,        N MB / window   secret-      device sig,     ▼       │
│    RTSP,        boundary)       stream       counter)    ┌────────┐  │
│    inline)                      encrypt,                 │Uploader│  │
│                                 seal DEK)                │  (s)   │  │
│                                                          └───┬────┘  │
│  ┌──────────────┐  ┌───────────┐  ┌────────────┐             ▼       │
│  │ Control plane│  │ Key store │  │ Health/    │      S3 / SFTP /    │
│  │ (QR, config, │  │ (pubkey   │  │ telemetry  │      HTTP / local   │
│  │  signals)    │  │ manifest) │  │            │      + catalog      │
│  └──────────────┘  └───────────┘  └────────────┘                     │
└──────────────────────────────────────────────────────────────────────┘
```

### Stage responsibilities

| Stage | Responsibility | Key decisions |
|-------|----------------|---------------|
| **Source** | Acquire footage bytes. Pluggable: directory watcher (v1), stdin/pipe, RTSP pull, inline hook. | See [05-ingestion.md](05-ingestion.md). |
| **Segmenter** | Cut the byte stream into segments by duration/size, and *always* at window boundaries (a segment never spans two windows). In watcher mode the recorder has already segmented; this stage just validates completeness (file closed, stable size). | Segment length default 60 s or 16 MB, whichever first. |
| **Sealer** | Per segment: generate random DEK, encrypt with streaming AEAD (XChaCha20-Poly1305 secretstream), seal the DEK to the current Window Key public key. | See [01-crypto-design.md](01-crypto-design.md). |
| **Chainer** | Build the authenticated header: previous segment's tag hash, monotonic counter, timestamps; sign with the device key. | See [04-tamper-evidence.md](04-tamper-evidence.md). |
| **Spooler** | Durable on-disk queue of sealed segments. Survives crashes/power loss; enforces disk quota. | Write sealed segment + fsync *before* deleting plaintext. |
| **Uploader** | Push segments to one or more storage backends with retry/backoff; report to the metadata catalog. | See [06-storage.md](06-storage.md). |
| **Control plane** | Config reload, QR-code actions, health endpoint, clock monitoring. | See [07-configuration.md](07-configuration.md), [08-qr-actions.md](08-qr-actions.md). |
| **Key store** | Holds the pubkey manifest, device signing key, chain state (last tag, counter). The only persistent secrets are the *device signing key* and chain state — no decryption capability. | Stored in a small append-friendly state dir; optionally in a TPM/secure element when present. |

### Concurrency model

- Tokio async runtime; each pipeline stage is a task connected by bounded
  channels (backpressure, bounded memory — critical on 128 MB boards).
- Crypto runs on a small blocking-thread pool sized to core count.
- One pipeline instance per camera/source; a single `sealerd` can host
  multiple sources (NVR sidecar scenario).

### Crash-safety invariants

1. Plaintext is deleted only after its sealed segment is fsync'd to the spool
   (watcher mode) or never written at all (inline mode).
2. Chain state (counter, last tag hash) is persisted before a segment is
   considered complete; on restart the chain resumes, and the restart itself
   is recorded as an authenticated "chain event" segment so reboots are
   visible, not exploitable.
3. The spool is the source of truth for "what still needs uploading";
   uploads are at-least-once, deduplicated by segment ID at the backend.

## Crate layout (Cargo workspace)

```
Sealer/
├── Cargo.toml                # workspace
├── crates/
│   ├── sks-format/           # .sks container: types, parse/serialize, no I/O
│   ├── sealer-crypto/        # DEK gen, secretstream, envelope seal, signing
│   ├── sealer-chain/         # hash chain, counters, chain state persistence
│   ├── sealer-keys/          # pubkey manifest parsing/verification, key store
│   ├── sealer-ingest/        # Source implementations (watch, pipe, rtsp)
│   ├── sealer-store/         # Uploader backends (fs, s3, sftp, http) + spool
│   ├── sealer-qr/            # QR action decoding + verification
│   ├── sealerd/              # the daemon: pipeline assembly, config, control
│   └── sealer-cli/           # `sealer` operator tool + `sks verify/inspect`
└── docs/                     # these documents
```

Rationale:

- `sks-format` and `sealer-crypto` are `no_std`-capable cores (alloc-only) so
  an eventual ESP32 port reuses them unchanged.
- `sks verify` (chain + signature verification **without decryption**) ships
  in `sealer-cli` so *anyone* — keyholders, auditors, courts — can verify
  integrity of sealed footage they cannot read. This tool is as important as
  the daemon.
- Backends and sources are feature-gated so a doorbell build can compile only
  `watch + s3` and stay small.

## Deployment shapes

1. **Sidecar (v1):** existing camera/NVR writes segment files; `sealerd`
   watches the directory, seals, uploads, deletes plaintext.
2. **Pipe (v1.5):** recorder writes to stdout / a FIFO; `sealerd` reads the
   stream, segments in RAM, plaintext never touches disk.
3. **RTSP puller (v2):** `sealerd` connects to an IP camera's RTSP feed and
   is the recorder. Enables sealing cameras you can't install software on.
4. **Inline / SDK (v3):** a library (`sealer-crypto` + `sks-format`) linked
   into the camera firmware's muxer (OpenIPC integration, vendor SDKs like
   Axis ACAP).

## Security boundaries

- **On device:** plaintext footage (transient), device signing key, chain
  state, pubkey manifest. *No decryption keys, ever.*
- **Threats addressed:** SD-card theft, device theft, storage-provider
  snooping, after-the-fact footage modification/deletion, segment reordering,
  silent gaps.
- **Threats *not* addressed by the Sealer:** a live-compromised device can
  record-and-leak going forward (it sees plaintext at capture time);
  physical lens obstruction; firmware tampering (see
  [12-ideas-for-splitkey.md](12-ideas-for-splitkey.md) for attestation
  ideas). These must be stated honestly in user-facing docs.
