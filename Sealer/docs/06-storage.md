# 06 — Storage & Metadata Catalog

After sealing, segments leave the device. The Sealer treats storage as a
pluggable, *untrusted* sink: confidentiality comes from sealing, integrity
from the chain — what storage must add is **availability and
non-deletability**.

## Spool (on-device staging)

- Sealed segments land in a spool directory (atomic rename on completion);
  the uploader drains it with at-least-once semantics.
- Store-and-forward: network outages just grow the spool.
- Disk quota with policy when full: `drop-oldest-uploaded` (safe; already
  stored remotely) → then `drop-oldest-unuploaded` (data loss, loud chain
  event + alert) or `stop-recording`. Default favors retaining unuploaded
  evidence until forced.
- Upload order: oldest-first FIFO; chain heads don't need special ordering
  (verification is content-based, not arrival-based).

## Backends (trait `StorageSink`, feature-gated)

| Backend | Priority | Notes |
|---------|----------|-------|
| `fs` (local/NAS path) | v1 | Also the test backend. SMB/NFS mounts are the OS's problem. |
| `s3` | v1 | The common real deployment: AWS S3, Backblaze B2, MinIO, **RustFS** (self-hosted S3-compatible — supported as "any S3 endpoint," nothing special needed; running it is the community's infra choice). Multipart for large segments; `If-None-Match`/precondition to make uploads idempotent. |
| `sftp` | v2 | Widely available on existing community servers. |
| `http` | v2 | Simple authenticated POST/PUT to a catalog-fronted endpoint; what a future SplitKey "drop server" would speak. |
| `ftp(s)` | v2, reluctantly | Listed in requirements; implement FTPS-only, document as legacy. |
| multi-sink fan-out | v2 | Same segment to ≥2 backends (e.g. local NAS + cloud) for the withholding defense. |

Key layout mirrors the segment path scheme
(`community/camera/epoch/window/seq.sks`,
[03-segment-format.md](03-segment-format.md)) so window-scoped listing is a
prefix operation.

## The withholding problem (and the answer: WORM + catalog + anchors)

The hash chain detects tampering, but a storage operator silently deleting
or withholding segments looks like "camera was offline" unless something
independent knows they existed. Three reinforcing controls:

1. **Object Lock / WORM + versioning** (S3 compliance mode, B2 lock,
   MinIO/RustFS object lock): retention policy set at bucket level so blobs
   cannot be deleted before policy allows, *even by an admin*. Turns "trust
   the operator" into a policy-enforced guarantee. The Sealer sets per-object
   retention headers when configured; `sealer doctor` verifies the bucket
   actually enforces lock at startup (config lies are common).
2. **Upload-only credentials**: the device's credentials must allow PUT but
   not DELETE/overwrite (IAM policy templates ship with the docs). A stolen
   camera then can't destroy history. Versioning + lock covers overwrite
   attempts.
3. **Independent catalog + anchoring**: the catalog (below) and transparency
   anchors ([04](04-tamper-evidence.md)) are the existence proof that makes
   withholding visible. Catalog and blob storage should be different trust
   domains where the community can manage it.

Retention duration is community policy (e.g. 30–90 days), and is the
flip-side of privacy: WORM means footage *cannot* be early-deleted even if
the subject asks. This tension goes to the open questions list.

## Metadata catalog

Something must know **what footage exists without being able to read it**:
which camera produced which segment, the time range, where the blob lives,
the sealed (still-encrypted) DEK, and the chain links/signatures — exactly
the catalog record defined in [03-segment-format.md](03-segment-format.md).

**Decided: dumb storage — no SplitKey-specific backend service required.**

- The catalog is **objects, not a service**: alongside each uploaded
  segment the Sealer writes a small device-signed CBOR catalog record
  (`<seq>.skc`). Window-scoped enumeration is a prefix LIST (≤ ~1440
  segments/day at 60 s cuts — one or two LIST pages); a rollup index object
  is a future optimization only.
- **Per-window rollup = `window_close` chain event** ✅: on window rollover
  the first segment sealed into the new window is a chained event whose
  *plaintext, header-signed* `content_meta` records the closed window's
  `min_seq`/`max_seq`/`count` (and it is copied into that segment's `.skc`).
  This closes the tail-truncation gap on non-WORM storage: the chain's
  seq-gap check catches deletions in the middle of history, but a deleted
  *tail* of window W just looks like the camera stopped — unless the next
  window's close event pins W's true `max_seq`. An attacker must now delete
  every later window too (a full-suffix wipe), which heartbeats and
  monitoring make conspicuous. Being a chained segment, the close event
  itself can't be dropped without creating a seq gap. Backlog segments
  sealed into an already-closed window carry seqs above the recorded
  `max_seq`; they remain covered by the ordinary seq-gap check.
- The Release/Keyholder tooling works directly against the bucket: list
  prefix → read `.skc` records → fetch the referenced `.sks` blobs. No
  server to run, nothing new to trust.
- Trust-domain note: with catalog and blobs in the same bucket, a
  withholding storage operator can hide both. Mitigations stay storage-side:
  Object Lock/WORM (above), optional second sink for `.skc` records only
  (they're tiny), and transparency-log anchoring
  ([04](04-tamper-evidence.md)).
- An HTTP catalog *service* remains a possible future optimization (faster
  queries, notifications) but is explicitly **not required** by the design;
  the `.skc` objects stay the source of truth either way.
- Catalog data is sensitive metadata (when cameras saw activity, and any
  `content_meta` labels) even though it can't show images — bucket access
  controls apply.

## Credentials handling

- Config file references credentials **indirectly**: `credential = "env:SEALER_S3_KEY"`,
  `"file:/etc/splitkey/s3.secret"`, or platform keychain/TPM-sealed blob
  where available. Plain inline secrets are accepted but warned about
  loudly (deployments will do it anyway; meet them where they are).
- Secrets never appear in logs, health output, or chain events; config hash
  in `config_change` events is computed over the *redacted* config.
- Rotation: SIGHUP/`sealer reload` re-reads credentials without dropping
  the pipeline.

## Released footage path (informational)

Release happens elsewhere (Keyholder app fetches blobs + sealed DEKs,
reconstructs the window key, decrypts). The Sealer's only obligations:
stable layouts, the catalog contract, and `sks verify` so the released
plaintext can be tied back to the verified chain.
