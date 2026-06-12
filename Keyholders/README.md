# Keyholders — release tooling (`keeper-cli`)

What a quorum of keyholders runs to release **exactly one window** of
footage, working only from: their paper shares, the public `manifest.skm`,
and read-only access to the storage bucket. No service, no Sealer, no
secrets other than the shares themselves. The future Keyholder desktop app
(`plans/keeper-app.md`, Tauri) wraps this crate's library layer; the CLI is
both the v1 product and the app's test harness.

Depends on `Sealer/crates/{sealer-crypto, sks-format, sealer-chain,
sealer-keys}` and `crates/sk-shares` (path deps, one-way).

## `keeper combine` — shares → window key

```
keeper combine \
  --manifest manifest.skm --admin-pub admin.pub \
  --date 2026-07-09 \
  alice.txt carol.txt erin.txt \
  --out window-20643.key
```

- Accepts whole booklet files (extracts the right line by window index) or
  single pasted lines via stdin — in the real flow each keyholder types
  *one line*, not their whole booklet.
- Each line's 2-byte checksum is verified first (binds window + epoch +
  community — catches typos and wrong-line entry, per share, with a named
  error: "carol.txt line for w20643 failed its checksum").
- After Lagrange combine: derive the X25519 keypair and **require the
  public key to equal the manifest's `window_pubs[w]`** before writing
  anything. A passing combine is therefore *proof* the key is correct.
- Output is the 32-byte window secret key file (0600), or `--stdout-hex`
  for piping straight into `release`.

## `keeper release` — bucket → verified plaintext

```
keeper release \
  --manifest manifest.skm --admin-pub admin.pub \
  --date 2026-07-09 --window-key window-20643.key \
  --store s3://footage?endpoint=http://minio:9000   # or fs:/path
  --out released/2026-07-09/
```

Pipeline (all against dumb storage, read-only credentials):

1. **Enumerate**: LIST the window prefix
   `community/camera/epoch/window/`, fetch `.skc` catalog records, verify
   each device signature against the device key pinned in the segments
   themselves (and cross-check `sig_hash` after fetching).
2. **Fetch** the referenced `.sks` segments.
3. **Verify keylessly** (existing `sealer-chain`): header signatures, body
   hashes, seq continuity, link continuity — the same checks as
   `sks verify`, before any decryption.
4. **Rollup cross-check**: find the `window_close` event for this window
   (first chain event in the next active window — its seq range is in
   plaintext `content_meta`, so this needs no key) and require our highest
   fetched seq to match its `max_seq`. A missing tail then fails loudly as
   *withholding*, not silently as "camera was off". If no close event
   exists yet (window still open / camera gone), that is reported as a
   caveat, not a pass.
5. **Decrypt** each segment with the window key, concatenate per
   `content_meta.container` (`.ts` streams concatenate directly).
6. Write footage + `report.txt`: chain spans, declared events
   (boots/heartbeats/source-loss), findings, notes, the rollup verdict —
   the document a community posts alongside released footage.

Failure stance: verification failures **never block decryption** (the
footage may still be the evidence that matters) but the report says
exactly what failed; the exit code reflects the worst finding.

## `keeper list` — what exists, without any key

```
keeper list --store ... --community maple-street [--camera porch]
```

Reads only `.skc` records: windows with footage, segment counts, time
ranges, content_meta labels, close-event status. This is the "browse before
you request a release" view — and it works for *anyone* with bucket read
access, which is the point: existence is public to the community,
content is not.

## Trust model notes

- The keeper machine sees plaintext (it's doing the release) — run it on a
  keyholder's own machine, not shared infrastructure.
- `admin.pub` must arrive out-of-band (it's the root of manifest trust);
  the CLI refuses to fetch it from the bucket.
- Storage credentials for keepers should be read-only; the camera's are
  write-only. Nobody needs read-write.
