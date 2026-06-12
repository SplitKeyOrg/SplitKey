# SplitKey

**Security without surveillance.**

SplitKey lets a community run security cameras
that *nobody* can secretly watch. Footage is encrypted the instant it leaves
the lens. The only way to ever see it: a quorum of trusted community members
— each holding printed paper key shares — agree to unlock **one specific
day**. Not the archive. Not a live feed. One day.

The camera keeps custody of what happened. The community keeps control of
who gets to see it.


---

## The problem

Every conventional camera system has a someone-with-the-password problem:

- **Stalking & abuse** — a landlord, manager, or anyone with dashboard access
  can watch individuals come and go
- **Mission creep** — "security" archives quietly become HR tools, eviction
  evidence, or feeds for whoever asks
- **One breach = everything** — a single compromised account or cloud bucket
  exposes months of footage of everyone
- **No accountability** — who watches the watchers? Nobody, verifiably.

## How SplitKey answers it

1. **Seal at the source.** The camera (or a small box next to it) encrypts
   footage in memory, immediately — plaintext video never even touches disk.
2. **One key per day.** Each day (a *window*) gets its own encryption key.
   Unlocking Tuesday reveals nothing about Wednesday.
3. **Split the keys onto paper.** At a public *key ceremony*, every day's key
   is split into shares (e.g. 5) and printed into booklets — one per
   *keyholder*. The master key is destroyed on the spot.
4. **Quorum to unlock.** Releasing a day takes a threshold (e.g. any 3 of 5)
   keyholders reading that day's line of words from their booklets. Fewer
   shares reveal mathematically *nothing* — not "hard to crack," nothing.
5. **Tamper-evident by construction.** Every sealed segment is signed and
   hash-chained. Anyone — no key required — can verify nothing was deleted,
   reordered, swapped, or spliced, and the verifier names the attack it finds.

No single person — not the camera owner, not a keyholder, not the storage
operator, not whoever steals the SD card — can watch footage alone.

---

## See it run

The entire loop, end to end, one command (needs Docker + Rust):

```bash
./demo-release-loop.sh
```

It holds a key ceremony (5 booklets, 3-of-5), seals footage into an
S3-compatible store, then plays three keyholders combining their paper words
to release exactly one verified day. Other demos:

| Demo | Shows |
|------|-------|
| `Sealer/demo.sh` | Seven tampering attacks, each caught **and named** by keyless verification |
| `Sealer/demo-usbcam.sh` | Live USB-camera footage sealed in RAM → released → playable video (macOS) |
| `Sealer/sim/` | Docker fleet with WORM object-lock storage — even the storage *admin* can't delete sealed footage |
| `Examples/splitkey-motion-cam/` | Real deployable appliance: motion-triggered USB camera, sealed archive |

---

## What's in this repo

```
Sealer/        the camera side: sealing daemon, formats, tamper verification
Ceremony/      ceremony-cli — generates an epoch: manifest + paper booklets
Keyholders/    keeper-cli — combine shares, verify, release one window
crates/        sk-shares — the share format both sides speak (spec + test vectors)
Examples/      deployable camera appliances
plans/         design notes for what's next (Keyholder desktop app, governance)
```

The layout enforces the security model: `Sealer/` never depends on the share
code — a camera *cannot* link the ability to reconstruct keys. It holds only
public keys and can only ever write.

**Status:** the cryptographic core, camera daemon, ceremony and release
tooling are built, tested (50+ tests including named tamper drills), and
validated live — real webcam footage sealed, a real MinIO store, real
booklet words typed back in. Next up: printable PDF booklets, a desktop
Keyholder app, and a request/release portal. See `Sealer/docs/10-roadmap.md`.

---

## Glossary

How all the pieces fit, in the order they meet the world:

### People

| Term | Meaning |
|------|---------|
| **Community** | Whoever the cameras serve — a block, an HOA, a co-op, a town. Picks its keyholders and its threshold. |
| **Keyholder** | A trusted community member holding one booklet of paper key shares. Participates in release decisions. |
| **Community admin** | Holds the signing key that blesses the manifest cameras trust. Signs *public* keys only — cannot decrypt anything. |
| **Petitioner** | Someone asking for a release (a resident, a victim, police). Today this is a human process; a portal is planned. |

### Ceremony & paper

| Term | Meaning |
|------|---------|
| **Key ceremony** | A public, offline event (once per epoch) where all keys are generated, split, printed — and the master key destroyed. Run by `ceremony-cli`. |
| **Epoch** | The period one ceremony covers (~18 months of daily keys). |
| **Window** | The unit of release — typically one UTC day. One key per window. |
| **CRK (Community Root Key)** | The master secret that derives every window key. Exists only in RAM, only during the ceremony, then is destroyed. Recovery redundancy comes from enrolling more keyholders than the threshold, not from backups. |
| **Window secret** | The 16-byte per-window value that is actually Shamir-split. Reconstructing it yields that window's private key — and only that window's. |
| **Share** | One keyholder's fragment of one window secret. Encoded as **14 words** with a checksum that catches typos *and* reading the wrong line. |
| **Booklet** | One keyholder's printed book: one line of words per day, ~550 lines per epoch. Made to be printed, handed over, and never stored digitally. |
| **Threshold (t-of-n)** | How many keyholders must combine shares to release a window — e.g. 3-of-5. Fewer than *t* shares carry zero information. |
| **Manifest (`.skm`)** | The signed list of every window's *public* key. The only key material a camera ever holds. |

### On the camera

| Term | Meaning |
|------|---------|
| **Sealer / `sealerd`** | The daemon that turns video into sealed segments. Takes footage from a watched folder or a direct in-memory pipe (plaintext never on disk). |
| **Sealing** | Envelope encryption: each segment gets a fresh random key (DEK), which is locked to the current window's public key. Write-only — the camera can encrypt to a window but never decrypt it. |
| **Segment (`.sks`)** | The sealed unit: ~a minute of encrypted footage plus a signed header (camera, time, window, chain link). Self-contained — everything needed to verify and (with the window key) decrypt. |
| **Hash chain** | Every segment cryptographically links to the previous one with a gap-free sequence number. Delete one, the chain says exactly which. |
| **Chain events** | Tiny signed segments declaring boots, heartbeats, camera-feed loss, and **window closes** — so silence is bounded and explainable. A camera that records nothing still proves it was alive. |
| **`window_close`** | The rollup event sealed when a day ends, pinning exactly how many segments that day produced. Truncating a day's tail then requires wiping every later day — conspicuous by design. |
| **Catalog record (`.skc`)** | A small signed sidecar uploaded with each segment: *what exists* (time range, labels, chain position) without being able to show a single pixel. Lets anyone browse and audit without keys. |
| **Spool / sink** | Store-and-forward: sealed segments queue locally and upload to any number of storage backends (local disk, NAS, any S3-compatible service). Storage is **untrusted** — it holds ciphertext and can't alter it undetected. |
| **WORM / object lock** | Recommended storage mode: write-once retention, so even the storage administrator cannot delete sealed footage before policy allows. |

### Release

| Term | Meaning |
|------|---------|
| **Combine** | `keeper combine`: t keyholders' lines → the window key, verified against the manifest before anything is decrypted. A passing combine is *proof* the key is right. |
| **Release** | `keeper release`: fetch one window from storage, verify every signature, the chain, and the rollup, then decrypt to playable video plus a report. |
| **Keyless verification** | The integrity checks (`sks verify`, and inside `release`) that anyone can run with **no decryption ability** — tampering is provable without exposing footage. |
| **Release report** | The document written next to released footage: what was verified, what was found, what was *not provable* — fit for posting publicly or handing to a court. |
| **Verdict** | `VERIFIED — no findings`, or `RELEASED WITH FINDINGS` naming each problem (gap, splice, truncated tail, missing blob…). Findings never block release; they get named. |

---

## Principles

1. **Privacy by default** — footage is sealed before anyone could view it
2. **Distributed trust** — no single point of control, failure, or coercion
3. **Bounded access** — one window per release; never the archive
4. **Verifiable, not trusted** — integrity is checked by math anyone can run
5. **Paper is a feature** — shares live offline, in pockets, not in clouds
6. **Community governance** — thresholds, keyholders, and retention are the
   community's choices, not the software's

---

## License

MIT — see [LICENSE](LICENSE).
