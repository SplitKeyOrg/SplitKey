# Ceremony — key ceremony tooling (`ceremony-cli`)

Generates everything a community needs to start an epoch, replacing
Sealer's test-only `ceremony_sim`. Runs **offline, once per epoch**, on a
machine that is wiped (or never networked) afterward. The real-world
procedure around it is `plans/community-signing.md`; this crate is just the
tool that procedure runs.

Depends on `Sealer/crates/{sealer-crypto, sealer-keys}` and
`crates/sk-shares` (path deps — same repo, one-way: nothing in Sealer
depends back).

## `ceremony new`

```
ceremony new \
  --community maple-street \
  --epoch 1 \
  --start 2026-07-01 --months 18 \
  --window-hours 24 \
  --threshold 3-of-5 \
  --keyholder alice --keyholder bob --keyholder carol \
  --keyholder dave  --keyholder erin \
  --out ./maple-street-epoch1/
```

Steps, in order:

1. Generate the **community admin signing key** (Ed25519) — signs the
   manifest; cameras pin `admin.pub` at enrollment.
2. Generate the **CRK** (32 random bytes, in RAM).
3. For every window in the range: derive the 16-byte window secret and the
   X25519 public key (`crates/sk-shares/README.md` derivation), split the
   secret t-of-n with `sk-shares`.
4. Write the signed **`manifest.skm`** (existing `.skm` format, unchanged).
5. Write one **booklet** per keyholder (below).
6. **Self-check before destroying anything**: for a sample of windows
   (first, last, + random ones), re-combine `t` of the just-written booklet
   *files* (re-parsed from disk, not from memory) and verify the derived
   public key against the manifest. Catches write/encode bugs while the CRK
   still exists to regenerate.
7. Drop the CRK (zeroize). `--keep-crk` writes `crk.secret` instead —
   **dev/sim only**, loudly warned.

Outputs:

```
maple-street-epoch1/
  manifest.skm        → enrolled into every camera
  admin.pub           → pinned by every camera
  admin.key           → community admin custody (signs future manifests);
                        0600, with a printed warning about where it goes
  booklets/
    alice.txt  alice.pdf  bob.txt  bob.pdf  ...   (one .txt + one .pdf per holder)
```

By default each holder gets both a `.txt` (canonical) and a print-ready
`.pdf`. `--no-pdf` skips the PDFs.

## Booklet format (`booklets/<name>.txt`)

Plain text, designed to be printed and then **deleted** (paper is the
medium; the file is an intermediate). The text format is the canonical one
and what `keeper-cli` parses directly in the sim; the PDF below is rendered
from the same data for convenient printing.

```
SplitKey keyholder booklet
community: maple-street    epoch: 1    holder: alice    share 2 of 5 (threshold 3)
windows: 24h UTC, 2026-07-01 .. 2027-12-31

2026-07-01  w20635  abandon ability able about above absent absorb abstract absurd abuse access accident
2026-07-02  w20636  ...
```

One line per window: UTC date, window index, 14 words. The date column is
what a human uses ("we're releasing footage from July 9th"); the window
index is what tooling uses; the words are the share.

## Booklet PDF (`booklets/<name>.pdf`)

Print-ready rendering of the same lines: **DejaVu Sans Mono 8pt**, three
columns per US-Letter page, narrow side margins and a wider top margin so a
stapled booklet's binding never bites the text. Each window is one entry —
its **date and window id in bold**, then the 14 words set fully justified to
the column width (the entry's last line left as-is). Every page is topped by
a plain bold title — `SplitKey share k/n for <community> — holder <name>` —
so a stray sheet is identifiable, with a smaller sub-line carrying epoch,
threshold, window range and page number.

The font is vendored under `assets/fonts/` (open-licensed; see its `LICENSE`)
and compiled into the binary with `include_bytes!`, so PDF output needs
nothing installed on the ceremony machine and the file is self-contained.

## Explicitly out of scope (v1)

- Share re-issuance / keyholder replacement mid-epoch (requires a new
  ceremony; the epoch model already assumes this).
- HSM/air-gap attestation theatrics — the procedure doc handles process;
  the tool stays auditable and small.
- QR codes / per-holder cover pages in the PDF — the booklet PDF prints the
  share lines and nothing fancier.
