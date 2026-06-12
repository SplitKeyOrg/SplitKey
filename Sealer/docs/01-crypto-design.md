# 01 — Cryptographic Design

## Cipher suites

Configurable, negotiated once per deployment and recorded in every segment
header (so verifiers know what to expect — no in-band negotiation, no
downgrade surface).

| Suite ID | AEAD | Envelope | When |
|----------|------|----------|------|
| `SKS1-XCHACHA` (default) | XChaCha20-Poly1305 secretstream | X25519 sealed box | Default. Cheap camera silicon without AES hardware; constant-time in pure software; tiny state. |
| `SKS1-AESGCM` | AES-256-GCM (STREAM construction) | X25519 sealed box | Opt-in when the SoC has ARMv8 Crypto Extensions or x86 AES-NI and throughput matters (4K multi-stream NVRs). |

Rationale (carried from planning discussion):

- **XChaCha20-Poly1305 is the default** because the target fleet skews toward
  cheap SoCs (Cortex-A7, RV1106) with no AES instructions. ChaCha20 is fast in
  software, constant-time by design (no table lookups → no cache-timing side
  channels), and its cipher state is a few hundred bytes.
- **The X (192-bit nonce) variant is load-bearing.** Random nonces are safe at
  any realistic volume, which sidesteps the catastrophic-nonce-reuse problem
  on devices that reboot, lose counters, or restore from backup. Nonce reuse
  under one key leaks keystream XOR for both families and additionally leaks
  the GHASH auth key for GCM. We choose *random XChaCha20 nonces* over
  *religiously persisted counters* as the primary design; AES-GCM mode must
  use the STREAM construction with a per-segment random prefix + counter and
  is only safe because each DEK is single-use (see below).
- **Every DEK is used for exactly one segment.** This bounds nonce-reuse risk
  structurally, limits blast radius of any single-key compromise, and is what
  makes per-window release granularity possible.

## Streaming AEAD — why not "encrypt the file"

A segment is encrypted as a **secretstream** (libsodium
`crypto_secretstream_xchacha20poly1305`): a sequence of AEAD chunks with:

- per-chunk authentication (corruption localized to one chunk),
- internal chunk sequencing (reordering within a segment is detectable),
- automatic rekeying support,
- an explicit **FINAL tag**, so truncation of a segment is detectable.

Naïve hand-rolled chunking is vulnerable to truncation and reordering
attacks (drop the last 10 chunks and nothing notices); secretstream's design
exists precisely to prevent that. Chunk size: 64 KiB default (tunable;
trade-off between RAM and per-chunk tag overhead of 17 B + header).

Cross-*segment* truncation/reordering is handled one layer up by the hash
chain ([04-tamper-evidence.md](04-tamper-evidence.md)).

## Envelope encryption

Per segment:

```
DEK        = random 32 bytes                      (CSPRNG, see RNG section)
ciphertext = SecretStream_Encrypt(DEK, plaintext chunks ... FINAL)
sealed_dek = crypto_box_seal(DEK ‖ stream_header, WK_pub[window_id])
```

- `crypto_box_seal` = ephemeral X25519 + XSalsa20/XChaCha-Poly1305; the
  sender needs **only the recipient public key** and the ciphertext is
  non-attributable to a sender key. Exactly the write-only property we want.
- The device holds the **pubkey manifest** (every window's public key for the
  epoch) and nothing else. It cannot decrypt anything, including its own
  past output.
- The sealed DEK travels *inside* the segment header, and is also reported to
  the metadata catalog so a release can proceed even if headers must be
  fetched lazily.

Decryption (Keyholder app, out of scope here) reconstructs the Window Key
private half via quorum, opens `sealed_dek`, then decrypts the stream.

**AAD binding:** the entire segment header (camera ID, window ID, segment
index, timestamps, prev-chain link, suite ID) is fed as additional
authenticated data into the first secretstream chunk, cryptographically
binding ciphertext to its claimed position and provenance. A segment cannot
be replayed under a different identity or time slot.

## Library choices

| Layer | Choice | Notes |
|-------|--------|-------|
| Primary crypto | **libsodium** (decided) via `libsodium-sys-stable` FFI + a thin safe wrapper inside `sealer-crypto` | `secretstream` + `box_seal` are purpose-built for this design. dryoc (pure-Rust, API-compatible) stays available as a feature-flag fallback for targets where the C toolchain is painful. |
| AES-GCM suite | RustCrypto `aes-gcm` | Only compiled when the suite is enabled. |
| Signing | Ed25519 (`ed25519-dalek` or libsodium) | Device identity + manifests + QR actions. |
| KDF | HKDF-SHA-256 / libsodium `kdf` | Window key derivation (ceremony side, not on device). |
| Shamir | `vsss-rs` or `sharks` (audit before adoption) | Used by ceremony/Keyholder tooling, **not** by the Sealer — listed here so the whole stack shares one choice. |
| Hashing | **BLAKE2b-256** (libsodium `crypto_generichash`) — decided | Chain links, body hashes, key fingerprints. Recorded in suite ID. |

Decided: **libsodium** is the backend (longest audit pedigree, hand-tuned
NEON) unless a specific hardware target forces otherwise. The `sealer-crypto`
API stays backend-agnostic so dryoc/RustCrypto can be swapped in behind a
feature flag for exotic targets (ESP32).

## RNG

- Primary: OS CSPRNG (`getrandom`).
- **Boot-time entropy on embedded is a real hazard**: a freshly booted
  headless board may have thin entropy, and DEK generation starts
  immediately. Mitigations, in order:
  1. If the SoC has a hardware TRNG (RV1106 does, BCM2710 has one), feed it
     in (typically the kernel already does; verify per target).
  2. Block sealing until the kernel reports the entropy pool initialized
     (`getrandom` blocking semantics already give us this on modern kernels —
     do not work around it).
  3. Persist a random seed file across boots (like `systemd-random-seed`),
     mixed in, never trusted alone.
- Nonces: random via the same CSPRNG (XChaCha's 192-bit space makes this
  safe). secretstream generates its own header nonce internally.

## What is deliberately NOT on the device

- Community Root Key or any share of it.
- Window Key private halves.
- Any symmetric key that outlives one segment.
- Credentials with delete/overwrite rights on storage (see
  [06-storage.md](06-storage.md) — upload-only credentials).

## Known cryptographic risks to track

1. **Pubkey manifest substitution**: if an attacker can swap the manifest,
   footage gets sealed to *their* key. Manifest is Ed25519-signed by the
   community admin key created at ceremony; device pins that verify key at
   enrollment. Rotation of the admin key requires a QR/ceremony action signed
   by the old key. See [08-qr-actions.md](08-qr-actions.md).
2. **Device signing key theft** ≠ footage exposure, but allows forging chain
   continuity for *future* fabricated segments. Mitigate: keep it in a TPM /
   OP-TEE / secure element where available; include device-key fingerprint in
   the catalog so a re-keyed device is conspicuous.
3. **Quantum**: X25519 sealed footage recorded today could be harvested for
   future decryption. Decided: v1 ships X25519-only, keeping it simple; the
   suite ID mechanism exists so a hybrid X25519+ML-KEM suite can be added
   later without format breakage.
