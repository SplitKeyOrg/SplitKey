
Context, read ../OVERVIEW.md

We will be implementation the on device software for encrpytion. 

# Need to detail software archetecture of the Sealer app

* runs on edge devices, any type of security cam. low power door bells, HD 4k
  cams and everything in between. 
  
* Ideally can be 'tacked' onto any existing system. Not sure of all the
  platforms, but Linux, Windows, (cross platform) but not sure if other major
  camera manufactures have their own custom OS platforms. 
  
* Potentially, just specify a directory and some keys and it waits for new
  files, makes sure they are closed, then encrypts the file.
  
* Should outline what the command line arguments might be, or how this thing
  will be configured. Preferably a file for easy deployments.

* Rust is the right language for targeting lower power devices.

* Chose encryption method. Should be configurable. To start:
  - AES-256-GCM if the camera SoC has AES hardware (ARMv8 Crypto Extensions, or x86 AES-NI). Fast, standard.
  - ChaCha20-Poly1305 / XChaCha20-Poly1305 if it doesn't. This is the one I'd default to for cheap camera silicon. It's fast in pure software, constant-time by design (no table lookups, so no cache-timing side channels), and tiny in memory — the cipher state is a few hundred bytes. It was basically built for the "no AES hardware" mobile/embedded case.

The "X" variant (XChaCha20) matters more than it looks: its 192-bit nonce means you can use random nonces without realistic collision risk. That's important on a device that reboots, loses a counter, or restores from backup — because nonce reuse under the same key is catastrophic for both GCM and ChaCha20-Poly1305 (you leak the keystream XOR, and for GCM you can recover the auth key). Either persist a monotonic counter to flash religiously, or sidestep the whole problem with random XChaCha20 nonces.


# Need to detail implementation of key rolling for time windows

* every defined period, like 1 hour, 12 hours, 24 hours (depending on community)
  a new key is derived from some master key (name?). Then they can release only
  a specific time period. Mind the gaps, DST, time zones. Time sync.

* the master key will get rotated like every 12 months on a community key
  signing meeting. May have extra 6 months incase they can't meet, or it will
  roll over to first of the year again and re-use keys. (leap year keys?)

# Tamper resistant

Tamper-evidence and chain of custody. This is almost free given per-segment AEAD tags, and it's the highest-value addition. Chain the segments — each segment's authenticated header commits to the previous segment's tag hash — so the whole recording becomes a hash chain (or a Merkle tree if you want efficient partial verification). Now anyone can prove the footage is continuous and unaltered, and critically, dropping or reordering segments becomes detectable rather than silent. Pair that with signed capture timestamps (a monotonic counter signed by the device key, optionally anchored to an RFC 3161 timestamp authority or a transparency log when network's available) and you can prove when something was recorded, not just that it wasn't tampered with. The endgame is footage that's actually evidentiary — admissible because its integrity is mathematically demonstrable, not just "trust our NVR." Gap detection drops out of the same chain: missing segments leave a visible discontinuity.

* Perhaps a secondary project, but need to also consider how we can verify the
  firmware has not been tampered with.


# Storage

After encryption, we should have configurable options to what to do next. I
think these make sense for a security cam.

* sft, ftp, http.
* S3 or eqiuvilant will be common.
* RustFS an s3 compatable we can run local (maybe overkill)
* Need config options and credentials handling.

considerations, withholding and deletion is the subtle issue. your hash chain
detects tampering, but a storage provider (or a malicious insider with storage
access) could silently delete or withhold segments, and a missing segment looks
the same as a camera that was offline. Object Lock / WORM (write-once-read-many)
and versioning are the answer — set a retention lock so blobs can't be deleted
before policy allows, even by an admin. That turns "trust the storage operator
not to destroy evidence" into a cryptographically/policy-enforced guarantee,
which is exactly the kind of property an institution needs.

* Might also need a metadata store. Something has to know what footage exists
  without being able to read it: a catalog of which camera produced which
  segment, the time range, where the blob lives, the sealed (still-encrypted)
  data key for that segment, and the hash-chain links and signatures. 
  (can be a seperate service but Sealer would need to interact with it)
  

# QR Code actions

Print out a qr code and show it to the security cam to adjust the SplitKey
settings or probe the device.

* Ex, show a qr code to update the master keys
* QR code for some kind of community verification.
* QR code security is a concern however.


# Inline vs. directory-watcher

The directory daemon (inotify, encrypt each completed segment, delete plaintext)
is simpler and crash-robust, but it has two real costs on embedded hardware:
plaintext hits the SD card before you encrypt it (a window of exposure), and you
triple your flash I/O — write plaintext, read it, write ciphertext, delete
plaintext. On a camera with a cheap SD card, flash wear is a genuine
concern. Inline encryption (encrypt segments in RAM as they're muxed, before
they ever touch disk) avoids both but means hooking into the recording
pipeline. For a privacy-focused design I'd lean inline; for a quick robust
prototype, the watcher gets you there faster.


Either way, don't encrypt the whole stream as one blob — segment it (per HLS .ts
chunk, or per N seconds / N MB) so you can stream, recover from partial
corruption, and decrypt incrementally. Use a proper streaming AEAD construction
rather than hand-rolling chunk boundaries, because naïve chunking is vulnerable
to truncation and reordering attacks (an attacker drops the last 10 segments and
you can't tell).

# Envelope encryption with an asymmetric key.

One potential implementation:

Per segment, generate a random symmetric data key (DEK).
Encrypt the video with the DEK (XChaCha20-Poly1305).
Encrypt the DEK to a public key (X25519).
The camera holds only the public key. It can encrypt but cannot decrypt
anything, including its own past footage. The private key lives off-device —
owner's phone, an offline machine, an HSM.

# Encryption Libraries

- libsodium is my top pick for embedded. crypto_secretstream_xchacha20poly1305_* is purpose-built for exactly this: encrypt a sequence of messages as a stream, with built-in chunking, per-chunk auth, rekeying for forward secrecy, and an explicit "final" tag so truncation is detectable. Pair it with crypto_box_seal for the envelope step (ephemeral X25519 + AEAD, camera needs only the recipient public key). Small, fast, portable, runs comfortably on embedded Linux.
- RustCrypto (chacha20poly1305, aes-gcm) if you want to build it in Rust
  directly.
  
   dryoc or a libsodium binding gives you secretstream directly, age/rage gives you the envelope design essentially for free, and the RustCrypto crates (chacha20poly1305, x25519-dalek, plus a Shamir crate)

If the SoC has a hardware TRNG, use it for key and nonce generation rather than
/dev/urandom alone on a freshly-booted device with thin entropy.


# Testing and builds

For primary release, we will have to focus on Linux. So perhaps we need a docker
container that we can run simulations in?


# Hardware
Will initially use Raspberry Pi Zero 2 W + Camera Module 3 (IMX708) for testing
and demo.

Other boards people will use:

Luckfox Pico family (Rockchip RV1106/RV1103). These are purpose-built as
IP-camera SoMs — Cortex-A7 at 1.2GHz, a hardware ISP doing up to 4–5MP at 30fps,
a 2-lane MIPI CSI input, and crucially hardware H.264/H.265 encoding on the SoC,
which is exactly the "compress, then hand the bitstream to your encrypt stage"
pipeline from earlier. The Pico Pro has 128MB DDR2, the Max 256MB,

ESP32 could possibly be another small device if we can make it work there.

OpenIPC will be another common place this will be deployed/installed.

Eventually vendors like Axis ACAP.

# Camera video feed

Consider the various outputs of the camera and how we will access those from windows,
linux, wire, or possibly IP. Essentialy, input to the Sealer.


# Demo deployments

https://github.com/Motion-Project/motion
Kerberos.io
Frigate https://frigate.video/


# Goal

Work inside the Sealer/ directory.

Generate complete plans for the software archetecture and implementation.

Generate as many files as needed but stay short of writing the implementation
code. Focus on planning.

Feel free to augment the software plans with new idea suggestions for SplitKey project as
a whole. 

Surface unresolved questions.

