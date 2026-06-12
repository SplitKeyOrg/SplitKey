//! Thin, safe wrapper over libsodium for the SplitKey Sealer.
//!
//! Exposes exactly the primitives the design uses (docs/01-crypto-design.md):
//! - XChaCha20-Poly1305 secretstream (per-segment streaming AEAD)
//! - `crypto_box_seal` envelope (X25519 sealed boxes, write-only device)
//! - Ed25519 detached signatures (device / admin keys)
//! - BLAKE2b-256 (`crypto_generichash`) for chain links and fingerprints
//! - `crypto_kdf` for ceremony-side window-key derivation
//!
//! Backend is libsodium (decided); the API deliberately hides FFI types so a
//! pure-Rust backend can be swapped in behind a feature flag later.

pub(crate) use libsodium_sys as ffi; // lib target of the libsodium-sys-stable package

use std::sync::Once;

pub mod hash;
pub mod kdf;
pub mod sealbox;
pub mod secretstream;
pub mod sign;

pub use hash::{blake2b256, fingerprint8, Hash32};
pub use sealbox::{seal, seal_open, BoxKeypair, SEALBYTES};
pub use secretstream::{PullStream, PushStream, Tag, KEYBYTES, STREAM_HEADERBYTES, TAG_OVERHEAD};
pub use sign::{sign_detached, verify_detached, SigKeypair, Signature, SIG_BYTES};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("AEAD authentication failed (corrupted or forged data)")]
    AuthFailed,
    #[error("signature verification failed")]
    BadSignature,
    #[error("sealed box could not be opened (wrong key or corrupted)")]
    SealOpenFailed,
    #[error("secretstream truncated: FINAL tag never seen")]
    Truncated,
    #[error("invalid key or input length")]
    BadLength,
}

static SODIUM_INIT: Once = Once::new();

/// Initialize libsodium. Idempotent; called lazily by every entry point,
/// callable explicitly at program start.
pub fn init() {
    SODIUM_INIT.call_once(|| {
        // SAFETY: sodium_init may be called multiple times; Once serializes
        // the first call. Negative return = failure.
        let rc = unsafe { ffi::sodium_init() };
        assert!(rc >= 0, "sodium_init failed: no safe way to continue");
    });
}

/// Fill `buf` with cryptographically secure random bytes (OS CSPRNG via
/// libsodium; on Linux this blocks until the kernel entropy pool is ready,
/// which is exactly the boot-entropy behavior the design requires).
pub fn random_bytes(buf: &mut [u8]) {
    init();
    unsafe { ffi::randombytes_buf(buf.as_mut_ptr().cast(), buf.len()) };
}

/// Convenience: a fresh random 32-byte key/seed.
pub fn random_32() -> [u8; 32] {
    let mut k = [0u8; 32];
    random_bytes(&mut k);
    k
}

/// Constant-time equality.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    init();
    unsafe { ffi::sodium_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0 }
}
