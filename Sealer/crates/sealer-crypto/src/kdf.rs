//! Ceremony-side key derivation: CRK → per-window X25519 keypair seeds.
//!
//! `crypto_kdf` (BLAKE2b-based): subkey_id = window_index, context fixed.
//! Deterministic, so the whole epoch's manifest is one generation pass and
//! a release tool holding the CRK (ceremony machine only!) can re-derive
//! any window. The Sealer never links this module's derivation path with a
//! secret — it only ever consumes public keys.

use crate::ffi;

/// 8-byte libsodium KDF context — fixed for window-key derivation.
pub const WINDOW_KDF_CONTEXT: &[u8; 8] = b"SKWINDOW";

/// Derive the **16-byte window secret** — the value the ceremony
/// Shamir-splits into keyholder shares (`crates/sk-shares`). 16 bytes, not
/// 32: X25519 offers ~128-bit security, so a longer secret would add
/// booklet words, not strength.
pub fn derive_window_secret(crk: &[u8; 32], window_index: u64) -> [u8; 16] {
    crate::init();
    let mut secret = [0u8; 16];
    // SAFETY: exact-size buffers; context is exactly 8 bytes; 16 is within
    // crypto_kdf's 16..=64 subkey range.
    let rc = unsafe {
        ffi::crypto_kdf_derive_from_key(
            secret.as_mut_ptr(),
            secret.len(),
            window_index,
            WINDOW_KDF_CONTEXT.as_ptr().cast(),
            crk.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    secret
}

/// Window secret → 32-byte X25519 seed. The release side reconstructs the
/// secret from shares and joins the derivation here.
pub fn window_seed_from_secret(secret: &[u8; 16]) -> [u8; 32] {
    crate::hash::blake2b256(secret)
}

/// Derive the 32-byte seed for window `window_index` from the CRK.
pub fn derive_window_seed(crk: &[u8; 32], window_index: u64) -> [u8; 32] {
    window_seed_from_secret(&derive_window_secret(crk, window_index))
}

/// Derive the full window keypair (ceremony / release tooling).
pub fn derive_window_keypair(crk: &[u8; 32], window_index: u64) -> crate::BoxKeypair {
    crate::BoxKeypair::from_seed(&derive_window_seed(crk, window_index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_distinct() {
        let crk = [42u8; 32];
        let a = derive_window_seed(&crk, 1000);
        let b = derive_window_seed(&crk, 1000);
        let c = derive_window_seed(&crk, 1001);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn share_reconstruction_path_matches_ceremony_path() {
        // The keeper only ever sees the 16-byte secret (from shares); its
        // derived keypair must equal the ceremony's manifest keypair.
        let crk = [7u8; 32];
        let secret = derive_window_secret(&crk, 20_000);
        let via_secret = crate::BoxKeypair::from_seed(&window_seed_from_secret(&secret));
        let via_crk = derive_window_keypair(&crk, 20_000);
        assert_eq!(via_secret.public, via_crk.public);
    }
}
