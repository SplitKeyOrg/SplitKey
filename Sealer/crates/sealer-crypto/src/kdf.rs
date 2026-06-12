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

/// Derive the 32-byte seed for window `window_index` from the CRK.
pub fn derive_window_seed(crk: &[u8; 32], window_index: u64) -> [u8; 32] {
    crate::init();
    let mut seed = [0u8; 32];
    // SAFETY: exact-size buffers; context is exactly 8 bytes.
    let rc = unsafe {
        ffi::crypto_kdf_derive_from_key(
            seed.as_mut_ptr(),
            seed.len(),
            window_index,
            WINDOW_KDF_CONTEXT.as_ptr().cast(),
            crk.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    seed
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
}
