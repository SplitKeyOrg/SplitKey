//! X25519 sealed boxes (`crypto_box_seal`): the envelope step.
//! The device holds only the recipient (Window Key) public key — it can
//! encrypt but never decrypt, including its own past output.

use crate::{ffi, CryptoError};

pub const PUBLICKEYBYTES: usize = 32;
pub const SECRETKEYBYTES: usize = 32;
pub const SEALBYTES: usize = 48; // crypto_box_SEALBYTES = 32 (epk) + 16 (mac)

/// An X25519 keypair (ceremony / release side; the Sealer only ever sees
/// `public`).
#[derive(Clone)]
pub struct BoxKeypair {
    pub public: [u8; PUBLICKEYBYTES],
    pub secret: [u8; SECRETKEYBYTES],
}

impl BoxKeypair {
    /// Deterministic keypair from a 32-byte seed (window-key derivation).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        crate::init();
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        // SAFETY: exact-size buffers.
        let rc = unsafe {
            ffi::crypto_box_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr())
        };
        assert_eq!(rc, 0);
        Self { public: pk, secret: sk }
    }

    pub fn generate() -> Self {
        Self::from_seed(&crate::random_32())
    }
}

/// Seal `plaintext` to `recipient_pk` (ephemeral X25519 + AEAD; anonymous
/// sender). Output is `plaintext.len() + SEALBYTES`.
pub fn seal(plaintext: &[u8], recipient_pk: &[u8; PUBLICKEYBYTES]) -> Vec<u8> {
    crate::init();
    let mut out = vec![0u8; plaintext.len() + SEALBYTES];
    // SAFETY: out sized per contract.
    let rc = unsafe {
        ffi::crypto_box_seal(
            out.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len() as u64,
            recipient_pk.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    out
}

/// Open a sealed box (release side).
pub fn seal_open(sealed: &[u8], kp: &BoxKeypair) -> Result<Vec<u8>, CryptoError> {
    crate::init();
    if sealed.len() < SEALBYTES {
        return Err(CryptoError::BadLength);
    }
    let mut out = vec![0u8; sealed.len() - SEALBYTES];
    // SAFETY: out sized per contract.
    let rc = unsafe {
        ffi::crypto_box_seal_open(
            out.as_mut_ptr(),
            sealed.as_ptr(),
            sealed.len() as u64,
            kp.public.as_ptr(),
            kp.secret.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(CryptoError::SealOpenFailed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_and_wrong_key() {
        let kp = BoxKeypair::generate();
        let other = BoxKeypair::generate();
        let sealed = seal(b"data encryption key", &kp.public);
        assert_eq!(seal_open(&sealed, &kp).unwrap(), b"data encryption key");
        assert_eq!(seal_open(&sealed, &other).unwrap_err(), CryptoError::SealOpenFailed);
    }

    #[test]
    fn deterministic_from_seed() {
        let seed = [7u8; 32];
        assert_eq!(
            BoxKeypair::from_seed(&seed).public,
            BoxKeypair::from_seed(&seed).public
        );
    }
}
