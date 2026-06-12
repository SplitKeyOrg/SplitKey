//! Ed25519 detached signatures — device identity, manifests, QR actions.

use crate::{ffi, CryptoError};

pub const PUBLICKEYBYTES: usize = 32;
pub const SECRETKEYBYTES: usize = 64;
pub const SIG_BYTES: usize = 64;

pub type Signature = [u8; SIG_BYTES];

#[derive(Clone)]
pub struct SigKeypair {
    pub public: [u8; PUBLICKEYBYTES],
    pub secret: [u8; SECRETKEYBYTES],
}

impl SigKeypair {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        crate::init();
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        // SAFETY: exact-size buffers.
        let rc = unsafe {
            ffi::crypto_sign_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr())
        };
        assert_eq!(rc, 0);
        Self { public: pk, secret: sk }
    }

    pub fn generate() -> Self {
        Self::from_seed(&crate::random_32())
    }

    /// 8-byte key ID (BLAKE2b fingerprint of the public key).
    pub fn key_id(&self) -> [u8; 8] {
        crate::hash::fingerprint8(&self.public)
    }
}

pub fn sign_detached(msg: &[u8], kp: &SigKeypair) -> Signature {
    crate::init();
    let mut sig = [0u8; SIG_BYTES];
    let mut sig_len: u64 = 0;
    // SAFETY: sig buffer is crypto_sign_BYTES.
    let rc = unsafe {
        ffi::crypto_sign_detached(
            sig.as_mut_ptr(),
            &mut sig_len,
            msg.as_ptr(),
            msg.len() as u64,
            kp.secret.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    debug_assert_eq!(sig_len as usize, SIG_BYTES);
    sig
}

pub fn verify_detached(
    sig: &Signature,
    msg: &[u8],
    public: &[u8; PUBLICKEYBYTES],
) -> Result<(), CryptoError> {
    crate::init();
    // SAFETY: exact-size inputs.
    let rc = unsafe {
        ffi::crypto_sign_verify_detached(
            sig.as_ptr(),
            msg.as_ptr(),
            msg.len() as u64,
            public.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(CryptoError::BadSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_reject() {
        let kp = SigKeypair::generate();
        let sig = sign_detached(b"hello", &kp);
        verify_detached(&sig, b"hello", &kp.public).unwrap();
        assert!(verify_detached(&sig, b"hallo", &kp.public).is_err());
        let other = SigKeypair::generate();
        assert!(verify_detached(&sig, b"hello", &other.public).is_err());
    }
}
