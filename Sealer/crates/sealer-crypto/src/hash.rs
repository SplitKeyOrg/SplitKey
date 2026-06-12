//! BLAKE2b-256 (libsodium `crypto_generichash`) — chain links, body hashes,
//! key fingerprints. Decided hash for the SKS1 suite family.

use crate::ffi;

pub type Hash32 = [u8; 32];

/// BLAKE2b-256 over `data` (unkeyed).
pub fn blake2b256(data: &[u8]) -> Hash32 {
    crate::init();
    let mut out = [0u8; 32];
    // SAFETY: out/data pointers and lengths are valid; key is null/0.
    let rc = unsafe {
        ffi::crypto_generichash(
            out.as_mut_ptr(),
            out.len(),
            data.as_ptr(),
            data.len() as u64,
            std::ptr::null(),
            0,
        )
    };
    debug_assert_eq!(rc, 0);
    out
}

/// Incremental BLAKE2b-256 for hashing large bodies without buffering.
pub struct Hasher {
    state: ffi::crypto_generichash_state,
}

impl Hasher {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        crate::init();
        let mut state = std::mem::MaybeUninit::<ffi::crypto_generichash_state>::uninit();
        // SAFETY: init writes the state; null key.
        let rc = unsafe {
            ffi::crypto_generichash_init(state.as_mut_ptr(), std::ptr::null(), 0, 32)
        };
        assert_eq!(rc, 0);
        Self {
            state: unsafe { state.assume_init() },
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let rc = unsafe {
            ffi::crypto_generichash_update(&mut self.state, data.as_ptr(), data.len() as u64)
        };
        debug_assert_eq!(rc, 0);
    }

    pub fn finalize(mut self) -> Hash32 {
        let mut out = [0u8; 32];
        let rc =
            unsafe { ffi::crypto_generichash_final(&mut self.state, out.as_mut_ptr(), out.len()) };
        debug_assert_eq!(rc, 0);
        out
    }
}

/// 8-byte key fingerprint: first 8 bytes of BLAKE2b-256(input).
/// Used for `device_key_id` / `admin key ID` fields.
pub fn fingerprint8(data: &[u8]) -> [u8; 8] {
    let h = blake2b256(data);
    let mut f = [0u8; 8];
    f.copy_from_slice(&h[..8]);
    f
}
