//! XChaCha20-Poly1305 secretstream: the per-segment streaming AEAD
//! (docs/01-crypto-design.md). Per-chunk auth, internal sequencing, and an
//! explicit FINAL tag so truncation is detectable.

use crate::{ffi, CryptoError};

pub const KEYBYTES: usize = 32; // crypto_secretstream_xchacha20poly1305_KEYBYTES
pub const STREAM_HEADERBYTES: usize = 24; // ..._HEADERBYTES
pub const TAG_OVERHEAD: usize = 17; // ..._ABYTES

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Message,
    /// Last chunk of the segment. Absence at end-of-data = truncation.
    Final,
}

fn tag_byte(tag: Tag) -> u8 {
    // SAFETY: plain constant getters.
    unsafe {
        match tag {
            Tag::Message => ffi::crypto_secretstream_xchacha20poly1305_tag_message(),
            Tag::Final => ffi::crypto_secretstream_xchacha20poly1305_tag_final(),
        }
    }
}

/// Encrypting side. Created with a fresh single-use DEK; yields the 24-byte
/// stream header that must be sealed into the envelope alongside the DEK.
pub struct PushStream {
    state: ffi::crypto_secretstream_xchacha20poly1305_state,
    header: [u8; STREAM_HEADERBYTES],
}

impl PushStream {
    pub fn new(key: &[u8; KEYBYTES]) -> Self {
        crate::init();
        let mut state =
            std::mem::MaybeUninit::<ffi::crypto_secretstream_xchacha20poly1305_state>::uninit();
        let mut header = [0u8; STREAM_HEADERBYTES];
        // SAFETY: state is written by init_push; header/key sizes are exact.
        let rc = unsafe {
            ffi::crypto_secretstream_xchacha20poly1305_init_push(
                state.as_mut_ptr(),
                header.as_mut_ptr(),
                key.as_ptr(),
            )
        };
        assert_eq!(rc, 0);
        Self {
            state: unsafe { state.assume_init() },
            header,
        }
    }

    /// The stream header to be sealed (with the DEK) into the envelope.
    pub fn header(&self) -> &[u8; STREAM_HEADERBYTES] {
        &self.header
    }

    /// Encrypt one chunk. `ad` is additional authenticated data (the segment
    /// header hash for the first chunk, empty afterwards).
    pub fn push(&mut self, plaintext: &[u8], ad: &[u8], tag: Tag) -> Vec<u8> {
        let mut out = vec![0u8; plaintext.len() + TAG_OVERHEAD];
        let mut out_len: u64 = 0;
        // SAFETY: out is sized to plaintext + ABYTES as required.
        let rc = unsafe {
            ffi::crypto_secretstream_xchacha20poly1305_push(
                &mut self.state,
                out.as_mut_ptr(),
                &mut out_len,
                plaintext.as_ptr(),
                plaintext.len() as u64,
                if ad.is_empty() { std::ptr::null() } else { ad.as_ptr() },
                ad.len() as u64,
                tag_byte(tag),
            )
        };
        assert_eq!(rc, 0);
        out.truncate(out_len as usize);
        out
    }
}

/// Decrypting side (release tooling / tests).
pub struct PullStream {
    state: ffi::crypto_secretstream_xchacha20poly1305_state,
    finished: bool,
}

impl PullStream {
    pub fn new(key: &[u8; KEYBYTES], header: &[u8; STREAM_HEADERBYTES]) -> Result<Self, CryptoError> {
        crate::init();
        let mut state =
            std::mem::MaybeUninit::<ffi::crypto_secretstream_xchacha20poly1305_state>::uninit();
        // SAFETY: exact-size inputs; init_pull validates the header.
        let rc = unsafe {
            ffi::crypto_secretstream_xchacha20poly1305_init_pull(
                state.as_mut_ptr(),
                header.as_ptr(),
                key.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(CryptoError::AuthFailed);
        }
        Ok(Self {
            state: unsafe { state.assume_init() },
            finished: false,
        })
    }

    /// Decrypt one chunk; returns (plaintext, tag). Errors on forgery,
    /// corruption, reordering, or chunks after FINAL.
    pub fn pull(&mut self, ciphertext: &[u8], ad: &[u8]) -> Result<(Vec<u8>, Tag), CryptoError> {
        if self.finished {
            return Err(CryptoError::AuthFailed); // data after FINAL
        }
        if ciphertext.len() < TAG_OVERHEAD {
            return Err(CryptoError::BadLength);
        }
        let mut out = vec![0u8; ciphertext.len() - TAG_OVERHEAD];
        let mut out_len: u64 = 0;
        let mut tag: u8 = 0;
        // SAFETY: out is sized to ciphertext - ABYTES as required.
        let rc = unsafe {
            ffi::crypto_secretstream_xchacha20poly1305_pull(
                &mut self.state,
                out.as_mut_ptr(),
                &mut out_len,
                &mut tag,
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                if ad.is_empty() { std::ptr::null() } else { ad.as_ptr() },
                ad.len() as u64,
            )
        };
        if rc != 0 {
            return Err(CryptoError::AuthFailed);
        }
        out.truncate(out_len as usize);
        let tag = if tag == tag_byte(Tag::Final) {
            self.finished = true;
            Tag::Final
        } else {
            Tag::Message
        };
        Ok((out, tag))
    }

    /// True once the FINAL-tagged chunk has been pulled. If the data ends
    /// before this is true, the stream was truncated.
    pub fn finished(&self) -> bool {
        self.finished
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_ad_and_final() {
        let key = crate::random_32();
        let mut push = PushStream::new(&key);
        let header = *push.header();
        let ad = b"segment-header-hash";
        let c1 = push.push(b"chunk one", ad, Tag::Message);
        let c2 = push.push(b"chunk two", &[], Tag::Final);

        let mut pull = PullStream::new(&key, &header).unwrap();
        let (p1, t1) = pull.pull(&c1, ad).unwrap();
        assert_eq!((p1.as_slice(), t1), (b"chunk one".as_slice(), Tag::Message));
        let (p2, t2) = pull.pull(&c2, &[]).unwrap();
        assert_eq!((p2.as_slice(), t2), (b"chunk two".as_slice(), Tag::Final));
        assert!(pull.finished());
    }

    #[test]
    fn detects_corruption_reorder_and_wrong_ad() {
        let key = crate::random_32();
        let mut push = PushStream::new(&key);
        let header = *push.header();
        let c1 = push.push(b"one", b"ad", Tag::Message);
        let c2 = push.push(b"two", &[], Tag::Final);

        // corruption
        let mut bad = c1.clone();
        bad[5] ^= 1;
        let mut pull = PullStream::new(&key, &header).unwrap();
        assert_eq!(pull.pull(&bad, b"ad").unwrap_err(), CryptoError::AuthFailed);

        // wrong AD
        let mut pull = PullStream::new(&key, &header).unwrap();
        assert_eq!(pull.pull(&c1, b"xx").unwrap_err(), CryptoError::AuthFailed);

        // reorder: c2 first fails (internal sequence)
        let mut pull = PullStream::new(&key, &header).unwrap();
        assert_eq!(pull.pull(&c2, &[]).unwrap_err(), CryptoError::AuthFailed);
    }
}
