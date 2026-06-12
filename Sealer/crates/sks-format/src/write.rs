//! Streaming segment writer: header fully known up front, chunks flow
//! through, footer + signature appended at close. No seek-back, so it can
//! write straight to a socket or a spool file on a tiny device.

use crate::types::{to_cbor, Footer, Header};
use crate::{FormatError, MAGIC};
use sealer_crypto::{blake2b256, hash::Hasher, secretstream, sign, SigKeypair};
use std::io::Write;

/// Everything the caller gets back after a successful close.
pub struct SealedInfo {
    /// BLAKE2b of the SIG block — the next segment's `prev_link`.
    pub link: [u8; 32],
    pub body_len: u64,
    pub chunk_count: u32,
}

/// Seals plaintext chunks into a `.sks` segment.
///
/// The DEK is generated inside and never exposed; only its envelope
/// (`header.sealed_dek`, prepared by the caller via [`prepare_envelope`])
/// can recover it — and only with the window private key.
pub struct SegmentWriter<W: Write> {
    out: W,
    push: secretstream::PushStream,
    header_hash: [u8; 32],
    header_sig: sign::Signature,
    device_key: SigKeypair,
    body_hasher: Hasher,
    body_len: u64,
    chunk_count: u32,
    first_chunk: bool,
    closed: bool,
}

/// Generate a fresh DEK + stream state and seal `DEK ‖ stream_header` to the
/// window public key. Returns (sealed_dek for the header, the push stream).
pub fn prepare_envelope(window_pub: &[u8; 32]) -> (Vec<u8>, secretstream::PushStream) {
    let dek = sealer_crypto::random_32();
    let push = secretstream::PushStream::new(&dek);
    let mut secret = Vec::with_capacity(32 + secretstream::STREAM_HEADERBYTES);
    secret.extend_from_slice(&dek);
    secret.extend_from_slice(push.header());
    let sealed = sealer_crypto::seal(&secret, window_pub);
    // `dek` and `secret` drop here; plaintext key material lives only as
    // long as this call. (Zeroization pass is a hardening TODO.)
    (sealed, push)
}

impl<W: Write> SegmentWriter<W> {
    /// Write magic + header + header signature. `header.sealed_dek` must be
    /// the envelope from [`prepare_envelope`], and `push` its stream.
    pub fn begin(
        mut out: W,
        header: &Header,
        push: secretstream::PushStream,
        device_key: &SigKeypair,
    ) -> Result<Self, FormatError> {
        let header_bytes = to_cbor(header);
        let mut signed = Vec::with_capacity(4 + header_bytes.len());
        signed.extend_from_slice(&MAGIC);
        signed.extend_from_slice(&header_bytes);
        let header_sig = sign::sign_detached(&signed, device_key);

        out.write_all(&MAGIC)?;
        out.write_all(&(header_bytes.len() as u32).to_be_bytes())?;
        out.write_all(&header_bytes)?;
        out.write_all(&header_sig)?;

        Ok(Self {
            out,
            push,
            header_hash: blake2b256(&header_bytes),
            header_sig,
            device_key: device_key.clone(),
            body_hasher: Hasher::new(),
            body_len: 0,
            chunk_count: 0,
            first_chunk: true,
            closed: false,
        })
    }

    /// Encrypt and write one plaintext chunk. `last` marks the FINAL chunk;
    /// exactly one call must pass `last = true`, after which no more chunks.
    pub fn write_chunk(&mut self, plaintext: &[u8], last: bool) -> Result<(), FormatError> {
        assert!(!self.closed, "write_chunk after FINAL");
        // First chunk carries the header hash as AAD, binding body→header.
        let ad: &[u8] = if self.first_chunk { &self.header_hash } else { &[] };
        let tag = if last {
            secretstream::Tag::Final
        } else {
            secretstream::Tag::Message
        };
        let sealed = self.push.push(plaintext, ad, tag);
        self.first_chunk = false;

        let len_be = (sealed.len() as u32).to_be_bytes();
        self.out.write_all(&len_be)?;
        self.out.write_all(&sealed)?;
        self.body_hasher.update(&len_be);
        self.body_hasher.update(&sealed);
        self.body_len += (4 + sealed.len()) as u64;
        self.chunk_count += 1;
        if last {
            self.closed = true;
        }
        Ok(())
    }

    /// Terminate the body, write footer + SIG block. Returns the chain link.
    pub fn finish(mut self) -> Result<SealedInfo, FormatError> {
        assert!(self.closed, "finish before FINAL chunk");
        // Zero length terminates the body region.
        self.out.write_all(&0u32.to_be_bytes())?;

        let footer = Footer {
            body_hash: std::mem::replace(&mut self.body_hasher, Hasher::new()).finalize(),
            chunk_count: self.chunk_count,
            body_len: self.body_len,
        };
        let footer_bytes = to_cbor(&footer);
        self.out.write_all(&(footer_bytes.len() as u32).to_be_bytes())?;
        self.out.write_all(&footer_bytes)?;

        let mut signed = Vec::with_capacity(64 + footer_bytes.len());
        signed.extend_from_slice(&self.header_sig);
        signed.extend_from_slice(&footer_bytes);
        let sig_block = sign::sign_detached(&signed, &self.device_key);
        self.out.write_all(&sig_block)?;
        self.out.flush()?;

        Ok(SealedInfo {
            link: blake2b256(&sig_block),
            body_len: footer.body_len,
            chunk_count: footer.chunk_count,
        })
    }
}
