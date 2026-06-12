//! Parsing and verification of `.sks` segments.
//!
//! Three levels, all keyless except the last:
//! 1. [`ParsedSegment::parse`] — structural parse, no trust decisions.
//! 2. [`ParsedSegment::verify`] — signatures (needs the device *public*
//!    key), body hash, body shape. Still zero decryption capability.
//! 3. [`ParsedSegment::decrypt`] — release side only: open the envelope
//!    with the window private key and pull the stream.

use crate::types::{from_cbor, Footer, Header};
use crate::{FormatError, FORMAT_VERSION, MAGIC};
use sealer_crypto::{blake2b256, secretstream, sign, BoxKeypair};

/// A structurally parsed segment. Borrowless: owns its bytes ranges as
/// offsets into the caller's buffer for body, and copies of the small parts.
pub struct ParsedSegment {
    pub header: Header,
    pub header_bytes: Vec<u8>,
    pub header_sig: sign::Signature,
    pub footer: Footer,
    pub footer_bytes: Vec<u8>,
    pub sig_block: sign::Signature,
    /// (offset, len) of the BODY region (chunk stream incl. len prefixes,
    /// excl. zero terminator) within the input buffer.
    pub body_range: (usize, usize),
    /// Offsets of each chunk's payload (excluding its 4-byte len prefix).
    pub chunks: Vec<(usize, usize)>,
}

/// Outcome of keyless verification — what `sks verify` reports per segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// BLAKE2b of this segment's SIG block (what the *next* prev_link
    /// must equal).
    pub link: [u8; 32],
}

fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize, what: &'static str) -> Result<&'a [u8], FormatError> {
    if buf.len() - *pos < n {
        return Err(FormatError::Malformed(what));
    }
    let s = &buf[*pos..*pos + n];
    *pos += n;
    Ok(s)
}

fn take_u32(buf: &[u8], pos: &mut usize, what: &'static str) -> Result<u32, FormatError> {
    let b = take(buf, pos, 4, what)?;
    Ok(u32::from_be_bytes(b.try_into().unwrap()))
}

impl ParsedSegment {
    pub fn parse(buf: &[u8]) -> Result<Self, FormatError> {
        let mut pos = 0usize;
        if take(buf, &mut pos, 4, "magic")? != MAGIC {
            return Err(FormatError::BadMagic);
        }
        let header_len = take_u32(buf, &mut pos, "header length")? as usize;
        if header_len > 1 << 20 {
            return Err(FormatError::Malformed("header length implausible"));
        }
        let header_bytes = take(buf, &mut pos, header_len, "header")?.to_vec();
        let header: Header = from_cbor(&header_bytes)?;
        if header.format_version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(header.format_version));
        }
        let header_sig: sign::Signature = take(buf, &mut pos, 64, "header signature")?
            .try_into()
            .unwrap();

        // BODY: chunks until zero terminator.
        let body_start = pos;
        let mut chunks = Vec::new();
        loop {
            let len = take_u32(buf, &mut pos, "chunk length")? as usize;
            if len == 0 {
                break;
            }
            if !(secretstream::TAG_OVERHEAD..=(1 << 26)).contains(&len) {
                return Err(FormatError::Malformed("chunk length implausible"));
            }
            let start = pos;
            take(buf, &mut pos, len, "chunk body")?;
            chunks.push((start, len));
        }
        let body_end = pos - 4; // exclude the zero terminator

        let footer_len = take_u32(buf, &mut pos, "footer length")? as usize;
        if footer_len > 1 << 16 {
            return Err(FormatError::Malformed("footer length implausible"));
        }
        let footer_bytes = take(buf, &mut pos, footer_len, "footer")?.to_vec();
        let footer: Footer = from_cbor(&footer_bytes)?;
        let sig_block: sign::Signature = take(buf, &mut pos, 64, "signature block")?
            .try_into()
            .unwrap();
        if pos != buf.len() {
            return Err(FormatError::Malformed("trailing bytes after signature block"));
        }

        Ok(Self {
            header,
            header_bytes,
            header_sig,
            footer,
            footer_bytes,
            sig_block,
            body_range: (body_start, body_end - body_start),
            chunks,
        })
    }

    /// Keyless verification (needs only the device *public* key):
    /// header signature, segment signature, body hash, body shape.
    pub fn verify(&self, buf: &[u8], device_pub: &[u8; 32]) -> Result<Verified, FormatError> {
        // 1. Header signature over MAGIC ‖ HEADER.
        let mut signed = Vec::with_capacity(4 + self.header_bytes.len());
        signed.extend_from_slice(&MAGIC);
        signed.extend_from_slice(&self.header_bytes);
        sign::verify_detached(&self.header_sig, &signed, device_pub)
            .map_err(|_| FormatError::HeaderSigInvalid)?;

        // 2. SIG block over HEADER_SIG ‖ FOOTER.
        let mut signed = Vec::with_capacity(64 + self.footer_bytes.len());
        signed.extend_from_slice(&self.header_sig);
        signed.extend_from_slice(&self.footer_bytes);
        sign::verify_detached(&self.sig_block, &signed, device_pub)
            .map_err(|_| FormatError::SigBlockInvalid)?;

        // 3. Body hash + shape vs the (now trusted) footer.
        let (off, len) = self.body_range;
        let body = &buf[off..off + len];
        if blake2b256(body) != self.footer.body_hash {
            return Err(FormatError::BodyHashMismatch);
        }
        if self.footer.chunk_count as usize != self.chunks.len()
            || self.footer.body_len != len as u64
        {
            return Err(FormatError::BodyShapeMismatch);
        }

        Ok(Verified {
            link: blake2b256(&self.sig_block),
        })
    }

    /// Release side: open the envelope with the window private key and
    /// decrypt the body. Also enforces the FINAL tag (truncation) and
    /// header binding (first-chunk AAD).
    pub fn decrypt(&self, buf: &[u8], window_key: &BoxKeypair) -> Result<Vec<u8>, FormatError> {
        let secret = sealer_crypto::seal_open(&self.header.sealed_dek, window_key)
            .map_err(|_| FormatError::SealOpenFailed)?;
        if secret.len() != 32 + secretstream::STREAM_HEADERBYTES {
            return Err(FormatError::Malformed("envelope payload wrong size"));
        }
        let dek: [u8; 32] = secret[..32].try_into().unwrap();
        let stream_header: [u8; secretstream::STREAM_HEADERBYTES] =
            secret[32..].try_into().unwrap();

        let mut pull = secretstream::PullStream::new(&dek, &stream_header)
            .map_err(|_| FormatError::SealOpenFailed)?;
        let header_hash = blake2b256(&self.header_bytes);

        let mut plaintext = Vec::new();
        for (i, &(off, len)) in self.chunks.iter().enumerate() {
            if pull.finished() {
                return Err(FormatError::TrailingData);
            }
            let ad: &[u8] = if i == 0 { &header_hash } else { &[] };
            let (mut chunk, _tag) = pull
                .pull(&buf[off..off + len], ad)
                .map_err(|_| FormatError::ChunkAuthFailed(i as u32))?;
            plaintext.append(&mut chunk);
        }
        if !pull.finished() {
            return Err(FormatError::MissingFinal);
        }
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ClockConfidence, Header};
    use crate::write::{prepare_envelope, SegmentWriter};
    use crate::{DEFAULT_CHUNK_BYTES, GENESIS_LINK, SUITE_XCHACHA};
    use sealer_crypto::SigKeypair;

    fn test_header(sealed_dek: Vec<u8>, seq: u64, key_id: [u8; 8]) -> Header {
        Header {
            format_version: crate::FORMAT_VERSION,
            suite_id: SUITE_XCHACHA.into(),
            community_id: "test-community".into(),
            camera_id: "cam-1".into(),
            device_key_id: key_id,
            epoch: 1,
            window_index: 493_000,
            segment_seq: seq,
            boot_id: [1; 8],
            ts_wall_start: 1_770_000_000_000,
            ts_wall_end: 1_770_000_060_000,
            ts_mono: 12_345,
            clock_confidence: ClockConfidence::Synced,
            prev_link: GENESIS_LINK,
            content_meta: Default::default(),
            sealed_dek,
        }
    }

    fn seal_bytes(data: &[u8], window_pub: &[u8; 32], dev: &SigKeypair) -> Vec<u8> {
        let (sealed_dek, push) = prepare_envelope(window_pub);
        let header = test_header(sealed_dek, 0, dev.key_id());
        let mut out = Vec::new();
        let mut w = SegmentWriter::begin(&mut out, &header, push, dev).unwrap();
        let mut chunks = data.chunks(DEFAULT_CHUNK_BYTES).peekable();
        while let Some(c) = chunks.next() {
            let last = chunks.peek().is_none();
            w.write_chunk(c, last).unwrap();
        }
        w.finish().unwrap();
        out
    }

    #[test]
    fn seal_parse_verify_decrypt_roundtrip() {
        let dev = SigKeypair::generate();
        let wk = sealer_crypto::BoxKeypair::generate();
        let data = vec![7u8; 200_000]; // multi-chunk
        let sealed = seal_bytes(&data, &wk.public, &dev);

        let parsed = ParsedSegment::parse(&sealed).unwrap();
        parsed.verify(&sealed, &dev.public).unwrap();
        assert_eq!(parsed.decrypt(&sealed, &wk).unwrap(), data);
    }

    #[test]
    fn ciphertext_is_unreadable_without_window_key() {
        let dev = SigKeypair::generate();
        let wk = sealer_crypto::BoxKeypair::generate();
        let wrong = sealer_crypto::BoxKeypair::generate();
        let sealed = seal_bytes(b"secret footage", &wk.public, &dev);
        let parsed = ParsedSegment::parse(&sealed).unwrap();
        assert!(matches!(
            parsed.decrypt(&sealed, &wrong).unwrap_err(),
            FormatError::SealOpenFailed
        ));
    }

    #[test]
    fn body_tamper_detected_without_keys() {
        let dev = SigKeypair::generate();
        let wk = sealer_crypto::BoxKeypair::generate();
        let mut sealed = seal_bytes(&vec![3u8; 100_000], &wk.public, &dev);
        let parsed = ParsedSegment::parse(&sealed).unwrap();
        let (off, _) = parsed.body_range;
        sealed[off + 10] ^= 0xff;
        let parsed = ParsedSegment::parse(&sealed).unwrap();
        assert!(matches!(
            parsed.verify(&sealed, &dev.public).unwrap_err(),
            FormatError::BodyHashMismatch
        ));
    }

    #[test]
    fn header_tamper_detected() {
        let dev = SigKeypair::generate();
        let wk = sealer_crypto::BoxKeypair::generate();
        let sealed = seal_bytes(b"x", &wk.public, &dev);
        // Re-encoding a modified header in place is fiddly; simulate by
        // flipping a byte inside the stored header bytes region (offset 9 =
        // inside CBOR header).
        let mut tampered = sealed.clone();
        tampered[9] ^= 1;
        if let Ok(p) = ParsedSegment::parse(&tampered) {
            assert!(p.verify(&tampered, &dev.public).is_err());
        } // else: parse failure is also detection
        // and an untampered one still verifies
        let parsed = ParsedSegment::parse(&sealed).unwrap();
        parsed.verify(&sealed, &dev.public).unwrap();
    }
}
