//! The `.sks` sealed-segment container (docs/03-segment-format.md).
//!
//! Layout:
//! ```text
//! MAGIC "SKS1"
//! u32be header_len ‖ HEADER (CBOR)          — authenticated + signed
//! HEADER_SIG (64 B)  Ed25519(MAGIC ‖ HEADER)
//! BODY: repeated  u32be chunk_len ‖ secretstream chunk   (first chunk AAD
//!       = BLAKE2b(HEADER)); a zero chunk_len terminates the body
//! u32be footer_len ‖ FOOTER (CBOR)
//! SIG block (64 B)   Ed25519(HEADER_SIG ‖ FOOTER)
//!       — BLAKE2b(SIG block) becomes the next segment's prev_link
//! ```
//!
//! Everything needed for *verification* (signatures, hashes, chain links) is
//! plaintext; the DEK is sealed to the window public key, so the writer can
//! never read its own output.

pub mod read;
pub mod types;
pub mod write;

pub use read::{ParsedSegment, Verified};
pub use types::{ClockConfidence, Footer, Header, SUITE_XCHACHA};
pub use write::SegmentWriter;

pub const MAGIC: [u8; 4] = *b"SKS1";
pub const FORMAT_VERSION: u8 = 1;
/// Default body chunk size (docs/01-crypto-design.md).
pub const DEFAULT_CHUNK_BYTES: usize = 64 * 1024;
/// prev_link value for the first segment of a chain.
pub const GENESIS_LINK: [u8; 32] = [0u8; 32];

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("not a .sks file (bad magic)")]
    BadMagic,
    #[error("malformed segment: {0}")]
    Malformed(&'static str),
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u8),
    #[error("header signature invalid (header forged or device key mismatch)")]
    HeaderSigInvalid,
    #[error("segment signature block invalid (footer/sig forged or device key mismatch)")]
    SigBlockInvalid,
    #[error("body hash mismatch (body bytes modified)")]
    BodyHashMismatch,
    #[error("body length/chunk count disagrees with footer (body truncated or padded)")]
    BodyShapeMismatch,
    #[error("sealed DEK could not be opened (wrong window key or envelope corrupted)")]
    SealOpenFailed,
    #[error("body chunk {0} failed AEAD authentication (modified, reordered, or wrong header binding)")]
    ChunkAuthFailed(u32),
    #[error("stream truncated: FINAL tag never seen (chunks dropped from end)")]
    MissingFinal,
    #[error("trailing data after FINAL chunk")]
    TrailingData,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
