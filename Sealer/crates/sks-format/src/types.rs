//! HEADER / FOOTER types — the CBOR schemas of the `.sks` container.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SUITE_XCHACHA: &str = "SKS1-XCHACHA";

/// Per-segment clock trust, recorded honestly (docs/02-key-management.md:
/// no-clock operation is supported).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClockConfidence {
    Synced,
    Drifting,
    Unknown,
}

/// The authenticated, signed segment header. Field names are the CBOR map
/// keys; the signed bytes are the exact encoded CBOR, kept verbatim by the
/// parser (no canonicalization needed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub format_version: u8,
    pub suite_id: String,
    pub community_id: String,
    pub camera_id: String,
    #[serde(with = "serde_bytes")]
    pub device_key_id: [u8; 8],
    pub epoch: u16,
    pub window_index: u64,
    /// Monotonic, gap-free per camera — THE chain counter.
    pub segment_seq: u64,
    /// Random per boot; reboots are visible, not silent.
    #[serde(with = "serde_bytes")]
    pub boot_id: [u8; 8],
    pub ts_wall_start: i64,
    pub ts_wall_end: i64,
    pub ts_mono: u64,
    pub clock_confidence: ClockConfidence,
    /// BLAKE2b of the previous segment's SIG block; zeros for genesis.
    #[serde(with = "serde_bytes")]
    pub prev_link: [u8; 32],
    /// Container hints + optional detection labels ("car", "person").
    /// Plaintext by design: searchable without decryption.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub content_meta: BTreeMap<String, String>,
    /// crypto_box_seal(DEK ‖ secretstream header) to the window public key.
    #[serde(with = "serde_bytes")]
    pub sealed_dek: Vec<u8>,
}

/// Plaintext trailer enabling verification without decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Footer {
    /// BLAKE2b over the BODY region (all `len ‖ chunk` pairs).
    #[serde(with = "serde_bytes")]
    pub body_hash: [u8; 32],
    pub chunk_count: u32,
    pub body_len: u64,
}

pub fn to_cbor<T: Serialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("CBOR encoding of fixed schema cannot fail");
    buf
}

pub fn from_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, crate::FormatError> {
    ciborium::from_reader(bytes).map_err(|_| crate::FormatError::Malformed("CBOR decode failed"))
}
