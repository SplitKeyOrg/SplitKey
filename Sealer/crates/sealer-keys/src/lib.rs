//! Pubkey Manifest (`.skm`) — the ceremony artifact the Sealer consumes
//! (docs/02-key-management.md) — plus the test-grade ceremony generator
//! (`ceremony-sim`, a throwaway stand-in for real ceremony tooling).
//!
//! File layout: `MAGIC "SKM1" ‖ u32be len ‖ CBOR body ‖ 64-byte Ed25519
//! signature by the community admin key over MAGIC ‖ body`.

use serde::{Deserialize, Serialize};
use sealer_crypto::{sign, BoxKeypair, SigKeypair};

pub const MANIFEST_MAGIC: [u8; 4] = *b"SKM1";

#[derive(Debug, thiserror::Error)]
pub enum KeysError {
    #[error("not a .skm manifest (bad magic)")]
    BadMagic,
    #[error("malformed manifest: {0}")]
    Malformed(&'static str),
    #[error("manifest signature invalid (not signed by the pinned admin key)")]
    BadSignature,
    #[error("window {0} outside manifest range {1}..={2}")]
    WindowOutOfRange(u64, u64, u64),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// CBOR body of the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestBody {
    pub community_id: String,
    pub epoch: u16,
    pub window_secs: u32,
    pub first_window: u64,
    /// Inclusive. Covers ~18 months (12 nominal + 6 grace) per the design.
    pub last_window: u64,
    /// One X25519 public key per window, ordered from `first_window`.
    pub window_pubs: Vec<serde_bytes::ByteArray<32>>,
    #[serde(with = "serde_bytes")]
    pub admin_key_id: [u8; 8],
    /// Unix seconds of the ceremony (informational).
    pub ceremony_date: i64,
    /// Threshold parameters, informational for verifiers/UI.
    pub threshold_t: u8,
    pub threshold_n: u8,
}

/// A parsed, signature-checked manifest.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub body: ManifestBody,
}

impl Manifest {
    pub fn window_index_for(unix_secs: i64, window_secs: u32) -> u64 {
        (unix_secs as u64) / (window_secs as u64)
    }

    /// Public key for `window`, or the *last* key if the manifest is
    /// exhausted (decided default `seal-to-last-key`; the caller is
    /// responsible for alerting loudly).
    pub fn pub_for_window(&self, window: u64) -> Result<(&[u8; 32], bool), KeysError> {
        let b = &self.body;
        if window < b.first_window {
            return Err(KeysError::WindowOutOfRange(window, b.first_window, b.last_window));
        }
        if window > b.last_window {
            let last = b.window_pubs.last().ok_or(KeysError::Malformed("empty key list"))?;
            return Ok((&**last, true)); // exhausted: sealing to last key
        }
        let idx = (window - b.first_window) as usize;
        let pk = b.window_pubs.get(idx).ok_or(KeysError::Malformed("key list shorter than range"))?;
        Ok((&**pk, false))
    }

    /// Serialize + sign with the admin key → `.skm` bytes.
    pub fn encode_signed(body: &ManifestBody, admin: &SigKeypair) -> Vec<u8> {
        let mut cbor = Vec::new();
        ciborium::into_writer(body, &mut cbor).expect("fixed schema");
        let mut signed = Vec::with_capacity(4 + cbor.len());
        signed.extend_from_slice(&MANIFEST_MAGIC);
        signed.extend_from_slice(&cbor);
        let sig = sign::sign_detached(&signed, admin);

        let mut out = Vec::with_capacity(8 + cbor.len() + 64);
        out.extend_from_slice(&MANIFEST_MAGIC);
        out.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
        out.extend_from_slice(&cbor);
        out.extend_from_slice(&sig);
        out
    }

    /// Parse `.skm` bytes, verifying against the pinned admin public key.
    pub fn decode_verified(buf: &[u8], admin_pub: &[u8; 32]) -> Result<Self, KeysError> {
        if buf.len() < 8 || buf[..4] != MANIFEST_MAGIC {
            return Err(KeysError::BadMagic);
        }
        let len = u32::from_be_bytes(buf[4..8].try_into().unwrap()) as usize;
        if buf.len() != 8 + len + 64 {
            return Err(KeysError::Malformed("length mismatch"));
        }
        let cbor = &buf[8..8 + len];
        let sig: sign::Signature = buf[8 + len..].try_into().unwrap();

        let mut signed = Vec::with_capacity(4 + len);
        signed.extend_from_slice(&MANIFEST_MAGIC);
        signed.extend_from_slice(cbor);
        sign::verify_detached(&sig, &signed, admin_pub).map_err(|_| KeysError::BadSignature)?;

        let body: ManifestBody =
            ciborium::from_reader(cbor).map_err(|_| KeysError::Malformed("CBOR decode failed"))?;
        if body.window_pubs.len() as u64 != body.last_window - body.first_window + 1 {
            return Err(KeysError::Malformed("key count != window range"));
        }
        Ok(Self { body })
    }
}

/// Ceremony simulation (test/dev only — real ceremony tooling is the
/// `community-signing` plan). Generates CRK + admin key + manifest, and can
/// re-derive any window's private key from the CRK, simulating a quorum
/// release. **The CRK leaving this module is the simulation's deliberate
/// cheat**; real ceremonies destroy it after share printing.
pub mod ceremony_sim {
    use super::*;

    pub struct SimCommunity {
        pub crk: [u8; 32],
        pub admin: SigKeypair,
        pub manifest_bytes: Vec<u8>,
        pub body: ManifestBody,
    }

    pub fn generate(
        community_id: &str,
        epoch: u16,
        window_secs: u32,
        first_window: u64,
        window_count: u64,
        ceremony_date: i64,
        threshold: (u8, u8),
    ) -> SimCommunity {
        let crk = sealer_crypto::random_32();
        let admin = SigKeypair::generate();
        let window_pubs = (0..window_count)
            .map(|i| {
                let kp = sealer_crypto::kdf::derive_window_keypair(&crk, first_window + i);
                serde_bytes::ByteArray::new(kp.public)
            })
            .collect();
        let body = ManifestBody {
            community_id: community_id.into(),
            epoch,
            window_secs,
            first_window,
            last_window: first_window + window_count - 1,
            window_pubs,
            admin_key_id: admin.key_id(),
            ceremony_date,
            threshold_t: threshold.0,
            threshold_n: threshold.1,
        };
        let manifest_bytes = Manifest::encode_signed(&body, &admin);
        SimCommunity {
            crk,
            admin,
            manifest_bytes,
            body,
        }
    }

    /// Simulated release: derive one window's private keypair from the CRK.
    pub fn release_window(crk: &[u8; 32], window: u64) -> BoxKeypair {
        sealer_crypto::kdf::derive_window_keypair(crk, window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip_and_tamper() {
        let sim = ceremony_sim::generate("testers", 1, 86_400, 20_000, 30, 1_770_000_000, (3, 5));
        let m = Manifest::decode_verified(&sim.manifest_bytes, &sim.admin.public).unwrap();
        assert_eq!(m.body.community_id, "testers");
        assert_eq!(m.body.window_pubs.len(), 30);

        // window lookup + exhaustion behavior
        let (pk, exhausted) = m.pub_for_window(20_010).unwrap();
        assert!(!exhausted);
        let released = ceremony_sim::release_window(&sim.crk, 20_010);
        assert_eq!(pk, &released.public);
        let (_, exhausted) = m.pub_for_window(20_050).unwrap();
        assert!(exhausted);
        assert!(m.pub_for_window(10).is_err());

        // tampering with the body breaks the signature
        let mut bad = sim.manifest_bytes.clone();
        bad[20] ^= 1;
        assert!(Manifest::decode_verified(&bad, &sim.admin.public).is_err());

        // wrong admin key rejected
        let other = SigKeypair::generate();
        assert!(matches!(
            Manifest::decode_verified(&sim.manifest_bytes, &other.public).unwrap_err(),
            KeysError::BadSignature
        ));
    }
}
