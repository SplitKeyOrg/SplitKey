//! `.skc` catalog records: `"SKC1" ‖ u32be len ‖ CBOR ‖ device sig64`
//! (written by sealerd's uploader — see Sealer docs/06-storage.md).

use anyhow::{bail, Context, Result};
use serde_json::Value;

pub const MAGIC: [u8; 4] = *b"SKC1";

pub struct SkcRecord {
    pub body: Value,
    /// (signed_bytes, signature) kept for device-key verification.
    signed: Vec<u8>,
    sig: [u8; 64],
}

impl SkcRecord {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 + 64 || buf[..4] != MAGIC {
            bail!("not a .skc record");
        }
        let len = u32::from_be_bytes(buf[4..8].try_into().unwrap()) as usize;
        if buf.len() != 8 + len + 64 {
            bail!(".skc length mismatch");
        }
        let cbor = &buf[8..8 + len];
        let body: Value = ciborium::from_reader(cbor).context(".skc CBOR decode")?;
        let mut signed = Vec::with_capacity(4 + len);
        signed.extend_from_slice(&MAGIC);
        signed.extend_from_slice(cbor);
        let sig: [u8; 64] = buf[8 + len..].try_into().unwrap();
        Ok(Self { body, signed, sig })
    }

    pub fn verify(&self, device_pub: &[u8; 32]) -> Result<()> {
        sealer_crypto::verify_detached(&self.sig, &self.signed, device_pub)
            .map_err(|_| anyhow::anyhow!(".skc device signature invalid"))
    }

    pub fn str_field(&self, key: &str) -> Option<&str> {
        self.body.get(key)?.as_str()
    }

    pub fn u64_field(&self, key: &str) -> Option<u64> {
        self.body.get(key)?.as_u64()
    }

    pub fn meta(&self, key: &str) -> Option<&str> {
        self.body.get("content_meta")?.get(key)?.as_str()
    }
}
