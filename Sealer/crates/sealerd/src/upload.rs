//! Spool drainer + storage sinks (docs/06-storage.md).
//!
//! Storage is untrusted: confidentiality comes from sealing, integrity from
//! the chain. Uploads are at-least-once and idempotent (PutMode::Create;
//! AlreadyExists counts as success). The catalog is dumb storage — a signed
//! `.skc` record object written next to each segment.

use crate::config::{self, AfterUpload, CatalogMode, Storage};
use anyhow::{Context, Result};
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, PutMode, PutOptions, PutPayload};
use sealer_crypto::{sign, SigKeypair};
use sks_format::ParsedSegment;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub const CATALOG_MAGIC: [u8; 4] = *b"SKC1";

pub struct Sink {
    pub name: String,
    store: Arc<dyn ObjectStore>,
    prefix: String,
}

impl Sink {
    fn key(&self, rel: &str) -> ObjPath {
        if self.prefix.is_empty() {
            ObjPath::from(rel)
        } else {
            ObjPath::from(format!("{}/{}", self.prefix, rel))
        }
    }

    /// Idempotent create-only put.
    async fn put(&self, rel: &str, bytes: Vec<u8>) -> Result<()> {
        let opts = PutOptions::from(PutMode::Create);
        match self
            .store
            .put_opts(&self.key(rel), PutPayload::from(bytes), opts)
            .await
        {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. }) => Ok(()), // dedupe
            Err(e) => Err(e.into()),
        }
    }

    /// Connectivity probe for `sealer doctor`.
    pub async fn probe(&self) -> Result<()> {
        let mut nonce = [0u8; 8];
        sealer_crypto::random_bytes(&mut nonce);
        self.put(&format!("_doctor/probe-{}", hex::encode(nonce)), b"ok".to_vec())
            .await
    }
}

pub fn build_sinks(storage: &[Storage]) -> Result<Vec<Sink>> {
    let mut sinks = Vec::new();
    for (i, s) in storage.iter().enumerate() {
        match s {
            Storage::Fs { path } => {
                std::fs::create_dir_all(path)?;
                let store = object_store::local::LocalFileSystem::new_with_prefix(path)
                    .with_context(|| format!("fs sink {}", path.display()))?;
                sinks.push(Sink {
                    name: format!("fs:{}", path.display()),
                    store: Arc::new(store),
                    prefix: String::new(),
                });
            }
            Storage::S3 { endpoint, bucket, prefix, region, credential } => {
                let mut b = object_store::aws::AmazonS3Builder::from_env()
                    .with_bucket_name(bucket)
                    .with_region(region.clone().unwrap_or_else(|| "us-east-1".into()));
                if let Some(ep) = endpoint {
                    b = b
                        .with_endpoint(ep)
                        .with_virtual_hosted_style_request(false)
                        .with_allow_http(ep.starts_with("http://"));
                }
                if let Some(spec) = credential {
                    let (id, secret) = config::resolve_credential(spec)?;
                    b = b.with_access_key_id(id).with_secret_access_key(secret);
                }
                sinks.push(Sink {
                    name: format!("s3:{bucket} (sink {i})"),
                    store: Arc::new(b.build()?),
                    prefix: prefix.trim_matches('/').to_string(),
                });
            }
        }
    }
    Ok(sinks)
}

/// Object key layout (docs/03-segment-format.md):
/// `<community>/<camera>/<epoch>/<window>/<seq>.sks`
pub fn object_key(p: &ParsedSegment) -> String {
    let h = &p.header;
    format!(
        "{}/{}/{}/{}/{:08}",
        h.community_id, h.camera_id, h.epoch, h.window_index, h.segment_seq
    )
}

/// Device-signed catalog record: everything the release tooling needs to
/// find footage without reading it. `SKC1 ‖ u32be len ‖ CBOR ‖ sig64`.
pub fn catalog_record(p: &ParsedSegment, key: &str, device: &SigKeypair) -> Vec<u8> {
    let h = &p.header;
    let record = serde_json::json!({
        "community_id": h.community_id,
        "camera_id": h.camera_id,
        "epoch": h.epoch,
        "window_index": h.window_index,
        "segment_seq": h.segment_seq,
        "ts_wall_start": h.ts_wall_start,
        "ts_wall_end": h.ts_wall_end,
        "clock_confidence": format!("{:?}", h.clock_confidence).to_lowercase(),
        "content_meta": h.content_meta,
        "sealed_dek": hex::encode(&h.sealed_dek),
        "prev_link": hex::encode(h.prev_link),
        "sig_hash": hex::encode(sealer_crypto::blake2b256(&p.sig_block)),
        "body_len": p.footer.body_len,
        "object_key": format!("{key}.sks"),
        "device_key_id": hex::encode(h.device_key_id),
    });
    let mut cbor = Vec::new();
    ciborium::into_writer(&record, &mut cbor).expect("fixed schema");
    let mut signed = Vec::with_capacity(4 + cbor.len());
    signed.extend_from_slice(&CATALOG_MAGIC);
    signed.extend_from_slice(&cbor);
    let sig = sign::sign_detached(&signed, device);

    let mut out = Vec::with_capacity(8 + cbor.len() + 64);
    out.extend_from_slice(&CATALOG_MAGIC);
    out.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
    out.extend_from_slice(&cbor);
    out.extend_from_slice(&sig);
    out
}

/// Spool-drainer configuration + state.
pub struct Uploader {
    pub spool_dir: PathBuf,
    pub sinks: Vec<Sink>,
    pub catalog: CatalogMode,
    pub after_upload: AfterUpload,
    pub device: SigKeypair,
    pub retry_secs: u64,
}

impl Uploader {
    /// Drain the spool forever: on wake (notify or timer), push every
    /// pending segment (+ catalog record) to every sink; on full success
    /// apply the after_upload policy. Failures leave the file for retry.
    pub async fn run(
        self,
        mut notify: tokio::sync::mpsc::Receiver<()>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let uploaded_dir = self.spool_dir.join("uploaded");
        if self.after_upload == AfterUpload::Keep {
            std::fs::create_dir_all(&uploaded_dir)?;
        }
        loop {
            if let Err(e) =
                drain_once(&self.spool_dir, &uploaded_dir, &self.sinks, self.catalog, self.after_upload, &self.device).await
            {
                tracing::warn!(error = %format!("{e:#}"), "upload pass failed; will retry");
            }
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        // Final best-effort drain so a clean stop leaves nothing behind.
                        let _ = drain_once(&self.spool_dir, &uploaded_dir, &self.sinks, self.catalog, self.after_upload, &self.device).await;
                        return Ok(());
                    }
                }
                _ = notify.recv() => {}
                _ = tokio::time::sleep(Duration::from_secs(self.retry_secs)) => {}
            }
        }
    }
}

async fn drain_once(
    spool_dir: &Path,
    uploaded_dir: &Path,
    sinks: &[Sink],
    catalog: CatalogMode,
    after_upload: AfterUpload,
    device: &SigKeypair,
) -> Result<()> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(spool_dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "sks"))
        .collect();
    files.sort(); // oldest-first (zero-padded seq names)

    for path in files {
        let bytes = std::fs::read(&path)?;
        let parsed = match ParsedSegment::parse(&bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(path = %path.display(), %e, "unparseable segment in spool; quarantining");
                let _ = std::fs::rename(&path, path.with_extension("sks.bad"));
                continue;
            }
        };
        let key = object_key(&parsed);
        let record = (catalog == CatalogMode::Objects)
            .then(|| catalog_record(&parsed, &key, device));

        let mut all_ok = true;
        for sink in sinks {
            let res = async {
                sink.put(&format!("{key}.sks"), bytes.clone()).await?;
                if let Some(rec) = &record {
                    sink.put(&format!("{key}.skc"), rec.clone()).await?;
                }
                anyhow::Ok(())
            }
            .await;
            if let Err(e) = res {
                tracing::warn!(sink = %sink.name, path = %path.display(),
                    error = %format!("{e:#}"), "upload failed");
                all_ok = false;
            }
        }

        if all_ok {
            tracing::info!(seq = parsed.header.segment_seq, key = %key, "uploaded");
            match after_upload {
                AfterUpload::Delete => std::fs::remove_file(&path)?,
                AfterUpload::Keep => {
                    std::fs::rename(&path, uploaded_dir.join(path.file_name().unwrap()))?;
                }
            }
        }
    }
    Ok(())
}
