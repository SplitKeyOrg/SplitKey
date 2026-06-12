//! The Sealer/Chainer stages: turn bytes into chained `.sks` segments in
//! the spool, maintaining the persistent chain state.
//!
//! Crash-safety invariants (docs/00-architecture.md):
//! 1. plaintext is deleted only after the sealed segment is fsync'd into
//!    the spool (the caller handles deletion; we fsync + atomic-rename);
//! 2. chain state is persisted before the segment is considered complete.

use crate::config::ManifestExhausted;
use crate::state::{self, ChainStateFile, DeviceState};
use anyhow::{bail, Context, Result};
use sks_format::{ClockConfidence, Header, SegmentWriter};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SealEngine {
    pub device: DeviceState,
    pub camera_id: String,
    pub spool_dir: PathBuf,
    pub chunk_bytes: usize,
    pub on_exhausted: ManifestExhausted,
    chain: ChainStateFile,
    boot_id: [u8; 8],
    started: std::time::Instant,
    exhausted_warned: bool,
}

pub enum SealInput<'a> {
    /// Footage from a watched file (timestamps from mtime).
    File { path: &'a Path, mtime_ms: i64 },
    /// Footage bytes straight from a pipe — plaintext never touches disk.
    /// Timestamps are real capture start/end times.
    Bytes {
        data: Vec<u8>,
        ts_start_ms: i64,
        ts_end_ms: i64,
        content_meta: BTreeMap<String, String>,
    },
    /// A chain event (boot, heartbeat, ...) — body is a small CBOR record,
    /// sealed and chained exactly like footage (docs/04-tamper-evidence.md).
    Event { kind: &'a str, detail: serde_json::Value },
}

pub struct SealOutcome {
    pub spool_path: PathBuf,
    pub seq: u64,
    pub window: u64,
    pub exhausted: bool,
}

impl SealEngine {
    pub fn new(
        device: DeviceState,
        camera_id: &str,
        spool_dir: &Path,
        chunk_bytes: usize,
        on_exhausted: ManifestExhausted,
    ) -> Result<Self> {
        fs::create_dir_all(spool_dir)?;
        let chain = state::load_chain_state(&device.dir, camera_id)?;
        let mut boot_id = [0u8; 8];
        sealer_crypto::random_bytes(&mut boot_id);
        Ok(Self {
            device,
            camera_id: camera_id.to_string(),
            spool_dir: spool_dir.to_path_buf(),
            chunk_bytes,
            on_exhausted,
            chain,
            boot_id,
            started: std::time::Instant::now(),
            exhausted_warned: false,
        })
    }

    pub fn next_seq(&self) -> u64 {
        self.chain.next_seq
    }

    fn now_ms() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
    }

    /// Seal one input into the spool. Returns the spooled segment path.
    pub fn seal(&mut self, input: SealInput<'_>) -> Result<SealOutcome> {
        let (data, ts_start_ms, ts_end_ms, content_meta): (Vec<u8>, i64, i64, BTreeMap<String, String>) = match input {
            SealInput::File { path, mtime_ms } => {
                let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
                let mut meta = BTreeMap::new();
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    meta.insert("container".into(), ext.to_lowercase());
                }
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    meta.insert("source_name".into(), name.to_string());
                }
                (data, mtime_ms, mtime_ms, meta)
            }
            SealInput::Bytes { data, ts_start_ms, ts_end_ms, content_meta } => {
                (data, ts_start_ms, ts_end_ms, content_meta)
            }
            SealInput::Event { kind, detail } => {
                let now = Self::now_ms();
                let mut body = Vec::new();
                ciborium::into_writer(
                    &serde_json::json!({ "event": kind, "ts_ms": now, "detail": detail }),
                    &mut body,
                )?;
                let mut meta = BTreeMap::new();
                meta.insert("kind".into(), "chain-event".into());
                meta.insert("event".into(), kind.to_string());
                (body, now, now, meta)
            }
        };

        let manifest = &self.device.manifest;
        // A segment belongs to the window containing its first frame.
        let window = sealer_keys::Manifest::window_index_for(ts_start_ms / 1000, manifest.body.window_secs);
        let (wk_pub, exhausted) = manifest.pub_for_window(window)?;
        if exhausted {
            match self.on_exhausted {
                ManifestExhausted::FailClosed => {
                    bail!(
                        "manifest exhausted (window {} > {}) and manifest_exhausted = fail-closed",
                        window, manifest.body.last_window
                    );
                }
                ManifestExhausted::SealToLastKey => {
                    if !self.exhausted_warned {
                        tracing::error!(
                            window,
                            last_window = manifest.body.last_window,
                            "MANIFEST EXHAUSTED: sealing to the LAST window key — hold a key ceremony"
                        );
                        self.exhausted_warned = true;
                    }
                }
            }
        }
        let wk_pub = *wk_pub;

        let (sealed_dek, push) = sks_format::write::prepare_envelope(&wk_pub);
        let header = Header {
            format_version: sks_format::FORMAT_VERSION,
            suite_id: sks_format::SUITE_XCHACHA.into(),
            community_id: manifest.body.community_id.clone(),
            camera_id: self.camera_id.clone(),
            device_key_id: self.device.device_key.key_id(),
            epoch: manifest.body.epoch,
            window_index: window,
            segment_seq: self.chain.next_seq,
            boot_id: self.boot_id,
            ts_wall_start: ts_start_ms,
            ts_wall_end: ts_end_ms,
            ts_mono: self.started.elapsed().as_nanos() as u64,
            clock_confidence: ClockConfidence::Synced,
            prev_link: hex::decode(&self.chain.prev_link_hex)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("corrupt chain state"))?,
            content_meta,
            sealed_dek,
        };

        let final_path = self.spool_dir.join(format!("{:08}.sks", self.chain.next_seq));
        let tmp_path = self.spool_dir.join(format!(".{:08}.sks.tmp", self.chain.next_seq));
        let file = fs::File::create(&tmp_path)?;
        let mut bw = std::io::BufWriter::new(file);
        let mut w = SegmentWriter::begin(&mut bw, &header, push, &self.device.device_key)?;
        if data.is_empty() {
            w.write_chunk(&[], true)?;
        } else {
            let mut it = data.chunks(self.chunk_bytes).peekable();
            while let Some(c) = it.next() {
                w.write_chunk(c, it.peek().is_none())?;
            }
        }
        let info = w.finish()?;
        // fsync before rename: invariant 1.
        bw.flush()?;
        bw.into_inner().map_err(|e| e.into_error())?.sync_all()?;

        // Invariant 2: persist chain state, then complete the segment.
        let seq = self.chain.next_seq;
        self.chain.next_seq += 1;
        self.chain.prev_link_hex = hex::encode(info.link);
        state::save_chain_state(&self.device.dir, &self.chain)?;
        fs::rename(&tmp_path, &final_path)?;

        Ok(SealOutcome { spool_path: final_path, seq, window, exhausted })
    }

    /// Remove stale tmp files from a previous crash (their plaintext is
    /// still present, so they will simply be re-sealed).
    pub fn clean_stale_tmp(&self) -> Result<()> {
        for e in fs::read_dir(&self.spool_dir)? {
            let p = e?.path();
            if p.extension().is_some_and(|x| x == "tmp") {
                tracing::warn!(path = %p.display(), "removing stale tmp segment from prior crash");
                fs::remove_file(&p)?;
            }
        }
        Ok(())
    }
}
