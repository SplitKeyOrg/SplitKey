//! Pipe-mode ingestion (docs/05-ingestion.md, Mode 2): a recorder streams
//! H.264/MPEG-TS bytes into sealerd; segments are cut **in RAM** and the
//! plaintext never touches disk.
//!
//! Two wirings:
//! - `command = "ffmpeg ..."` — sealerd spawns and supervises the recorder
//!   (restart with backoff, `source_lost`/`source_restored` chain events);
//! - no command — sealerd reads its own stdin (`recorder | sealerd`).

use crate::config::{Pipe, PipeFormat};
use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, watch};

const TS_PACKET: usize = 188;
const READ_BUF: usize = 64 * 1024;

/// A cut segment, ready to seal.
pub struct PipeSegment {
    pub data: Vec<u8>,
    pub ts_start_ms: i64,
    pub ts_end_ms: i64,
    pub content_meta: BTreeMap<String, String>,
}

/// Source lifecycle notifications → chain events.
pub enum SourceEvent {
    Lost { reason: String },
    Restored,
}

pub enum PipeMsg {
    Segment(PipeSegment),
    Event(SourceEvent),
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

/// RAM segmenter: cuts on max bytes, max seconds, or window boundary.
/// MPEG-TS cuts are aligned to 188-byte packets so every segment starts on
/// a packet boundary (decoders resync on PAT/PMT).
pub struct Segmenter {
    format: PipeFormat,
    max_bytes: usize,
    max_secs: u64,
    window_secs: u32,
    buf: Vec<u8>,
    started_ms: i64,
    started_at: Option<Instant>,
}

impl Segmenter {
    pub fn new(format: PipeFormat, max_bytes: usize, max_secs: u64, window_secs: u32) -> Self {
        Self {
            format,
            max_bytes,
            max_secs,
            window_secs,
            buf: Vec::new(),
            started_ms: 0,
            started_at: None,
        }
    }

    fn meta(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(
            "container".into(),
            match self.format {
                PipeFormat::Mpegts => "ts",
                PipeFormat::H264Es => "h264-es",
                PipeFormat::Raw => "raw",
            }
            .into(),
        );
        m
    }

    /// Append bytes; returns any segments that became complete.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<PipeSegment> {
        if self.started_at.is_none() && !bytes.is_empty() {
            self.started_at = Some(Instant::now());
            self.started_ms = now_ms();
        }
        self.buf.extend_from_slice(bytes);

        let mut out = Vec::new();
        loop {
            let over_time = self
                .started_at
                .is_some_and(|t| t.elapsed() >= Duration::from_secs(self.max_secs));
            // Window boundary: never let a segment span two windows.
            let window_crossed = !self.buf.is_empty()
                && self.started_ms / 1000 / self.window_secs as i64
                    != now_ms() / 1000 / self.window_secs as i64;

            // Size cuts carve exactly max_bytes; time/window cuts take all.
            let target = if self.buf.len() >= self.max_bytes {
                self.max_bytes
            } else if over_time || window_crossed {
                self.buf.len()
            } else {
                break;
            };
            match self.cut(target) {
                Some(seg) => out.push(seg),
                None => break, // not enough aligned bytes yet
            }
        }
        out
    }

    /// Cut whatever is buffered (stream end / shutdown).
    pub fn flush(&mut self) -> Option<PipeSegment> {
        if self.buf.is_empty() {
            return None;
        }
        let data = std::mem::take(&mut self.buf);
        Some(self.finish(data))
    }

    fn cut(&mut self, target: usize) -> Option<PipeSegment> {
        let cut_at = match self.format {
            // Largest multiple of 188 ≤ target; remainder starts the next
            // segment, so every segment begins on a packet boundary.
            PipeFormat::Mpegts => (target / TS_PACKET) * TS_PACKET,
            PipeFormat::H264Es | PipeFormat::Raw => target,
        };
        if cut_at == 0 {
            return None;
        }
        let rest = self.buf.split_off(cut_at);
        let data = std::mem::replace(&mut self.buf, rest);
        Some(self.finish(data))
    }

    fn finish(&mut self, data: Vec<u8>) -> PipeSegment {
        let seg = PipeSegment {
            data,
            ts_start_ms: self.started_ms,
            ts_end_ms: now_ms(),
            content_meta: self.meta(),
        };
        // Next segment starts now (carry-over bytes belong to "now").
        self.started_ms = now_ms();
        self.started_at = if self.buf.is_empty() { None } else { Some(Instant::now()) };
        seg
    }
}

/// Read one stream until EOF/error, emitting segments. Returns bytes read.
async fn pump<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    seg: &mut Segmenter,
    tx: &mpsc::Sender<PipeMsg>,
    shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<u64> {
    let mut buf = vec![0u8; READ_BUF];
    let mut total = 0u64;
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { return Ok(total); }
            }
            n = reader.read(&mut buf) => {
                let n = n?;
                if n == 0 {
                    return Ok(total);
                }
                total += n as u64;
                for s in seg.push(&buf[..n]) {
                    // Bounded channel: if sealing falls behind, this blocks,
                    // the recorder's stdout backs up, and the recorder
                    // throttles — the "block" backpressure policy.
                    if tx.send(PipeMsg::Segment(s)).await.is_err() {
                        return Ok(total);
                    }
                }
            }
        }
    }
}

/// Pipe source task: supervise the recorder (or stdin) until shutdown.
pub async fn pipe_loop(
    cfg: Pipe,
    max_bytes: usize,
    max_secs: u64,
    window_secs: u32,
    tx: mpsc::Sender<PipeMsg>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut seg = Segmenter::new(cfg.format, max_bytes, max_secs, window_secs);
    let mut backoff = cfg.restart_secs.max(1);
    let mut was_lost = false;

    loop {
        if *shutdown.borrow() {
            break;
        }
        match &cfg.command {
            Some(command) => {
                let mut child = tokio::process::Command::new("sh")
                    .arg("-c")
                    .arg(command)
                    .stdout(Stdio::piped())
                    .stdin(Stdio::null())
                    .kill_on_drop(true)
                    .spawn()?;
                let stdout = child.stdout.take().expect("piped stdout");
                tracing::info!(%command, "recorder started");
                if was_lost {
                    let _ = tx.send(PipeMsg::Event(SourceEvent::Restored)).await;
                    // (was_lost is set on every recorder exit below, so no
                    // reset is needed here)
                }

                let read = pump(stdout, &mut seg, &tx, &mut shutdown).await.unwrap_or(0);
                if read > 0 {
                    backoff = cfg.restart_secs.max(1); // healthy run resets backoff
                }
                if *shutdown.borrow() {
                    let _ = child.kill().await;
                    break;
                }
                let status = child.wait().await?;
                tracing::warn!(%status, read, "recorder exited; restarting in {backoff}s");
                let _ = tx
                    .send(PipeMsg::Event(SourceEvent::Lost {
                        reason: format!("recorder exited: {status}"),
                    }))
                    .await;
                was_lost = true;
                // Cut whatever we have — don't sit on footage during an outage.
                if let Some(s) = seg.flush() {
                    let _ = tx.send(PipeMsg::Segment(s)).await;
                }
                tokio::select! {
                    _ = shutdown.changed() => {}
                    _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
                }
                backoff = (backoff * 2).min(30);
            }
            None => {
                // stdin mode: one stream, EOF ends the source.
                pump(tokio::io::stdin(), &mut seg, &tx, &mut shutdown).await?;
                tracing::info!("stdin closed; pipe source done");
                break;
            }
        }
    }

    if let Some(s) = seg.flush() {
        let _ = tx.send(PipeMsg::Segment(s)).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cuts_align_to_ts_packets() {
        let mut s = Segmenter::new(PipeFormat::Mpegts, 1880, 3600, 86_400);
        // 5000 bytes, max 1880 → two cuts of exactly 1880 (10 TS packets),
        // 1240 carried over for flush.
        let segs = s.push(&vec![0u8; 5000]);
        assert_eq!(segs.len(), 2);
        for seg in &segs {
            assert_eq!(seg.data.len(), 1880);
            assert_eq!(seg.data.len() % TS_PACKET, 0, "cut not packet-aligned");
        }
        let tail = s.flush().unwrap();
        assert_eq!(tail.data.len(), 1240);
    }

    #[test]
    fn raw_format_cuts_exactly_at_max() {
        let mut s = Segmenter::new(PipeFormat::Raw, 1000, 3600, 86_400);
        let segs = s.push(&vec![1u8; 2500]);
        assert_eq!(segs.len(), 2);
        assert!(segs.iter().all(|x| x.data.len() == 1000));
        assert_eq!(s.flush().unwrap().data.len(), 500);
    }
}
