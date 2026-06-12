//! Pipeline assembly (docs/00-architecture.md): source (watcher | pipe) →
//! sealer → spool → uploader, plus chain events and graceful shutdown.

use crate::config::{AfterSeal, Config, SourceMode};
use crate::pipe::{pipe_loop, PipeMsg, SourceEvent};
use crate::seal::{SealEngine, SealInput};
use crate::watch::{watch_loop, ReadyFile};
use crate::{state, upload};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Unified message from whichever source is configured.
enum SourceMsg {
    /// Watched file, ready to seal (delete plaintext after if configured).
    File(ReadyFile),
    /// In-RAM segment from the pipe source.
    Bytes {
        data: Vec<u8>,
        ts_start_ms: i64,
        ts_end_ms: i64,
        content_meta: BTreeMap<String, String>,
    },
    /// Source lifecycle → chain event.
    Event { kind: &'static str, detail: serde_json::Value },
}

/// Run the daemon until `shutdown` flips true (ctrl-c or test harness).
pub async fn run(cfg: Config, shutdown: watch::Receiver<bool>) -> Result<()> {
    let device = state::load(&cfg.device.state_dir)?;
    if device.manifest.body.community_id != cfg.community.id {
        anyhow::bail!(
            "config community.id '{}' != enrolled manifest community '{}'",
            cfg.community.id,
            device.manifest.body.community_id
        );
    }

    let spool_dir = cfg.spool_dir();
    let mut engine = SealEngine::new(
        device,
        &cfg.device.camera_id,
        &spool_dir,
        cfg.sealing.chunk_bytes.0 as usize,
        cfg.sealing.manifest_exhausted,
    )?;
    engine.clean_stale_tmp()?;
    let device_key = engine.device.device_key.clone();

    // Uploader. It gets its own shutdown signal, flipped only AFTER the
    // source drain — so the final partial segment still gets uploaded.
    let sinks = upload::build_sinks(&cfg.storage)?;
    let (upload_tx, upload_rx) = mpsc::channel::<()>(16);
    let (uploader_stop_tx, uploader_stop_rx) = watch::channel(false);
    let uploader = tokio::spawn(
        upload::Uploader {
            spool_dir: spool_dir.clone(),
            sinks,
            catalog: cfg.catalog.mode,
            after_upload: cfg.spool.after_upload,
            device: device_key,
            retry_secs: 10,
        }
        .run(upload_rx, uploader_stop_rx),
    );

    // Source → unified channel. Bounded: a slow sealer backpressures the
    // source (and through it, a piped recorder).
    let (src_tx, mut src_rx) = mpsc::channel::<SourceMsg>(8);
    let mut after_seal = AfterSeal::Keep;
    let source = match cfg.source.mode {
        SourceMode::Watch => {
            let watch_cfg = cfg.source.watch.clone().context("watch config")?;
            after_seal = watch_cfg.after_seal;
            let (file_tx, mut file_rx) = mpsc::channel::<ReadyFile>(8);
            let watcher = tokio::spawn(watch_loop(watch_cfg, file_tx, shutdown.clone()));
            let tx = src_tx.clone();
            tokio::spawn(async move {
                while let Some(f) = file_rx.recv().await {
                    if tx.send(SourceMsg::File(f)).await.is_err() {
                        break;
                    }
                }
                let _ = watcher.await;
            })
        }
        SourceMode::Pipe => {
            let pipe_cfg = cfg.source.pipe.clone().context("pipe config")?;
            let window_secs = engine.device.manifest.body.window_secs;
            let (pipe_tx, mut pipe_rx) = mpsc::channel::<PipeMsg>(4);
            let pump = tokio::spawn(pipe_loop(
                pipe_cfg,
                cfg.sealing.segment_max_bytes.0 as usize,
                cfg.sealing.segment_max_secs,
                window_secs,
                pipe_tx,
                shutdown.clone(),
            ));
            let tx = src_tx.clone();
            tokio::spawn(async move {
                while let Some(msg) = pipe_rx.recv().await {
                    let m = match msg {
                        PipeMsg::Segment(s) => SourceMsg::Bytes {
                            data: s.data,
                            ts_start_ms: s.ts_start_ms,
                            ts_end_ms: s.ts_end_ms,
                            content_meta: s.content_meta,
                        },
                        PipeMsg::Event(SourceEvent::Lost { reason }) => SourceMsg::Event {
                            kind: "source_lost",
                            detail: serde_json::json!({ "reason": reason }),
                        },
                        PipeMsg::Event(SourceEvent::Restored) => SourceMsg::Event {
                            kind: "source_restored",
                            detail: serde_json::json!({}),
                        },
                    };
                    if tx.send(m).await.is_err() {
                        break;
                    }
                }
                let _ = pump.await;
            })
        }
    };
    drop(src_tx);

    // Boot chain event: reboots are declared, not silent.
    let boot = engine.seal(SealInput::Event {
        kind: "boot",
        detail: serde_json::json!({
            "camera_id": cfg.device.camera_id,
            "version": env!("CARGO_PKG_VERSION"),
        }),
    })?;
    tracing::info!(seq = boot.seq, "chain event: boot");
    let _ = upload_tx.try_send(());

    // Seal loop + heartbeat.
    let heartbeat = cfg.chain.heartbeat_secs;
    let mut last_seal = std::time::Instant::now();
    let mut tick =
        tokio::time::interval(Duration::from_secs(if heartbeat == 0 { 3600 } else { heartbeat }));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut shutdown_rx = shutdown.clone();
    let fail_closed = matches!(
        cfg.sealing.manifest_exhausted,
        crate::config::ManifestExhausted::FailClosed
    );

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
            msg = src_rx.recv() => {
                let Some(msg) = msg else { break }; // source finished (stdin EOF)
                let (input, plaintext_path): (SealInput<'_>, Option<PathBuf>) = match &msg {
                    SourceMsg::File(f) => (
                        SealInput::File { path: &f.path, mtime_ms: f.mtime_ms },
                        (after_seal == AfterSeal::Delete).then(|| f.path.clone()),
                    ),
                    SourceMsg::Bytes { data, ts_start_ms, ts_end_ms, content_meta } => (
                        SealInput::Bytes {
                            data: data.clone(),
                            ts_start_ms: *ts_start_ms,
                            ts_end_ms: *ts_end_ms,
                            content_meta: content_meta.clone(),
                        },
                        None,
                    ),
                    SourceMsg::Event { kind, detail } => (
                        SealInput::Event { kind, detail: detail.clone() },
                        None,
                    ),
                };
                match engine.seal(input) {
                    Ok(out) => {
                        tracing::info!(seq = out.seq, window = out.window, "sealed");
                        last_seal = std::time::Instant::now();
                        if let Some(path) = plaintext_path {
                            // Invariant 1: sealed segment is fsync'd + renamed
                            // into the spool before plaintext deletion.
                            if let Err(e) = std::fs::remove_file(&path) {
                                tracing::warn!(path = %path.display(), %e, "plaintext delete failed");
                            }
                        }
                        let _ = upload_tx.try_send(());
                    }
                    Err(e) => {
                        tracing::error!(error = %format!("{e:#}"), "seal failed");
                        // fail-closed stops rather than silently dropping footage
                        if fail_closed {
                            return Err(e);
                        }
                    }
                }
            }
            _ = tick.tick() => {
                if heartbeat > 0 && last_seal.elapsed() >= Duration::from_secs(heartbeat) {
                    match engine.seal(SealInput::Event { kind: "heartbeat", detail: serde_json::json!({}) }) {
                        Ok(out) => {
                            tracing::debug!(seq = out.seq, "chain event: heartbeat");
                            last_seal = std::time::Instant::now();
                            let _ = upload_tx.try_send(());
                        }
                        Err(e) => tracing::error!(error = %format!("{e:#}"), "heartbeat seal failed"),
                    }
                }
            }
        }
    }

    // Drain anything the source flushes during shutdown (e.g. the pipe's
    // final partial segment) — footage beats latency. The source task drops
    // its sender when done, closing the channel.
    loop {
        match tokio::time::timeout(Duration::from_secs(5), src_rx.recv()).await {
            Ok(Some(SourceMsg::Bytes { data, ts_start_ms, ts_end_ms, content_meta })) => {
                match engine.seal(SealInput::Bytes { data, ts_start_ms, ts_end_ms, content_meta }) {
                    Ok(out) => tracing::info!(seq = out.seq, "sealed final segment"),
                    Err(e) => tracing::error!(error = %format!("{e:#}"), "final seal failed"),
                }
            }
            Ok(Some(_)) => {}        // files/events: skip during shutdown
            Ok(None) | Err(_) => break, // channel closed or grace expired
        }
    }
    let _ = upload_tx.try_send(());

    let _ = source.await;
    // Now (and only now) let the uploader do its final drain and stop.
    let _ = uploader_stop_tx.send(true);
    let _ = uploader.await;
    tracing::info!("sealerd stopped cleanly");
    Ok(())
}
