//! Pipeline assembly (docs/00-architecture.md): watcher → sealer → spool →
//! uploader, plus the chain-event heartbeat and graceful shutdown.

use crate::config::{AfterSeal, Config, SourceMode};
use crate::seal::{SealEngine, SealInput};
use crate::watch::{watch_loop, ReadyFile};
use crate::{state, upload};
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

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

    // Uploader.
    let sinks = upload::build_sinks(&cfg.storage)?;
    let (upload_tx, upload_rx) = mpsc::channel::<()>(16);
    let uploader = tokio::spawn(
        upload::Uploader {
            spool_dir: spool_dir.clone(),
            sinks,
            catalog: cfg.catalog.mode,
            after_upload: cfg.spool.after_upload,
            device: device_key,
            retry_secs: 10,
        }
        .run(upload_rx, shutdown.clone()),
    );

    // Watcher.
    let (file_tx, mut file_rx) = mpsc::channel::<ReadyFile>(64);
    let watch_cfg = match cfg.source.mode {
        SourceMode::Watch => cfg.source.watch.clone().context("watch config")?,
    };
    let after_seal = watch_cfg.after_seal;
    let watcher = tokio::spawn(watch_loop(watch_cfg, file_tx, shutdown.clone()));

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
    let mut tick = tokio::time::interval(Duration::from_secs(if heartbeat == 0 { 3600 } else { heartbeat }));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut shutdown_rx = shutdown.clone();

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
            Some(f) = file_rx.recv() => {
                match engine.seal(SealInput::File { path: &f.path, mtime_ms: f.mtime_ms }) {
                    Ok(out) => {
                        tracing::info!(
                            src = %f.path.display(), seq = out.seq, window = out.window,
                            "sealed"
                        );
                        last_seal = std::time::Instant::now();
                        if after_seal == AfterSeal::Delete {
                            // Invariant 1: sealed segment is fsync'd + renamed
                            // into the spool before plaintext deletion.
                            if let Err(e) = std::fs::remove_file(&f.path) {
                                tracing::warn!(path = %f.path.display(), %e, "plaintext delete failed");
                            }
                        }
                        let _ = upload_tx.try_send(());
                    }
                    Err(e) => {
                        tracing::error!(path = %f.path.display(), error = %format!("{e:#}"), "seal failed");
                        // fail-closed manifests stop the pipeline rather than
                        // silently dropping footage on the floor
                        if matches!(cfg.sealing.manifest_exhausted, crate::config::ManifestExhausted::FailClosed) {
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

    drop(file_rx);
    let _ = watcher.await;
    let _ = uploader.await;
    tracing::info!("sealerd stopped cleanly");
    Ok(())
}
