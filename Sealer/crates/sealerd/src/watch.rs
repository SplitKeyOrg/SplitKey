//! Polling directory watcher (docs/05-ingestion.md, Mode 1).
//!
//! Completion detection: a candidate file is "ready" once its (size, mtime)
//! has been stable for `stable_secs`. Polling is the crash-robust,
//! cross-platform baseline; inotify CLOSE_WRITE is a later optimization.

use crate::config::Watch;
use glob::Pattern;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyFile {
    pub path: PathBuf,
    pub mtime_ms: i64,
    pub size: u64,
}

#[derive(Clone, Copy, PartialEq)]
struct Observation {
    size: u64,
    mtime_ms: i64,
    stable_polls: u32,
}

/// Watch loop: emits each ready file exactly once (per daemon run), then
/// forgets it once it disappears (after_seal = delete) or keeps ignoring it.
pub async fn watch_loop(
    cfg: Watch,
    tx: mpsc::Sender<ReadyFile>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let ready_glob = Pattern::new(&cfg.ready_glob)?;
    let ignore_glob = cfg.ignore_glob.as_deref().map(Pattern::new).transpose()?;
    let polls_needed = if cfg.stable_secs == 0 {
        1
    } else {
        ((cfg.stable_secs * 1000).div_ceil(cfg.poll_ms)).max(1) as u32
    };

    let mut seen: HashMap<PathBuf, Observation> = HashMap::new();
    let mut emitted: HashMap<PathBuf, i64> = HashMap::new();

    loop {
        tokio::select! {
            _ = shutdown.changed() => if *shutdown.borrow() { return Ok(()); },
            _ = tokio::time::sleep(Duration::from_millis(cfg.poll_ms)) => {}
        }

        let entries = match std::fs::read_dir(&cfg.path) {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(path = %cfg.path.display(), %err, "watch dir unreadable");
                continue;
            }
        };

        let mut present: Vec<PathBuf> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            if !path.is_file()
                || name.starts_with('.')
                || !ready_glob.matches(name)
                || ignore_glob.as_ref().is_some_and(|g| g.matches(name))
            {
                continue;
            }
            present.push(path.clone());

            let Ok(md) = entry.metadata() else { continue };
            let mtime_ms = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            let size = md.len();

            // Already emitted this exact version? (re-emits if rewritten)
            if emitted.get(&path) == Some(&mtime_ms) {
                continue;
            }

            let obs = seen.entry(path.clone()).or_insert(Observation {
                size,
                mtime_ms,
                stable_polls: 0,
            });
            if obs.size == size && obs.mtime_ms == mtime_ms {
                obs.stable_polls += 1;
            } else {
                *obs = Observation { size, mtime_ms, stable_polls: 1 };
            }

            if obs.stable_polls >= polls_needed {
                emitted.insert(path.clone(), mtime_ms);
                seen.remove(&path);
                if tx.send(ReadyFile { path, mtime_ms, size }).await.is_err() {
                    return Ok(()); // pipeline gone
                }
            }
        }

        // Forget files that disappeared so the maps stay bounded.
        seen.retain(|p, _| present.contains(p));
        emitted.retain(|p, _| present.contains(p));
    }
}
