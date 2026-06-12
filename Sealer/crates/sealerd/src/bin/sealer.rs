//! `sealer` — operator tool: enroll, doctor, status.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sealerd::config::Config;
use sealerd::{state, upload};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sealer", version, about = "SplitKey Sealer operator tool")]
struct Cli {
    #[arg(long, env = "SEALER_CONFIG", default_value = "/etc/splitkey/sealer.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// First-time setup: pin admin key + manifest, generate device key.
    Enroll,
    /// Check config, enrollment, manifest coverage, storage reachability.
    Doctor,
    /// Show chain head, spool depth, enrollment summary.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;
    match cli.cmd {
        Cmd::Enroll => enroll(&cfg),
        Cmd::Doctor => doctor(&cfg).await,
        Cmd::Status => status(&cfg),
    }
}

fn enroll(cfg: &Config) -> Result<()> {
    let st = state::enroll(&cfg.device.state_dir, &cfg.community.manifest, &cfg.community.admin_pubkey)?;
    if st.manifest.body.community_id != cfg.community.id {
        // Enrolled, but flag the mismatch loudly.
        println!(
            "WARNING: manifest community '{}' != config community.id '{}'",
            st.manifest.body.community_id, cfg.community.id
        );
    }
    println!("enrolled camera '{}' in community '{}'", cfg.device.camera_id, st.manifest.body.community_id);
    println!("  state dir : {}", st.dir.display());
    println!("  device key: {}", hex::encode(st.device_key.key_id()));
    println!("  epoch {} windows {}..={} ({}s each)",
        st.manifest.body.epoch, st.manifest.body.first_window,
        st.manifest.body.last_window, st.manifest.body.window_secs);
    Ok(())
}

async fn doctor(cfg: &Config) -> Result<()> {
    let mut failures = 0usize;
    let mut check = |name: &str, ok: bool, detail: String| {
        println!("{} {:<28} {}", if ok { "✔" } else { "✘" }, name, detail);
        if !ok {
            failures += 1;
        }
    };

    check("config", true, "parsed + validated".into());

    match state::load(&cfg.device.state_dir) {
        Ok(st) => {
            check("enrollment", true, format!("device key {}", hex::encode(st.device_key.key_id())));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as i64;
            let window = sealer_keys::Manifest::window_index_for(now, st.manifest.body.window_secs);
            let b = &st.manifest.body;
            if window > b.last_window {
                check("manifest coverage", false, format!(
                    "EXHAUSTED: current window {} > last {} — hold a ceremony",
                    window, b.last_window));
            } else if window < b.first_window {
                check("manifest coverage", false, format!(
                    "current window {} before manifest start {} — clock wrong?",
                    window, b.first_window));
            } else {
                let days_left = (b.last_window - window) * b.window_secs as u64 / 86_400;
                check("manifest coverage", days_left >= 30,
                    format!("{days_left} days of window keys remaining"));
            }
        }
        Err(e) => check("enrollment", false, format!("{e:#}")),
    }

    if let Some(w) = &cfg.source.watch {
        check("watch dir", w.path.is_dir(), w.path.display().to_string());
    }

    match upload::build_sinks(&cfg.storage) {
        Ok(sinks) => {
            for sink in &sinks {
                match sink.probe().await {
                    Ok(()) => check("storage", true, format!("{} reachable (probe object written)", sink.name)),
                    Err(e) => check("storage", false, format!("{}: {e:#}", sink.name)),
                }
            }
            if sinks.len() < 2 {
                println!("  note: single storage sink — consider a second for the withholding defense");
            }
        }
        Err(e) => check("storage", false, format!("{e:#}")),
    }

    if failures > 0 {
        anyhow::bail!("{failures} check(s) failed");
    }
    println!("all checks passed");
    Ok(())
}

fn status(cfg: &Config) -> Result<()> {
    let st = state::load(&cfg.device.state_dir).context("not enrolled")?;
    let chain = state::load_chain_state(&cfg.device.state_dir, &cfg.device.camera_id)?;
    let spool = cfg.spool_dir();
    let pending = std::fs::read_dir(&spool)
        .map(|d| d.flatten().filter(|e| e.path().extension().is_some_and(|x| x == "sks")).count())
        .unwrap_or(0);

    println!("camera     : {} ({})", cfg.device.camera_id, st.manifest.body.community_id);
    println!("device key : {}", hex::encode(st.device_key.key_id()));
    println!("chain head : seq {} link {}…", chain.next_seq, &chain.prev_link_hex[..16]);
    println!("spool      : {pending} segment(s) pending upload in {}", spool.display());
    println!("epoch      : {} (windows {}..={}, {}s each)",
        st.manifest.body.epoch, st.manifest.body.first_window,
        st.manifest.body.last_window, st.manifest.body.window_secs);
    Ok(())
}
