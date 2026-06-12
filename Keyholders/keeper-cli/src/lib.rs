//! keeper-cli core (see ../README.md): what a quorum of keyholders runs to
//! release exactly one window from dumb storage. Library layer so the
//! future Keyholder desktop app (and tests) can drive it without the CLI.

pub mod combine;
pub mod list;
pub mod release;
pub mod skc;
pub mod store;

use anyhow::{Context, Result};
use sealer_keys::Manifest;
use std::path::Path;

/// Load manifest + the out-of-band admin key it must verify against.
pub fn load_manifest(manifest_path: &Path, admin_pub_path: &Path) -> Result<Manifest> {
    let admin_pub: [u8; 32] = std::fs::read(admin_pub_path)
        .with_context(|| format!("reading {}", admin_pub_path.display()))?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("admin.pub: expected 32 bytes"))?;
    Manifest::decode_verified(
        &std::fs::read(manifest_path)
            .with_context(|| format!("reading {}", manifest_path.display()))?,
        &admin_pub,
    )
    .context("manifest does not verify against the admin key")
}

/// Resolve `--date` / `--window` to a window index, validated against the
/// manifest range.
pub fn resolve_window(
    manifest: &Manifest,
    date: Option<&str>,
    window: Option<u64>,
) -> Result<u64> {
    let w = match (date, window) {
        (Some(d), None) => sk_shares::dates::window_for_date(d, manifest.body.window_secs)
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        (None, Some(w)) => w,
        _ => anyhow::bail!("give exactly one of --date or --window"),
    };
    let b = &manifest.body;
    anyhow::ensure!(
        (b.first_window..=b.last_window).contains(&w),
        "window {w} ({}) is outside the manifest range {} .. {}",
        sk_shares::dates::label_for_window(w, b.window_secs),
        sk_shares::dates::label_for_window(b.first_window, b.window_secs),
        sk_shares::dates::label_for_window(b.last_window, b.window_secs),
    );
    Ok(w)
}
