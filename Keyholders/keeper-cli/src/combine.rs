//! Shares → verified window key. The manifest public key check makes a
//! passing combine *proof* of correctness — garbage can't pass.

use anyhow::{bail, Context, Result};
use sealer_crypto::{kdf, BoxKeypair};
use sealer_keys::Manifest;
use sk_shares::{booklet, LineCtx};
use std::path::Path;

/// Read one share for `window` from a file that is either a whole booklet
/// or a single 14-word line.
fn share_from_file(
    path: &Path,
    ctx: &LineCtx<'_>,
) -> Result<sk_shares::Share> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let words = match booklet::find_line(&text, ctx.window) {
        Some(w) => w,
        None if text.split_whitespace().count() == sk_shares::WORDS_PER_LINE => {
            text.trim().to_string()
        }
        None => bail!(
            "{}: no booklet line for window {} (and not a bare 14-word line)",
            path.display(),
            ctx.window
        ),
    };
    sk_shares::decode_words(&words, ctx)
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
}

/// Combine shares from `files`, verify against the manifest, return the
/// window keypair (seed is `BoxKeypair`-derivable, see `seed`).
pub fn window_key_from_shares(
    manifest: &Manifest,
    window: u64,
    files: &[std::path::PathBuf],
) -> Result<([u8; 32], BoxKeypair)> {
    let b = &manifest.body;
    anyhow::ensure!(
        files.len() >= b.threshold_t as usize,
        "need {} shares (threshold), got {} files",
        b.threshold_t,
        files.len()
    );
    let ctx = LineCtx { community_id: &b.community_id, epoch: b.epoch, window };
    let mut shares = Vec::new();
    for f in files {
        shares.push(share_from_file(f, &ctx)?);
    }
    let secret = sk_shares::combine(&shares).map_err(|e| anyhow::anyhow!("{e}"))?;
    let seed = kdf::window_seed_from_secret(&secret);
    let kp = BoxKeypair::from_seed(&seed);

    let (expect, exhausted) = manifest
        .pub_for_window(window)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if exhausted {
        bail!("window {window} is beyond the manifest — cannot verify a key for it");
    }
    if expect != &kp.public {
        bail!(
            "reconstructed key does NOT match the manifest for window {window}.\n\
             All share checksums passed, so this is not a typo: wrong epoch's\n\
             booklets, or a share booklet from a different ceremony."
        );
    }
    Ok((seed, kp))
}

/// Load a previously combined key (32-byte seed file) and re-verify it.
pub fn window_key_from_file(
    manifest: &Manifest,
    window: u64,
    path: &Path,
) -> Result<BoxKeypair> {
    let seed: [u8; 32] = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{}: expected 32 bytes", path.display()))?;
    let kp = BoxKeypair::from_seed(&seed);
    let (expect, _) = manifest
        .pub_for_window(window)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    anyhow::ensure!(
        expect == &kp.public,
        "{} is not the key for window {window} (manifest mismatch)",
        path.display()
    );
    Ok(kp)
}
