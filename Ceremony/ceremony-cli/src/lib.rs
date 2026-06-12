//! Ceremony core (see ../README.md): one offline run per epoch produces the
//! manifest, the admin keypair, and n keyholder booklets — then destroys
//! the CRK. The CLI in `main.rs` is a thin wrapper.

use anyhow::{bail, Context, Result};
use sealer_crypto::{kdf, BoxKeypair, SigKeypair};
use sealer_keys::{Manifest, ManifestBody};
use sk_shares::{booklet, dates, LineCtx};
use std::fs;
use std::path::{Path, PathBuf};

pub struct NewParams {
    pub community_id: String,
    pub epoch: u16,
    pub window_secs: u32,
    pub first_window: u64,
    pub window_count: u64,
    pub threshold_t: u8,
    pub keyholders: Vec<String>,
    pub out_dir: PathBuf,
    pub keep_crk: bool,
    pub ceremony_date: i64,
}

fn write_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn run_new(p: &NewParams) -> Result<()> {
    let n = p.keyholders.len();
    if n == 0 || n > 255 {
        bail!("need 1..=255 keyholders, got {n}");
    }
    if p.threshold_t == 0 || p.threshold_t as usize > n {
        bail!("threshold {} impossible with {} keyholders", p.threshold_t, n);
    }
    let mut sorted = p.keyholders.clone();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != n {
        bail!("duplicate keyholder names");
    }
    for name in &p.keyholders {
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            bail!("keyholder name '{name}' — use only letters, digits, '-', '_'");
        }
    }
    if p.window_count == 0 {
        bail!("empty window range");
    }
    fs::create_dir_all(p.out_dir.join("booklets"))?;

    // 1–2. Admin signing key + CRK (CRK lives only in this function).
    let admin = SigKeypair::generate();
    let crk = sealer_crypto::random_32();

    // 3. Derive + split every window; accumulate booklets in memory.
    let mut window_pubs = Vec::with_capacity(p.window_count as usize);
    let mut booklets: Vec<String> = vec![String::new(); n];
    for i in 0..p.window_count {
        let w = p.first_window + i;
        let secret = kdf::derive_window_secret(&crk, w);
        let kp = BoxKeypair::from_seed(&kdf::window_seed_from_secret(&secret));
        window_pubs.push(serde_bytes::ByteArray::new(kp.public));

        let ctx = LineCtx { community_id: &p.community_id, epoch: p.epoch, window: w };
        let shares = sk_shares::split(&secret, p.threshold_t, n as u8)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        for (k, share) in shares.iter().enumerate() {
            let words = sk_shares::encode_words(share, &ctx);
            booklets[k].push_str(&booklet::format_line(w, p.window_secs, &words));
            booklets[k].push('\n');
        }
    }

    // 4. Signed manifest.
    let body = ManifestBody {
        community_id: p.community_id.clone(),
        epoch: p.epoch,
        window_secs: p.window_secs,
        first_window: p.first_window,
        last_window: p.first_window + p.window_count - 1,
        window_pubs,
        admin_key_id: admin.key_id(),
        ceremony_date: p.ceremony_date,
        threshold_t: p.threshold_t,
        threshold_n: n as u8,
    };
    let manifest_bytes = Manifest::encode_signed(&body, &admin);
    fs::write(p.out_dir.join("manifest.skm"), &manifest_bytes)?;
    fs::write(p.out_dir.join("admin.pub"), admin.public)?;
    write_0600(&p.out_dir.join("admin.key"), &admin.secret)?;

    // 5. Booklets (header + lines).
    let first_label = dates::label_for_window(p.first_window, p.window_secs);
    let last_label = dates::label_for_window(body.last_window, p.window_secs);
    for (k, name) in p.keyholders.iter().enumerate() {
        let header = format!(
            "SplitKey keyholder booklet\n\
             community: {}    epoch: {}    holder: {}    share {} of {} (threshold {})\n\
             windows: {}h UTC, {} .. {}\n\n",
            p.community_id, p.epoch, name, k + 1, n, p.threshold_t,
            p.window_secs / 3600, first_label, last_label,
        );
        fs::write(
            p.out_dir.join("booklets").join(format!("{name}.txt")),
            format!("{header}{}", booklets[k]),
        )?;
    }

    // 6. Self-check FROM DISK before the CRK goes away: re-combine t shares
    // out of the written booklet files for sample windows and require the
    // derived pubkey to match the manifest. Catches encode/write bugs while
    // regeneration is still possible.
    let manifest = Manifest::decode_verified(&manifest_bytes, &admin.public)
        .context("freshly written manifest failed to verify")?;
    let mut samples = vec![p.first_window, body.last_window];
    for _ in 0..3.min(p.window_count) {
        let mut r = [0u8; 8];
        sealer_crypto::random_bytes(&mut r);
        samples.push(p.first_window + u64::from_le_bytes(r) % p.window_count);
    }
    for &w in &samples {
        self_check_window(p, &manifest, w)
            .with_context(|| format!("ceremony self-check FAILED for window {w}"))?;
    }

    // 7. The CRK is dropped here (end of scope) unless explicitly kept.
    if p.keep_crk {
        write_0600(&p.out_dir.join("crk.secret"), &crk)?;
        eprintln!(
            "WARNING: --keep-crk wrote crk.secret — DEV/SIM ONLY.\n\
             Anyone holding this file can decrypt the ENTIRE epoch.\n\
             Real ceremonies destroy the CRK; recovery redundancy comes from\n\
             enrolling more than t keyholders."
        );
    }

    println!(
        "ceremony complete: {} windows ({} .. {}), {} keyholders, threshold {}-of-{}\n\
         out: {}\n\
         self-check: {} sample windows re-combined from booklet files — OK\n\
         next: print + hand out booklets/, DELETE the booklet files,\n\
               enroll cameras with manifest.skm + admin.pub",
        p.window_count, first_label, last_label, n, p.threshold_t, n,
        p.out_dir.display(),
        samples.len(),
    );
    Ok(())
}

fn self_check_window(p: &NewParams, manifest: &Manifest, w: u64) -> Result<()> {
    let n = p.keyholders.len();
    // pick t distinct holders pseudo-randomly (offset by a random start)
    let mut r = [0u8; 8];
    sealer_crypto::random_bytes(&mut r);
    let start = (u64::from_le_bytes(r) % n as u64) as usize;
    let ctx = LineCtx { community_id: &p.community_id, epoch: p.epoch, window: w };
    let mut shares = Vec::new();
    for k in 0..p.threshold_t as usize {
        let name = &p.keyholders[(start + k) % n];
        let text = fs::read_to_string(p.out_dir.join("booklets").join(format!("{name}.txt")))?;
        let words = booklet::find_line(&text, w)
            .with_context(|| format!("booklet {name}.txt has no line for window {w}"))?;
        shares.push(sk_shares::decode_words(&words, &ctx).map_err(|e| anyhow::anyhow!("{e}"))?);
    }
    let secret = sk_shares::combine(&shares).map_err(|e| anyhow::anyhow!("{e}"))?;
    let kp = BoxKeypair::from_seed(&kdf::window_seed_from_secret(&secret));
    let (expect, exhausted) = manifest.pub_for_window(w).map_err(|e| anyhow::anyhow!("{e}"))?;
    if exhausted || expect != &kp.public {
        bail!("reconstructed key does not match manifest");
    }
    Ok(())
}
