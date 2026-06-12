//! Device state directory: enrollment artifacts + persistent chain state.
//!
//! ```text
//! <state_dir>/
//!   device.key          Ed25519 secret (0600)
//!   device.pub
//!   admin.pub           pinned community admin verify key
//!   manifest.skm        current pubkey manifest (verified on load)
//!   chain-state.json    { next_seq, prev_link } — persisted BEFORE a
//!                       segment is considered complete (crash invariant 2)
//!   spool/              sealed segments awaiting upload (default location)
//! ```

use anyhow::{bail, Context, Result};
use sealer_crypto::SigKeypair;
use sealer_keys::Manifest;
use std::fs;
use std::path::{Path, PathBuf};

pub struct DeviceState {
    pub dir: PathBuf,
    pub device_key: SigKeypair,
    pub admin_pub: [u8; 32],
    pub manifest: Manifest,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainStateFile {
    pub camera_id: String,
    pub next_seq: u64,
    pub prev_link_hex: String,
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

fn read_key32(path: &Path) -> Result<[u8; 32]> {
    let b = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    b.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{}: expected 32 bytes", path.display()))
}

/// One-time setup: pin admin key, install + verify manifest, generate the
/// device signing key. Idempotence: refuses to overwrite an enrolled dir.
pub fn enroll(state_dir: &Path, manifest_path: &Path, admin_pub_path: &Path) -> Result<DeviceState> {
    if state_dir.join("device.key").exists() {
        bail!(
            "{} is already enrolled (device.key exists); refusing to overwrite",
            state_dir.display()
        );
    }
    fs::create_dir_all(state_dir)?;
    fs::create_dir_all(state_dir.join("spool"))?;

    let admin_pub = read_key32(admin_pub_path)?;
    let manifest_bytes = fs::read(manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest = Manifest::decode_verified(&manifest_bytes, &admin_pub)
        .context("manifest does not verify against the admin key — wrong files?")?;

    let device_key = SigKeypair::generate();
    write_0600(&state_dir.join("device.key"), &device_key.secret)?;
    fs::write(state_dir.join("device.pub"), device_key.public)?;
    fs::write(state_dir.join("admin.pub"), admin_pub)?;
    fs::write(state_dir.join("manifest.skm"), &manifest_bytes)?;

    Ok(DeviceState { dir: state_dir.to_path_buf(), device_key, admin_pub, manifest })
}

/// Load an enrolled state dir, re-verifying the manifest against the
/// pinned admin key every time.
pub fn load(state_dir: &Path) -> Result<DeviceState> {
    let secret = fs::read(state_dir.join("device.key"))
        .with_context(|| format!("{} not enrolled (run `sealer enroll`)", state_dir.display()))?;
    let secret: [u8; 64] = secret
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("device.key: expected 64 bytes"))?;
    let public: [u8; 32] = secret[32..].try_into().unwrap();
    let device_key = SigKeypair { public, secret };

    let admin_pub = read_key32(&state_dir.join("admin.pub"))?;
    let manifest = Manifest::decode_verified(&fs::read(state_dir.join("manifest.skm"))?, &admin_pub)
        .context("pinned manifest failed verification — state dir corrupted?")?;

    Ok(DeviceState { dir: state_dir.to_path_buf(), device_key, admin_pub, manifest })
}

pub fn chain_state_path(state_dir: &Path) -> PathBuf {
    state_dir.join("chain-state.json")
}

pub fn load_chain_state(state_dir: &Path, camera_id: &str) -> Result<ChainStateFile> {
    let path = chain_state_path(state_dir);
    if !path.exists() {
        return Ok(ChainStateFile {
            camera_id: camera_id.to_string(),
            next_seq: 0,
            prev_link_hex: hex::encode(sks_format::GENESIS_LINK),
        });
    }
    let s: ChainStateFile = serde_json::from_slice(&fs::read(&path)?)
        .context("chain-state.json corrupted")?;
    if s.camera_id != camera_id {
        bail!(
            "chain state belongs to camera '{}', config says '{}'",
            s.camera_id,
            camera_id
        );
    }
    Ok(s)
}

/// Atomic persist (write tmp + rename) — called before a sealed segment is
/// considered complete.
pub fn save_chain_state(state_dir: &Path, s: &ChainStateFile) -> Result<()> {
    let path = chain_state_path(state_dir);
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(s)?)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}
