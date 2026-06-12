//! `sks` — SplitKey Sealer operator tool (Phase 1).
//!
//! Subcommands cover the full seal→verify→release loop with no daemon yet:
//! `ceremony-sim` (test community), `keygen-device`, `seal`, `inspect`,
//! `verify` (keyless tamper/chain check), `release` (simulated quorum),
//! `unseal` (decrypt with a released window key).

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use sealer_crypto::{BoxKeypair, SigKeypair};
use sealer_keys::{ceremony_sim, Manifest};
use sks_format::{ClockConfidence, Header, ParsedSegment, SegmentWriter};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "sks", version, about = "SplitKey Sealer tools: seal, verify, inspect, release")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a simulated community (CRK + admin key + signed manifest).
    /// Test/dev stand-in for the real key ceremony.
    CeremonySim {
        #[arg(long)]
        community: String,
        #[arg(long, default_value_t = 1)]
        epoch: u16,
        /// Window length in seconds (decided default: 24 h).
        #[arg(long, default_value_t = 86_400)]
        window_secs: u32,
        /// First covered unix time (defaults to now).
        #[arg(long)]
        start_unix: Option<i64>,
        /// Number of windows to cover (decided: ~18 months for real
        /// ceremonies; small values fine for tests).
        #[arg(long, default_value_t = 30)]
        windows: u64,
        #[arg(long, default_value = "3-of-5")]
        threshold: String,
        /// Output directory (admin.key, admin.pub, crk.secret, manifest.skm).
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate a device signing keypair.
    KeygenDevice {
        #[arg(long)]
        out: PathBuf,
    },
    /// Seal plaintext files into chained .sks segments.
    Seal {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        admin_pub: PathBuf,
        #[arg(long)]
        device_key: PathBuf,
        #[arg(long)]
        camera_id: String,
        /// Output directory; chain state persists here across invocations.
        #[arg(long)]
        out: PathBuf,
        /// Optional content labels, comma-separated k=v (e.g. kind=mp4).
        #[arg(long)]
        meta: Option<String>,
        /// Plaintext files, sealed in the order given.
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Dump a segment's plaintext metadata (header/footer). No keys needed.
    Inspect {
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify segments + chain. Needs only the device PUBLIC key.
    Verify {
        /// .sks files or a directory of them.
        path: PathBuf,
        #[arg(long)]
        device_pub: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Simulated quorum release: derive one window's private key from the
    /// CRK (real releases reconstruct via keyholder shares instead).
    Release {
        #[arg(long)]
        crk: PathBuf,
        #[arg(long)]
        window: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Decrypt a segment with a released window key.
    Unseal {
        file: PathBuf,
        #[arg(long)]
        window_key: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    sealer_crypto::init();
    match Cli::parse().cmd {
        Cmd::CeremonySim { community, epoch, window_secs, start_unix, windows, threshold, out } =>
            ceremony_sim_cmd(&community, epoch, window_secs, start_unix, windows, &threshold, &out),
        Cmd::KeygenDevice { out } => keygen_device(&out),
        Cmd::Seal { manifest, admin_pub, device_key, camera_id, out, meta, files } =>
            seal_cmd(&manifest, &admin_pub, &device_key, &camera_id, &out, meta.as_deref(), &files),
        Cmd::Inspect { file, json } => inspect_cmd(&file, json),
        Cmd::Verify { path, device_pub, json } => verify_cmd(&path, &device_pub, json),
        Cmd::Release { crk, window, out } => release_cmd(&crk, window, &out),
        Cmd::Unseal { file, window_key, out } => unseal_cmd(&file, &window_key, &out),
    }
}

// ---------- key file helpers (raw 32-byte files) ----------

fn write_key(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn read_key32(path: &Path) -> Result<[u8; 32]> {
    let b = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let arr: [u8; 32] = b.as_slice().try_into()
        .map_err(|_| anyhow::anyhow!("{}: expected exactly 32 bytes", path.display()))?;
    Ok(arr)
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

// ---------- subcommands ----------

fn ceremony_sim_cmd(
    community: &str,
    epoch: u16,
    window_secs: u32,
    start_unix: Option<i64>,
    windows: u64,
    threshold: &str,
    out: &Path,
) -> Result<()> {
    let (t, n) = threshold
        .split_once("-of-")
        .and_then(|(a, b)| Some((a.parse().ok()?, b.parse().ok()?)))
        .context("--threshold must look like 3-of-5")?;
    let start = start_unix.unwrap_or_else(|| now_unix_ms() / 1000);
    let first_window = Manifest::window_index_for(start, window_secs);

    fs::create_dir_all(out)?;
    let sim = ceremony_sim::generate(community, epoch, window_secs, first_window, windows, start, (t, n));

    write_key(&out.join("crk.secret"), &sim.crk)?;
    write_key(&out.join("admin.key"), &sim.admin.secret)?;
    write_key(&out.join("admin.pub"), &sim.admin.public)?;
    fs::write(out.join("manifest.skm"), &sim.manifest_bytes)?;

    eprintln!(
        "ceremony-sim: community '{}' epoch {} — windows {}..={} ({} × {}s), threshold {}-of-{}",
        community, epoch, sim.body.first_window, sim.body.last_window, windows, window_secs, t, n
    );
    eprintln!("  {} (SIMULATION ONLY: a real ceremony destroys the CRK)", out.join("crk.secret").display());
    eprintln!("  {}", out.join("manifest.skm").display());
    Ok(())
}

fn keygen_device(out: &Path) -> Result<()> {
    fs::create_dir_all(out)?;
    let kp = SigKeypair::generate();
    write_key(&out.join("device.key"), &kp.secret)?;
    write_key(&out.join("device.pub"), &kp.public)?;
    eprintln!("device key id {}", hex::encode(kp.key_id()));
    eprintln!("  {}", out.join("device.key").display());
    eprintln!("  {}", out.join("device.pub").display());
    Ok(())
}

fn read_sig_keypair(path: &Path) -> Result<SigKeypair> {
    let b = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    match b.len() {
        64 => {
            let secret: [u8; 64] = b.as_slice().try_into().unwrap();
            // Recover the public half from the secret key's trailing 32 bytes.
            let public: [u8; 32] = secret[32..].try_into().unwrap();
            Ok(SigKeypair { public, secret })
        }
        32 => Ok(SigKeypair::from_seed(&b.as_slice().try_into().unwrap())),
        _ => bail!("{}: expected 32-byte seed or 64-byte secret key", path.display()),
    }
}

/// Persisted chain state (docs/00-architecture.md crash-safety invariant 2).
#[derive(serde::Serialize, serde::Deserialize)]
struct ChainStateFile {
    camera_id: String,
    next_seq: u64,
    prev_link_hex: String,
}

fn seal_cmd(
    manifest_path: &Path,
    admin_pub: &Path,
    device_key: &Path,
    camera_id: &str,
    out: &Path,
    meta: Option<&str>,
    files: &[PathBuf],
) -> Result<()> {
    let admin_pub = read_key32(admin_pub)?;
    let manifest = Manifest::decode_verified(&fs::read(manifest_path)?, &admin_pub)
        .context("manifest verification failed")?;
    let device = read_sig_keypair(device_key)?;
    fs::create_dir_all(out)?;

    let content_meta: BTreeMap<String, String> = meta
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|kv| kv.split_once('=').map(|(k, v)| (k.into(), v.into())))
        .collect();

    // Resume or start the chain.
    let state_path = out.join("chain-state.json");
    let mut state: ChainStateFile = if state_path.exists() {
        let s: ChainStateFile = serde_json::from_slice(&fs::read(&state_path)?)?;
        if s.camera_id != camera_id {
            bail!("chain state in {} belongs to camera '{}'", out.display(), s.camera_id);
        }
        s
    } else {
        ChainStateFile {
            camera_id: camera_id.into(),
            next_seq: 0,
            prev_link_hex: hex::encode(sks_format::GENESIS_LINK),
        }
    };
    let mut prev_link: [u8; 32] = hex::decode(&state.prev_link_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("corrupt chain state"))?;
    let mut boot_id = [0u8; 8];
    sealer_crypto::random_bytes(&mut boot_id);
    let t0 = std::time::Instant::now();

    for path in files {
        let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let mtime_ms = fs::metadata(path)?
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or_else(now_unix_ms);
        let window = Manifest::window_index_for(mtime_ms / 1000, manifest.body.window_secs);
        let (wk_pub, exhausted) = manifest.pub_for_window(window)?;
        if exhausted {
            eprintln!(
                "WARNING: manifest exhausted (window {} > {}); sealing to LAST key — schedule a ceremony",
                window, manifest.body.last_window
            );
        }

        let (sealed_dek, push) = sks_format::write::prepare_envelope(wk_pub);
        let header = Header {
            format_version: sks_format::FORMAT_VERSION,
            suite_id: sks_format::SUITE_XCHACHA.into(),
            community_id: manifest.body.community_id.clone(),
            camera_id: camera_id.into(),
            device_key_id: device.key_id(),
            epoch: manifest.body.epoch,
            window_index: window,
            segment_seq: state.next_seq,
            boot_id,
            ts_wall_start: mtime_ms,
            ts_wall_end: mtime_ms,
            ts_mono: t0.elapsed().as_nanos() as u64,
            clock_confidence: ClockConfidence::Synced,
            prev_link,
            content_meta: content_meta.clone(),
            sealed_dek,
        };

        let seg_path = out.join(format!("{:08}.sks", state.next_seq));
        let tmp_path = out.join(format!(".{:08}.sks.tmp", state.next_seq));
        let f = fs::File::create(&tmp_path)?;
        let mut w = SegmentWriter::begin(std::io::BufWriter::new(f), &header, push, &device)?;
        let mut it = data.chunks(sks_format::DEFAULT_CHUNK_BYTES).peekable();
        if data.is_empty() {
            w.write_chunk(&[], true)?;
        } else {
            while let Some(c) = it.next() {
                w.write_chunk(c, it.peek().is_none())?;
            }
        }
        let info = w.finish()?;
        fs::rename(&tmp_path, &seg_path)?; // atomic completion

        prev_link = info.link;
        state.next_seq += 1;
        state.prev_link_hex = hex::encode(prev_link);
        // Persist chain state before the segment is considered complete.
        fs::write(&state_path, serde_json::to_vec_pretty(&state)?)?;

        eprintln!(
            "sealed {} → {} (window {}, {} chunks, {} B body)",
            path.display(), seg_path.display(), window, info.chunk_count, info.body_len
        );
    }
    Ok(())
}

fn parse_file(path: &Path) -> Result<(Vec<u8>, ParsedSegment)> {
    let buf = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let parsed = ParsedSegment::parse(&buf)
        .with_context(|| format!("{}: parse failed", path.display()))?;
    Ok((buf, parsed))
}

fn header_json(p: &ParsedSegment) -> serde_json::Value {
    let h = &p.header;
    serde_json::json!({
        "suite_id": h.suite_id,
        "community_id": h.community_id,
        "camera_id": h.camera_id,
        "device_key_id": hex::encode(h.device_key_id),
        "epoch": h.epoch,
        "window_index": h.window_index,
        "segment_seq": h.segment_seq,
        "boot_id": hex::encode(h.boot_id),
        "ts_wall_start": h.ts_wall_start,
        "ts_wall_end": h.ts_wall_end,
        "clock_confidence": format!("{:?}", h.clock_confidence).to_lowercase(),
        "prev_link": hex::encode(h.prev_link),
        "content_meta": h.content_meta,
        "sealed_dek_len": h.sealed_dek.len(),
        "footer": {
            "body_hash": hex::encode(p.footer.body_hash),
            "chunk_count": p.footer.chunk_count,
            "body_len": p.footer.body_len,
        },
    })
}

fn inspect_cmd(file: &Path, json: bool) -> Result<()> {
    let (_buf, parsed) = parse_file(file)?;
    let v = header_json(&parsed);
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        let h = &parsed.header;
        println!("{}: {} segment", file.display(), h.suite_id);
        println!("  community/camera : {} / {}", h.community_id, h.camera_id);
        println!("  epoch/window/seq : {} / {} / {}", h.epoch, h.window_index, h.segment_seq);
        println!("  wall time        : {} .. {} ({:?})", h.ts_wall_start, h.ts_wall_end, h.clock_confidence);
        println!("  boot/device key  : {} / {}", hex::encode(h.boot_id), hex::encode(h.device_key_id));
        println!("  prev_link        : {}", hex::encode(h.prev_link));
        println!("  body             : {} chunks, {} B, hash {}",
            parsed.footer.chunk_count, parsed.footer.body_len, hex::encode(parsed.footer.body_hash));
        if !h.content_meta.is_empty() {
            println!("  content_meta     : {:?}", h.content_meta);
        }
    }
    Ok(())
}

fn collect_sks(path: &Path) -> Result<Vec<PathBuf>> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        for e in fs::read_dir(dir)? {
            let p = e?.path();
            if p.is_dir() {
                walk(&p, out)?; // archives use nested community/camera/epoch/window/ layout
            } else if p.extension().is_some_and(|x| x == "sks") {
                out.push(p);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    if path.is_dir() {
        walk(path, &mut files)?;
        files.sort();
    } else {
        files.push(path.to_path_buf());
    }
    if files.is_empty() {
        bail!("no .sks files under {}", path.display());
    }
    Ok(files)
}

fn verify_cmd(path: &Path, device_pub: &Path, json: bool) -> Result<()> {
    let device_pub = read_key32(device_pub)?;
    let files = collect_sks(path)?;

    let mut parsed_ok: Vec<(PathBuf, Vec<u8>, ParsedSegment)> = Vec::new();
    let mut seg_failures: Vec<(String, String)> = Vec::new();

    for f in &files {
        match parse_file(f) {
            Ok((buf, p)) => parsed_ok.push((f.clone(), buf, p)),
            Err(e) => seg_failures.push((f.display().to_string(), format!("{e:#}"))),
        }
    }

    // Per-segment keyless verification.
    let mut verified: Vec<(&ParsedSegment, [u8; 32])> = Vec::new();
    for (f, buf, p) in &parsed_ok {
        match p.verify(buf, &device_pub) {
            Ok(v) => verified.push((p, v.link)),
            Err(e) => seg_failures.push((f.display().to_string(), e.to_string())),
        }
    }

    // Chain verification over the segments that passed.
    let report = sealer_chain::verify_chain(&verified);

    let ok = seg_failures.is_empty() && report.findings.is_empty();
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "files": files.len(),
            "segments_verified": verified.len(),
            "segment_failures": seg_failures.iter().map(|(f, e)| serde_json::json!({"file": f, "error": e})).collect::<Vec<_>>(),
            "chain_spans": report.spans,
            "chain_findings": report.findings.iter().map(|f| serde_json::json!({"seq": f.seq, "problem": f.problem.to_string()})).collect::<Vec<_>>(),
            "chain_notes": report.notes.iter().map(|f| serde_json::json!({"seq": f.seq, "note": f.problem.to_string()})).collect::<Vec<_>>(),
            "ok": ok,
        }))?);
    } else {
        println!("verified {} of {} segment file(s)", verified.len(), files.len());
        for (f, e) in &seg_failures {
            println!("  SEGMENT FAIL  {f}: {e}");
        }
        for (a, b) in &report.spans {
            println!("  chain span    seq {a}..={b} continuous");
        }
        for f in &report.findings {
            println!("  CHAIN FINDING at seq {}: {}", f.seq, f.problem);
        }
        for n in &report.notes {
            println!("  note at seq {}: {}", n.seq, n.problem);
        }
        println!("{}", if ok { "OK: chain verifies; no tampering detected" } else { "FAILED: see findings above" });
    }
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

fn release_cmd(crk: &Path, window: u64, out: &Path) -> Result<()> {
    let crk = read_key32(crk)?;
    let seed = sealer_crypto::kdf::derive_window_seed(&crk, window);
    write_key(out, &seed)?;
    eprintln!("released window {} private key → {} (simulated quorum)", window, out.display());
    Ok(())
}

fn unseal_cmd(file: &Path, window_key: &Path, out: &Path) -> Result<()> {
    let seed = read_key32(window_key)?;
    let kp = BoxKeypair::from_seed(&seed);
    let (buf, parsed) = parse_file(file)?;
    let plaintext = parsed.decrypt(&buf, &kp)
        .with_context(|| format!("{}: decryption failed", file.display()))?;
    fs::write(out, &plaintext)?;
    eprintln!("unsealed {} → {} ({} B, window {})",
        file.display(), out.display(), plaintext.len(), parsed.header.window_index);
    Ok(())
}
