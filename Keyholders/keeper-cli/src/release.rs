//! `keeper release`: enumerate one window from the bucket via `.skc`
//! records, verify keylessly (per-segment + chain + window_close rollup),
//! decrypt with the reconstructed window key, write footage + report.
//!
//! Failure stance (README): verification failures never block decryption —
//! the report names them and the exit code reflects them.

use crate::skc::SkcRecord;
use crate::store::{window_prefix, Store};
use anyhow::{Context, Result};
use sealer_crypto::{blake2b256, fingerprint8, BoxKeypair};
use sealer_keys::Manifest;
use sk_shares::dates;
use sks_format::ParsedSegment;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

pub struct ReleaseParams {
    pub window: u64,
    pub key: BoxKeypair,
    pub camera: Option<String>,
    /// Out-of-band device verify keys, looked up by fingerprint.
    pub device_pubs: Vec<[u8; 32]>,
    pub out_dir: PathBuf,
}

pub struct ReleaseOutcome {
    /// True when every check that could run passed.
    pub clean: bool,
    pub report: String,
}

struct Seg {
    bytes: Vec<u8>,
    parsed: ParsedSegment,
    link: [u8; 32],
    sig_ok: Option<bool>, // None = no device key available
}

fn fmt_ts(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000) / 1000;
    format!(
        "{} {:02}:{:02}:{:02}Z",
        dates::label_for_window(days as u64, 86_400),
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

pub async fn run(
    manifest: &Manifest,
    store: &Store,
    p: &ReleaseParams,
) -> Result<ReleaseOutcome> {
    let b = &manifest.body;
    let cameras = match &p.camera {
        Some(c) => vec![c.clone()],
        None => {
            let mut c = store.dirs(&b.community_id).await?;
            c.sort();
            anyhow::ensure!(!c.is_empty(), "no cameras under '{}/' in the store", b.community_id);
            c
        }
    };
    let device_keys: BTreeMap<[u8; 8], [u8; 32]> =
        p.device_pubs.iter().map(|pk| (fingerprint8(pk), *pk)).collect();

    let mut report = String::new();
    let mut clean = true;
    writeln!(report, "SplitKey release report — keeper-cli v{}", env!("CARGO_PKG_VERSION"))?;
    writeln!(
        report,
        "community: {}  epoch: {}  window: {} ({})\n",
        b.community_id,
        b.epoch,
        p.window,
        dates::label_for_window(p.window, b.window_secs)
    )?;

    let mut released_any = false;
    for camera in &cameras {
        let ok = release_camera(manifest, store, p, camera, &device_keys, &mut report, &mut released_any)
            .await
            .with_context(|| format!("camera {camera}"))?;
        clean &= ok;
    }
    anyhow::ensure!(released_any, "no segments found for window {} on any camera", p.window);

    writeln!(
        report,
        "verdict: {}",
        if clean { "VERIFIED — no findings" } else { "RELEASED WITH FINDINGS (see above)" }
    )?;
    std::fs::create_dir_all(&p.out_dir)?;
    std::fs::write(p.out_dir.join("report.txt"), &report)?;
    Ok(ReleaseOutcome { clean, report })
}

#[allow(clippy::too_many_arguments)]
async fn release_camera(
    manifest: &Manifest,
    store: &Store,
    p: &ReleaseParams,
    camera: &str,
    device_keys: &BTreeMap<[u8; 8], [u8; 32]>,
    report: &mut String,
    released_any: &mut bool,
) -> Result<bool> {
    let b = &manifest.body;
    let mut ok = true;
    let prefix = window_prefix(&b.community_id, camera, b.epoch, p.window);
    let objs = store.objects(&prefix).await?;
    writeln!(report, "camera: {camera}")?;
    if objs.is_empty() {
        writeln!(report, "  no objects in this window\n")?;
        return Ok(true);
    }

    // ---- fetch + per-segment verify ------------------------------------
    let mut segs: Vec<Seg> = Vec::new();
    let mut skc_by_seq: BTreeMap<u64, SkcRecord> = BTreeMap::new();
    let mut problems: Vec<String> = Vec::new();

    for meta in &objs {
        let name = meta.location.filename().unwrap_or_default().to_string();
        let bytes = store.get(&meta.location).await?;
        if name.ends_with(".skc") {
            match SkcRecord::parse(&bytes) {
                Ok(rec) => {
                    if let Some(seq) = rec.u64_field("segment_seq") {
                        skc_by_seq.insert(seq, rec);
                    } else {
                        problems.push(format!("{name}: .skc record without segment_seq"));
                    }
                }
                Err(e) => problems.push(format!("{name}: {e}")),
            }
        } else if name.ends_with(".sks") {
            match ParsedSegment::parse(&bytes) {
                Ok(parsed) => {
                    let link = blake2b256(&parsed.sig_block);
                    let sig_ok = device_keys.get(&parsed.header.device_key_id).map(|pk| {
                        parsed.verify(&bytes, pk).is_ok()
                    });
                    segs.push(Seg { bytes, parsed, link, sig_ok });
                }
                Err(e) => problems.push(format!("{name}: unparseable segment: {e}")),
            }
        }
    }
    segs.sort_by_key(|s| s.parsed.header.segment_seq);

    for s in &segs {
        match s.sig_ok {
            Some(false) => problems.push(format!(
                "seq {}: device signature INVALID",
                s.parsed.header.segment_seq
            )),
            None => problems.push(format!(
                "seq {}: signatures NOT verified — no --device-pub for key id {}",
                s.parsed.header.segment_seq,
                hex::encode(s.parsed.header.device_key_id)
            )),
            Some(true) => {}
        }
        // identity: the segment must belong to this community/camera/window
        let h = &s.parsed.header;
        if h.community_id != b.community_id || h.camera_id != *camera || h.window_index != p.window
        {
            problems.push(format!(
                "seq {}: header identity mismatch (claims {}/{} window {})",
                h.segment_seq, h.community_id, h.camera_id, h.window_index
            ));
        }
    }

    // ---- catalog ⇄ blob cross-check ------------------------------------
    for s in &segs {
        let seq = s.parsed.header.segment_seq;
        match skc_by_seq.get(&seq) {
            None => problems.push(format!("seq {seq}: segment has no .skc catalog record")),
            Some(rec) => {
                if let Some(pk) = device_keys.get(&s.parsed.header.device_key_id) {
                    if rec.verify(pk).is_err() {
                        problems.push(format!("seq {seq}: .skc device signature INVALID"));
                    }
                }
                if rec.str_field("sig_hash") != Some(hex::encode(blake2b256(&s.parsed.sig_block)).as_str()) {
                    problems.push(format!("seq {seq}: .skc sig_hash does not match the blob"));
                }
            }
        }
    }
    let have: std::collections::BTreeSet<u64> =
        segs.iter().map(|s| s.parsed.header.segment_seq).collect();
    for seq in skc_by_seq.keys() {
        if !have.contains(seq) {
            problems.push(format!(
                "seq {seq}: catalog record exists but the .sks blob is MISSING (withheld?)"
            ));
        }
    }

    // ---- chain verification ---------------------------------------------
    let pairs: Vec<(&ParsedSegment, [u8; 32])> =
        segs.iter().map(|s| (&s.parsed, s.link)).collect();
    let chain = sealer_chain::verify_chain(&pairs);

    let first_is_boundary = segs.first().is_some_and(|s| {
        s.parsed.header.segment_seq == 0
            || s.parsed.header.content_meta.get("event").map(String::as_str)
                == Some("window_close")
    });
    for f in &chain.findings {
        use sealer_chain::ChainProblem::DanglingHead;
        if matches!(f.problem, DanglingHead) && first_is_boundary {
            // A window slice legitimately starts mid-chain; the boundary
            // event (or genesis) pins where it should start.
            continue;
        }
        problems.push(format!("chain: seq {}: {}", f.seq, f.problem));
    }

    // ---- window_close rollup check (tail pinning) ------------------------
    let close = find_close_event(store, b, camera, p.window).await?;
    let max_seq = segs.last().map(|s| s.parsed.header.segment_seq);
    let tail_line = match (close, max_seq) {
        (Some((in_window, close_max)), Some(max)) if close_max == max => {
            format!("tail pinned: window_close in window {in_window} declares max_seq {close_max} — all present")
        }
        (Some((in_window, close_max)), Some(max)) => {
            problems.push(format!(
                "TAIL TRUNCATED: window_close in window {in_window} declares max_seq \
                 {close_max}, but the highest segment present is {max}"
            ));
            format!("tail check FAILED ({} > {} present)", close_max, max)
        }
        (None, _) => "tail not pinned: no window_close event found in a later window \
                      (window still open, or camera stopped) — completeness of the \
                      final segments is NOT provable yet"
            .to_string(),
        (_, None) => unreachable!("objs nonempty"),
    };

    // ---- decrypt ----------------------------------------------------------
    let cam_dir = p.out_dir.join(camera);
    std::fs::create_dir_all(&cam_dir)?;
    let mut events: Vec<String> = Vec::new();
    let mut footage: Vec<(u64, String, Vec<u8>)> = Vec::new(); // (seq, container, plain)
    let mut decrypted = 0usize;
    let total = segs.len();
    let (mut ts_min, mut ts_max) = (i64::MAX, i64::MIN);
    for s in &segs {
        let h = &s.parsed.header;
        ts_min = ts_min.min(h.ts_wall_start);
        ts_max = ts_max.max(h.ts_wall_end);
        match s.parsed.decrypt(&s.bytes, &p.key) {
            Ok(plain) => {
                decrypted += 1;
                if h.content_meta.get("kind").map(String::as_str) == Some("chain-event") {
                    let kind = h.content_meta.get("event").cloned().unwrap_or_default();
                    events.push(format!("seq {} @ {}: {kind}", h.segment_seq, fmt_ts(h.ts_wall_start)));
                    let _ = plain; // event bodies duplicate content_meta
                } else {
                    let container = h
                        .content_meta
                        .get("container")
                        .cloned()
                        .unwrap_or_else(|| "bin".into());
                    footage.push((h.segment_seq, container, plain));
                }
            }
            Err(e) => {
                problems.push(format!("seq {}: DECRYPT FAILED: {e}", h.segment_seq));
            }
        }
    }

    // ---- write footage ----------------------------------------------------
    let mut outputs: Vec<String> = Vec::new();
    let concat_safe = |c: &str| matches!(c, "ts" | "h264-es" | "raw");
    let containers: std::collections::BTreeSet<&str> =
        footage.iter().map(|(_, c, _)| c.as_str()).collect();
    if containers.len() == 1 && concat_safe(containers.iter().next().unwrap()) {
        let container = containers.iter().next().unwrap().to_string();
        let ext = match container.as_str() {
            "ts" => "ts",
            "h264-es" => "h264",
            _ => "bin",
        };
        let path = cam_dir.join(format!("footage.{ext}"));
        let mut all = Vec::new();
        for (_, _, plain) in &footage {
            all.extend_from_slice(plain);
        }
        std::fs::write(&path, &all)?;
        outputs.push(format!("{} ({:.1} MB)", path.display(), all.len() as f64 / 1e6));
    } else {
        for (seq, container, plain) in &footage {
            let path = cam_dir.join(format!("{seq:08}.{container}"));
            std::fs::write(&path, plain)?;
            outputs.push(path.display().to_string());
        }
    }

    // ---- camera report section --------------------------------------------
    *released_any |= !footage.is_empty();
    writeln!(report, "  segments: {} (.sks), catalog records: {} (.skc)", total, skc_by_seq.len())?;
    if ts_min != i64::MAX {
        writeln!(report, "  covers: {} .. {}", fmt_ts(ts_min), fmt_ts(ts_max))?;
    }
    writeln!(
        report,
        "  chain spans: {}",
        chain
            .spans
            .iter()
            .map(|(a, z)| format!("{a}..={z}"))
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    if first_is_boundary {
        writeln!(report, "  head pinned: window starts at a window_close boundary event (or genesis)")?;
    }
    writeln!(report, "  {tail_line}")?;
    for n in &chain.notes {
        writeln!(report, "  note: seq {}: {}", n.seq, n.problem)?;
    }
    for e in &events {
        writeln!(report, "  event: {e}")?;
    }
    writeln!(report, "  decrypt: {decrypted}/{total} segments")?;
    for o in &outputs {
        writeln!(report, "  output: {o}")?;
    }
    if problems.is_empty() {
        writeln!(report, "  findings: none\n")?;
    } else {
        ok = false;
        for pr in &problems {
            writeln!(report, "  FINDING: {pr}")?;
        }
        writeln!(report)?;
    }
    Ok(ok)
}

/// Find the `window_close` record for `window` in the next active window
/// (scanning that window's `.skc` records — plaintext, no key needed).
/// Returns (window it was found in, declared max_seq).
async fn find_close_event(
    store: &Store,
    b: &sealer_keys::ManifestBody,
    camera: &str,
    window: u64,
) -> Result<Option<(u64, u64)>> {
    let epoch_prefix = format!("{}/{}/{}", b.community_id, camera, b.epoch);
    let mut windows: Vec<u64> = store
        .dirs(&epoch_prefix)
        .await?
        .iter()
        .filter_map(|d| d.parse().ok())
        .filter(|w| *w > window)
        .collect();
    windows.sort_unstable();
    // The close event is the first segment of the next *active* window.
    if let Some(&next) = windows.first() {
        let prefix = window_prefix(&b.community_id, camera, b.epoch, next);
        for meta in store.objects(&prefix).await? {
            if meta.location.filename().is_some_and(|n| n.ends_with(".skc")) {
                let Ok(rec) = SkcRecord::parse(&store.get(&meta.location).await?) else {
                    continue;
                };
                if rec.meta("event") == Some("window_close")
                    && rec.meta("closed_window") == Some(window.to_string().as_str())
                {
                    if let Some(max) = rec.meta("max_seq").and_then(|s| s.parse().ok()) {
                        return Ok(Some((next, max)));
                    }
                }
            }
        }
    }
    Ok(None)
}
