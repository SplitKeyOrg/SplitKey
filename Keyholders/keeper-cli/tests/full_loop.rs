//! The Phase-4 milestone test: the complete SplitKey loop with no GUI.
//!
//! ceremony (booklets + manifest, CRK destroyed) → sealerd seals footage
//! into a bucket → three keyholders' booklet files + read access release
//! exactly one window, tamper-checked, via the real `keeper` binary.

use ceremony_cli::{run_new, NewParams};
use sealerd::config::{AfterUpload, CatalogMode, ManifestExhausted, Storage};
use sealerd::seal::{SealEngine, SealInput};
use sealerd::upload::{build_sinks, Uploader};
use sealerd::state;
use std::collections::BTreeMap;
use std::process::Command;

const WSECS: u64 = 86_400;

fn now_window() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / WSECS
}

fn footage(window: u64, offset_secs: u64, body: &[u8]) -> SealInput<'static> {
    let t0 = ((window * WSECS + offset_secs) * 1000) as i64;
    let mut meta = BTreeMap::new();
    meta.insert("container".into(), "raw".into());
    SealInput::Bytes {
        data: body.to_vec(),
        ts_start_ms: t0,
        ts_end_ms: t0 + 5_000,
        content_meta: meta,
    }
}

/// Seal a two-window history into an fs bucket; return paths.
struct Rig {
    _tmp: tempfile::TempDir,
    epoch_dir: std::path::PathBuf,
    state_dir: std::path::PathBuf,
    bucket: std::path::PathBuf,
    target_window: u64,
}

async fn build_rig() -> Rig {
    let tmp = tempfile::tempdir().unwrap();
    let w_now = now_window();
    let target_window = w_now - 1;

    // 1. Ceremony: 3-of-5, CRK destroyed.
    let epoch_dir = tmp.path().join("epoch1");
    run_new(&NewParams {
        community_id: "testers".into(),
        epoch: 1,
        window_secs: WSECS as u32,
        first_window: w_now - 2,
        window_count: 10,
        threshold_t: 3,
        keyholders: ["alice", "bob", "carol", "dave", "erin"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        out_dir: epoch_dir.clone(),
        keep_crk: false,
        ceremony_date: 0,
        pdf: false, // this loop exercises the crypto, not the printed booklet
    })
    .unwrap();

    // 2. Enroll a camera + seal: 3 footage segments in the target window,
    // then 1 in the current window (emits window_close for the target).
    let state_dir = tmp.path().join("camera-state");
    let device = state::enroll(
        &state_dir,
        &epoch_dir.join("manifest.skm"),
        &epoch_dir.join("admin.pub"),
    )
    .unwrap();
    let spool = state_dir.join("spool");
    let mut engine = SealEngine::new(
        device,
        "cam-1",
        &spool,
        64 * 1024,
        ManifestExhausted::SealToLastKey,
    )
    .unwrap();
    for (i, body) in [b"AAAA".as_slice(), b"BBBBBB", b"CC"].iter().enumerate() {
        engine.seal(footage(target_window, 100 * (i as u64 + 1), body)).unwrap();
    }
    engine.seal(footage(w_now, 100, b"NEXT-WINDOW")).unwrap();

    // 3. Upload spool → fs bucket with .skc catalog records (the real
    // Uploader, told to shut down after its first drain).
    let bucket = tmp.path().join("bucket");
    std::fs::create_dir_all(&bucket).unwrap();
    let sinks = build_sinks(&[Storage::Fs { path: bucket.clone() }]).unwrap();
    let (_ntx, nrx) = tokio::sync::mpsc::channel::<()>(1);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let device_key = engine.device.device_key.clone();
    let up = tokio::spawn(
        Uploader {
            spool_dir: spool,
            sinks,
            catalog: CatalogMode::Objects,
            after_upload: AfterUpload::Delete,
            device: device_key,
            retry_secs: 1,
        }
        .run(nrx, stop_rx),
    );
    stop_tx.send(true).unwrap();
    up.await.unwrap().unwrap();

    Rig { _tmp: tmp, epoch_dir, state_dir, bucket, target_window }
}

fn keeper() -> Command {
    Command::new(env!("CARGO_BIN_EXE_keeper"))
}

#[tokio::test]
async fn full_release_loop_is_clean() {
    let rig = build_rig().await;
    let out = rig._tmp.path().join("released");
    let keyfile = rig._tmp.path().join("window.key");

    // Keyholders alice + carol + erin combine their booklet lines.
    let combine = keeper()
        .args(["combine", "--manifest"])
        .arg(rig.epoch_dir.join("manifest.skm"))
        .arg("--admin-pub")
        .arg(rig.epoch_dir.join("admin.pub"))
        .args(["--window", &rig.target_window.to_string(), "--out"])
        .arg(&keyfile)
        .arg(rig.epoch_dir.join("booklets/alice.txt"))
        .arg(rig.epoch_dir.join("booklets/carol.txt"))
        .arg(rig.epoch_dir.join("booklets/erin.txt"))
        .output()
        .unwrap();
    assert!(
        combine.status.success(),
        "combine failed: {}",
        String::from_utf8_lossy(&combine.stderr)
    );
    assert!(String::from_utf8_lossy(&combine.stdout).contains("VERIFIED against the manifest"));

    // Release straight from the bucket with the key + device.pub.
    let release = keeper()
        .args(["release", "--manifest"])
        .arg(rig.epoch_dir.join("manifest.skm"))
        .arg("--admin-pub")
        .arg(rig.epoch_dir.join("admin.pub"))
        .args(["--window", &rig.target_window.to_string(), "--window-key"])
        .arg(&keyfile)
        .arg("--store")
        .arg(format!("fs:{}", rig.bucket.display()))
        .arg("--device-pub")
        .arg(rig.state_dir.join("device.pub"))
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&release.stdout);
    assert!(
        release.status.success(),
        "release not clean:\nstdout: {report}\nstderr: {}",
        String::from_utf8_lossy(&release.stderr)
    );
    assert!(report.contains("VERIFIED — no findings"), "{report}");
    assert!(report.contains("tail pinned"), "{report}");
    assert!(report.contains("head pinned"), "{report}");
    assert!(report.contains("decrypt: 3/3"), "{report}");

    // Exactly the target window's plaintext, in seq order.
    let footage = std::fs::read(out.join("cam-1/footage.bin")).unwrap();
    assert_eq!(footage, b"AAAABBBBBBCC");
    assert!(std::fs::read_to_string(out.join("report.txt")).unwrap().contains("VERIFIED"));
}

#[tokio::test]
async fn tail_withholding_is_named() {
    let rig = build_rig().await;
    let out = rig._tmp.path().join("released");

    // Storage operator quietly removes the last segment of the window
    // (blob only — the catalog record and the close event still exist).
    let win_dir = rig
        .bucket
        .join("testers/cam-1/1")
        .join(rig.target_window.to_string());
    std::fs::remove_file(win_dir.join("00000002.sks")).unwrap();

    let release = keeper()
        .args(["release", "--manifest"])
        .arg(rig.epoch_dir.join("manifest.skm"))
        .arg("--admin-pub")
        .arg(rig.epoch_dir.join("admin.pub"))
        .args(["--window", &rig.target_window.to_string()])
        .arg("--share")
        .arg(rig.epoch_dir.join("booklets/bob.txt"))
        .arg("--share")
        .arg(rig.epoch_dir.join("booklets/dave.txt"))
        .arg("--share")
        .arg(rig.epoch_dir.join("booklets/erin.txt"))
        .arg("--store")
        .arg(format!("fs:{}", rig.bucket.display()))
        .arg("--device-pub")
        .arg(rig.state_dir.join("device.pub"))
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&release.stdout);
    assert_eq!(release.status.code(), Some(2), "{report}");
    assert!(report.contains("TAIL TRUNCATED"), "{report}");
    assert!(report.contains("blob is MISSING"), "{report}");
    assert!(report.contains("RELEASED WITH FINDINGS"), "{report}");
}

#[tokio::test]
async fn too_few_or_wrong_shares_fail_loudly() {
    let rig = build_rig().await;

    // 2-of-3 threshold not met.
    let two = keeper()
        .args(["combine", "--manifest"])
        .arg(rig.epoch_dir.join("manifest.skm"))
        .arg("--admin-pub")
        .arg(rig.epoch_dir.join("admin.pub"))
        .args(["--window", &rig.target_window.to_string()])
        .arg(rig.epoch_dir.join("booklets/alice.txt"))
        .arg(rig.epoch_dir.join("booklets/bob.txt"))
        .output()
        .unwrap();
    assert!(!two.status.success());
    assert!(String::from_utf8_lossy(&two.stderr).contains("threshold"));

    // Right booklets, wrong window for one line: simulate a hand-typed
    // wrong-line mistake by feeding a bare line from another window.
    let alice = std::fs::read_to_string(rig.epoch_dir.join("booklets/alice.txt")).unwrap();
    let wrong_line =
        sk_shares::booklet::find_line(&alice, rig.target_window + 1).unwrap();
    let wrong_file = rig._tmp.path().join("alice-wrong-line.txt");
    std::fs::write(&wrong_file, wrong_line).unwrap();
    let wrong = keeper()
        .args(["combine", "--manifest"])
        .arg(rig.epoch_dir.join("manifest.skm"))
        .arg("--admin-pub")
        .arg(rig.epoch_dir.join("admin.pub"))
        .args(["--window", &rig.target_window.to_string()])
        .arg(&wrong_file)
        .arg(rig.epoch_dir.join("booklets/carol.txt"))
        .arg(rig.epoch_dir.join("booklets/erin.txt"))
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert!(
        String::from_utf8_lossy(&wrong.stderr).contains("checksum"),
        "expected a checksum error naming the bad share: {}",
        String::from_utf8_lossy(&wrong.stderr)
    );
}
