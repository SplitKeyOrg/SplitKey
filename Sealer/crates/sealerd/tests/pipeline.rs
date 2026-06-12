//! In-process integration tests for the sealerd pipeline:
//! watch → seal → spool → upload(fs sink) → verify chain → decrypt,
//! plaintext deletion, .skc catalog records, and chain resume across
//! restarts (the crash-safety story).

use sealerd::{config::Config, pipeline, state};
use sks_format::ParsedSegment;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct World {
    #[allow(dead_code)]
    tmp: tempfile::TempDir,
    root: PathBuf,
    cfg: Config,
    crk: [u8; 32],
    device_pub: [u8; 32],
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn setup() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let (clips, archive, state_dir) = (root.join("clips"), root.join("archive"), root.join("state"));
    fs::create_dir_all(&clips).unwrap();

    // Ceremony: daily windows, generous coverage around "now".
    let start = now_unix() - 86_400;
    let first_window = sealer_keys::Manifest::window_index_for(start, 86_400);
    let sim = sealer_keys::ceremony_sim::generate(
        "test-community", 1, 86_400, first_window, 30, start, (3, 5),
    );
    let ceremony = root.join("ceremony");
    fs::create_dir_all(&ceremony).unwrap();
    fs::write(ceremony.join("manifest.skm"), &sim.manifest_bytes).unwrap();
    fs::write(ceremony.join("admin.pub"), sim.admin.public).unwrap();

    let toml = format!(
        r#"
        [community]
        id = "test-community"
        manifest = "{m}"
        admin_pubkey = "{a}"
        [device]
        camera_id = "cam-1"
        state_dir = "{s}"
        [source]
        mode = "watch"
        [source.watch]
        path = "{c}"
        ready_glob = "*.bin"
        stable_secs = 0
        poll_ms = 50
        [chain]
        heartbeat_secs = 0
        [[storage]]
        type = "fs"
        path = "{ar}"
        "#,
        m = ceremony.join("manifest.skm").display(),
        a = ceremony.join("admin.pub").display(),
        s = state_dir.display(),
        c = clips.display(),
        ar = archive.display(),
    );
    let cfg: Config = toml::from_str(&toml).unwrap();
    cfg.validate().unwrap();

    let st = state::enroll(&state_dir, &ceremony.join("manifest.skm"), &ceremony.join("admin.pub")).unwrap();
    World { tmp, root, cfg, crk: sim.crk, device_pub: st.device_key.public }
}

/// Run the pipeline until `done` returns true (or panic at timeout).
async fn run_until(cfg: Config, done: impl Fn() -> bool) {
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(pipeline::run(cfg, rx));
    for _ in 0..200 {
        if done() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(done(), "condition not reached within timeout");
    tx.send(true).unwrap();
    handle.await.unwrap().unwrap();
}

fn archive_files(archive: &Path, ext: &str) -> Vec<PathBuf> {
    fn walk(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, ext, out);
                } else if p.extension().is_some_and(|x| x == ext) {
                    out.push(p);
                }
            }
        }
    }
    let mut v = Vec::new();
    walk(archive, ext, &mut v);
    v.sort();
    v
}

fn verify_archive(archive: &Path, device_pub: &[u8; 32]) -> (Vec<(Vec<u8>, ParsedSegment)>, sealer_chain::ChainReport) {
    let mut parsed = Vec::new();
    for f in archive_files(archive, "sks") {
        let buf = fs::read(&f).unwrap();
        let p = ParsedSegment::parse(&buf).unwrap();
        p.verify(&buf, device_pub).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        parsed.push((buf, p));
    }
    let with_links: Vec<(&ParsedSegment, [u8; 32])> = parsed
        .iter()
        .map(|(buf, p)| {
            let v = p.verify(buf, device_pub).unwrap();
            (p, v.link)
        })
        .collect();
    let report = sealer_chain::verify_chain(&with_links);
    (parsed, report)
}

#[tokio::test(flavor = "multi_thread")]
async fn watch_seal_upload_verify_decrypt() {
    let w = setup();
    let clips = w.root.join("clips");
    let archive = w.root.join("archive");

    // Drop three clips (one pre-existing before start, two during).
    let data0: Vec<u8> = (0..150_000u32).map(|i| i as u8).collect();
    fs::write(clips.join("a.bin"), &data0).unwrap();

    let clips2 = clips.clone();
    let archive2 = archive.clone();
    let cfg = w.cfg.clone();
    let dropped = std::sync::atomic::AtomicBool::new(false);
    let drop_more = || {
        if !dropped.swap(true, std::sync::atomic::Ordering::SeqCst) {
            fs::write(clips2.join("b.bin"), vec![7u8; 80_000]).unwrap();
            fs::write(clips2.join("c.bin"), vec![9u8; 80_000]).unwrap();
        }
        // boot event + 3 clips = 4 segments and 4 catalog records uploaded
        archive_files(&archive2, "sks").len() == 4 && archive_files(&archive2, "skc").len() == 4
    };
    run_until(cfg, drop_more).await;

    // Plaintext deleted (after_seal default = delete).
    assert!(!clips.join("a.bin").exists());
    assert!(!clips.join("b.bin").exists());
    assert!(!clips.join("c.bin").exists());
    // Spool drained (after_upload default = delete).
    assert!(archive_files(&w.cfg.spool_dir(), "sks").is_empty());

    // Keyless verification: signatures + continuous chain 0..=3.
    let (parsed, report) = verify_archive(&archive, &w.device_pub);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(report.spans, vec![(0, 3)]);

    // Segment 0 is the boot chain event.
    let boot = &parsed[0].1;
    assert_eq!(boot.header.content_meta.get("kind").unwrap(), "chain-event");
    assert_eq!(boot.header.content_meta.get("event").unwrap(), "boot");

    // Release the day's window key and decrypt clip a.bin (found by its
    // content_meta label — seal order among same-poll files is arbitrary).
    let (buf, seg_a) = parsed
        .iter()
        .find(|(_, p)| p.header.content_meta.get("source_name").map(String::as_str) == Some("a.bin"))
        .expect("a.bin segment present");
    let wk = sealer_keys::ceremony_sim::release_window(&w.crk, seg_a.header.window_index);
    let plain = seg_a.decrypt(buf, &wk).unwrap();
    assert_eq!(plain, data0);
}

#[tokio::test(flavor = "multi_thread")]
async fn chain_resumes_across_restarts() {
    let w = setup();
    let clips = w.root.join("clips");
    let archive = w.root.join("archive");

    // Run 1: boot + one clip.
    fs::write(clips.join("r1.bin"), vec![1u8; 50_000]).unwrap();
    let a = archive.clone();
    run_until(w.cfg.clone(), move || archive_files(&a, "sks").len() == 2).await;

    // Run 2 ("reboot"): another boot event + one more clip.
    fs::write(clips.join("r2.bin"), vec![2u8; 50_000]).unwrap();
    let a = archive.clone();
    run_until(w.cfg.clone(), move || archive_files(&a, "sks").len() == 4).await;

    // One continuous chain across both runs, no findings; the two runs are
    // distinguishable by boot_id but the links must hold.
    let (parsed, report) = verify_archive(&archive, &w.device_pub);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(report.spans, vec![(0, 3)]);
    assert_eq!(parsed[2].1.header.content_meta.get("event").unwrap(), "boot");
    assert_ne!(parsed[0].1.header.boot_id, parsed[2].1.header.boot_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn catalog_records_are_signed_and_point_at_segments() {
    let w = setup();
    let clips = w.root.join("clips");
    let archive = w.root.join("archive");

    fs::write(clips.join("x.bin"), vec![5u8; 10_000]).unwrap();
    let a = archive.clone();
    run_until(w.cfg.clone(), move || archive_files(&a, "skc").len() == 2).await;

    for skc in archive_files(&archive, "skc") {
        let b = fs::read(&skc).unwrap();
        assert_eq!(&b[..4], b"SKC1");
        let len = u32::from_be_bytes(b[4..8].try_into().unwrap()) as usize;
        let cbor = &b[8..8 + len];
        let sig: [u8; 64] = b[8 + len..].try_into().unwrap();
        let mut signed = b"SKC1".to_vec();
        signed.extend_from_slice(cbor);
        sealer_crypto::verify_detached(&sig, &signed, &w.device_pub).unwrap();

        let rec: serde_json::Value = {
            // CBOR → JSON value via ciborium round-trip
            ciborium::from_reader::<ciborium::Value, _>(cbor)
                .map(|v| serde_json::to_value(cbor_to_json(v)).unwrap())
                .unwrap()
        };
        let object_key = rec["object_key"].as_str().unwrap();
        assert!(skc.to_str().unwrap().contains(object_key.trim_end_matches(".sks").split('/').next_back().unwrap()));
        // The referenced segment exists in the same sink.
        assert!(archive.join(object_key).exists(), "{object_key} missing");
    }
}

fn cbor_to_json(v: ciborium::Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        ciborium::Value::Text(s) => J::String(s),
        ciborium::Value::Integer(i) => J::Number(serde_json::Number::from(i128::from(i) as i64)),
        ciborium::Value::Bool(b) => J::Bool(b),
        ciborium::Value::Null => J::Null,
        ciborium::Value::Map(m) => J::Object(
            m.into_iter()
                .map(|(k, v)| (k.into_text().unwrap_or_default(), cbor_to_json(v)))
                .collect(),
        ),
        ciborium::Value::Array(a) => J::Array(a.into_iter().map(cbor_to_json).collect()),
        other => J::String(format!("{other:?}")),
    }
}
