//! Pipe-mode integration: a synthetic recorder command streams bytes into
//! sealerd; plaintext never touches disk. Covers RAM segmentation, recorder
//! exit → source_lost / restart → source_restored chain events, chain
//! continuity across restarts, and decrypt roundtrip.

use sealerd::{config::Config, pipeline, state};
use sks_format::ParsedSegment;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
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

#[tokio::test(flavor = "multi_thread")]
async fn pipe_seals_restarts_and_decrypts() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let archive = root.join("archive");
    let state_dir = root.join("state");
    let ceremony = root.join("ceremony");
    fs::create_dir_all(&ceremony).unwrap();

    let start = now_unix() - 86_400;
    let first_window = sealer_keys::Manifest::window_index_for(start, 86_400);
    let sim = sealer_keys::ceremony_sim::generate(
        "pipe-community", 1, 86_400, first_window, 30, start, (3, 5),
    );
    fs::write(ceremony.join("manifest.skm"), &sim.manifest_bytes).unwrap();
    fs::write(ceremony.join("admin.pub"), sim.admin.public).unwrap();
    let st = state::enroll(&state_dir, &ceremony.join("manifest.skm"), &ceremony.join("admin.pub")).unwrap();
    let device_pub = st.device_key.public;

    // Synthetic recorder: 20 000 zero bytes per run, then exit. With
    // segment_max_bytes = 8 KB that's 2 full cuts + a flushed tail per run,
    // and each exit exercises source_lost → restart → source_restored.
    let toml = format!(
        r#"
        [community]
        id = "pipe-community"
        manifest = "{m}"
        admin_pubkey = "{a}"
        [device]
        camera_id = "pipe-cam"
        state_dir = "{s}"
        [source]
        mode = "pipe"
        [source.pipe]
        format = "raw"
        command = "head -c 20000 /dev/zero"
        restart_secs = 1
        [sealing]
        segment_max_secs = 30
        segment_max_bytes = "8KB"
        [chain]
        heartbeat_secs = 0
        [[storage]]
        type = "fs"
        path = "{ar}"
        "#,
        m = ceremony.join("manifest.skm").display(),
        a = ceremony.join("admin.pub").display(),
        s = state_dir.display(),
        ar = archive.display(),
    );
    let cfg: Config = toml::from_str(&toml).unwrap();
    cfg.validate().unwrap();

    // Run until two recorder generations have landed (≥ 9 segments:
    // boot + run1(2 cuts + tail + lost) + restored + run2(2 cuts...)).
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(pipeline::run(cfg, rx));
    let a = archive.clone();
    for _ in 0..300 {
        if archive_files(&a, "sks").len() >= 9 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(archive_files(&a, "sks").len() >= 9, "pipeline too slow");
    tx.send(true).unwrap();
    handle.await.unwrap().unwrap();

    // Verify every segment + the chain.
    let mut parsed: Vec<(Vec<u8>, ParsedSegment)> = Vec::new();
    for f in archive_files(&archive, "sks") {
        let buf = fs::read(&f).unwrap();
        let p = ParsedSegment::parse(&buf).unwrap();
        p.verify(&buf, &device_pub).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        parsed.push((buf, p));
    }
    let with_links: Vec<(&ParsedSegment, [u8; 32])> = parsed
        .iter()
        .map(|(b, p)| (p, p.verify(b, &device_pub).unwrap().link))
        .collect();
    let report = sealer_chain::verify_chain(&with_links);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(report.spans.len(), 1, "chain must be one continuous span");

    // Lifecycle events present.
    let events: Vec<&str> = parsed
        .iter()
        .filter_map(|(_, p)| p.header.content_meta.get("event").map(String::as_str))
        .collect();
    assert!(events.contains(&"boot"), "{events:?}");
    assert!(events.contains(&"source_lost"), "{events:?}");
    assert!(events.contains(&"source_restored"), "{events:?}");

    // Footage segments: raw container, decrypt to all-zero bytes, sizes as
    // segmented (8 KB cuts + tails), and ts_end >= ts_start (real spans).
    let mut total = 0usize;
    for (buf, p) in &parsed {
        if p.header.content_meta.get("kind").map(String::as_str) == Some("chain-event") {
            continue;
        }
        assert_eq!(p.header.content_meta.get("container").unwrap(), "raw");
        assert!(p.header.ts_wall_end >= p.header.ts_wall_start);
        let wk = sealer_keys::ceremony_sim::release_window(&sim.crk, p.header.window_index);
        let plain = p.decrypt(buf, &wk).unwrap();
        assert!(plain.iter().all(|&b| b == 0), "decrypted bytes not from /dev/zero");
        assert!(plain.len() <= 8 * 1024);
        total += plain.len();
    }
    // Two full runs of 20 000 bytes are at least 40 000 plaintext bytes.
    assert!(total >= 40_000, "only {total} plaintext bytes recovered");
}
