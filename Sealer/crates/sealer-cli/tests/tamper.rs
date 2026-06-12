//! Phase 1 exit criterion (docs/10-roadmap.md): seal footage, tamper with it
//! seven different ways, and watch `sks verify` name each attack. Plus the
//! full seal→release→unseal loop.
//!
//! Drives the real `sks` binary via CARGO_BIN_EXE.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Env {
    #[allow(dead_code)]
    tmp: tempfile::TempDir,
    root: PathBuf,
}

fn sks(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sks"))
        .args(args)
        .output()
        .expect("spawn sks")
}

fn ok(args: &[&str]) -> String {
    let out = sks(args);
    assert!(
        out.status.success(),
        "sks {:?} failed:\n{}\n{}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Run `sks verify`, expect failure, return combined output for matching.
fn verify_expect_fail(env: &Env, dir: &Path) -> String {
    let out = sks(&[
        "verify",
        dir.to_str().unwrap(),
        "--device-pub",
        env.root.join("dev/device.pub").to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "verify unexpectedly passed");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn verify_expect_ok(env: &Env, dir: &Path) -> String {
    ok(&[
        "verify",
        dir.to_str().unwrap(),
        "--device-pub",
        env.root.join("dev/device.pub").to_str().unwrap(),
    ])
}

/// Build a community, a device, and five sealed segments of known plaintext.
fn setup() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let ceremony = root.join("ceremony");
    let dev = root.join("dev");
    let plain = root.join("plain");
    let sealed = root.join("sealed");
    fs::create_dir_all(&plain).unwrap();

    // Sealing uses file mtimes (= now), so the manifest must cover today:
    // start Feb 2026, 540 daily windows ≈ 18 months (the real-world shape).
    ok(&[
        "ceremony-sim",
        "--community", "maplecourt-test",
        "--window-secs", "86400",
        "--start-unix", "1770000000",
        "--windows", "540",
        "--out", ceremony.to_str().unwrap(),
    ]);
    ok(&["keygen-device", "--out", dev.to_str().unwrap()]);

    let mut files: Vec<String> = Vec::new();
    for i in 0..5u32 {
        let p = plain.join(format!("clip-{i}.bin"));
        // >64 KiB so segments are multi-chunk.
        let data: Vec<u8> = (0..100_000u32).map(|j| (i + j) as u8).collect();
        fs::write(&p, data).unwrap();
        files.push(p.to_str().unwrap().to_string());
    }

    let mut args: Vec<&str> = vec![
        "seal",
        "--manifest", Box::leak(ceremony.join("manifest.skm").to_str().unwrap().to_string().into_boxed_str()),
        "--admin-pub", Box::leak(ceremony.join("admin.pub").to_str().unwrap().to_string().into_boxed_str()),
        "--device-key", Box::leak(dev.join("device.key").to_str().unwrap().to_string().into_boxed_str()),
        "--camera-id", "lobby-east",
        "--out", Box::leak(sealed.to_str().unwrap().to_string().into_boxed_str()),
    ];
    let leaked: Vec<&str> = files
        .iter()
        .map(|f| &*Box::leak(f.clone().into_boxed_str()))
        .collect();
    args.extend(leaked);
    ok(&args);

    Env { tmp, root }
}

/// Copy the sealed dir so each attack mutates a fresh copy.
fn fresh_copy(env: &Env, name: &str) -> PathBuf {
    let src = env.root.join("sealed");
    let dst = env.root.join(name);
    fs::create_dir_all(&dst).unwrap();
    for e in fs::read_dir(&src).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "sks") {
            fs::copy(&p, dst.join(p.file_name().unwrap())).unwrap();
        }
    }
    dst
}

fn seg(dir: &Path, i: u32) -> PathBuf {
    dir.join(format!("{i:08}.sks"))
}

#[test]
fn baseline_verifies_clean() {
    let env = setup();
    let out = verify_expect_ok(&env, &env.root.join("sealed"));
    assert!(out.contains("chain span    seq 0..=4 continuous"), "{out}");
    assert!(out.contains("OK: chain verifies"), "{out}");
}

#[test]
fn attack_1_flip_body_byte() {
    let env = setup();
    let dir = fresh_copy(&env, "a1");
    let p = seg(&dir, 2);
    let mut b = fs::read(&p).unwrap();
    let mid = b.len() / 2; // safely inside the body of a 100 kB segment
    b[mid] ^= 0xff;
    fs::write(&p, b).unwrap();
    let out = verify_expect_fail(&env, &dir);
    assert!(out.contains("body hash mismatch"), "{out}");
}

#[test]
fn attack_2_truncate_segment() {
    let env = setup();
    let dir = fresh_copy(&env, "a2");
    let p = seg(&dir, 4);
    let b = fs::read(&p).unwrap();
    fs::write(&p, &b[..b.len() - 5000]).unwrap(); // chop the tail
    let out = verify_expect_fail(&env, &dir);
    assert!(out.contains("SEGMENT FAIL"), "{out}");
}

#[test]
fn attack_3_delete_middle_segment() {
    let env = setup();
    let dir = fresh_copy(&env, "a3");
    fs::remove_file(seg(&dir, 2)).unwrap();
    let out = verify_expect_fail(&env, &dir);
    assert!(out.contains("sequence gap"), "{out}");
    assert!(out.contains("2..=2"), "{out}");
}

#[test]
fn attack_4_renaming_files_is_not_an_attack_but_header_edit_is() {
    let env = setup();
    let dir = fresh_copy(&env, "a4");
    // Swapping filenames proves ordering is content-based, not name-based.
    let (a, b) = (seg(&dir, 1), seg(&dir, 3));
    let tmp = dir.join("x.sks");
    fs::rename(&a, &tmp).unwrap();
    fs::rename(&b, &a).unwrap();
    fs::rename(&tmp, &b).unwrap();
    verify_expect_ok(&env, &dir);

    // Actually editing a header (e.g. trying to renumber/redate a segment)
    // breaks the device signature.
    let p = seg(&dir, 1); // contains seq 3's segment now; irrelevant
    let mut bytes = fs::read(&p).unwrap();
    bytes[12] ^= 1; // inside the CBOR header region
    fs::write(&p, bytes).unwrap();
    let out = verify_expect_fail(&env, &dir);
    assert!(
        out.contains("header signature invalid") || out.contains("parse failed"),
        "{out}"
    );
}

#[test]
fn attack_5_swap_body_between_segments() {
    let env = setup();
    let dir = fresh_copy(&env, "a5");
    // Graft segment 3's body region onto segment 1's header/footer.
    let b1 = fs::read(seg(&dir, 1)).unwrap();
    let b3 = fs::read(seg(&dir, 3)).unwrap();
    let p1 = sks_format::ParsedSegment::parse(&b1).unwrap();
    let p3 = sks_format::ParsedSegment::parse(&b3).unwrap();
    let (o1, l1) = p1.body_range;
    let (o3, l3) = p3.body_range;
    let mut grafted = Vec::new();
    grafted.extend_from_slice(&b1[..o1]);
    grafted.extend_from_slice(&b3[o3..o3 + l3]);
    grafted.extend_from_slice(&b1[o1 + l1..]);
    fs::write(seg(&dir, 1), grafted).unwrap();
    let out = verify_expect_fail(&env, &dir);
    assert!(out.contains("body hash mismatch"), "{out}");
}

#[test]
fn attack_6_replace_segment_wholesale() {
    let env = setup();
    let dir = fresh_copy(&env, "a6");
    // The attacker fabricates their own community/device and forges a
    // perfectly self-consistent segment 2 — but it isn't signed by OUR
    // device key, and its SIG hash can't match segment 3's prev_link.
    let evil = env.root.join("evil");
    ok(&[
        "ceremony-sim", "--community", "maplecourt-test",
        "--window-secs", "86400", "--start-unix", "1770000000",
        "--windows", "540", "--out", evil.join("ceremony").to_str().unwrap(),
    ]);
    ok(&["keygen-device", "--out", evil.join("dev").to_str().unwrap()]);
    let fake_plain = evil.join("fake.bin");
    fs::write(&fake_plain, vec![0u8; 100_000]).unwrap();
    ok(&[
        "seal",
        "--manifest", evil.join("ceremony/manifest.skm").to_str().unwrap(),
        "--admin-pub", evil.join("ceremony/admin.pub").to_str().unwrap(),
        "--device-key", evil.join("dev/device.key").to_str().unwrap(),
        "--camera-id", "lobby-east",
        "--out", evil.join("sealed").to_str().unwrap(),
        fake_plain.to_str().unwrap(),
    ]);
    // Forged segment has seq 0; rename it over our seq 2 (the verifier reads
    // seq from the signed header, so it shows up as a forged segment 0).
    fs::copy(evil.join("sealed/00000000.sks"), seg(&dir, 2)).unwrap();
    let out = verify_expect_fail(&env, &dir);
    assert!(out.contains("header signature invalid"), "{out}");
    // ...and the real segment 2 is now missing → gap is also reported.
    assert!(out.contains("sequence gap"), "{out}");
}

#[test]
fn attack_7_splice_other_cameras_chain() {
    let env = setup();
    let dir = fresh_copy(&env, "a7");
    // Same device key, different camera: seal a parallel chain for
    // "garage-west" and splice its segment 2 into lobby-east's chain.
    let other = env.root.join("other-sealed");
    let fake_plain = env.root.join("fake2.bin");
    fs::write(&fake_plain, vec![9u8; 100_000]).unwrap();
    let ceremony = env.root.join("ceremony");
    for _ in 0..3 {
        ok(&[
            "seal",
            "--manifest", ceremony.join("manifest.skm").to_str().unwrap(),
            "--admin-pub", ceremony.join("admin.pub").to_str().unwrap(),
            "--device-key", env.root.join("dev/device.key").to_str().unwrap(),
            "--camera-id", "garage-west",
            "--out", other.to_str().unwrap(),
            fake_plain.to_str().unwrap(),
        ]);
    }
    fs::copy(other.join("00000002.sks"), seg(&dir, 2)).unwrap();
    let out = verify_expect_fail(&env, &dir);
    // Signed by the right key but for another camera → identity mismatch;
    // its prev_link also can't match → link break.
    assert!(
        out.contains("camera identity changed") || out.contains("prev_link mismatch"),
        "{out}"
    );
}

#[test]
fn release_loop_unseals_only_the_released_window() {
    let env = setup();
    let sealed = env.root.join("sealed");
    let ceremony = env.root.join("ceremony");

    // Window of all five segments (mtime ≈ now): derive from inspect output.
    let insp = ok(&["inspect", seg(&sealed, 0).to_str().unwrap(), "--json"]);
    let v: serde_json::Value = serde_json::from_str(&insp).unwrap();
    let window = v["window_index"].as_u64().unwrap().to_string();

    let wk = env.root.join("wk.key");
    ok(&[
        "release",
        "--crk", ceremony.join("crk.secret").to_str().unwrap(),
        "--window", &window,
        "--out", wk.to_str().unwrap(),
    ]);
    let out_plain = env.root.join("recovered.bin");
    ok(&[
        "unseal", seg(&sealed, 0).to_str().unwrap(),
        "--window-key", wk.to_str().unwrap(),
        "--out", out_plain.to_str().unwrap(),
    ]);
    let expected: Vec<u8> = (0..100_000u32).map(|j| j as u8).collect();
    assert_eq!(fs::read(&out_plain).unwrap(), expected);

    // A different window's key opens nothing.
    let wrong = env.root.join("wk-wrong.key");
    ok(&[
        "release",
        "--crk", ceremony.join("crk.secret").to_str().unwrap(),
        "--window", &(v["window_index"].as_u64().unwrap() + 1).to_string(),
        "--out", wrong.to_str().unwrap(),
    ]);
    let fail = sks(&[
        "unseal", seg(&sealed, 0).to_str().unwrap(),
        "--window-key", wrong.to_str().unwrap(),
        "--out", env.root.join("nope.bin").to_str().unwrap(),
    ]);
    assert!(!fail.status.success());
}
