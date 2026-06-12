//! Runs the real `ceremony` binary and checks its outputs are mutually
//! consistent: manifest verifies, booklets reconstruct manifest keys.

use sealer_crypto::{kdf, BoxKeypair};
use sealer_keys::Manifest;
use sk_shares::{booklet, LineCtx};
use std::fs;
use std::process::Command;

#[test]
fn ceremony_outputs_are_consistent() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("epoch1");
    let status = Command::new(env!("CARGO_BIN_EXE_ceremony"))
        .args([
            "new",
            "--community", "testers",
            "--epoch", "1",
            "--start", "2026-07-01",
            "--windows", "12",
            "--threshold", "3-of-5",
            "--keyholder", "alice",
            "--keyholder", "bob",
            "--keyholder", "carol",
            "--keyholder", "dave",
            "--keyholder", "erin",
            "--no-pdf", // crypto consistency check — keep it font-independent
            "--out",
        ])
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success(), "ceremony new failed");

    // No CRK on disk by default — the whole point.
    assert!(!out.join("crk.secret").exists());

    // Manifest verifies against admin.pub and has the right shape.
    let admin_pub: [u8; 32] =
        fs::read(out.join("admin.pub")).unwrap().as_slice().try_into().unwrap();
    let manifest =
        Manifest::decode_verified(&fs::read(out.join("manifest.skm")).unwrap(), &admin_pub)
            .unwrap();
    assert_eq!(manifest.body.window_pubs.len(), 12);
    assert_eq!((manifest.body.threshold_t, manifest.body.threshold_n), (3, 5));
    let w0 = manifest.body.first_window;
    assert_eq!(w0, sk_shares::dates::window_for_date("2026-07-01", 86_400).unwrap());

    // A keeper-style reconstruction from 3 booklets matches the manifest —
    // for every window, using a different holder subset than the ceremony's
    // own self-check probably picked.
    let holders = ["bob", "dave", "erin"];
    for i in 0..12u64 {
        let w = w0 + i;
        let ctx = LineCtx { community_id: "testers", epoch: 1, window: w };
        let shares: Vec<_> = holders
            .iter()
            .map(|h| {
                let text =
                    fs::read_to_string(out.join("booklets").join(format!("{h}.txt"))).unwrap();
                sk_shares::decode_words(&booklet::find_line(&text, w).unwrap(), &ctx).unwrap()
            })
            .collect();
        let secret = sk_shares::combine(&shares).unwrap();
        let kp = BoxKeypair::from_seed(&kdf::window_seed_from_secret(&secret));
        let (expect, _) = manifest.pub_for_window(w).unwrap();
        assert_eq!(expect, &kp.public, "window {w} mismatch");
    }

    // Booklets carry a human-readable header.
    let alice = fs::read_to_string(out.join("booklets/alice.txt")).unwrap();
    assert!(alice.contains("holder: alice"));
    assert!(alice.contains("share 1 of 5 (threshold 3)"));
    assert!(alice.contains("2026-07-01"));
}

#[test]
fn keep_crk_writes_secret_for_dev() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("dev");
    let status = Command::new(env!("CARGO_BIN_EXE_ceremony"))
        .args([
            "new", "--community", "dev", "--epoch", "1", "--start", "2026-07-01",
            "--windows", "3", "--threshold", "2-of-3",
            "--keyholder", "a", "--keyholder", "b", "--keyholder", "c",
            "--keep-crk", "--no-pdf", "--out",
        ])
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success());
    let crk: [u8; 32] = fs::read(out.join("crk.secret")).unwrap().as_slice().try_into().unwrap();

    // CRK rederives the same manifest keys (sim release path still works).
    let admin_pub: [u8; 32] =
        fs::read(out.join("admin.pub")).unwrap().as_slice().try_into().unwrap();
    let manifest =
        Manifest::decode_verified(&fs::read(out.join("manifest.skm")).unwrap(), &admin_pub)
            .unwrap();
    let w = manifest.body.first_window + 1;
    let kp = kdf::derive_window_keypair(&crk, w);
    assert_eq!(manifest.pub_for_window(w).unwrap().0, &kp.public);
}

#[test]
fn pdf_booklets_are_written_alongside_text() {
    // The booklet font is embedded, so PDF output is always available.
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("epoch1");
    let status = Command::new(env!("CARGO_BIN_EXE_ceremony"))
        .args([
            "new", "--community", "testers", "--epoch", "1", "--start", "2026-07-01",
            "--windows", "8", "--threshold", "2-of-3",
            "--keyholder", "alice", "--keyholder", "bob", "--keyholder", "carol", "--out",
        ])
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success(), "ceremony new failed");

    for h in ["alice", "bob", "carol"] {
        let pdf = out.join("booklets").join(format!("{h}.pdf"));
        let bytes = fs::read(&pdf).unwrap_or_else(|_| panic!("missing {h}.pdf"));
        assert!(bytes.starts_with(b"%PDF"), "{h}.pdf is not a PDF");
        assert!(bytes.len() > 1000, "{h}.pdf suspiciously small");
        // the canonical text booklet is still written alongside the PDF
        assert!(out.join("booklets").join(format!("{h}.txt")).exists());
    }
}
