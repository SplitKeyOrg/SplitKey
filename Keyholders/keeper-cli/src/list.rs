//! `keeper list`: what footage exists, from `.skc` records alone — no key,
//! no segment downloads. Anyone with bucket read access can run this.

use crate::skc::SkcRecord;
use crate::store::Store;
use anyhow::Result;
use sealer_keys::Manifest;
use sk_shares::dates;
use std::collections::BTreeMap;

pub async fn run(manifest: &Manifest, store: &Store, camera: Option<&str>) -> Result<String> {
    let b = &manifest.body;
    let cameras = match camera {
        Some(c) => vec![c.to_string()],
        None => {
            let mut c = store.dirs(&b.community_id).await?;
            c.sort();
            c
        }
    };

    let mut out = String::new();
    for camera in &cameras {
        out.push_str(&format!("camera: {camera}\n"));
        let epoch_prefix = format!("{}/{}/{}", b.community_id, camera, b.epoch);
        let mut windows: Vec<u64> = store
            .dirs(&epoch_prefix)
            .await?
            .iter()
            .filter_map(|d| d.parse().ok())
            .collect();
        windows.sort_unstable();

        // One pass: per-window stats + the close events that pin other windows.
        let mut closed: BTreeMap<u64, u64> = BTreeMap::new(); // window -> declared max_seq
        let mut stats: BTreeMap<u64, (usize, u64, i64, i64, Vec<String>)> = BTreeMap::new();
        for &w in &windows {
            let prefix = format!("{epoch_prefix}/{w}");
            let (mut n, mut bytes, mut t0, mut t1, mut kinds) =
                (0usize, 0u64, i64::MAX, i64::MIN, Vec::new());
            for meta in store.objects(&prefix).await? {
                if !meta.location.filename().is_some_and(|f| f.ends_with(".skc")) {
                    continue;
                }
                let Ok(rec) = SkcRecord::parse(&store.get(&meta.location).await?) else {
                    continue;
                };
                n += 1;
                bytes += rec.u64_field("body_len").unwrap_or(0);
                if let Some(ts) = rec.body.get("ts_wall_start").and_then(|v| v.as_i64()) {
                    t0 = t0.min(ts);
                }
                if let Some(ts) = rec.body.get("ts_wall_end").and_then(|v| v.as_i64()) {
                    t1 = t1.max(ts);
                }
                if let Some(ev) = rec.meta("event") {
                    kinds.push(ev.to_string());
                    if ev == "window_close" {
                        if let (Some(cw), Some(max)) = (
                            rec.meta("closed_window").and_then(|s| s.parse().ok()),
                            rec.meta("max_seq").and_then(|s| s.parse().ok()),
                        ) {
                            closed.insert(cw, max);
                        }
                    }
                }
            }
            stats.insert(w, (n, bytes, t0, t1, kinds));
        }

        for (&w, (n, bytes, _t0, _t1, kinds)) in &stats {
            let label = dates::label_for_window(w, b.window_secs);
            let pin = if closed.contains_key(&w) { "closed" } else { "open " };
            let events = if kinds.is_empty() {
                String::new()
            } else {
                format!("  events: {}", kinds.join(","))
            };
            out.push_str(&format!(
                "  w{w}  {label}  [{pin}]  {n} records  {:.1} MB sealed{events}\n",
                *bytes as f64 / 1e6
            ));
        }
        if windows.is_empty() {
            out.push_str("  (no windows)\n");
        }
    }
    Ok(out)
}
