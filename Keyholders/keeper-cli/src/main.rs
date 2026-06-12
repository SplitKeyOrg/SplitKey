use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use keeper_cli::release::{ReleaseOutcome, ReleaseParams};
use keeper_cli::store::Store;
use keeper_cli::{combine, list, load_manifest, release, resolve_window};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "keeper",
    about = "SplitKey keyholder release tooling: combine paper shares, \
             release exactly one window from dumb storage.\n\
             Exit codes: 0 = verified clean, 2 = released with findings."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Common {
    /// Signed pubkey manifest from the ceremony
    #[arg(long)]
    manifest: PathBuf,
    /// Community admin verify key — must arrive out-of-band, never from the bucket
    #[arg(long)]
    admin_pub: PathBuf,
}

#[derive(Args)]
struct WindowSel {
    /// UTC day, YYYY-MM-DD (resolved via the manifest's window length)
    #[arg(long)]
    date: Option<String>,
    /// Raw window index (alternative to --date)
    #[arg(long)]
    window: Option<u64>,
}

#[derive(Args)]
struct StoreArgs {
    /// fs:/path or s3://bucket[/prefix] (creds from AWS_* env, read-only)
    #[arg(long)]
    store: String,
    /// S3-compatible endpoint (MinIO/B2/RustFS); http:// allowed for LAN sims
    #[arg(long)]
    endpoint: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Combine t keyholder shares into one verified window key.
    Combine {
        #[command(flatten)]
        common: Common,
        #[command(flatten)]
        win: WindowSel,
        /// Booklet files (or single 14-word line files), one per keyholder
        #[arg(required = true)]
        shares: Vec<PathBuf>,
        /// Where to write the 32-byte window key (default: window-<W>.key)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Fetch, verify, and decrypt one window from the bucket.
    Release {
        #[command(flatten)]
        common: Common,
        #[command(flatten)]
        win: WindowSel,
        #[command(flatten)]
        store: StoreArgs,
        /// Previously combined window key file (from `keeper combine`)
        #[arg(long, conflicts_with = "share")]
        window_key: Option<PathBuf>,
        /// Combine inline instead: repeat per keyholder booklet
        #[arg(long = "share")]
        share: Vec<PathBuf>,
        /// Camera id (default: every camera found in the store)
        #[arg(long)]
        camera: Option<String>,
        /// Device verify key file (32 bytes); repeat per enrolled camera.
        /// Without it, device signatures are reported as unverified.
        #[arg(long = "device-pub")]
        device_pubs: Vec<PathBuf>,
        #[arg(long, default_value = "released")]
        out: PathBuf,
    },
    /// Browse what exists (from .skc records only — needs no key).
    List {
        #[command(flatten)]
        common: Common,
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        camera: Option<String>,
    },
}

fn write_0600(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Combine { common, win, shares, out } => {
            let manifest = load_manifest(&common.manifest, &common.admin_pub)?;
            let w = resolve_window(&manifest, win.date.as_deref(), win.window)?;
            let (seed, _kp) = combine::window_key_from_shares(&manifest, w, &shares)?;
            let out = out.unwrap_or_else(|| PathBuf::from(format!("window-{w}.key")));
            write_0600(&out, &seed)?;
            println!(
                "window {w} ({}) key reconstructed from {} shares and VERIFIED \
                 against the manifest\nwritten: {}",
                sk_shares::dates::label_for_window(w, manifest.body.window_secs),
                shares.len(),
                out.display()
            );
            Ok(())
        }
        Cmd::Release { common, win, store, window_key, share, camera, device_pubs, out } => {
            let manifest = load_manifest(&common.manifest, &common.admin_pub)?;
            let w = resolve_window(&manifest, win.date.as_deref(), win.window)?;
            let key = match (&window_key, share.is_empty()) {
                (Some(path), _) => combine::window_key_from_file(&manifest, w, path)?,
                (None, false) => combine::window_key_from_shares(&manifest, w, &share)?.1,
                (None, true) => anyhow::bail!("give --window-key or --share files"),
            };
            let mut pubs = Vec::new();
            for p in &device_pubs {
                pubs.push(
                    std::fs::read(p)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("{}: expected 32 bytes", p.display()))?,
                );
            }
            let store = Store::open(&store.store, store.endpoint.as_deref())?;
            let ReleaseOutcome { clean, report } = release::run(
                &manifest,
                &store,
                &ReleaseParams { window: w, key, camera, device_pubs: pubs, out_dir: out },
            )
            .await?;
            print!("{report}");
            if !clean {
                std::process::exit(2);
            }
            Ok(())
        }
        Cmd::List { common, store, camera } => {
            let manifest = load_manifest(&common.manifest, &common.admin_pub)?;
            let store = Store::open(&store.store, store.endpoint.as_deref())?;
            print!("{}", list::run(&manifest, &store, camera.as_deref()).await?);
            Ok(())
        }
    }
}
