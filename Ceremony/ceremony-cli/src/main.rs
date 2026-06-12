use anyhow::Result;
use ceremony_cli::{run_new, NewParams};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ceremony", about = "SplitKey key ceremony tooling (offline, once per epoch)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an epoch: manifest + admin key + keyholder booklets.
    New {
        /// Community identifier (goes into manifest + every segment header)
        #[arg(long)]
        community: String,
        #[arg(long)]
        epoch: u16,
        /// First covered day, UTC (YYYY-MM-DD)
        #[arg(long)]
        start: String,
        /// Coverage in months (~30.44 days each); design default 18 = 12 + 6 grace
        #[arg(long, default_value_t = 18)]
        months: u32,
        /// Exact window count — overrides --months (tests/dev)
        #[arg(long)]
        windows: Option<u64>,
        #[arg(long, default_value_t = 24)]
        window_hours: u32,
        /// e.g. "3-of-5" (n must equal the number of --keyholder flags)
        #[arg(long)]
        threshold: String,
        /// Repeat once per keyholder, in share order
        #[arg(long = "keyholder", required = true)]
        keyholders: Vec<String>,
        #[arg(long)]
        out: PathBuf,
        /// DEV/SIM ONLY: also write crk.secret instead of destroying the CRK
        #[arg(long)]
        keep_crk: bool,
        /// Skip the print-ready PDF booklets (text booklets are always written)
        #[arg(long)]
        no_pdf: bool,
    },
}

fn parse_threshold(s: &str) -> Result<(u8, u8)> {
    let parts: Vec<&str> = s.split(['-', '/']).filter(|p| *p != "of").collect();
    let [t, n] = parts.as_slice() else {
        anyhow::bail!("threshold must look like '3-of-5' (got '{s}')")
    };
    Ok((t.trim().parse()?, n.trim().parse()?))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::New {
            community, epoch, start, months, windows, window_hours, threshold,
            keyholders, out, keep_crk, no_pdf,
        } => {
            let (t, n) = parse_threshold(&threshold)?;
            anyhow::ensure!(
                n as usize == keyholders.len(),
                "threshold says n={n} but {} --keyholder flags given",
                keyholders.len()
            );
            anyhow::ensure!(window_hours >= 1, "--window-hours must be >= 1");
            let window_secs = window_hours * 3600;
            let first_window = sk_shares::dates::window_for_date(&start, window_secs)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let window_count = windows.unwrap_or_else(|| {
                // months × mean Gregorian month, rounded to whole windows
                let secs = months as f64 * 30.436_875 * 86_400.0;
                (secs / window_secs as f64).round() as u64
            });
            let ceremony_date = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as i64;
            run_new(&NewParams {
                community_id: community,
                epoch,
                window_secs,
                first_window,
                window_count,
                threshold_t: t,
                keyholders,
                out_dir: out,
                keep_crk,
                ceremony_date,
                pdf: !no_pdf,
            })
        }
    }
}
