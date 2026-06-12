//! `sealer.toml` parsing + validation (docs/07-configuration.md).
//!
//! Unknown keys are a hard error (a typo must not silently no-op a security
//! setting), hence `deny_unknown_fields` everywhere.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub community: Community,
    pub device: Device,
    pub source: Source,
    #[serde(default)]
    pub sealing: Sealing,
    #[serde(default)]
    pub chain: Chain,
    #[serde(default)]
    pub spool: Spool,
    #[serde(default)]
    pub storage: Vec<Storage>,
    #[serde(default)]
    pub catalog: Catalog,
    #[serde(default)]
    pub log: Log,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Community {
    pub id: String,
    pub manifest: PathBuf,
    pub admin_pubkey: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub camera_id: String,
    pub state_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub mode: SourceMode,
    pub watch: Option<Watch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceMode {
    Watch,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watch {
    pub path: PathBuf,
    #[serde(default = "default_ready_glob")]
    pub ready_glob: String,
    #[serde(default)]
    pub ignore_glob: Option<String>,
    /// File must be size/mtime-stable this long before sealing.
    #[serde(default = "default_stable_secs")]
    pub stable_secs: u64,
    /// Poll interval in milliseconds (inotify integration is a later
    /// optimization; polling is the crash-robust baseline).
    #[serde(default = "default_poll_ms")]
    pub poll_ms: u64,
    #[serde(default)]
    pub after_seal: AfterSeal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AfterSeal {
    #[default]
    Delete,
    Keep,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Sealing {
    pub suite: String,
    pub chunk_bytes: ByteSize,
    pub manifest_exhausted: ManifestExhausted,
}

impl Default for Sealing {
    fn default() -> Self {
        Self {
            suite: sks_format::SUITE_XCHACHA.into(),
            chunk_bytes: ByteSize(sks_format::DEFAULT_CHUNK_BYTES as u64),
            manifest_exhausted: ManifestExhausted::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ManifestExhausted {
    /// Decided default (docs/02): keep sealing to the last key + alert.
    #[default]
    SealToLastKey,
    FailClosed,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Chain {
    /// Heartbeat chain-event interval when no footage flows. 0 disables.
    pub heartbeat_secs: u64,
}

impl Default for Chain {
    fn default() -> Self {
        Self { heartbeat_secs: 300 }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Spool {
    /// Defaults to `<state_dir>/spool`.
    pub dir: Option<PathBuf>,
    pub after_upload: AfterUpload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AfterUpload {
    /// Remove from spool once every sink has it (bounded disk).
    #[default]
    Delete,
    Keep,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "lowercase")]
pub enum Storage {
    Fs {
        path: PathBuf,
    },
    S3 {
        endpoint: Option<String>,
        bucket: String,
        #[serde(default)]
        prefix: String,
        #[serde(default)]
        region: Option<String>,
        /// "env:NAME" or "file:/path" → contents "ACCESS_KEY_ID:SECRET".
        /// Omitted → standard AWS environment/instance credentials.
        #[serde(default)]
        credential: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Catalog {
    pub mode: CatalogMode,
}

impl Default for Catalog {
    fn default() -> Self {
        Self { mode: CatalogMode::Objects }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CatalogMode {
    /// Decided design: signed .skc records written to the storage sinks.
    Objects,
    None,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    pub level: String,
}

impl Default for Log {
    fn default() -> Self {
        Self { level: "info".into() }
    }
}

/// "16MB" / "64KB" / "4GB" / plain integer bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSize(pub u64);

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Int(u64),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Int(n) => Ok(ByteSize(n)),
            Raw::Str(s) => parse_size(&s).map(ByteSize).map_err(serde::de::Error::custom),
        }
    }
}

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| format!("bad size '{s}'"))?;
    let mult = match unit.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "KB" | "K" | "KIB" => 1024,
        "MB" | "M" | "MIB" => 1024 * 1024,
        "GB" | "G" | "GIB" => 1024 * 1024 * 1024,
        u => return Err(format!("unknown size unit '{u}'")),
    };
    Ok(n * mult)
}

fn default_ready_glob() -> String {
    "*".into()
}
fn default_stable_secs() -> u64 {
    2
}
fn default_poll_ms() -> u64 {
    1000
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.source.mode == SourceMode::Watch && self.source.watch.is_none() {
            bail!("source.mode = \"watch\" requires a [source.watch] section");
        }
        if self.sealing.suite != sks_format::SUITE_XCHACHA {
            bail!("unsupported sealing.suite '{}' (only {} is implemented)",
                self.sealing.suite, sks_format::SUITE_XCHACHA);
        }
        if self.sealing.chunk_bytes.0 < 1024 || self.sealing.chunk_bytes.0 > (1 << 26) {
            bail!("sealing.chunk_bytes out of range (1KB..64MB)");
        }
        if self.storage.is_empty() {
            bail!("at least one [[storage]] sink is required");
        }
        Ok(())
    }

    pub fn spool_dir(&self) -> PathBuf {
        self.spool
            .dir
            .clone()
            .unwrap_or_else(|| self.device.state_dir.join("spool"))
    }
}

/// Resolve "env:NAME" / "file:/path" credential refs → "ID:SECRET" pair.
pub fn resolve_credential(spec: &str) -> Result<(String, String)> {
    let value = if let Some(name) = spec.strip_prefix("env:") {
        std::env::var(name).with_context(|| format!("credential env var {name} not set"))?
    } else if let Some(path) = spec.strip_prefix("file:") {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading credential file {path}"))?
    } else {
        bail!("credential must be 'env:NAME' or 'file:/path', got '{spec}'");
    };
    let value = value.trim();
    let (id, secret) = value
        .split_once(':')
        .context("credential must be 'ACCESS_KEY_ID:SECRET'")?;
    Ok((id.to_string(), secret.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [community]
        id = "c"
        manifest = "/etc/splitkey/manifest.skm"
        admin_pubkey = "/etc/splitkey/admin.pub"
        [device]
        camera_id = "cam"
        state_dir = "/var/lib/splitkey"
        [source]
        mode = "watch"
        [source.watch]
        path = "/clips"
        [[storage]]
        type = "fs"
        path = "/archive"
    "#;

    #[test]
    fn minimal_config_parses_with_defaults() {
        let c: Config = toml::from_str(MINIMAL).unwrap();
        c.validate().unwrap();
        assert_eq!(c.sealing.chunk_bytes.0, 64 * 1024);
        assert_eq!(c.chain.heartbeat_secs, 300);
        assert!(matches!(c.catalog.mode, CatalogMode::Objects));
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let bad = MINIMAL.replace("[source]", "[source]\ntypo_key = 1");
        assert!(toml::from_str::<Config>(&bad).is_err());
    }

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_size("16MB").unwrap(), 16 * 1024 * 1024);
        assert_eq!(parse_size("64KB").unwrap(), 64 * 1024);
        assert_eq!(parse_size("123").unwrap(), 123);
        assert!(parse_size("16XB").is_err());
    }
}
