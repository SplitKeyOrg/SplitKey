//! Read-only access to the dumb storage bucket.
//!
//! URL forms: `fs:/path/to/dir` (local/NAS) and `s3://bucket[/prefix]`
//! (credentials from the standard AWS env vars; `--endpoint` for
//! MinIO/B2/RustFS, plain-http endpoints allowed for LAN sims).

use anyhow::{Context, Result};
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, ObjectMeta};
use std::sync::Arc;

pub struct Store {
    inner: Arc<dyn ObjectStore>,
    prefix: String,
}

impl Store {
    pub fn open(url: &str, endpoint: Option<&str>) -> Result<Self> {
        if let Some(path) = url.strip_prefix("fs:") {
            let store = object_store::local::LocalFileSystem::new_with_prefix(path)
                .with_context(|| format!("fs store {path}"))?;
            return Ok(Self { inner: Arc::new(store), prefix: String::new() });
        }
        if let Some(rest) = url.strip_prefix("s3://") {
            let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
            let mut b = object_store::aws::AmazonS3Builder::from_env()
                .with_bucket_name(bucket)
                .with_region(std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into()));
            if let Some(ep) = endpoint {
                b = b
                    .with_endpoint(ep)
                    .with_virtual_hosted_style_request(false)
                    .with_allow_http(ep.starts_with("http://"));
            }
            return Ok(Self {
                inner: Arc::new(b.build()?),
                prefix: prefix.trim_matches('/').to_string(),
            });
        }
        anyhow::bail!("store URL must be fs:/path or s3://bucket[/prefix] (got '{url}')");
    }

    fn key(&self, rel: &str) -> ObjPath {
        if self.prefix.is_empty() {
            ObjPath::from(rel)
        } else {
            ObjPath::from(format!("{}/{}", self.prefix, rel))
        }
    }

    /// Immediate children "directories" under `rel` (no recursion).
    pub async fn dirs(&self, rel: &str) -> Result<Vec<String>> {
        let res = self.inner.list_with_delimiter(Some(&self.key(rel))).await?;
        Ok(res
            .common_prefixes
            .iter()
            .filter_map(|p| p.parts().last().map(|s| s.as_ref().to_string()))
            .collect())
    }

    /// Objects directly under `rel`.
    pub async fn objects(&self, rel: &str) -> Result<Vec<ObjectMeta>> {
        Ok(self.inner.list_with_delimiter(Some(&self.key(rel))).await?.objects)
    }

    pub async fn get(&self, location: &ObjPath) -> Result<Vec<u8>> {
        Ok(self.inner.get(location).await?.bytes().await?.to_vec())
    }
}

/// `community/camera/epoch/window` prefix helpers.
pub fn window_prefix(community: &str, camera: &str, epoch: u16, window: u64) -> String {
    format!("{community}/{camera}/{epoch}/{window}")
}
