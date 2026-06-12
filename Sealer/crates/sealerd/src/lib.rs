//! sealerd — the SplitKey Sealer daemon (Phase 2: watcher → storage).
//!
//! Library form so integration tests can run the pipeline in-process;
//! the `sealerd` and `sealer` binaries are thin wrappers.

pub mod config;
pub mod pipe;
pub mod pipeline;
pub mod seal;
pub mod state;
pub mod upload;
pub mod watch;
