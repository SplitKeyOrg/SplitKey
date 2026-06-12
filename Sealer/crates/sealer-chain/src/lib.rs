//! Hash-chain construction and multi-segment verification
//! (docs/04-tamper-evidence.md).
//!
//! The per-segment work (signatures, body hash) lives in `sks-format`; this
//! crate judges the *sequence*: ordering, continuity, identity consistency,
//! and chain-link integrity — with named, court-readable failure reasons.

use sks_format::{ParsedSegment, GENESIS_LINK};

/// Device-side chain state: what the Chainer persists between segments.
#[derive(Debug, Clone)]
pub struct ChainState {
    pub next_seq: u64,
    pub prev_link: [u8; 32],
    pub boot_id: [u8; 8],
}

impl ChainState {
    /// Fresh chain (first segment ever for this camera).
    pub fn genesis() -> Self {
        let mut boot_id = [0u8; 8];
        sealer_crypto::random_bytes(&mut boot_id);
        Self {
            next_seq: 0,
            prev_link: GENESIS_LINK,
            boot_id,
        }
    }

    /// Advance after sealing a segment whose SIG-block hash is `link`.
    pub fn advance(&mut self, link: [u8; 32]) {
        self.next_seq += 1;
        self.prev_link = link;
    }
}

/// One finding from chain verification. `seq` is the segment where the
/// problem becomes visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainFinding {
    pub seq: u64,
    pub problem: ChainProblem,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainProblem {
    #[error("sequence gap: segment(s) {missing_from}..={missing_to} missing (dropped or withheld)")]
    SeqGap { missing_from: u64, missing_to: u64 },
    #[error("duplicate sequence number (two conflicting segments claim seq {0})")]
    DuplicateSeq(u64),
    #[error("prev_link mismatch: segment does not link to its predecessor (replaced or reordered)")]
    LinkMismatch,
    #[error("first available segment is not genesis and its predecessor is absent (head of chain missing)")]
    DanglingHead,
    #[error("camera identity changed mid-chain (spliced from another camera?)")]
    IdentityMismatch,
    #[error("device key id changed mid-chain (re-keyed device or forgery; requires enrollment-record check)")]
    DeviceKeyChanged,
    #[error("capture wall-clock goes backwards vs predecessor within one boot (backlog seal or clock step)")]
    ClockAnomaly,
    #[error("window index decreases while sequence increases (out-of-order capture times)")]
    WindowRegression,
}

/// Result of verifying an ordered run of parsed-and-individually-verified
/// segments.
#[derive(Debug)]
pub struct ChainReport {
    /// Verified contiguous spans as (first_seq, last_seq).
    pub spans: Vec<(u64, u64)>,
    /// Integrity failures: evidence of tampering, loss, or forgery.
    pub findings: Vec<ChainFinding>,
    /// Informational observations that are NOT integrity failures — e.g.
    /// capture-time regressions, which occur legitimately when a backlog is
    /// sealed after a reboot (header timestamps are capture times, and the
    /// seq chain — not the wall clock — is what orders segments).
    pub notes: Vec<ChainFinding>,
}

impl ChainReport {
    pub fn is_continuous(&self) -> bool {
        self.findings.is_empty() && self.spans.len() <= 1
    }
}

/// Verify chain relationships over segments that have **already passed**
/// per-segment verification (`ParsedSegment::verify`), paired with their
/// SIG-block links. Caller supplies them sorted however they were found;
/// this function sorts by `segment_seq` itself — order on disk proves
/// nothing, the chain does.
pub fn verify_chain(segments: &[(&ParsedSegment, [u8; 32])]) -> ChainReport {
    let mut findings = Vec::new();
    let mut notes = Vec::new();
    let mut spans: Vec<(u64, u64)> = Vec::new();

    if segments.is_empty() {
        return ChainReport { spans, findings, notes };
    }

    let mut ordered: Vec<&(&ParsedSegment, [u8; 32])> = segments.iter().collect();
    ordered.sort_by_key(|(p, _)| p.header.segment_seq);

    // Duplicates first: conflicting same-seq segments are their own finding.
    for pair in ordered.windows(2) {
        let (a, b) = (pair[0].0, pair[1].0);
        if a.header.segment_seq == b.header.segment_seq {
            findings.push(ChainFinding {
                seq: a.header.segment_seq,
                problem: ChainProblem::DuplicateSeq(a.header.segment_seq),
            });
        }
    }

    let first = ordered[0].0;
    if first.header.segment_seq != 0 && first.header.prev_link != GENESIS_LINK {
        // We can't see the head of the chain; not an error by itself (a
        // window-scoped release sees a mid-chain slice), but reported so the
        // verifier output states what was NOT provable.
        findings.push(ChainFinding {
            seq: first.header.segment_seq,
            problem: ChainProblem::DanglingHead,
        });
    }
    if first.header.segment_seq == 0 && first.header.prev_link != GENESIS_LINK {
        findings.push(ChainFinding {
            seq: 0,
            problem: ChainProblem::LinkMismatch,
        });
    }

    let mut span_start = first.header.segment_seq;
    let mut prev = ordered[0];

    for cur in ordered.iter().skip(1) {
        let (p, _link) = cur;
        let (pp, plink) = prev;
        let pseq = pp.header.segment_seq;
        let seq = p.header.segment_seq;

        if seq == pseq {
            prev = cur;
            continue; // duplicate already reported
        }

        // Identity consistency.
        if p.header.camera_id != pp.header.camera_id
            || p.header.community_id != pp.header.community_id
        {
            findings.push(ChainFinding {
                seq,
                problem: ChainProblem::IdentityMismatch,
            });
        } else if p.header.device_key_id != pp.header.device_key_id {
            findings.push(ChainFinding {
                seq,
                problem: ChainProblem::DeviceKeyChanged,
            });
        }

        if seq != pseq + 1 {
            // Gap: close current span, open a new one.
            findings.push(ChainFinding {
                seq,
                problem: ChainProblem::SeqGap {
                    missing_from: pseq + 1,
                    missing_to: seq - 1,
                },
            });
            spans.push((span_start, pseq));
            span_start = seq;
        } else {
            // Adjacent: the link must hold.
            if p.header.prev_link != *plink {
                findings.push(ChainFinding {
                    seq,
                    problem: ChainProblem::LinkMismatch,
                });
                spans.push((span_start, pseq));
                span_start = seq;
            }
            // Capture-time regressions are NOTES, not failures: header
            // timestamps are capture times (file mtime in watcher mode),
            // and sealing a backlog after boot legitimately runs backwards.
            if p.header.boot_id == pp.header.boot_id
                && p.header.ts_mono > pp.header.ts_mono
                && p.header.ts_wall_start < pp.header.ts_wall_start
            {
                notes.push(ChainFinding {
                    seq,
                    problem: ChainProblem::ClockAnomaly,
                });
            }
            if p.header.window_index < pp.header.window_index {
                notes.push(ChainFinding {
                    seq,
                    problem: ChainProblem::WindowRegression,
                });
            }
        }
        prev = cur;
    }
    spans.push((span_start, prev.0.header.segment_seq));

    ChainReport { spans, findings, notes }
}
