//! `review/commented-code-block` detector — introduced comment runs of >=3
//! lines that re-parse as code (a "code-shaped" node present, zero ERROR
//! nodes), excluding JSDoc / license headers.
//!
//! STUB (06-02): the call site is live so `review::run`'s dispatch graph is
//! complete and clippy-clean; the real comment-run extraction + capped
//! re-parse lands in 06-03/06-04 and only rewrites THIS file's body — never
//! `review/mod.rs`.

use super::ReviewFile;
use crate::findings::Finding;

/// Detect introduced commented-out code blocks. Returns no findings until
/// the re-parse discriminator is implemented in 06-03/06-04.
pub(crate) fn detect(_files: &[ReviewFile]) -> Vec<Finding> {
    Vec::new()
}
