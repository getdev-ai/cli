//! `review/duplicate-helper` detector — near-duplicate function bodies
//! introduced in the diff (>=85% normalized-token similarity).
//!
//! STUB (06-02): the call site is live so `review::run`'s dispatch graph is
//! complete and clippy-clean; the real MinHash-LSH fingerprint algorithm
//! lands in 06-03/06-04 and only rewrites THIS file's body — never
//! `review/mod.rs`.

use super::ReviewFile;
use crate::findings::Finding;

/// Detect introduced near-duplicate helper functions. Returns no findings
/// until the fingerprint algorithm is implemented in 06-03/06-04.
pub(crate) fn detect(_files: &[ReviewFile]) -> Vec<Finding> {
    Vec::new()
}
