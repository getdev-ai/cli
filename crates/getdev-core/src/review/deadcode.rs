//! `review/dead-code-introduced` detector — newly introduced named
//! declarations with zero references anywhere in the tree.
//!
//! STUB (06-02): the call site is live so `review::run`'s dispatch graph is
//! complete and clippy-clean; the real whole-tree reference index lands in
//! 06-03/06-04 and only rewrites THIS file's body — never `review/mod.rs`.

use super::ReviewFile;
use crate::findings::Finding;

/// Detect introduced dead code. Returns no findings until the whole-tree
/// reference index is implemented in 06-03/06-04.
pub(crate) fn detect(_files: &[ReviewFile]) -> Vec<Finding> {
    Vec::new()
}
