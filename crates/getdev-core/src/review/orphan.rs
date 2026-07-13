//! `review/orphan-file` detector — a newly introduced file whose path is
//! referenced by no relative import anywhere in the project.
//!
//! STUB (06-02): the call site is live so `review::run`'s dispatch graph is
//! complete and clippy-clean; the real relative-import reference set (reusing
//! `deps::imports_*`) lands in 06-03/06-04 and only rewrites THIS file's body
//! — never `review/mod.rs`.

use std::path::Path;

use super::ReviewFile;
use crate::findings::Finding;

/// Detect introduced orphan files. Returns no findings until the
/// relative-import reference set is implemented in 06-03/06-04.
pub(crate) fn detect(_root: &Path, _files: &[ReviewFile]) -> Vec<Finding> {
    Vec::new()
}
