//! Installed-package API-surface introspection: enumerate the exported
//! surface of a `node_modules/<pkg>` or `site-packages/<pkg>` directory from
//! files already on disk (`.d.ts` exports, Python AST), and compare it
//! against actual usage sites extracted from project source.
//!
//! **No project code is ever executed** (REQ-privacy / docs/PLAN.md's core
//! invariant) — this is pure static tree-sitter parsing, mirroring
//! `crate::scan`'s parse-once, skip-not-fail contract. Confidence is
//! tiered per docs/PLAN.md §2.3/§9.2: an exact miss against a fully
//! resolved surface is `high` confidence; a miss against a package whose
//! surface could not be fully resolved statically (dynamic `__getattr__`,
//! compiled-only, ambient wildcard `.d.ts`, unresolvable re-export) is
//! downgraded to `low` confidence rather than suppressed outright, so the
//! `real` command can still surface it as an `info`-tier hint.

pub mod dts;

use std::collections::BTreeSet;
use std::path::Path;

use crate::scan::ScanError;

#[derive(Debug, thiserror::Error)]
pub enum SurfaceError {
    #[error(transparent)]
    Scan(#[from] ScanError),
}

/// How completely a package's public surface could be determined
/// statically. Only [`SurfaceTier::Resolved`] licenses a high-confidence
/// "member does not exist" result — Pitfalls 5/6 (03-RESEARCH.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceTier {
    /// Every export was enumerated with no unresolved dynamic construct.
    Resolved,
    /// The package uses a construct static analysis cannot see through
    /// (Python module-level `__getattr__`, TS ambient wildcard module,
    /// an unresolvable re-export target) — the surface may be incomplete.
    Dynamic,
    /// No readable source/types were found at all (compiled-only package,
    /// JS package shipping no `.d.ts`).
    Unreadable,
}

/// The enumerated exported surface of one installed package.
#[derive(Debug, Clone)]
pub struct ApiSurface {
    pub exported: BTreeSet<String>,
    pub tier: SurfaceTier,
}

/// One `pkg.member` (or named-import) access site found in project source.
#[derive(Debug, Clone)]
pub struct UsageSite {
    pub package: String,
    pub member: String,
    pub file: String,
    pub line: u32,
}

/// Project-relative display path, forward slashes — mirrors
/// `deps::relative_display`/`env::plan`'s convention. Duplicated locally
/// (rather than imported) since `deps`'s copy is crate-private to that
/// module and this plan's file scope does not touch `deps/mod.rs`.
pub(crate) fn relative_display(path: &Path, root: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_display_strips_root_and_normalizes_separators() {
        let root = Path::new("/proj");
        assert_eq!(
            relative_display(Path::new("/proj/src/a.ts"), root),
            "src/a.ts"
        );
    }
}
