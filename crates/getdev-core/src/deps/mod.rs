//! Network-free dependency graph: declared packages (manifests/lockfiles)
//! reconciled against AST-derived imports.
//!
//! Pure static parsing of files already on disk — no network, no code
//! execution (REQ-privacy). `real/nonexistent-package` needs the declared+
//! imported package set; `real/phantom-import` is fully computable here
//! without any registry call (03-RESEARCH.md "Spec clarification", resolving
//! Open Question 2: `real`'s checks are a programmatic core-analyzer
//! category, like `core::secrets`, not a YAML matcher pack).
//!
//! This module grows across 03-02's three tasks: JS/TS manifest parsing
//! (this commit), Python manifest parsing, then AST import extraction +
//! the `DependencyGraph` reconciliation.

mod manifest_js;

use std::path::PathBuf;

pub use manifest_js::declared_npm;

#[derive(Debug, thiserror::Error)]
pub enum DepsError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid JSON in {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid YAML in {path}: {source}")]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("invalid TOML in {path}: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("invalid yarn.lock at {path}: {source}")]
    YarnLock {
        path: PathBuf,
        #[source]
        source: yarn_lock_parser::YarnLockError,
    },
}
