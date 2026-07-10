//! Network-free dependency graph: declared packages (manifests/lockfiles)
//! reconciled against AST-derived imports.
//!
//! Pure static parsing of files already on disk — no network, no code
//! execution (REQ-privacy). `real/nonexistent-package` needs the declared+
//! imported package set; `real/phantom-import` is fully computable here
//! without any registry call (03-RESEARCH.md "Spec clarification", resolving
//! Open Question 2: `real`'s checks are a programmatic core-analyzer
//! category, like `core::secrets`, not a YAML matcher pack).

mod imports_js;
mod imports_py;
mod manifest_js;
mod manifest_py;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use crate::scan::{Lang, ScanError};

pub use manifest_js::declared_npm;
pub use manifest_py::{declared_pypi, normalize_pep503};

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
    // pyproject-toml (0.13, transitively toml 0.9) returns its own
    // `toml::de::Error` type, distinct from this crate's `toml` 0.8
    // dependency — captured as a message rather than a typed `#[source]` to
    // avoid depending on a second `toml` major version just to name it.
    #[error("invalid pyproject.toml at {path}: {message}")]
    PyProjectToml { path: PathBuf, message: String },
    #[error(transparent)]
    Scan(#[from] ScanError),
}

/// Package ecosystem a declared/imported name belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosystem {
    Npm,
    Pypi,
}

/// What an [`ImportRef`] resolved to when reconciled against the declared
/// package set, the embedded builtin/stdlib dataset, and the local module
/// set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportResolution {
    /// present in a manifest/lockfile
    Declared,
    /// language/runtime builtin (Node `node:fs`, Python `os`, ...)
    Builtin,
    /// relative import, or matches a local project module
    Local,
    /// declared nowhere, not a builtin, not local — hallucination candidate
    /// for `real/phantom-import`
    Phantom,
}

/// A single import/require statement extracted from source, reconciled
/// against the declared package set.
#[derive(Debug, Clone)]
pub struct ImportRef {
    pub module: String,
    /// project-relative path, forward slashes
    pub file: String,
    pub line: u32,
    pub ecosystem: Ecosystem,
    pub resolution: ImportResolution,
}

/// The project's dominant source language isn't JS/TS/Python and no
/// supported manifest is present — `real` has nothing to analyze here, and
/// the caller should surface an info finding rather than a silent empty
/// graph (REQ-language-support).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackHint {
    /// best-effort detected stack, e.g. "go", "rust", "ruby"
    pub detected: String,
}

/// The reconciled view: everything declared, every import, and its
/// classification.
#[derive(Debug, Default)]
pub struct DependencyGraph {
    pub declared: BTreeMap<Ecosystem, BTreeSet<String>>,
    pub imports: Vec<ImportRef>,
    pub unsupported_stack: Option<StackHint>,
}

/// A raw import/require extraction, before reconciliation — internal to the
/// `deps` module; [`ImportRef`] is the public, classified shape.
#[derive(Debug, Clone)]
pub(crate) struct RawImport {
    pub module: String,
    pub is_relative: bool,
    pub file: String,
    pub line: u32,
}

const SUPPORTED_MANIFESTS: &[&str] = &[
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
];

/// Other-language file extensions checked when no JS/TS/Python source or
/// manifest was found under `root`.
const OTHER_LANG_EXTENSIONS: &[(&str, &str)] = &[
    ("go", "go"),
    ("rb", "ruby"),
    ("rs", "rust"),
    ("java", "java"),
    ("php", "php"),
    ("cs", "csharp"),
];

/// Build the dependency graph for `root`: parse every JS/TS + Python
/// manifest/lockfile dialect present, extract every import, and classify
/// each one as declared / builtin / local / phantom.
///
/// File read/parse errors during the import walk are collected in the
/// second return value rather than aborting (same skip-not-fail contract as
/// [`crate::scan::collect_string_assignments`]); manifest parse failures are
/// fatal (`DepsError`) — see `DepsError::PyProjectToml`/`Json`/`Yaml`/`Toml`.
pub fn build_graph(root: &Path) -> Result<(DependencyGraph, Vec<ScanError>), DepsError> {
    let declared_npm_set = manifest_js::declared_npm(root)?;
    let declared_pypi_set = manifest_py::declared_pypi(root)?;

    let node_builtins = imports_js::node_builtins()?;
    let python_stdlib = imports_py::python_stdlib()?;

    let (js_raw, mut skipped) = imports_js::collect_imports(root)?;
    let (py_raw, py_skipped) = imports_py::collect_imports(root)?;
    skipped.extend(py_skipped);

    let locals = local_module_names(root);

    let mut imports = Vec::with_capacity(js_raw.len() + py_raw.len());
    for raw in js_raw {
        // npm: the declared set is never normalized, so the raw import
        // specifier is the correct lookup key as-is.
        let declared_key = raw.module.clone();
        let resolution = classify(
            &raw,
            &declared_npm_set,
            &declared_key,
            &node_builtins,
            &locals,
        );
        imports.push(ImportRef {
            module: raw.module,
            file: raw.file,
            line: raw.line,
            ecosystem: Ecosystem::Npm,
            resolution,
        });
    }
    for raw in py_raw {
        // pypi: `declared_pypi_set` is PEP 503-normalized (manifest_py.rs),
        // but `raw.module` is the raw import spelling (e.g. the underscore
        // form `typing_extensions`/`acme_api_client` that mirrors the
        // installed package's real directory name) — normalize the lookup
        // key here too, or every PyPI package whose distribution name uses
        // hyphens where its import name uses underscores (an extremely
        // common convention) is misclassified as `real/phantom-import`
        // despite being correctly declared. `builtins`/`locals` are
        // deliberately checked against the UNNORMALIZED `raw.module` below
        // (via `classify`) since those sets are raw filesystem/stdlib names,
        // not PEP 503 identifiers.
        let declared_key = normalize_pep503(&raw.module);
        let resolution = classify(
            &raw,
            &declared_pypi_set,
            &declared_key,
            &python_stdlib,
            &locals,
        );
        imports.push(ImportRef {
            module: raw.module,
            file: raw.file,
            line: raw.line,
            ecosystem: Ecosystem::Pypi,
            resolution,
        });
    }

    let has_supported_manifest = SUPPORTED_MANIFESTS
        .iter()
        .any(|name| root.join(name).is_file());
    let unsupported_stack = detect_unsupported_stack(root, has_supported_manifest);

    let mut declared = BTreeMap::new();
    declared.insert(Ecosystem::Npm, declared_npm_set);
    declared.insert(Ecosystem::Pypi, declared_pypi_set);

    Ok((
        DependencyGraph {
            declared,
            imports,
            unsupported_stack,
        },
        skipped,
    ))
}

/// `declared_key` is the lookup key to use against `declared` specifically —
/// callers pass a PEP 503-normalized key for Pypi (matching how
/// `declared_pypi_set` itself was built) and the raw specifier as-is for
/// npm. `builtins`/`locals` are always checked against `raw.module`
/// unnormalized, since those sets are raw filesystem/stdlib names, not
/// PEP 503 identifiers.
fn classify(
    raw: &RawImport,
    declared: &BTreeSet<String>,
    declared_key: &str,
    builtins: &HashSet<String>,
    locals: &HashSet<String>,
) -> ImportResolution {
    if raw.is_relative {
        return ImportResolution::Local;
    }
    if builtins.contains(&raw.module) {
        return ImportResolution::Builtin;
    }
    if declared.contains(declared_key) {
        return ImportResolution::Declared;
    }
    if locals.contains(&raw.module) {
        return ImportResolution::Local;
    }
    ImportResolution::Phantom
}

/// Walk `root` once: if any JS/TS/Python source file exists, the stack is
/// supported (regardless of manifest presence — a fresh clone may not have
/// installed deps yet). Otherwise, if no supported manifest is present
/// either and some other-language source file is found, surface it as a
/// hint instead of silently returning an empty graph.
fn detect_unsupported_stack(root: &Path, has_supported_manifest: bool) -> Option<StackHint> {
    if has_supported_manifest {
        return None;
    }
    let mut other_lang: Option<&'static str> = None;
    for entry in WalkBuilder::new(root).build().flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        if Lang::from_path(path).is_some() {
            return None;
        }
        if other_lang.is_none() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if let Some((_, name)) = OTHER_LANG_EXTENSIONS.iter().find(|(e, _)| *e == ext) {
                    other_lang = Some(name);
                }
            }
        }
    }
    other_lang.map(|detected| StackHint {
        detected: detected.to_owned(),
    })
}

/// Top-level directory/file names under `root` (and `root/src`) that a bare
/// import could plausibly resolve to as a local project module.
fn local_module_names(root: &Path) -> HashSet<String> {
    let mut names = HashSet::new();
    for base in [root.to_path_buf(), root.join("src")] {
        let Ok(entries) = std::fs::read_dir(&base) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name != "node_modules" && !name.starts_with('.') {
                        names.insert(name.to_owned());
                    }
                }
            } else if Lang::from_path(&path).is_some() {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.insert(stem.to_owned());
                }
            }
        }
    }
    names
}

/// Project-relative display path, forward slashes — mirrors `env::plan`'s
/// convention.
pub(crate) fn relative_display(path: &Path, root: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.to_string_lossy().replace('\\', "/")
}
