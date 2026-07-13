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

use crate::scan::{project_walker, Lang, ScanError};

pub use manifest_js::declared_npm;
pub use manifest_py::{declared_pypi, normalize_pep503};

/// `(all declared names, direct/manifest-only subset, skip list)` — shared
/// return shape for `manifest_js::declared_npm`/`manifest_py::declared_pypi`
/// (F5). A named alias rather than an inline 3-tuple-in-a-Result to keep
/// clippy's `type_complexity` lint happy.
pub(crate) type DeclaredNamesResult =
    Result<(BTreeSet<String>, BTreeSet<String>, Vec<ScanError>), DepsError>;

/// Bound on recursive manifest/lockfile discovery (A4): deep enough to find
/// a realistic monorepo/service layout (`backend/requirements.txt`,
/// `apps/web/package.json`, ...) without walking into pathological depth on
/// a hostile or degenerate tree. Depth is measured from `root` (`root`
/// itself is depth 0; `root/package.json` is depth 1).
pub(crate) const MANIFEST_DISCOVERY_DEPTH: usize = 6;

/// Recursively discover every occurrence of `filename` anywhere under
/// `root`, bounded to [`MANIFEST_DISCOVERY_DEPTH`] and built on
/// [`project_walker`] — so the same `node_modules`/`.venv`/`.git`/etc.
/// exclusions and non-git `.gitignore` handling that cover import extraction
/// (A7) also cover manifest discovery (A4). A manifest previously only
/// looked for at `root` (e.g. `backend/requirements.txt` in a
/// service-per-directory layout) is now found regardless of nesting.
pub(crate) fn discover_manifests(root: &Path, filename: &str) -> Vec<PathBuf> {
    let mut builder = project_walker(root);
    builder.max_depth(Some(MANIFEST_DISCOVERY_DEPTH));
    builder
        .build()
        .flatten()
        .filter(|entry| entry.file_type().is_some_and(|t| t.is_file()))
        .filter(|entry| entry.file_name().to_str() == Some(filename))
        .map(ignore::DirEntry::into_path)
        .collect()
}

/// A10: classify a manifest-related [`DepsError`] encountered while parsing
/// one discovered manifest instance as either a recoverable skip (malformed
/// JSON/YAML/TOML content — folded into `skipped` via
/// [`ScanError::Skipped`], the caller continues to the next manifest) or a
/// genuine I/O catastrophe (`DepsError::Read` — the walker already
/// confirmed the file exists, so a read failure past that point means
/// something is structurally wrong, e.g. permission denied mid-run — still
/// fatal). Shared by `manifest_js`/`manifest_py`'s per-instance parse loops.
pub(crate) fn record_or_fail(
    err: DepsError,
    path: &Path,
    skipped: &mut Vec<ScanError>,
) -> Result<(), DepsError> {
    match err {
        DepsError::Read { .. } => Err(err),
        other => {
            skipped.push(ScanError::Skipped {
                path: path.to_path_buf(),
                reason: other.to_string(),
            });
            Ok(())
        }
    }
}

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
    /// F5: the subset of `declared` that came directly from a manifest
    /// (`package.json` / `requirements.txt` / `pyproject.toml`) rather than
    /// only from a lockfile. Lockfile-only entries are transitive
    /// dependencies the project never asked for by name — existence checks
    /// still cover them (via `declared`), but typosquat scoring is scoped
    /// to `direct` (plus imported names) to avoid scoring thousands of
    /// transitives on every run (F5, interacts with E1's DoS guard).
    pub direct: BTreeMap<Ecosystem, BTreeSet<String>>,
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
/// manifest/lockfile dialect present anywhere under `root` (A4), extract
/// every import, and classify each one as declared / builtin / local /
/// phantom.
///
/// File read/parse errors during the import walk, AND a manifest that fails
/// to *parse* (malformed JSON/YAML/TOML), are collected in the second return
/// value rather than aborting the run (A10) — only a genuine I/O catastrophe
/// while reading a manifest that the walker already found on disk (e.g.
/// permission denied) is still fatal (`DepsError::Read`).
pub fn build_graph(root: &Path) -> Result<(DependencyGraph, Vec<ScanError>), DepsError> {
    let (declared_npm_set, direct_npm_set, npm_skipped) = manifest_js::declared_npm(root)?;
    let (declared_pypi_set, direct_pypi_set, pypi_skipped) = manifest_py::declared_pypi(root)?;

    let node_builtins = imports_js::node_builtins()?;
    let python_stdlib = imports_py::python_stdlib()?;
    let python_import_aliases = imports_py::python_import_aliases()?;

    let (js_raw, mut skipped) = imports_js::collect_imports(root)?;
    let (py_raw, py_skipped) = imports_py::collect_imports(root)?;
    skipped.extend(py_skipped);
    skipped.extend(npm_skipped);
    skipped.extend(pypi_skipped);

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
        let mut declared_key = normalize_pep503(&raw.module);
        // A5: the import's own normalized spelling isn't declared, but a
        // known alias target is (`import yaml` declares as `pyyaml`) — swap
        // in whichever alias target is actually present in the declared set
        // so `classify` resolves it to `Declared` rather than `Phantom`.
        if !declared_pypi_set.contains(&declared_key) {
            if let Some(targets) = python_import_aliases.get(raw.module.as_str()) {
                if let Some(matched) = targets
                    .iter()
                    .map(|target| normalize_pep503(target))
                    .find(|target| declared_pypi_set.contains(target))
                {
                    declared_key = matched;
                }
            }
        }
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

    let has_supported_manifest = has_any_supported_manifest(root);
    let unsupported_stack = detect_unsupported_stack(root, has_supported_manifest);

    let mut declared = BTreeMap::new();
    declared.insert(Ecosystem::Npm, declared_npm_set);
    declared.insert(Ecosystem::Pypi, declared_pypi_set);

    let mut direct = BTreeMap::new();
    direct.insert(Ecosystem::Npm, direct_npm_set);
    direct.insert(Ecosystem::Pypi, direct_pypi_set);

    Ok((
        DependencyGraph {
            declared,
            direct,
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

/// Single bounded-depth walk (A4) checking whether ANY [`SUPPORTED_MANIFESTS`]
/// filename exists anywhere under `root`, short-circuiting on the first hit
/// — replaces the old root-only `root.join(name).is_file()` check, which
/// missed every nested-manifest layout (`backend/requirements.txt`, a
/// monorepo `apps/*/package.json`, ...).
fn has_any_supported_manifest(root: &Path) -> bool {
    let mut builder = project_walker(root);
    builder.max_depth(Some(MANIFEST_DISCOVERY_DEPTH));
    builder.build().flatten().any(|entry| {
        entry.file_type().is_some_and(|t| t.is_file())
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| SUPPORTED_MANIFESTS.contains(&name))
    })
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
    for entry in project_walker(root).build().flatten() {
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

/// Crate-internal accessor for `review::orphan`: run both existing import
/// collectors over `root` and return only the RELATIVE (`is_relative == true`)
/// subset, plus any per-file scan skips. A thin wrapper over the same
/// `imports_js`/`imports_py` machinery `build_graph` uses — `orphan-file`
/// reconciles these raw relative specifiers against local file paths rather
/// than declared packages (06-RESEARCH.md "Don't Hand-Roll"). A fatal
/// grammar/query error from a collector degrades to a collected skip here
/// (orphan detection must never panic the run), not a hard failure.
pub(crate) fn relative_import_targets(root: &Path) -> (Vec<RawImport>, Vec<ScanError>) {
    let mut imports = Vec::new();
    let mut skipped = Vec::new();
    for result in [
        imports_js::collect_imports(root),
        imports_py::collect_imports(root),
    ] {
        match result {
            Ok((raw, sk)) => {
                imports.extend(raw.into_iter().filter(|r| r.is_relative));
                skipped.extend(sk);
            }
            Err(err) => skipped.push(err),
        }
    }
    (imports, skipped)
}

/// Project-relative display path, forward slashes — mirrors `env::plan`'s
/// convention.
pub(crate) fn relative_display(path: &Path, root: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.to_string_lossy().replace('\\', "/")
}
