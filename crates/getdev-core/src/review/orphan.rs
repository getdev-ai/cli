//! `review/orphan-file` detector — a newly INTRODUCED source file whose
//! project-relative path is the target of no relative import anywhere in the
//! project, and which is not itself a framework/entry-point convention.
//!
//! ## Algorithm (06-RESEARCH.md Q6 / "Don't Hand-Roll")
//! Rather than a bespoke import walk, this REUSES `deps`'s existing
//! relative-import extraction ([`crate::deps::relative_import_targets`], the
//! `is_relative == true` subset of the same `imports_js`/`imports_py`
//! collectors `deps::build_graph` uses). Each relative specifier is resolved
//! against the importing file's directory — trying the language's module
//! resolution suffixes — into a SET of project-relative "referenced" paths. A
//! newly added file (`ReviewFile::is_new_file`) whose own path is absent from
//! that set, and which is not a framework/entry/test convention, is an orphan.
//!
//! ## False-positive guards (Pitfall 5-adjacent, framework-routing FP)
//! Entry points and framework-router files are referenced by a runtime, not by
//! a textual import, so they are exempt whole: top-level `index`/`main`/`app`/
//! `server` files, Next.js `pages/**` + app-router `page`/`layout`/`route`,
//! Django `urls.py`/`views.py`/`settings.py`/`manage.py`, tooling config files
//! (`*.config.*`), standalone `scripts/**`, Python `conftest.py`/`wsgi.py`/
//! `asgi.py`, test files, and Python `__init__.py`.
//!
//! ## Path-traversal safety (T-06-12)
//! Import resolution normalizes `.`/`..` components and DISCARDS any specifier
//! that escapes the project root (a leading `..` past the top) — such a target
//! is never added to the referenced set and never touched on disk.
//!
//! This file is the ONLY review submodule 06-04 rewrites for this rule (plus a
//! thin `pub(crate)` accessor in `deps/mod.rs`); `review/mod.rs` is never
//! touched (Wave 3 stays parallel with 06-03).

use std::collections::HashSet;
use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};

use super::ReviewFile;
use crate::deps::{relative_import_targets, RawImport};
use crate::findings::{Confidence, Finding, Severity};

/// JS/TS module-resolution suffixes tried for a bare relative specifier
/// (`./foo` -> `foo.ts`, `foo/index.ts`, ...).
const JS_FILE_SUFFIXES: &[&str] = &[".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"];
const JS_INDEX_SUFFIXES: &[&str] = &[
    "/index.js",
    "/index.jsx",
    "/index.mjs",
    "/index.cjs",
    "/index.ts",
    "/index.tsx",
];

/// Framework-entry / test / package-init path conventions whose files are
/// exempt from orphan detection (framework-routing FP guard). A file matching
/// any of these is referenced by a runtime, not by a textual import.
const EXEMPT_PATH_GLOBS: &[&str] = &[
    // top-level entry points (any directory)
    "index.*",
    "**/index.*",
    "main.*",
    "**/main.*",
    "app.*",
    "**/app.*",
    "server.*",
    "**/server.*",
    // Next.js file-based routers
    "pages/**",
    "**/pages/**",
    "app/**/page.*",
    "app/**/layout.*",
    "app/**/route.*",
    "**/app/**/page.*",
    "**/app/**/layout.*",
    "**/app/**/route.*",
    // Django URL/view/config modules
    "urls.py",
    "**/urls.py",
    "views.py",
    "**/views.py",
    "settings.py",
    "**/settings.py",
    "manage.py",
    "**/manage.py",
    // Python package initializers
    "__init__.py",
    "**/__init__.py",
    // Tooling config files (B-03): loaded by a build tool / framework by name,
    // never `import`ed — e.g. next.config.js, vite.config.ts, tailwind.config.js,
    // jest.config.js, eslint.config.mjs, drizzle.config.ts, ...
    "*.config.*",
    "**/*.config.*",
    // Standalone scripts (B-03): run directly (node/python foo.js, npm scripts,
    // CI steps), not imported by application code.
    "scripts/**",
    "**/scripts/**",
    // Python server/test entry points invoked by a runtime, not imported:
    // pytest's conftest, and the WSGI/ASGI app modules gunicorn/uvicorn load.
    "conftest.py",
    "**/conftest.py",
    "wsgi.py",
    "**/wsgi.py",
    "asgi.py",
    "**/asgi.py",
    // test files
    "**/*.test.*",
    "**/*.spec.*",
    "*.test.*",
    "*.spec.*",
    "**/tests/**",
    "**/test_*.py",
    "**/*_test.py",
];

/// Detect introduced orphan files — newly added, unreferenced, non-entry files.
pub(crate) fn detect(root: &Path, files: &[ReviewFile]) -> Vec<Finding> {
    let (imports, _skipped) = relative_import_targets(root);
    let referenced = referenced_paths(&imports);
    detect_with_referenced(&referenced, files)
}

/// The pure core, split out so it can be unit-tested with an in-memory
/// referenced set and in-memory [`ReviewFile`]s — no filesystem writes, keeping
/// this module free of any file-mutation token for the "review never mutates"
/// grep gate.
fn detect_with_referenced(referenced: &HashSet<String>, files: &[ReviewFile]) -> Vec<Finding> {
    let exemptions = compile_exemptions();
    let mut findings = Vec::new();
    for file in files {
        // Introduced-gate: only a newly added file can be an orphan.
        if !file.is_new_file {
            continue;
        }
        // FP guard: framework-entry / test / package-init files are exempt.
        if path_is_exempt(exemptions.as_ref(), &file.rel) {
            continue;
        }
        if referenced.contains(&file.rel) {
            continue;
        }
        findings.push(orphan_finding(&file.rel));
    }
    findings
}

/// Resolve every relative import into the SET of project-relative paths it
/// could target (candidate expansion over module-resolution suffixes).
fn referenced_paths(imports: &[RawImport]) -> HashSet<String> {
    let mut set = HashSet::new();
    for imp in imports {
        add_candidates(imp, &mut set);
    }
    set
}

/// Expand one relative import into candidate target paths, inserting each into
/// `set`. Python importers resolve dotted relative modules; everything else is
/// treated as a JS/TS path specifier.
fn add_candidates(imp: &RawImport, set: &mut HashSet<String>) {
    if imp.file.ends_with(".py") {
        if let Some(base) = resolve_py(&imp.file, &imp.module) {
            // package-dir, `base.py`, and `base/__init__.py` all satisfy a
            // Python relative import target (best-effort — the collector does
            // not carry the imported symbol names).
            set.insert(base.clone());
            set.insert(format!("{base}.py"));
            set.insert(format!("{base}/__init__.py"));
        }
    } else if let Some(base) = resolve_js(&imp.file, &imp.module) {
        // the specifier may already carry an extension (`./x.js`)
        set.insert(base.clone());
        for suffix in JS_FILE_SUFFIXES {
            set.insert(format!("{base}{suffix}"));
        }
        for suffix in JS_INDEX_SUFFIXES {
            set.insert(format!("{base}{suffix}"));
        }
    }
}

/// Resolve a JS/TS path specifier (`./foo`, `../bar/baz`) against the
/// importer's directory into a normalized project-relative base path.
/// Returns `None` if the specifier escapes the project root (T-06-12).
fn resolve_js(importer_rel: &str, spec: &str) -> Option<String> {
    let mut comps: Vec<&str> = importer_rel.split('/').collect();
    comps.pop(); // drop the importer's own filename -> its directory
    for part in spec.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                comps.pop()?; // escaping above root -> discard
            }
            other => comps.push(other),
        }
    }
    Some(comps.join("/"))
}

/// Resolve a Python relative import (`.`, `..pkg`, `.mod.sub`) against the
/// importer's directory into a normalized project-relative base path. Leading
/// dots select the package level (1 dot = current package, each extra = one
/// parent up); the remainder is the dotted submodule. Returns `None` on a
/// non-relative spec or one escaping the root (T-06-12).
fn resolve_py(importer_rel: &str, module: &str) -> Option<String> {
    let dots = module.chars().take_while(|&c| c == '.').count();
    if dots == 0 {
        return None;
    }
    let remainder = &module[dots..];
    let mut comps: Vec<&str> = importer_rel.split('/').collect();
    comps.pop(); // importer directory == current package
    for _ in 0..dots.saturating_sub(1) {
        comps.pop()?; // escaping above root -> discard
    }
    for part in remainder.split('.') {
        if !part.is_empty() {
            comps.push(part);
        }
    }
    Some(comps.join("/"))
}

/// Compile the [`EXEMPT_PATH_GLOBS`] set once, mirroring `deadcode`'s
/// exemption compilation. A malformed pattern is skipped, never fatal.
fn compile_exemptions() -> Option<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in EXEMPT_PATH_GLOBS {
        if let Ok(glob) = Glob::new(pattern) {
            builder.add(glob);
        }
    }
    builder.build().ok()
}

fn path_is_exempt(globs: Option<&GlobSet>, rel: &str) -> bool {
    globs.is_some_and(|set| set.is_match(rel))
}

/// Build the `review/orphan-file` finding — a file-level finding (no line/
/// column, like audit's text-regex findings) with the mandatory caveat
/// `detail` (SPEC-RULES heuristic-detail requirement — confidence != high).
fn orphan_finding(rel: &str) -> Finding {
    Finding {
        id: "review/orphan-file".to_owned(),
        command: "review".to_owned(),
        severity: Severity::Low,
        confidence: Confidence::Medium,
        file: rel.to_owned(),
        line: None,
        column: None,
        end_line: None,
        message: format!("Introduced file '{rel}' is not imported by any project file"),
        detail: Some(
            "newly added but not referenced by any relative import; may be an unused orphan \
             or a legitimate entry point (heuristic; confidence: medium)"
                .to_owned(),
        ),
        suggestion: None,
        remediation: Some(
            "import/use the file, delete it if it is dead, or ignore if it is an entry point"
                .to_owned(),
        ),
        fixable: false,
        refs: vec!["https://getdev.ai/rules/review/orphan-file".to_owned()],
        fingerprint: None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::scan::Lang;
    use getdev_grammars::tree_sitter::Parser;

    /// In-memory [`ReviewFile`] — the tree content is irrelevant to orphan
    /// detection (only `rel` + `is_new_file` matter), so a trivial source
    /// keeps this fs-free.
    fn review_file(rel: &str, is_new_file: bool) -> ReviewFile {
        let lang = Lang::JavaScript;
        let src = "const x = 1;\n";
        let mut parser = Parser::new();
        parser.set_language(&lang.language()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        ReviewFile {
            rel: rel.to_owned(),
            lang,
            source: src.to_owned(),
            tree,
            added_ranges: vec![(1, 1)],
            is_new_file,
        }
    }

    fn rel_import(file: &str, module: &str) -> RawImport {
        RawImport {
            module: module.to_owned(),
            is_relative: true,
            file: file.to_owned(),
            line: 1,
        }
    }

    #[test]
    fn new_file_referenced_by_a_sibling_is_not_orphan() {
        // `src/index.js` imports `./newmod`; `src/newmod.js` is therefore
        // referenced and must not fire.
        let referenced = referenced_paths(&[rel_import("src/index.js", "./newmod")]);
        let files = [review_file("src/newmod.js", true)];
        assert!(
            detect_with_referenced(&referenced, &files).is_empty(),
            "a file imported by a sibling must not be flagged orphan"
        );
    }

    #[test]
    fn new_file_referenced_by_nobody_fires() {
        let referenced = referenced_paths(&[]);
        let files = [review_file("src/newmod.js", true)];
        let findings = detect_with_referenced(&referenced, &files);
        assert_eq!(findings.len(), 1, "an unreferenced new file must fire");
        assert_eq!(findings[0].id, "review/orphan-file");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].confidence, Confidence::Medium);
        assert_eq!(findings[0].line, None, "orphan is a file-level finding");
        assert!(
            findings[0].detail.as_ref().is_some_and(|d| !d.is_empty()),
            "must carry a non-empty caveat detail"
        );
    }

    #[test]
    fn new_framework_router_file_is_exempt() {
        // A Next.js router file imported by nobody is framework-referenced.
        let referenced = referenced_paths(&[]);
        let files = [review_file("pages/about.tsx", true)];
        assert!(
            detect_with_referenced(&referenced, &files).is_empty(),
            "a pages/ router file must be exempt (framework entry)"
        );
    }

    #[test]
    fn new_entry_file_is_exempt() {
        let referenced = referenced_paths(&[]);
        let files = [review_file("index.js", true)];
        assert!(
            detect_with_referenced(&referenced, &files).is_empty(),
            "a top-level index.js must be exempt (entry point)"
        );
    }

    #[test]
    fn tooling_config_and_scripts_and_py_entry_points_are_exempt() {
        // B-03: framework/tooling entry points are loaded by a runtime, not by a
        // textual import, so a newly added one must NOT be flagged an orphan.
        let referenced = referenced_paths(&[]);
        for rel in [
            "next.config.js",
            "vite.config.ts",
            "tailwind.config.js",
            "scripts/train.py",
            "scripts/seed.js",
            "conftest.py",
            "app/wsgi.py",
        ] {
            let files = [review_file(rel, true)];
            assert!(
                detect_with_referenced(&referenced, &files).is_empty(),
                "{rel} is a tooling/entry-point convention and must be exempt"
            );
        }

        // Guard the widening: an ordinary unreferenced module next to them must
        // still fire (the allowlist did not swallow real orphans).
        let files = [review_file("src/orphaned.js", true)];
        assert_eq!(
            detect_with_referenced(&referenced, &files).len(),
            1,
            "a plain unreferenced new module must still be flagged"
        );
    }

    #[test]
    fn pre_existing_unreferenced_file_is_gated_out() {
        let referenced = referenced_paths(&[]);
        let files = [review_file("src/newmod.js", false)];
        assert!(
            detect_with_referenced(&referenced, &files).is_empty(),
            "a pre-existing (non-new) unreferenced file must produce zero findings"
        );
    }

    #[test]
    fn js_resolution_handles_parent_and_index() {
        assert_eq!(
            resolve_js("src/index.js", "./newmod").as_deref(),
            Some("src/newmod")
        );
        assert_eq!(
            resolve_js("src/a/b.js", "../util/helper").as_deref(),
            Some("src/util/helper")
        );
        // escaping the project root is discarded (T-06-12)
        assert_eq!(resolve_js("index.js", "../../etc/passwd"), None);
    }

    #[test]
    fn py_resolution_handles_dot_levels() {
        // `from .mod import x` in pkg/a.py -> pkg/mod
        assert_eq!(resolve_py("pkg/a.py", ".mod").as_deref(), Some("pkg/mod"));
        // `from ..other import x` in pkg/sub/a.py -> pkg/other
        assert_eq!(
            resolve_py("pkg/sub/a.py", "..other").as_deref(),
            Some("pkg/other")
        );
        // a non-relative module is not our concern
        assert_eq!(resolve_py("pkg/a.py", "os"), None);
    }
}
