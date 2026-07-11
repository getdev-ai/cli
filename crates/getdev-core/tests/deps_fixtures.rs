//! Fixture gate for `getdev_core::deps` (docs/TESTING.md): every manifest
//! dialect fixture must yield its expected declared-package set via
//! `build_graph`, and the phantom-import fixtures must classify builtin /
//! declared / local imports as NOT phantom while the one hallucinated
//! import in each is classified `Phantom`.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use getdev_core::deps::{self, Ecosystem, ImportResolution};

fn fixtures(subdir: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/fixtures/deps")
        .join(subdir)
}

fn declared_npm_set(dir: &str) -> BTreeSet<String> {
    let (graph, skipped) = deps::build_graph(&fixtures(dir)).unwrap();
    assert!(skipped.is_empty(), "{dir}: unexpected skipped files");
    graph
        .declared
        .get(&Ecosystem::Npm)
        .cloned()
        .unwrap_or_default()
}

fn declared_pypi_set(dir: &str) -> BTreeSet<String> {
    let (graph, skipped) = deps::build_graph(&fixtures(dir)).unwrap();
    assert!(skipped.is_empty(), "{dir}: unexpected skipped files");
    graph
        .declared
        .get(&Ecosystem::Pypi)
        .cloned()
        .unwrap_or_default()
}

fn names(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn js_package_json_only_declares_all_four_groups() {
    assert_eq!(
        declared_npm_set("js/package-json-only"),
        names(&["lodash", "@scope/pkg", "eslint", "fsevents", "react"])
    );
}

#[test]
fn js_package_lock_v1_walks_nested_dependencies() {
    assert_eq!(
        declared_npm_set("js/package-lock-v1"),
        names(&["left-pad", "chalk", "ansi-styles"])
    );
}

#[test]
fn js_package_lock_v3_walks_flat_packages_map() {
    assert_eq!(
        declared_npm_set("js/package-lock-v3"),
        names(&["lodash", "@babel/core", "semver"])
    );
}

#[test]
fn js_pnpm_lock_importers_and_packages() {
    assert_eq!(
        declared_npm_set("js/pnpm-lock"),
        names(&["fastify", "@fastify/error"])
    );
}

#[test]
fn js_yarn_lock_entries() {
    assert_eq!(
        declared_npm_set("js/yarn-lock"),
        names(&["is-odd", "is-number"])
    );
}

#[test]
fn py_requirements_skips_options_vcs_and_comments() {
    assert_eq!(
        declared_pypi_set("py/requirements"),
        names(&["flask", "requests"])
    );
}

#[test]
fn py_pyproject_pep621_dependencies() {
    assert_eq!(
        declared_pypi_set("py/pyproject-pep621"),
        names(&["requests", "typing-extensions"])
    );
}

#[test]
fn py_pyproject_poetry_excludes_python_pin() {
    assert_eq!(
        declared_pypi_set("py/pyproject-poetry"),
        names(&["django", "requests"])
    );
}

#[test]
fn py_poetry_lock_package_table() {
    assert_eq!(
        declared_pypi_set("py/poetry-lock"),
        names(&["certifi", "charset-normalizer"])
    );
}

#[test]
fn py_uv_lock_package_table() {
    assert_eq!(declared_pypi_set("py/uv-lock"), names(&["idna", "sniffio"]));
}

#[test]
fn py_normalization_collapses_mixed_case_across_manifests() {
    assert_eq!(declared_pypi_set("py/normalization"), names(&["flask"]));
}

fn resolution_of<'a>(imports: &'a [deps::ImportRef], module: &str) -> Option<&'a ImportResolution> {
    imports
        .iter()
        .find(|i| i.module == module)
        .map(|i| &i.resolution)
}

#[test]
fn js_phantom_fixture_classifies_every_import_correctly() {
    let dir = fixtures("js/phantom");
    let (graph, skipped) = deps::build_graph(&dir).unwrap();
    assert!(skipped.is_empty());

    assert_eq!(
        resolution_of(&graph.imports, "node:fs"),
        Some(&ImportResolution::Builtin),
        "node: prefixed builtin must not be phantom (Pitfall 7)"
    );
    assert_eq!(
        resolution_of(&graph.imports, "path"),
        Some(&ImportResolution::Builtin)
    );
    assert_eq!(
        resolution_of(&graph.imports, "lodash"),
        Some(&ImportResolution::Declared)
    );
    assert_eq!(
        resolution_of(&graph.imports, "./utils"),
        Some(&ImportResolution::Local),
        "relative import must never be phantom"
    );
    assert_eq!(
        resolution_of(&graph.imports, "totally-fake-package-xyz"),
        Some(&ImportResolution::Phantom)
    );
}

#[test]
fn py_phantom_fixture_classifies_every_import_correctly() {
    let dir = fixtures("py/phantom");
    let (graph, skipped) = deps::build_graph(&dir).unwrap();
    assert!(skipped.is_empty());

    assert_eq!(
        resolution_of(&graph.imports, "os"),
        Some(&ImportResolution::Builtin),
        "stdlib module must not be phantom"
    );
    assert_eq!(
        resolution_of(&graph.imports, "requests"),
        Some(&ImportResolution::Declared)
    );
    assert_eq!(
        resolution_of(&graph.imports, "totally_fake_module_xyz"),
        Some(&ImportResolution::Phantom)
    );

    let relative_is_local = graph
        .imports
        .iter()
        .any(|i| i.resolution == ImportResolution::Local && i.module.starts_with('.'));
    assert!(
        relative_is_local,
        "relative Python import must classify as Local, never Phantom"
    );
}

#[test]
fn go_only_project_sets_unsupported_stack_hint() {
    let dir = fixtures("go-only");
    let (graph, skipped) = deps::build_graph(&dir).unwrap();
    assert!(skipped.is_empty());
    assert!(graph
        .declared
        .get(&Ecosystem::Npm)
        .is_none_or(BTreeSet::is_empty));
    assert!(graph
        .declared
        .get(&Ecosystem::Pypi)
        .is_none_or(BTreeSet::is_empty));
    assert_eq!(
        graph
            .unsupported_stack
            .as_ref()
            .map(|h| h.detected.as_str()),
        Some("go")
    );
}

#[test]
fn supported_stack_never_reports_unsupported_hint() {
    let dir = fixtures("js/phantom");
    let (graph, skipped) = deps::build_graph(&dir).unwrap();
    assert!(skipped.is_empty());
    assert!(graph.unsupported_stack.is_none());
}

/// A4: a manifest nested inside a subdirectory (`backend/requirements.txt`,
/// mirroring a real `backend/` + `frontend/` service layout) must be
/// discovered, not just a root-level manifest — on the old root-only
/// discovery this fixture's `flask` import wrongly classified as
/// `real/phantom-import` despite being correctly declared one directory
/// down.
#[test]
fn py_nested_manifest_is_discovered_and_declared_import_is_not_phantom() {
    let dir = fixtures("py/nested-manifest");
    let (graph, skipped) = deps::build_graph(&dir).unwrap();
    assert!(skipped.is_empty());
    assert_eq!(
        resolution_of(&graph.imports, "flask"),
        Some(&ImportResolution::Declared),
        "a manifest nested under backend/ must still be discovered (A4)"
    );
    assert_eq!(
        resolution_of(&graph.imports, "totally_fake_nested_phantom_module"),
        Some(&ImportResolution::Phantom),
        "control: an undeclared import in the same nested file must still be Phantom"
    );
}

/// A5: `import yaml` with `pyyaml` declared (not `yaml`) must resolve as
/// `Declared` via the import-name -> distribution-name alias table, not
/// `real/phantom-import`.
#[test]
fn py_import_alias_yaml_declares_as_pyyaml_is_not_phantom() {
    let dir = fixtures("py/alias");
    let (graph, skipped) = deps::build_graph(&dir).unwrap();
    assert!(skipped.is_empty());
    assert_eq!(
        resolution_of(&graph.imports, "yaml"),
        Some(&ImportResolution::Declared),
        "import yaml must resolve via the pyyaml alias (A5)"
    );
}

/// A6: `operator`/`shlex`/`optparse` are Python stdlib and must never be
/// phantom, even with zero manifests present.
#[test]
fn py_stdlib_gap_modules_are_never_phantom() {
    let dir = fixtures("py/stdlib-gap");
    let (graph, skipped) = deps::build_graph(&dir).unwrap();
    assert!(skipped.is_empty());
    for module in ["operator", "shlex", "optparse"] {
        assert_eq!(
            resolution_of(&graph.imports, module),
            Some(&ImportResolution::Builtin),
            "{module} must be recognized as stdlib (A6)"
        );
    }
}

/// A10: a malformed manifest (invalid JSON) must become a skip entry, not
/// abort `build_graph` for the whole project — a sibling manifest's
/// declared names must still come through.
#[test]
fn js_malformed_manifest_is_skipped_not_fatal() {
    let dir = fixtures("js/malformed-manifest");
    let (graph, skipped) = deps::build_graph(&dir).unwrap();
    assert_eq!(skipped.len(), 1, "the malformed manifest must be skipped");
    assert!(
        skipped[0].to_string().contains("backend/package.json")
            || skipped[0].to_string().contains("backend"),
        "skip reason should reference the malformed file: {}",
        skipped[0]
    );
    assert!(
        graph
            .declared
            .get(&Ecosystem::Npm)
            .is_some_and(|set| set.contains("lodash")),
        "the sibling, valid root manifest must still be parsed"
    );
}

/// A11: PEP 621 `[project.optional-dependencies]` (every extras group) and
/// PEP 735 `[dependency-groups]` must be unioned into the declared set.
#[test]
fn py_pyproject_optional_dependencies_and_dependency_groups() {
    assert_eq!(
        declared_pypi_set("py/pyproject-optional-deps"),
        names(&["requests", "pytest", "ruff", "black"])
    );
}

/// A11: `[tool.poetry.group.*.dependencies]` and
/// `[tool.poetry.dev-dependencies]` must be unioned into the declared set.
#[test]
fn py_pyproject_poetry_group_and_dev_dependencies() {
    assert_eq!(
        declared_pypi_set("py/pyproject-poetry-groups"),
        names(&["django", "black", "mypy"])
    );
}

/// A16: dynamic `import("pkg")` and `export ... from "pkg"` sources must be
/// extracted and reconciled just like a static `import`/`require`.
#[test]
fn js_dynamic_import_and_export_from_are_reconciled() {
    let dir = fixtures("js/dynamic-import");
    let (graph, skipped) = deps::build_graph(&dir).unwrap();
    assert!(skipped.is_empty());
    assert_eq!(
        resolution_of(&graph.imports, "left-pad"),
        Some(&ImportResolution::Declared),
        "export {{ x }} from \"pkg\" must be extracted and reconciled (A16)"
    );
    assert_eq!(
        resolution_of(&graph.imports, "totally-fake-dynamic-only-pkg"),
        Some(&ImportResolution::Phantom),
        "dynamic import(\"pkg\") must be extracted and reconciled (A16)"
    );
}

/// F8: `-r base.txt` must be resolved (relative to the requirements file)
/// and recursively parsed, and a bare `.` line must yield NO declared name
/// (never the bogus literal `.`/`-`).
#[test]
fn py_requirements_include_is_resolved_and_bare_dot_yields_no_name() {
    let declared = declared_pypi_set("py/requirements-include");
    assert_eq!(declared, names(&["requests"]));
    assert!(
        !declared.contains("."),
        "bare `.` line must not yield a name"
    );
    assert!(
        !declared.contains("-"),
        "bare `.` line must not yield \"-\""
    );
}

/// A7 regression, exercised at the `build_graph` level (not just the raw
/// walker unit tests in `scan.rs`): a `node_modules` tree outside a git
/// repository must be excluded from both manifest discovery and import
/// extraction — this tempdir is deliberately never `git init`-ed.
#[test]
fn node_modules_is_excluded_outside_a_git_repo_at_build_graph_level() {
    let dir = std::env::temp_dir().join(format!(
        "getdev-deps-a7-regression-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("node_modules/vendored-pkg")).unwrap();
    std::fs::write(
        dir.join("node_modules/vendored-pkg/package.json"),
        r#"{"dependencies": {"should-never-be-declared": "^1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("node_modules/vendored-pkg/index.js"),
        "require(\"should-never-be-an-import\");\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies": {"left-pad": "^1.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("index.js"), "require(\"left-pad\");\n").unwrap();

    let (graph, skipped) = deps::build_graph(&dir).unwrap();
    assert!(skipped.is_empty());
    assert!(
        graph
            .declared
            .get(&Ecosystem::Npm)
            .is_some_and(|set| !set.contains("should-never-be-declared")),
        "node_modules/vendored-pkg/package.json must never be discovered"
    );
    assert!(
        resolution_of(&graph.imports, "should-never-be-an-import").is_none(),
        "node_modules source must never be walked for imports"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// Ensure the fixture directory itself is what the doc comment claims —
// guards against silently pointing at an empty/renamed directory.
#[test]
fn fixture_root_exists() {
    for dir in [
        "js/package-json-only",
        "js/package-lock-v1",
        "js/package-lock-v3",
        "js/pnpm-lock",
        "js/yarn-lock",
        "js/phantom",
        "js/malformed-manifest",
        "js/dynamic-import",
        "py/requirements",
        "py/requirements-include",
        "py/pyproject-pep621",
        "py/pyproject-poetry",
        "py/pyproject-optional-deps",
        "py/pyproject-poetry-groups",
        "py/poetry-lock",
        "py/uv-lock",
        "py/normalization",
        "py/phantom",
        "py/nested-manifest",
        "py/alias",
        "py/stdlib-gap",
        "go-only",
    ] {
        let path = fixtures(dir);
        assert!(Path::new(&path).is_dir(), "missing fixture dir: {dir}");
    }
}
