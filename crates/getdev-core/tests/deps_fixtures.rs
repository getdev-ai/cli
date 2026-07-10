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
        "py/requirements",
        "py/pyproject-pep621",
        "py/pyproject-poetry",
        "py/poetry-lock",
        "py/uv-lock",
        "py/normalization",
        "py/phantom",
        "go-only",
    ] {
        let path = fixtures(dir);
        assert!(Path::new(&path).is_dir(), "missing fixture dir: {dir}");
    }
}
