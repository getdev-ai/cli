//! Fixture gate for `getdev_core::apisurface` (docs/TESTING.md): a genuine
//! nonexistent member on a fully resolved installed package must yield
//! exactly one High-confidence `NonexistentApi` result, and the identical
//! access-pattern shape on a package whose surface could not be resolved
//! statically (Python module-level `__getattr__`, Pitfall 5) must yield
//! zero High-confidence results — the FP-budget guard docs/PLAN.md §9.2
//! requires (< 5% FP ceiling).

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use getdev_core::apisurface::{self, ApiResultKind, SurfaceTier};
use getdev_core::deps;
use getdev_core::findings::Confidence;

fn fixtures(subdir: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/fixtures/apisurface")
        .join(subdir)
}

fn run_check(root: &Path) -> Vec<apisurface::ApiResult> {
    let (graph, dep_skipped) = deps::build_graph(root).unwrap();
    assert!(dep_skipped.is_empty(), "unexpected skipped manifest files");
    let (usages, usage_skipped) = apisurface::collect_usages(root).unwrap();
    assert!(usage_skipped.is_empty(), "unexpected skipped source files");
    apisurface::check(
        &graph,
        &usages,
        &root.join("node_modules"),
        &root.join("site-packages"),
    )
}

#[test]
fn resolved_js_package_missing_member_is_high_confidence() {
    let root = fixtures("js/resolved");
    let results = run_check(&root);

    let misses: Vec<_> = results
        .iter()
        .filter(|r| r.package == "typed-pkg" && r.member == "fakeFn")
        .collect();
    assert_eq!(misses.len(), 1, "expected exactly one fakeFn miss");
    assert_eq!(misses[0].confidence, Confidence::High);
    assert_eq!(misses[0].kind, ApiResultKind::NonexistentApi);

    // The real member (accessed both as a named import and via the
    // namespace-import member access) must never be flagged.
    assert!(!results
        .iter()
        .any(|r| r.package == "typed-pkg" && r.member == "realFn"));
}

#[test]
fn resolved_python_package_missing_member_is_high_confidence() {
    let root = fixtures("py/resolved");
    let results = run_check(&root);

    let misses: Vec<_> = results
        .iter()
        .filter(|r| r.package == "typed_pkg" && r.member == "fake_fn")
        .collect();
    assert_eq!(misses.len(), 1, "expected exactly one fake_fn miss");
    assert_eq!(misses[0].confidence, Confidence::High);

    assert!(!results
        .iter()
        .any(|r| r.package == "typed_pkg" && r.member == "real_fn"));
}

#[test]
fn dynamic_python_package_never_yields_high_confidence_results() {
    // Same access-pattern shape as the resolved-Python fixture above
    // (`import pkg; pkg.something()`) but against a package whose surface
    // uses a module-level `__getattr__` — this is the FP-budget guard: a
    // dynamic package's misses must downgrade, never stay High.
    let root = fixtures("py/dynamic");
    let results = run_check(&root);

    assert!(
        results.iter().all(|r| r.confidence != Confidence::High),
        "dynamic package produced a High-confidence result: {results:?}"
    );
    let downgraded: Vec<_> = results
        .iter()
        .filter(|r| r.package == "dynamic_pkg" && r.member == "anything_at_all")
        .collect();
    assert_eq!(downgraded.len(), 1);
    // A2: Dynamic-tier confidence is `Medium` (real source was read, just
    // not fully resolved statically) — never `High` (the FP-budget guard
    // above), and never silently `Low` either (that tier is reserved for
    // NotInstalled/Unreadable, audit A2/A3).
    assert_eq!(downgraded[0].confidence, Confidence::Medium);
    assert!(
        !downgraded[0].detail.is_empty(),
        "detail must explain the reasoning"
    );
}

/// A3 — a declared-but-never-installed Python package must never produce
/// one `NonexistentApi` per usage site (the "not installed" noise wall):
/// exactly one aggregated, Info-severity/Low-confidence result for the
/// whole package, regardless of how many usage sites reference it.
#[test]
fn not_installed_python_package_aggregates_to_one_low_confidence_result() {
    let root = fixtures("py/not-installed");
    let results = run_check(&root);

    let misses: Vec<_> = results
        .iter()
        .filter(|r| r.package == "never_installed_pkg")
        .collect();
    assert_eq!(
        misses.len(),
        1,
        "expected exactly one aggregated result regardless of 3 usage sites: {results:?}"
    );
    assert_eq!(misses[0].confidence, Confidence::Low);
    assert_eq!(misses[0].tier, SurfaceTier::NotInstalled);
    assert_eq!(misses[0].usage_count, 3);
}

/// A3 — same noise-wall guarantee for a declared-but-never-installed JS
/// package (`node_modules/<pkg>` absent entirely).
#[test]
fn not_installed_js_package_aggregates_to_one_low_confidence_result() {
    let root = fixtures("js/not-installed");
    let results = run_check(&root);

    let misses: Vec<_> = results
        .iter()
        .filter(|r| r.package == "never-installed-pkg")
        .collect();
    assert_eq!(
        misses.len(),
        1,
        "expected exactly one aggregated result regardless of 3 usage sites: {results:?}"
    );
    assert_eq!(misses[0].confidence, Confidence::Low);
    assert_eq!(misses[0].tier, SurfaceTier::NotInstalled);
    assert_eq!(misses[0].usage_count, 3);
}

/// A8 — `from djangolike import forms` must resolve against the package's
/// top-level submodule surface (`forms.py`'s stem), not just its
/// `__init__.py` — a genuinely nonexistent submodule must still miss.
#[test]
fn django_style_submodule_import_resolves_no_fp() {
    let root = fixtures("py/submodules");
    let results = run_check(&root);

    assert!(
        !results
            .iter()
            .any(|r| r.package == "djangolike" && r.member == "forms"),
        "a real top-level submodule must never be flagged: {results:?}"
    );
    let misses: Vec<_> = results
        .iter()
        .filter(|r| r.package == "djangolike" && r.member == "fake_submodule")
        .collect();
    assert_eq!(
        misses.len(),
        1,
        "a genuinely nonexistent submodule must still be flagged: {results:?}"
    );
    assert_eq!(misses[0].tier, SurfaceTier::Resolved);
    assert_eq!(misses[0].confidence, Confidence::High);
}

/// A13 — a JS subpath import (`react-dom-like/server`) must be judged
/// against its own subpath surface, never the (unrelated) root surface: a
/// member that is genuinely exported by the subpath's own `.d.ts` must
/// never be flagged, even though the root surface doesn't have it either.
#[test]
fn subpath_import_is_judged_against_its_own_surface_not_root() {
    let root = fixtures("js/subpath");
    let results = run_check(&root);

    assert!(
        !results
            .iter()
            .any(|r| r.package == "react-dom-like" && r.member == "renderToString"),
        "a member exported by the subpath's own surface must never be flagged against root: \
         {results:?}"
    );
}
