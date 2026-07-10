//! Fixture gate for `getdev_core::apisurface` (docs/TESTING.md): a genuine
//! nonexistent member on a fully resolved installed package must yield
//! exactly one High-confidence `NonexistentApi` result, and the identical
//! access-pattern shape on a package whose surface could not be resolved
//! statically (Python module-level `__getattr__`, Pitfall 5) must yield
//! zero High-confidence results — the FP-budget guard docs/PLAN.md §9.2
//! requires (< 5% FP ceiling).

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use getdev_core::apisurface::{self, ApiResultKind};
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
    let low: Vec<_> = results
        .iter()
        .filter(|r| r.package == "dynamic_pkg" && r.member == "anything_at_all")
        .collect();
    assert_eq!(low.len(), 1);
    assert_eq!(low[0].confidence, Confidence::Low);
    assert!(
        !low[0].detail.is_empty(),
        "detail must explain the reasoning"
    );
}
