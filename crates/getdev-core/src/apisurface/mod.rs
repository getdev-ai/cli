//! Installed-package API-surface introspection: enumerate the exported
//! surface of a `node_modules/<pkg>` or `site-packages/<pkg>` directory from
//! files already on disk (`.d.ts` exports, Python AST), and compare it
//! against actual usage sites extracted from project source.
//!
//! **No project code is ever executed** (REQ-privacy / docs/PLAN.md's core
//! invariant) — this is pure static tree-sitter parsing, mirroring
//! `crate::scan`'s parse-once, skip-not-fail contract. Severity/confidence
//! are tiered per docs/PLAN.md §2.3/§9.2 (audit A2/A3):
//! - [`SurfaceTier::Resolved`]: every export was enumerated with no
//!   unresolved dynamic construct — an exact miss is `high` severity/`high`
//!   confidence, one result per usage site.
//! - [`SurfaceTier::Dynamic`]: the package uses a construct static analysis
//!   cannot see through — downgraded to `info` severity/`medium`
//!   confidence, still one result per usage site (real source was read; the
//!   location is still useful).
//! - [`SurfaceTier::NotInstalled`]/[`SurfaceTier::Unreadable`]: no readable
//!   source/types exist at all for the package — never one result per usage
//!   site (a fresh-clone/untyped-JS noise wall, audit A3); instead a single
//!   `info`/`low`-confidence result per package summarizing how many usage
//!   sites could not be verified.

pub mod dts;
pub mod pysurface;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::deps::{normalize_pep503, DependencyGraph, Ecosystem};
use crate::findings::Confidence;
use crate::scan::ScanError;

#[derive(Debug, thiserror::Error)]
pub enum SurfaceError {
    #[error(transparent)]
    Scan(#[from] ScanError),
}

/// How completely a package's public surface could be determined
/// statically. Only [`SurfaceTier::Resolved`] licenses a high-confidence
/// "member does not exist" result — Pitfalls 5/6 (03-RESEARCH.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SurfaceTier {
    /// Every export was enumerated with no unresolved dynamic construct.
    Resolved,
    /// The package uses a construct static analysis cannot see through
    /// (Python module-level `__getattr__`, TS ambient wildcard module,
    /// an unresolvable re-export target) — the surface may be incomplete.
    Dynamic,
    /// The package directory (`node_modules/<pkg>`/`site-packages/<pkg>`)
    /// does not exist at all — a fresh clone that never ran `npm
    /// install`/`pip install` (audit A3). Distinct from [`Self::Unreadable`]
    /// so `real` can word the finding accurately ("not installed" vs.
    /// "no readable types/source").
    NotInstalled,
    /// The package directory exists but ships no readable source/types
    /// (compiled-only package, untyped JS package with no `.d.ts`).
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
    /// Which ecosystem extracted this usage (audit A14) — set directly by
    /// the JS/Python extractor rather than re-derived by guessing which
    /// declared set the bare name happens to fall into (which could
    /// misjudge a Python `import yaml` against an npm `node_modules/yaml`
    /// if a project happens to declare both).
    pub ecosystem: Ecosystem,
    /// The subpath of a JS subpath import (`react-dom/server` -> `Some
    /// ("server")`), if any (audit A13). Always `None` for Python usage
    /// sites — Python submodule usage is `pkg.submodule` member access
    /// (A8), not a distinct import specifier shape needing its own surface.
    pub subpath: Option<String>,
}

/// The kind of API-surface mismatch found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiResultKind {
    /// The member is absent from every surface this tool could enumerate
    /// for the installed package.
    NonexistentApi,
    /// The member is absent from the installed version's surface but is
    /// known (from evidence local to the installed metadata) to exist in a
    /// different major version — conservative in v0.1: only ever emitted
    /// when the installed-version evidence is unambiguous, `NonexistentApi`
    /// is preferred otherwise (docs/PLAN.md §2.3).
    VersionMismatchApi,
}

/// One `real/nonexistent-api` or `real/version-mismatch-api` candidate.
/// Plain data — no `Finding`/CLI/report concerns live here; the `real`
/// command (03-05) maps these to the unified findings schema.
#[derive(Debug, Clone)]
pub struct ApiResult {
    pub kind: ApiResultKind,
    pub package: String,
    /// The missed member name. Empty for an aggregated
    /// [`SurfaceTier::NotInstalled`]/[`SurfaceTier::Unreadable`] result
    /// (`usage_count > 1`) — there is no single member to name (audit A3).
    pub member: String,
    pub file: String,
    pub line: u32,
    pub confidence: Confidence,
    /// The surface tier this result was judged against (audit A2) — `real`
    /// derives the finding's *severity* from this, never re-deriving it
    /// from `confidence`.
    pub tier: SurfaceTier,
    /// Heuristic reasoning surfaced to the user (FP policy, docs/PLAN.md
    /// §9.2) — always populated, explains *why* at low confidence.
    pub detail: String,
    /// How many usage sites this one result represents. `1` for a normal
    /// per-usage-site result (`Resolved`/`Dynamic` tiers); `> 1` for an
    /// aggregated `NotInstalled`/`Unreadable` result rolling up every
    /// usage site of that package into a single finding (audit A3 — never
    /// one result per usage site for a package with no readable surface at
    /// all).
    pub usage_count: usize,
}

/// Compare every usage site's `pkg.member` access against the installed
/// package's statically enumerated surface and emit confidence-tiered
/// results. Surfaces are cached per package (an installed package is
/// enumerated at most once per `check` call regardless of usage count).
///
/// Each usage site already carries its own extractor-assigned ecosystem
/// (`UsageSite::ecosystem`, audit A14), so `check` knows directly whether to
/// look under `node_modules` or `site_packages` — `graph` is consulted only
/// to confirm the package is declared under that ecosystem; a usage that
/// matches no declared set is skipped (it is `deps`'s job to have already
/// classified it as `Phantom`/`Builtin`/`Local` — `apisurface` only judges
/// packages that are genuinely installed dependencies).
///
/// `real/version-mismatch-api` is never emitted in v0.1: getdev-core has no
/// local, network-free evidence source for "this member exists in another
/// installed-version-adjacent snapshot" (that would require a registry
/// version-history dataset, which is `getdev-registry`'s concern, not
/// core's) — every miss conservatively resolves to `NonexistentApi`
/// (docs/PLAN.md §2.3: "prefer NonexistentApi" when version evidence is
/// unavailable).
pub fn check(
    graph: &DependencyGraph,
    usages: &[UsageSite],
    node_modules: &Path,
    site_packages: &Path,
) -> Vec<ApiResult> {
    // Keyed by (ecosystem, package, subpath) — a subpath surface (audit
    // A13) is judged independently of the package's root surface, and
    // keying by ecosystem too means a same-named npm/pypi package (however
    // unlikely) never shares a cache entry (audit A14).
    let mut cache: BTreeMap<(Ecosystem, String, Option<String>), ApiSurface> = BTreeMap::new();
    let mut results = Vec::new();
    // Rolled-up NotInstalled/Unreadable misses, one entry per package (audit
    // A3 — never one result per usage site for a package with no readable
    // surface at all). Keyed by (ecosystem, package) since a package could
    // in principle appear unreadable under one ecosystem's usage sites and
    // readable under a wrongly-guessed other one — A14 makes that
    // impossible now, but the key stays ecosystem-qualified for clarity.
    let mut aggregated: BTreeMap<(Ecosystem, String), AggregateMiss> = BTreeMap::new();

    for usage in usages {
        if !is_declared(graph, usage) {
            continue;
        }

        let surface = cache
            .entry((
                usage.ecosystem,
                usage.package.clone(),
                usage.subpath.clone(),
            ))
            .or_insert_with(|| {
                enumerate_installed(
                    usage.ecosystem,
                    &usage.package,
                    usage.subpath.as_deref(),
                    node_modules,
                    site_packages,
                )
            });

        if surface.exported.contains(&usage.member) {
            continue; // confirmed present — never a finding, regardless of tier
        }

        match surface.tier {
            SurfaceTier::Resolved => {
                results.push(ApiResult {
                    kind: ApiResultKind::NonexistentApi,
                    package: usage.package.clone(),
                    member: usage.member.clone(),
                    file: usage.file.clone(),
                    line: usage.line,
                    confidence: Confidence::High,
                    tier: SurfaceTier::Resolved,
                    detail: format!(
                        "'{}' is not present in {}'s statically enumerated exports",
                        usage.member, usage.package
                    ),
                    usage_count: 1,
                });
            }
            SurfaceTier::Dynamic => {
                results.push(ApiResult {
                    kind: ApiResultKind::NonexistentApi,
                    package: usage.package.clone(),
                    member: usage.member.clone(),
                    file: usage.file.clone(),
                    line: usage.line,
                    confidence: Confidence::Medium,
                    tier: SurfaceTier::Dynamic,
                    detail: format!(
                        "{}'s surface could not be fully resolved statically (dynamic export, \
                         ambient wildcard, or unresolvable re-export) — '{}' may exist but was \
                         not discoverable without executing code",
                        usage.package, usage.member
                    ),
                    usage_count: 1,
                });
            }
            SurfaceTier::NotInstalled | SurfaceTier::Unreadable => {
                let miss = aggregated
                    .entry((usage.ecosystem, usage.package.clone()))
                    .or_insert_with(|| AggregateMiss {
                        file: usage.file.clone(),
                        line: usage.line,
                        tier: surface.tier,
                        count: 0,
                    });
                miss.count += 1;
            }
        }
    }

    for ((_, package), miss) in aggregated {
        let (reason, remediation_hint) = match miss.tier {
            SurfaceTier::NotInstalled => (
                "not installed",
                "install it (e.g. `npm install`/`pip install`) so its surface can be verified",
            ),
            SurfaceTier::Unreadable => (
                "no readable types/source",
                "check that it ships type declarations (`.d.ts`) or readable Python source",
            ),
            SurfaceTier::Resolved | SurfaceTier::Dynamic => unreachable!(
                "aggregated only ever holds NotInstalled/Unreadable misses (see match above)"
            ),
        };
        results.push(ApiResult {
            kind: ApiResultKind::NonexistentApi,
            package: package.clone(),
            member: String::new(),
            file: miss.file,
            line: miss.line,
            confidence: Confidence::Low,
            tier: miss.tier,
            detail: format!(
                "could not verify {} usage(s) of '{package}' — {reason}; {remediation_hint}",
                miss.count
            ),
            usage_count: miss.count,
        });
    }

    results
}

struct AggregateMiss {
    file: String,
    line: u32,
    tier: SurfaceTier,
    count: usize,
}

/// Whether `usage`'s package is declared under its own extractor-assigned
/// ecosystem ([`UsageSite::ecosystem`], audit A14) — no more guessing by
/// trying `Npm` first and falling back to `Pypi` (which could wrongly judge
/// a Python `import yaml` usage against a coincidentally-declared npm
/// `yaml` package). A name declared in neither set is not a package
/// `apisurface` should judge (that's `deps::ImportResolution`'s job
/// upstream).
///
/// The `Pypi` declared set is PEP 503-normalized at graph-construction time
/// (`deps::normalize_pep503`: lowercase, runs of `-`/`_`/`.` collapse to a
/// single `-`), but a Python `import`/`from` statement's module name is the
/// raw underscore-form identifier (matching the `site-packages/<pkg>`
/// directory name, e.g. `typed_pkg`) — so the usage-side name must be
/// normalized the same way before membership is checked, or every
/// underscore-named PyPI package would silently never match.
fn is_declared(graph: &DependencyGraph, usage: &UsageSite) -> bool {
    match usage.ecosystem {
        Ecosystem::Npm => graph
            .declared
            .get(&Ecosystem::Npm)
            .is_some_and(|set| set.contains(&usage.package)),
        Ecosystem::Pypi => graph
            .declared
            .get(&Ecosystem::Pypi)
            .is_some_and(|set| set.contains(&normalize_pep503(&usage.package))),
    }
}

fn enumerate_installed(
    ecosystem: Ecosystem,
    package: &str,
    subpath: Option<&str>,
    node_modules: &Path,
    site_packages: &Path,
) -> ApiSurface {
    let outcome = match (ecosystem, subpath) {
        (Ecosystem::Npm, Some(sub)) => dts::enumerate_js_subpath(&node_modules.join(package), sub),
        (Ecosystem::Npm, None) => dts::enumerate_js(&node_modules.join(package)),
        // Python usage sites never carry a subpath (A8 handles submodule
        // usage as ordinary member access against the root surface
        // instead) — `subpath` is always `None` here.
        (Ecosystem::Pypi, _) => pysurface::enumerate_py(&site_packages.join(package)),
    };
    // A hard parse/grammar failure (a programming bug, never expected from
    // hostile third-party input — see SurfaceError's #[from] ScanError) is
    // treated the same as "could not determine": Unreadable, never a panic
    // and never silently promoted to Resolved.
    outcome.unwrap_or(ApiSurface {
        exported: BTreeSet::new(),
        tier: SurfaceTier::Unreadable,
    })
}

/// Collect every JS/TS/TSX and Python usage site under `root`'s project
/// source (never `node_modules`/`site-packages` — those are the surfaces
/// being checked against, not usage sites). Same skip-not-fail contract as
/// [`crate::scan::scan_path`]: grammar/query errors are programming bugs
/// and propagate; per-file read/parse trouble is collected, never fatal.
pub fn collect_usages(root: &Path) -> Result<(Vec<UsageSite>, Vec<ScanError>), ScanError> {
    let (mut sites, mut skipped) = dts::collect_js_usages(root)?;
    let (py_sites, py_skipped) = pysurface::collect_py_usages(root)?;
    sites.extend(py_sites);
    skipped.extend(py_skipped);
    Ok((sites, skipped))
}

/// Project-relative display path, forward slashes — mirrors
/// `deps::relative_display`/`env::plan`'s convention. Duplicated locally
/// (rather than imported) since `deps`'s copy is crate-private to that
/// module and this plan's file scope does not touch `deps/mod.rs`.
pub(crate) fn relative_display(path: &Path, root: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.to_string_lossy().replace('\\', "/")
}

// `dts::collect_js_usages`/`pysurface::collect_py_usages` walk *project*
// source, never the installed packages under `node_modules`/`site-packages`
// — those are the surfaces being checked against, and treating their own
// source as "usage sites" would be both semantically wrong and, on a real
// project, prohibitively slow to walk. This exclusion (plus `.venv`, `.git`,
// `dist`, `build`, `target`, ...) is now enforced uniformly by
// `crate::scan::project_walker` (A7) — both call sites build on it directly
// rather than layering a second, narrower `filter_entry` on top (which would
// silently replace, not compose with, the shared one; `ignore::WalkBuilder`
// stores at most one filter).

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::deps::ImportResolution;
    use std::path::PathBuf;

    fn graph_with(npm: &[&str], pypi: &[&str]) -> DependencyGraph {
        let mut declared = BTreeMap::new();
        declared.insert(
            Ecosystem::Npm,
            npm.iter().map(|s| (*s).to_owned()).collect(),
        );
        // Mirror deps::build_graph's real pipeline: the Pypi declared set
        // is always PEP 503-normalized before insertion (manifest_py.rs),
        // never the raw requirement-line spelling.
        declared.insert(
            Ecosystem::Pypi,
            pypi.iter().map(|s| normalize_pep503(s)).collect(),
        );
        DependencyGraph {
            declared,
            direct: BTreeMap::new(),
            imports: Vec::new(),
            unsupported_stack: None,
        }
    }

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-apisurface-test-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn relative_display_strips_root_and_normalizes_separators() {
        let root = Path::new("/proj");
        assert_eq!(
            relative_display(Path::new("/proj/src/a.ts"), root),
            "src/a.ts"
        );
    }

    #[test]
    fn collect_usages_combines_js_and_python_sites() {
        let dir = tempdir("collect-usages");
        std::fs::write(
            dir.join("a.ts"),
            "import { helper } from 'js-pkg';\nhelper();\n",
        )
        .unwrap();
        std::fs::write(dir.join("b.py"), "from json import dumps\ndumps({})\n").unwrap();

        let (usages, skipped) = collect_usages(&dir).unwrap();
        assert!(skipped.is_empty());
        let pairs: Vec<(&str, &str)> = usages
            .iter()
            .map(|u| (u.package.as_str(), u.member.as_str()))
            .collect();
        assert!(pairs.contains(&("js-pkg", "helper")));
        assert!(pairs.contains(&("json", "dumps")));
    }

    fn npm_usage(package: &str, member: &str, file: &str, line: u32) -> UsageSite {
        UsageSite {
            package: package.to_owned(),
            member: member.to_owned(),
            file: file.to_owned(),
            line,
            ecosystem: Ecosystem::Npm,
            subpath: None,
        }
    }

    fn py_usage(package: &str, member: &str, file: &str, line: u32) -> UsageSite {
        UsageSite {
            package: package.to_owned(),
            member: member.to_owned(),
            file: file.to_owned(),
            line,
            ecosystem: Ecosystem::Pypi,
            subpath: None,
        }
    }

    #[test]
    fn is_declared_checks_the_usages_own_ecosystem() {
        let graph = graph_with(&["left-pad"], &["requests"]);
        assert!(is_declared(&graph, &npm_usage("left-pad", "x", "a.js", 1)));
        assert!(is_declared(&graph, &py_usage("requests", "x", "a.py", 1)));
        assert!(!is_declared(
            &graph,
            &npm_usage("unknown-pkg", "x", "a.js", 1)
        ));
        // A14: a Python usage must never resolve against the npm declared
        // set, even if a same-named npm package happens to be declared too.
        assert!(!is_declared(&graph, &py_usage("left-pad", "x", "a.py", 1)));
    }

    #[test]
    fn is_declared_normalizes_pep503_for_pypi_lookup() {
        // declared_pypi is PEP 503-normalized ("typed-pkg"), but a Python
        // import statement uses the raw underscore module name
        // ("typed_pkg", matching the site-packages directory) — this must
        // still resolve as declared, not silently fail to match.
        let graph = graph_with(&[], &["typed-pkg"]);
        assert!(is_declared(&graph, &py_usage("typed_pkg", "x", "a.py", 1)));
    }

    #[test]
    fn check_resolved_miss_is_high_confidence_and_present_member_is_silent() {
        let dir = tempdir("resolved");
        let node_modules = dir.join("node_modules");
        let pkg_dir = node_modules.join("typed-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("package.json"), r#"{"types":"index.d.ts"}"#).unwrap();
        std::fs::write(
            pkg_dir.join("index.d.ts"),
            "export function realFn(): void;\n",
        )
        .unwrap();

        let graph = graph_with(&["typed-pkg"], &[]);
        let usages = vec![
            npm_usage("typed-pkg", "realFn", "src/a.ts", 1),
            npm_usage("typed-pkg", "fakeFn", "src/a.ts", 2),
        ];

        let results = check(&graph, &usages, &node_modules, &dir.join("site-packages"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].member, "fakeFn");
        assert_eq!(results[0].confidence, Confidence::High);
        assert_eq!(results[0].tier, SurfaceTier::Resolved);
        assert_eq!(results[0].kind, ApiResultKind::NonexistentApi);
        assert_eq!(results[0].usage_count, 1);
    }

    #[test]
    fn check_dynamic_package_never_yields_high_confidence() {
        let dir = tempdir("dynamic");
        let site_packages = dir.join("site-packages");
        let pkg_dir = site_packages.join("dynamic_pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("__init__.py"),
            "def __getattr__(name):\n    pass\n",
        )
        .unwrap();

        let graph = graph_with(&[], &["dynamic_pkg"]);
        let usages = vec![py_usage("dynamic_pkg", "anything", "main.py", 1)];

        let results = check(&graph, &usages, &dir.join("node_modules"), &site_packages);
        assert!(results.iter().all(|r| r.confidence != Confidence::High));
        // FP-budget guard: identical access pattern on a dynamic package
        // must never produce a High-confidence result at all.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].confidence, Confidence::Medium);
        assert_eq!(results[0].tier, SurfaceTier::Dynamic);
    }

    #[test]
    fn check_skips_undeclared_packages() {
        let dir = tempdir("undeclared");
        let graph = graph_with(&[], &[]);
        let usages = vec![npm_usage("not-declared", "x", "a.js", 1)];
        let results = check(
            &graph,
            &usages,
            &dir.join("node_modules"),
            &dir.join("site-packages"),
        );
        assert!(results.is_empty());
    }

    #[test]
    fn check_not_installed_package_aggregates_to_a_single_low_confidence_result() {
        // A3: a package with no directory at all under node_modules (a
        // fresh clone that never ran `npm install`) must never produce one
        // NonexistentApi per usage site — exactly one Info/Low result for
        // the whole package, regardless of how many usage sites exist.
        let dir = tempdir("not-installed");
        let node_modules = dir.join("node_modules"); // deliberately never created
        let graph = graph_with(&["never-installed-pkg"], &[]);
        let usages = vec![
            npm_usage("never-installed-pkg", "a", "src/a.ts", 1),
            npm_usage("never-installed-pkg", "b", "src/a.ts", 2),
            npm_usage("never-installed-pkg", "c", "src/b.ts", 1),
        ];

        let results = check(&graph, &usages, &node_modules, &dir.join("site-packages"));
        assert_eq!(
            results.len(),
            1,
            "expected exactly one aggregated result, got: {results:?}"
        );
        assert_eq!(results[0].confidence, Confidence::Low);
        assert_eq!(results[0].tier, SurfaceTier::NotInstalled);
        assert_eq!(results[0].usage_count, 3);
        assert!(results[0].detail.contains("not installed"));
    }

    // Sanity that ImportResolution import used in doc examples elsewhere
    // still compiles against this module's dependency on `crate::deps`.
    #[test]
    fn deps_types_are_reachable_from_apisurface() {
        let _ = ImportResolution::Phantom;
    }
}
