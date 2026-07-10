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
    pub member: String,
    pub file: String,
    pub line: u32,
    pub confidence: Confidence,
    /// Heuristic reasoning surfaced to the user (FP policy, docs/PLAN.md
    /// §9.2) — always populated, explains *why* at low confidence.
    pub detail: String,
}

/// Compare every usage site's `pkg.member` access against the installed
/// package's statically enumerated surface and emit confidence-tiered
/// results. Surfaces are cached per package (an installed package is
/// enumerated at most once per `check` call regardless of usage count).
///
/// `graph` determines which ecosystem (`Npm`/`Pypi`) a used package belongs
/// to, so `check` knows whether to look under `node_modules` or
/// `site_packages`; a package usage that matches neither declared set is
/// skipped (it is `deps`'s job to have already classified it as
/// `Phantom`/`Builtin`/`Local` — `apisurface` only judges packages that are
/// genuinely installed dependencies).
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
    let mut cache: BTreeMap<String, ApiSurface> = BTreeMap::new();
    let mut results = Vec::new();

    for usage in usages {
        let Some(ecosystem) = ecosystem_of(graph, &usage.package) else {
            continue;
        };

        let surface = cache.entry(usage.package.clone()).or_insert_with(|| {
            enumerate_installed(ecosystem, &usage.package, node_modules, site_packages)
        });

        if surface.exported.contains(&usage.member) {
            continue; // confirmed present — never a finding, regardless of tier
        }

        let (confidence, detail) = match surface.tier {
            SurfaceTier::Resolved => (
                Confidence::High,
                format!(
                    "'{}' is not present in {}'s statically enumerated exports",
                    usage.member, usage.package
                ),
            ),
            SurfaceTier::Dynamic => (
                Confidence::Low,
                format!(
                    "{}'s surface could not be fully resolved statically (dynamic export, \
                     ambient wildcard, or unresolvable re-export) — '{}' may exist but was \
                     not discoverable without executing code",
                    usage.package, usage.member
                ),
            ),
            SurfaceTier::Unreadable => (
                Confidence::Low,
                format!(
                    "no readable source/types were found for {} — '{}' could not be verified \
                     without executing code",
                    usage.package, usage.member
                ),
            ),
        };

        results.push(ApiResult {
            kind: ApiResultKind::NonexistentApi,
            package: usage.package.clone(),
            member: usage.member.clone(),
            file: usage.file.clone(),
            line: usage.line,
            confidence,
            detail,
        });
    }

    results
}

/// Determine which ecosystem a used package name belongs to from the
/// dependency graph's declared sets. A name declared in neither set is not
/// a package `apisurface` should judge (that's `deps::ImportResolution`'s
/// job upstream).
///
/// The `Pypi` declared set is PEP 503-normalized at graph-construction time
/// (`deps::normalize_pep503`: lowercase, runs of `-`/`_`/`.` collapse to a
/// single `-`), but a Python `import`/`from` statement's module name is the
/// raw underscore-form identifier (matching the `site-packages/<pkg>`
/// directory name, e.g. `typed_pkg`) — so the usage-side name must be
/// normalized the same way before membership is checked, or every
/// underscore-named PyPI package would silently never match.
fn ecosystem_of(graph: &DependencyGraph, package: &str) -> Option<Ecosystem> {
    if graph
        .declared
        .get(&Ecosystem::Npm)
        .is_some_and(|set| set.contains(package))
    {
        return Some(Ecosystem::Npm);
    }
    if graph
        .declared
        .get(&Ecosystem::Pypi)
        .is_some_and(|set| set.contains(&normalize_pep503(package)))
    {
        return Some(Ecosystem::Pypi);
    }
    None
}

fn enumerate_installed(
    ecosystem: Ecosystem,
    package: &str,
    node_modules: &Path,
    site_packages: &Path,
) -> ApiSurface {
    let outcome = match ecosystem {
        Ecosystem::Npm => dts::enumerate_js(&node_modules.join(package)),
        Ecosystem::Pypi => pysurface::enumerate_py(&site_packages.join(package)),
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

/// `WalkBuilder::filter_entry` predicate shared by `dts::collect_js_usages`
/// and `pysurface::collect_py_usages`: usage extraction walks *project*
/// source, never the installed packages under `node_modules`/
/// `site-packages` — those are the surfaces being checked against, and
/// treating their own source as "usage sites" would be both semantically
/// wrong and, on a real project, prohibitively slow to walk.
pub(crate) fn is_not_installed_package_dir(entry: &ignore::DirEntry) -> bool {
    !matches!(
        entry.file_name().to_str(),
        Some("node_modules" | "site-packages")
    )
}

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

    #[test]
    fn ecosystem_of_prefers_declared_set_membership() {
        let graph = graph_with(&["left-pad"], &["requests"]);
        assert_eq!(ecosystem_of(&graph, "left-pad"), Some(Ecosystem::Npm));
        assert_eq!(ecosystem_of(&graph, "requests"), Some(Ecosystem::Pypi));
        assert_eq!(ecosystem_of(&graph, "unknown-pkg"), None);
    }

    #[test]
    fn ecosystem_of_normalizes_pep503_for_pypi_lookup() {
        // declared_pypi is PEP 503-normalized ("typed-pkg"), but a Python
        // import statement uses the raw underscore module name
        // ("typed_pkg", matching the site-packages directory) — this must
        // still resolve to Pypi, not silently fail to match.
        let graph = graph_with(&[], &["typed-pkg"]);
        assert_eq!(ecosystem_of(&graph, "typed_pkg"), Some(Ecosystem::Pypi));
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
            UsageSite {
                package: "typed-pkg".to_owned(),
                member: "realFn".to_owned(),
                file: "src/a.ts".to_owned(),
                line: 1,
            },
            UsageSite {
                package: "typed-pkg".to_owned(),
                member: "fakeFn".to_owned(),
                file: "src/a.ts".to_owned(),
                line: 2,
            },
        ];

        let results = check(&graph, &usages, &node_modules, &dir.join("site-packages"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].member, "fakeFn");
        assert_eq!(results[0].confidence, Confidence::High);
        assert_eq!(results[0].kind, ApiResultKind::NonexistentApi);
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
        let usages = vec![UsageSite {
            package: "dynamic_pkg".to_owned(),
            member: "anything".to_owned(),
            file: "main.py".to_owned(),
            line: 1,
        }];

        let results = check(&graph, &usages, &dir.join("node_modules"), &site_packages);
        assert!(results.iter().all(|r| r.confidence != Confidence::High));
        // FP-budget guard: identical access pattern on a dynamic package
        // must never produce a High-confidence result at all.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].confidence, Confidence::Low);
    }

    #[test]
    fn check_skips_undeclared_packages() {
        let dir = tempdir("undeclared");
        let graph = graph_with(&[], &[]);
        let usages = vec![UsageSite {
            package: "not-declared".to_owned(),
            member: "x".to_owned(),
            file: "a.js".to_owned(),
            line: 1,
        }];
        let results = check(
            &graph,
            &usages,
            &dir.join("node_modules"),
            &dir.join("site-packages"),
        );
        assert!(results.is_empty());
    }

    // Sanity that ImportResolution import used in doc examples elsewhere
    // still compiles against this module's dependency on `crate::deps`.
    #[test]
    fn deps_types_are_reachable_from_apisurface() {
        let _ = ImportResolution::Phantom;
    }
}
