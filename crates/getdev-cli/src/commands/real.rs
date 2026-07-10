//! `getdev real` — verify packages/APIs/model strings actually exist
//! (docs/PLAN.md §2.3). Orchestrates: `core::deps` (declared+imported+
//! phantom) -> `getdev-registry` verdicts (rayon-batched, offline-aware) ->
//! `core::apisurface` (nonexistent/version-mismatch API) -> `core::models`
//! (unknown-model-string) -> unified `FindingsReport` -> render -> exit
//! code. **This is the only module allowed to call `getdev-registry`** —
//! `getdev-core::real`/`models` stay network-free (docs/ARCHITECTURE.md
//! network boundary). No mutation anywhere.

use std::io::IsTerminal;
use std::path::Path;

use rayon::prelude::*;

use getdev_core::apisurface::{self, ApiResult};
use getdev_core::deps::{self, DependencyGraph, Ecosystem as CoreEco};
use getdev_core::findings::{Finding, FindingsReport, ProjectInfo, Severity};
use getdev_core::models::ModelMatcher;
use getdev_core::real::{self, ExistenceLite, PackageVerdictInput, RealScope, TyposquatLite};
use getdev_core::report::{self, ColorMode};
use getdev_core::scan;
use getdev_registry::{
    Cache, Datasets, Ecosystem as RegEco, Existence, RegistryClient, RegistryVerdict, TyposquatHit,
    TyposquatReason,
};

pub struct RealArgs {
    pub path: std::path::PathBuf,
    pub json: bool,
    pub no_color: bool,
    pub fail_on: Option<Severity>,
    /// Never hit the network; use cache only (global flag, resolved once by
    /// `main` via `config::offline_resolved`).
    pub offline: bool,
    pub deps_only: bool,
    pub apis_only: bool,
    pub models_only: bool,
    /// Suppress banner/summary chatter; findings still render (global flag).
    pub quiet: bool,
    /// Debug-level detail, repeatable (global flag) — shows per-file skip
    /// reasons instead of just a count.
    pub verbose: u8,
}

pub fn run(args: &RealArgs) -> anyhow::Result<u8> {
    let only_count = [args.deps_only, args.apis_only, args.models_only]
        .iter()
        .filter(|&&only| only)
        .count();
    if only_count > 1 {
        anyhow::bail!("only one of --deps-only, --apis-only, --models-only may be given at a time");
    }
    let scope = if args.deps_only {
        RealScope {
            deps: true,
            apis: false,
            models: false,
        }
    } else if args.apis_only {
        RealScope {
            deps: false,
            apis: true,
            models: false,
        }
    } else if args.models_only {
        RealScope {
            deps: false,
            apis: false,
            models: true,
        }
    } else {
        RealScope::default()
    };

    // The dependency graph is always computed once — `apis` needs its
    // declared sets to know which ecosystem a used package belongs to, and
    // `unsupported_stack` must be surfaced regardless of scope.
    let (graph, deps_skipped) = deps::build_graph(&args.path)?;
    let mut skipped: Vec<String> = deps_skipped.iter().map(ToString::to_string).collect();

    let mut findings = Vec::new();

    if scope.deps {
        run_deps_group(&graph, args.offline, &mut findings)?;
    }
    if scope.apis {
        let apis_skipped = run_apis_group(&graph, &args.path, &mut findings)?;
        skipped.extend(apis_skipped.into_iter().map(|e| e.to_string()));
    }
    if scope.models {
        let models_skipped = run_models_group(&args.path, &mut findings)?;
        skipped.extend(models_skipped.into_iter().map(|e| e.to_string()));
    }
    if let Some(hint) = &graph.unsupported_stack {
        findings.push(real::unsupported_stack_finding(hint));
    }

    let report = FindingsReport::new(
        env!("CARGO_PKG_VERSION"),
        ProjectInfo {
            path: display_path(&args.path),
            stack: Vec::new(),
        },
        findings,
    );

    if args.json {
        print!("{}", report::render_json(&report)?);
    } else {
        let color = ColorMode::resolve(args.no_color, std::io::stdout().is_terminal());
        print!("{}", report::render_terminal(&report, color));
        if !skipped.is_empty() {
            if args.verbose > 0 {
                println!("{} unreadable file(s) skipped:", skipped.len());
                for reason in &skipped {
                    println!("  - {reason}");
                }
            } else if !args.quiet {
                println!(
                    "{} unreadable file(s) skipped (-v for details)",
                    skipped.len()
                );
            }
        }
    }

    let failed = args
        .fail_on
        .is_some_and(|threshold| report.summary.at_or_above(threshold) > 0);
    Ok(u8::from(failed))
}

/// `real/nonexistent-package` + `real/typosquat-suspect` +
/// `real/phantom-import`. Every registry call is confined to this function
/// (and its rayon-batched closure below) — the sole network egress point of
/// the whole `real` pipeline.
fn run_deps_group(
    graph: &DependencyGraph,
    offline: bool,
    findings: &mut Vec<Finding>,
) -> anyhow::Result<()> {
    let cache = Cache::open()?;
    let datasets = Datasets::embedded()?;
    let client = RegistryClient::new(offline)?;

    let mut names: Vec<(CoreEco, String)> = Vec::new();
    for (eco, set) in &graph.declared {
        for name in set {
            names.push((*eco, name.clone()));
        }
    }

    // Single mutex-guarded `Cache`/`RegistryClient` shared by reference
    // across rayon threads — never one SQLite connection per thread
    // (03-RESEARCH.md Pitfall 4).
    let verdicts: Vec<(CoreEco, String, RegistryVerdict)> = names
        .par_iter()
        .map(|(eco, name)| {
            let verdict = client
                .verify_full(&cache, &datasets, to_registry_eco(*eco), name)
                .unwrap_or(RegistryVerdict {
                    existence: Existence::Inconclusive,
                    downloads: None,
                    created_at: None,
                    typosquat: None,
                });
            (*eco, name.clone(), verdict)
        })
        .collect();

    for (eco, name, verdict) in verdicts {
        let import_site = graph.imports.iter().find(|imp| {
            imp.ecosystem == eco
                && match eco {
                    CoreEco::Npm => imp.module == name,
                    CoreEco::Pypi => deps::normalize_pep503(&imp.module) == name,
                }
        });
        let (file, line) = match import_site {
            Some(imp) => (imp.file.clone(), Some(imp.line)),
            None => (default_manifest_file(eco).to_owned(), None),
        };
        let input = PackageVerdictInput {
            ecosystem: eco_label(eco).to_owned(),
            name: name.clone(),
            file,
            line,
            existence: to_existence_lite(verdict.existence),
            downloads: verdict.downloads,
            created_at: verdict.created_at,
            typosquat: verdict.typosquat.map(to_typosquat_lite),
            declared: true,
            imported: import_site.is_some(),
        };
        if let Some(finding) = real::nonexistent_package_finding(&input) {
            findings.push(finding);
        }
        if let Some(finding) = real::typosquat_finding(&input) {
            findings.push(finding);
        }
    }

    for import_ref in &graph.imports {
        if let Some(finding) = real::phantom_import_finding(import_ref) {
            findings.push(finding);
        }
    }

    Ok(())
}

/// `real/nonexistent-api` + `real/version-mismatch-api`. No network,
/// no code execution — pure static introspection of files already on disk.
fn run_apis_group(
    graph: &DependencyGraph,
    root: &Path,
    findings: &mut Vec<Finding>,
) -> anyhow::Result<Vec<getdev_core::scan::ScanError>> {
    let (usages, skipped) = apisurface::collect_usages(root)?;
    let node_modules = root.join("node_modules");
    let site_packages = root.join("site-packages");
    let results: Vec<ApiResult> = apisurface::check(graph, &usages, &node_modules, &site_packages);
    findings.extend(real::api_findings(&results));
    Ok(skipped)
}

/// `real/unknown-model-string`. Reuses the same string-literal collection
/// `env`/`audit` build on; the model call-site gating + family-prefix
/// matching lives in `core::models`.
fn run_models_group(
    root: &Path,
    findings: &mut Vec<Finding>,
) -> anyhow::Result<Vec<getdev_core::scan::ScanError>> {
    let matcher = ModelMatcher::embedded()?;
    let (assignments, skipped) = scan::collect_string_assignments(root)?;
    for assignment in assignments {
        if let Some(verdict) = matcher.classify_model(&assignment.value, &assignment.name) {
            let file = relative_display(&assignment.path, root);
            findings.push(real::unknown_model_finding(
                &verdict,
                &file,
                Some(assignment.line),
            ));
        }
    }
    Ok(skipped)
}

fn to_registry_eco(eco: CoreEco) -> RegEco {
    match eco {
        CoreEco::Npm => RegEco::Npm,
        CoreEco::Pypi => RegEco::Pypi,
    }
}

fn eco_label(eco: CoreEco) -> &'static str {
    match eco {
        CoreEco::Npm => "npm",
        CoreEco::Pypi => "pypi",
    }
}

fn default_manifest_file(eco: CoreEco) -> &'static str {
    match eco {
        CoreEco::Npm => "package.json",
        CoreEco::Pypi => "requirements.txt",
    }
}

fn to_existence_lite(existence: Existence) -> ExistenceLite {
    match existence {
        Existence::Found => ExistenceLite::Found,
        Existence::Missing => ExistenceLite::Missing,
        Existence::Inconclusive => ExistenceLite::Inconclusive,
    }
}

fn to_typosquat_lite(hit: TyposquatHit) -> TyposquatLite {
    TyposquatLite {
        nearest: hit.nearest,
        distance: hit.distance,
        reasons: hit
            .reasons
            .into_iter()
            .map(typosquat_reason_label)
            .collect(),
    }
}

fn typosquat_reason_label(reason: TyposquatReason) -> String {
    match reason {
        TyposquatReason::NearName => "name closely resembles a popular package".to_owned(),
        TyposquatReason::LowDownloads => "low download count".to_owned(),
        TyposquatReason::NewPackage => "package created less than 90 days ago".to_owned(),
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn relative_display(path: &Path, root: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.to_string_lossy().replace('\\', "/")
}
