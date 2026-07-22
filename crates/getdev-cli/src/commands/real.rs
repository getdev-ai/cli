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

use getdev_core::apisurface::{self, ApiResult, UsageSite};
use getdev_core::config::Config;
use getdev_core::deps::{self, DependencyGraph, Ecosystem as CoreEco};
use getdev_core::findings::{Finding, FindingsReport, ProjectInfo, Severity};
use getdev_core::models::ModelMatcher;
use getdev_core::real::{self, ExistenceLite, PackageVerdictInput, RealScope, TyposquatLite};
use getdev_core::report::{self, ColorMode};
use getdev_core::scan::{self, ScanContext, ScanError, StringAssignment};
use getdev_core::suppress;
use getdev_registry::{
    Cache, Datasets, Ecosystem as RegEco, Existence, RegistryClient, RegistryError,
    RegistryVerdict, Sensitivity, TyposquatHit, TyposquatReason,
};

pub struct RealArgs {
    pub path: std::path::PathBuf,
    pub json: bool,
    /// Write the full JSON report here; terminal keeps a short summary (global flag).
    pub output: Option<std::path::PathBuf>,
    pub no_color: bool,
    pub fail_on: Option<Severity>,
    /// Never hit the network; use cache only (global flag, resolved once by
    /// `main` via `config::offline_resolved`).
    pub offline: bool,
    pub deps_only: bool,
    pub apis_only: bool,
    pub models_only: bool,
    /// `[real].check_apis` (B2 audit fix) — when `false`, the apis group is
    /// skipped for the default (no `--*-only`) scope. `--apis-only`
    /// overrides this (an explicit flag beats config, per
    /// docs/SPEC-CONFIG.md's flags > config precedence).
    pub check_apis: bool,
    /// `[real].typosquat_sensitivity` (B2 audit fix) — "strict" | "normal" |
    /// "off", parsed by `getdev_registry::typosquat::Sensitivity::parse`.
    pub typosquat_sensitivity: String,
    /// Resolved config (B2 audit fix) — `[ignore]`/`[[suppress]]` filtering.
    pub cfg: Config,
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
    // B2: `[real].check_apis = false` skips the apis group for the default
    // scope; an explicit `--apis-only` still wins (flags > config,
    // docs/SPEC-CONFIG.md precedence).
    let scope = RealScope {
        apis: scope.apis && (args.check_apis || args.apis_only),
        ..scope
    };
    let sensitivity = Sensitivity::parse(&args.typosquat_sensitivity);

    // Interactive-only stderr spinner (auto-suppressed under --json/-o/--quiet/
    // non-TTY); torn down before any report renders to stdout.
    let show_progress = !args.json && !args.quiet && args.output.is_none();
    let progress =
        crate::progress::Progress::start(show_progress, args.no_color, "resolving dependencies…");

    // The dependency graph is always computed once — `apis` needs its
    // declared sets to know which ecosystem a used package belongs to, and
    // `unsupported_stack` must be surfaced regardless of scope.
    let (graph, deps_skipped) = deps::build_graph(&args.path)?;
    progress.phase(if args.offline {
        "checking packages, APIs & models (offline)…"
    } else {
        "checking packages against registries…"
    });
    let mut skip_errors: Vec<getdev_core::scan::ScanError> = deps_skipped;

    let mut findings = Vec::new();

    if scope.deps {
        run_deps_group(&graph, args.offline, sensitivity, &mut findings)?;
    }
    if scope.apis {
        let apis_skipped = run_apis_group(&graph, &args.path, &mut findings)?;
        skip_errors.extend(apis_skipped);
    }
    if scope.models {
        let models_skipped = run_models_group(&args.path, &mut findings)?;
        skip_errors.extend(models_skipped);
    }
    if let Some(hint) = &graph.unsupported_stack {
        findings.push(real::unsupported_stack_finding(hint));
    }

    // B2(b): `[ignore] rules`/`paths` and `[[suppress]]` actually filter now.
    let filter_outcome = suppress::filter_findings(findings, &args.cfg);
    let findings = filter_outcome.kept;

    let skipped: Vec<String> = skip_errors.iter().map(ToString::to_string).collect();

    let mut report = FindingsReport::new(
        env!("CARGO_PKG_VERSION"),
        ProjectInfo {
            path: display_path(&args.path),
            stack: Vec::new(),
        },
        findings,
    );
    // F4: skip-list surfaced in --json too (previously terminal-only).
    report.skipped = skip_errors
        .iter()
        .map(|e| getdev_core::findings::SkippedEntry {
            path: e.path().map(|p| p.display().to_string()),
            reason: e.to_string(),
        })
        .collect();

    progress.finish();

    if let Some(out_path) = args.output.as_deref() {
        super::emit_report_file(&report, out_path, args.json, args.no_color)?;
    } else if args.json {
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
        if !filter_outcome.suppressed.is_empty() {
            if args.verbose > 0 {
                println!(
                    "{} finding(s) suppressed by config:",
                    filter_outcome.suppressed.len()
                );
                for s in &filter_outcome.suppressed {
                    println!(
                        "  - {} {} — {}",
                        s.finding.id,
                        s.finding.file,
                        s.reason.describe()
                    );
                }
            } else if !args.quiet {
                println!(
                    "{} finding(s) suppressed by config (-v for details)",
                    filter_outcome.suppressed.len()
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
    sensitivity: Sensitivity,
    findings: &mut Vec<Finding>,
) -> anyhow::Result<()> {
    let cache = Cache::open()?;
    let datasets = Datasets::embedded()?;
    let client = RegistryClient::new(offline)?;

    // A15: the registry lookup set is declared UNION imported (bare
    // package name, non-stdlib/non-local) — an import that resolves to
    // `Phantom` (declared nowhere, not a builtin, not local) is exactly
    // that: undeclared but still worth a nonexistent-package/typosquat
    // registry check ("did you mean the package you forgot to
    // declare?"), not just a `real/phantom-import` finding.
    //
    // F5: `bool` tracks whether the name is direct/manifest-declared (or
    // came from an import — a bare import IS the direct signal of use) as
    // opposed to a lockfile-only transitive. EXISTENCE checks below always
    // run for every name in this list; typosquat SCORING is scoped to
    // direct names only by forcing `Sensitivity::Off` for transitives.
    let mut names: Vec<(CoreEco, String, bool)> = Vec::new();
    let mut seen: std::collections::HashSet<(CoreEco, String)> = std::collections::HashSet::new();
    for (eco, set) in &graph.declared {
        let direct_set = graph.direct.get(eco);
        for name in set {
            if seen.insert((*eco, name.clone())) {
                let is_direct = direct_set.is_some_and(|d| d.contains(name));
                names.push((*eco, name.clone(), is_direct));
            }
        }
    }
    for import_ref in &graph.imports {
        if import_ref.resolution != deps::ImportResolution::Phantom {
            continue;
        }
        let key = match import_ref.ecosystem {
            CoreEco::Npm => import_ref.module.clone(),
            CoreEco::Pypi => deps::normalize_pep503(&import_ref.module),
        };
        if seen.insert((import_ref.ecosystem, key.clone())) {
            // An import site is itself the direct signal of use — always
            // scored regardless of manifest/lockfile membership.
            names.push((import_ref.ecosystem, key, true));
        }
    }

    // Single mutex-guarded `Cache`/`RegistryClient` shared by reference
    // across rayon threads — never one SQLite connection per thread
    // (03-RESEARCH.md Pitfall 4).
    let verdicts: Vec<(CoreEco, String, RegistryVerdict)> = names
        .par_iter()
        .map(|(eco, name, is_direct)| {
            // F5: a lockfile-only transitive never gets typosquat-scored,
            // regardless of the configured `[real].typosquat_sensitivity`
            // — only its existence is checked. Reuses the existing `Off`
            // semantics rather than adding a second code path.
            let name_sensitivity = if *is_direct {
                sensitivity
            } else {
                Sensitivity::Off
            };
            match client.verify_full_with_sensitivity(
                &cache,
                &datasets,
                to_registry_eco(*eco),
                name,
                name_sensitivity,
            ) {
                Ok(verdict) => Ok((*eco, name.clone(), verdict)),
                // W4: a genuine infrastructure failure (corrupt registry
                // cache, failed http-client build) must NOT be swallowed
                // into a falsely "clean" exit-0 run — that hides a broken
                // environment and reports trust it hasn't earned. Surface it
                // as an execution error (docs/PLAN.md §2.2 exit code 2).
                Err(err) if is_infra_failure(&err) => Err(err),
                // An offline lookup or a transient network error is
                // expected-inconclusive — never proof a package is missing
                // (03-RESEARCH.md Anti-Patterns) — so it resolves to
                // Inconclusive and the run continues.
                Err(_) => Ok((
                    *eco,
                    name.clone(),
                    RegistryVerdict {
                        existence: Existence::Inconclusive,
                        downloads: None,
                        created_at: None,
                        typosquat: None,
                    },
                )),
            }
        })
        .collect::<Result<Vec<_>, RegistryError>>()?;

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
            // Declared but never imported: report the actual manifest that
            // declared it (root-relative — resolvable by monorepo triage and
            // `[ignore] paths` prefixes alike). The bare-basename default only
            // survives as a last resort for lockfile dialects that predate
            // `declared_in` tracking.
            None => (
                graph
                    .declared_in
                    .get(&eco)
                    .and_then(|origins| origins.get(&name))
                    .cloned()
                    .unwrap_or_else(|| default_manifest_file(eco).to_owned()),
                None,
            ),
        };
        // A15: `declared` reflects actual manifest membership now, not a
        // hardcoded `true` — a Phantom-resolution import added to `names`
        // above was never declared, and `nonexistent_package_finding`'s
        // `where_found` wording ("imported" vs. "declared in the
        // manifest") depends on this being accurate.
        let declared = graph
            .declared
            .get(&eco)
            .is_some_and(|set| set.contains(&name));
        let input = PackageVerdictInput {
            ecosystem: eco_label(eco).to_owned(),
            name: name.clone(),
            file,
            line,
            existence: to_existence_lite(verdict.existence),
            downloads: verdict.downloads,
            created_at: verdict.created_at,
            typosquat: verdict.typosquat.map(to_typosquat_lite),
            declared,
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
/// Standalone entry: walks the project itself for usage sites. `check` (07-04)
/// uses [`run_apis_group_with_context`] to reuse its shared parse-once context.
fn run_apis_group(
    graph: &DependencyGraph,
    root: &Path,
    findings: &mut Vec<Finding>,
) -> anyhow::Result<Vec<ScanError>> {
    let (usages, skipped) = apisurface::collect_usages(root)?;
    apis_findings_from_usages(graph, &usages, root, findings);
    Ok(skipped)
}

/// [`run_apis_group`] over a caller-provided parse-once [`ScanContext`] — the
/// path `check` uses so API-usage collection reuses check's single shared scan
/// instead of walking the project a second time (CLAUDE.md rule 5). The
/// context's own source skips live in `ctx.skipped`, surfaced by its owner, so
/// this returns nothing extra.
fn run_apis_group_with_context(
    graph: &DependencyGraph,
    ctx: &ScanContext,
    root: &Path,
    findings: &mut Vec<Finding>,
) {
    let usages = apisurface::collect_usages_with_context(ctx);
    apis_findings_from_usages(graph, &usages, root, findings);
}

/// Shared tail of both apis entries: introspect *installed* packages
/// (`node_modules`/`site-packages`) against the collected usage sites and turn
/// the results into findings. Factored out so the walking and shared-context
/// paths produce identical API findings (one code path, never two).
fn apis_findings_from_usages(
    graph: &DependencyGraph,
    usages: &[UsageSite],
    root: &Path,
    findings: &mut Vec<Finding>,
) {
    let node_modules = root.join("node_modules");
    let site_packages = resolve_site_packages(root);
    let results: Vec<ApiResult> = apisurface::check(graph, usages, &node_modules, &site_packages);
    findings.extend(real::api_findings(&results));
}

/// A1: resolve the real installed Python `site-packages` directory instead
/// of the fictional literal `<root>/site-packages` — on every real Python
/// project (venv-based, which is the overwhelming majority) that literal
/// path never exists, so every package silently enumerated as
/// `Unreadable`/`NotInstalled`. Resolution order:
/// 1. `$VIRTUAL_ENV/lib/python*/site-packages` (Windows: `Lib/site-packages`)
///    if the `VIRTUAL_ENV` environment variable is set (an activated venv).
/// 2. `<root>/.venv|venv|env/lib/python*/site-packages` (same Windows
///    layout checked too) — an unactivated but project-local venv.
/// 3. `<root>/site-packages` — the literal fallback, kept so the corpus
///    fixtures (which seed a flat `site-packages/` at project root) keep
///    passing; on a real project this path simply won't exist, which
///    resolves every package to `NotInstalled` (A3) rather than fabricating
///    a `Missing member` wall.
fn resolve_site_packages(root: &Path) -> std::path::PathBuf {
    if let Ok(venv) = std::env::var("VIRTUAL_ENV") {
        let venv_path = std::path::PathBuf::from(venv);
        if let Some(site_packages) = find_venv_site_packages(&venv_path) {
            return site_packages;
        }
    }
    for candidate in [".venv", "venv", "env"] {
        let venv_path = root.join(candidate);
        if venv_path.is_dir() {
            if let Some(site_packages) = find_venv_site_packages(&venv_path) {
                return site_packages;
            }
        }
    }
    root.join("site-packages")
}

/// Locate a venv root's `site-packages` directory: the POSIX layout
/// (`lib/pythonX.Y/site-packages` — the Python minor version directory is
/// globbed since it varies per interpreter) or the Windows layout
/// (`Lib/site-packages`, no per-version subdirectory).
fn find_venv_site_packages(venv_root: &Path) -> Option<std::path::PathBuf> {
    let windows_layout = venv_root.join("Lib").join("site-packages");
    if windows_layout.is_dir() {
        return Some(windows_layout);
    }

    let lib_dir = venv_root.join("lib");
    let mut python_dirs: Vec<std::path::PathBuf> = std::fs::read_dir(&lib_dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("python"))
        })
        .collect();
    // Deterministic + prefers the newest interpreter directory when a venv
    // somehow has more than one (shouldn't normally happen, but never
    // arbitrary iteration-order dependent).
    python_dirs.sort();
    python_dirs.into_iter().rev().find_map(|python_dir| {
        let site_packages = python_dir.join("site-packages");
        site_packages.is_dir().then_some(site_packages)
    })
}

/// `real/unknown-model-string`. Reuses the same string-literal collection
/// `env`/`audit` build on; the model call-site gating + family-prefix
/// matching lives in `core::models`.
fn run_models_group(root: &Path, findings: &mut Vec<Finding>) -> anyhow::Result<Vec<ScanError>> {
    let matcher = ModelMatcher::embedded()?;
    let (assignments, skipped) = scan::collect_string_assignments(root)?;
    model_findings_from_assignments(&matcher, &assignments, root, findings);
    Ok(skipped)
}

/// [`run_models_group`] over a caller-provided parse-once [`ScanContext`] — the
/// path `check` uses so the model-string matcher reuses check's single shared
/// scan (string literals from cached trees) instead of walking again.
fn run_models_group_with_context(
    ctx: &ScanContext,
    root: &Path,
    findings: &mut Vec<Finding>,
) -> anyhow::Result<()> {
    let matcher = ModelMatcher::embedded()?;
    let assignments = scan::string_assignments_from_context(ctx);
    model_findings_from_assignments(&matcher, &assignments, root, findings);
    Ok(())
}

/// Shared body of both model entries: classify each string literal against the
/// embedded model dataset and emit `real/unknown-model-string` findings.
fn model_findings_from_assignments(
    matcher: &ModelMatcher,
    assignments: &[StringAssignment],
    root: &Path,
    findings: &mut Vec<Finding>,
) {
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
}

/// The full `real` analysis over a caller-provided parse-once
/// [`ScanContext`] — the aggregation entry `check` (07-04) consumes so
/// `real`'s deps/registry + apis + model-string checks run over check's ONE
/// shared scan (no second walk/parse; CLAUDE.md rule 5 / Phase 7 Success
/// Criterion 1). The dependency `graph` is built by the caller via
/// [`deps::build_graph_with_context`] over the same context. This is the SOLE
/// network path check reuses — every registry call is confined to
/// [`run_deps_group`], honoring `offline` (cache-only) exactly as standalone
/// `real` does; check adds no new call site. Skips are NOT returned here: the
/// context's source read/parse skips live in `ctx.skipped`, surfaced once by
/// check (no double-count — the ownership split 07-02/07-03 established).
pub(crate) fn collect_real_findings(
    ctx: &ScanContext,
    graph: &DependencyGraph,
    root: &Path,
    offline: bool,
    typosquat_sensitivity: &str,
    check_apis: bool,
) -> anyhow::Result<Vec<Finding>> {
    // Parse the typosquat sensitivity HERE (inside the sole registry-aware
    // module) so `check` never has to name a `getdev_registry` type — the
    // registry boundary stays confined to `real` (CLAUDE.md / ARCHITECTURE.md).
    let sensitivity = Sensitivity::parse(typosquat_sensitivity);
    let mut findings = Vec::new();
    // deps + registry verdicts (the only network; cache-only under --offline).
    run_deps_group(graph, offline, sensitivity, &mut findings)?;
    // apis: gated by `[real].check_apis` exactly like standalone real's default
    // scope (an installed-package introspection, no network, no execution).
    if check_apis {
        run_apis_group_with_context(graph, ctx, root, &mut findings);
    }
    // model strings (embedded dataset; --offline uses the embedded copy).
    run_models_group_with_context(ctx, root, &mut findings)?;
    // `unsupported-stack` is surfaced regardless of scope (matches real::run).
    if let Some(hint) = &graph.unsupported_stack {
        findings.push(real::unsupported_stack_finding(hint));
    }
    Ok(findings)
}

/// W4: distinguish a genuine infrastructure failure — which must surface as
/// an execution error, never a falsely "clean" exit-0 — from an
/// expected/benign inconclusive lookup. A corrupt registry cache
/// ([`RegistryError::Cache`]) or a failed http-client build
/// ([`RegistryError::Client`]) is the former; an offline lookup or a
/// transient network error is the latter (safely mapped to `Inconclusive`,
/// since a 5xx/timeout is never proof a package does not exist).
fn is_infra_failure(err: &RegistryError) -> bool {
    matches!(err, RegistryError::Cache(_) | RegistryError::Client { .. })
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

#[cfg(test)]
mod tests {
    use getdev_registry::{CacheError, RegistryError};

    use super::is_infra_failure;

    #[test]
    fn cache_and_client_errors_are_infra_failures_not_silent_clean() {
        // W4: a corrupt registry cache (or a failed http-client build) is a
        // genuine infra failure — `is_infra_failure` returns `true`, so the
        // `?` in `run_deps_group` propagates it as an execution error rather
        // than swallowing it into a falsely clean exit-0 run.
        let cache_err = RegistryError::Cache(CacheError::Io {
            path: std::path::PathBuf::from("/nonexistent/cache"),
            source: std::io::Error::other("corrupt cache"),
        });
        assert!(
            is_infra_failure(&cache_err),
            "a cache error must surface, never report clean"
        );

        let client_err = RegistryError::Client {
            message: "tls backend failed to initialize".to_owned(),
        };
        assert!(is_infra_failure(&client_err));
    }

    #[test]
    fn offline_and_transient_network_errors_are_benign_inconclusive() {
        // These are NOT infra failures — a lookup that couldn't be confirmed
        // (offline, 5xx, timeout, oversized body) is never proof a package
        // is missing, so it resolves to Inconclusive and the run continues.
        let url = || "https://registry.npmjs.org/foo".to_owned();
        assert!(!is_infra_failure(&RegistryError::Offline { url: url() }));
        assert!(!is_infra_failure(&RegistryError::Http {
            url: url(),
            message: "503".to_owned(),
        }));
        assert!(!is_infra_failure(&RegistryError::Exhausted { url: url() }));
        assert!(!is_infra_failure(&RegistryError::Body {
            url: url(),
            limit: 1024,
        }));
    }
}
