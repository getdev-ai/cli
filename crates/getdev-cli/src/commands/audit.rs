//! `getdev audit` — a thin clap subcommand that loads the embedded rule
//! pack (optionally merging a `--rules <dir>` user pack), detects
//! frameworks, runs `core::audit::run`, filters by `--severity`/`--ignore`
//! through the existing `suppress`/severity machinery, renders via the
//! existing report renderers, and returns the exit-code contract. Mirrors
//! `commands::real`'s shape MINUS any registry crate — audit is fully
//! offline. **This module imports NO `getdev_registry` type and makes no
//! network call** (REQ-privacy); it never mutates (REQ-safe-by-default; no
//! `core::mutate` involvement).

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use getdev_core::audit::{self, AuditOptions};
use getdev_core::config::Config;
use getdev_core::deps;
use getdev_core::findings::{FindingsReport, ProjectInfo, Severity, SkippedEntry};
use getdev_core::frameworks;
use getdev_core::report::{self, ColorMode};
use getdev_core::rules;
use getdev_core::suppress;

pub struct AuditArgs {
    pub path: PathBuf,
    pub json: bool,
    pub no_color: bool,
    pub fail_on: Option<Severity>,
    /// `--severity <min>` else `[audit] severity_min` (resolved by `main`
    /// before this struct is built).
    pub severity_min: Severity,
    /// `--ignore <rule-id>`, repeatable — merged into `cfg.ignore.rules`
    /// before `suppress::filter_findings` runs.
    pub ignore: Vec<String>,
    /// `--rules <dir>` — a declarative-only user pack merged over the
    /// embedded pack (T-4-15: identical load/validate/compile path as the
    /// embedded pack, never executable).
    pub rules_dir: Option<PathBuf>,
    /// Resolved config — `[ignore]`/`[[suppress]]` filtering.
    pub cfg: Config,
    /// Suppress banner/summary chatter; findings still render (global flag).
    pub quiet: bool,
    /// Debug-level detail, repeatable (global flag) — shows per-file skip
    /// reasons instead of just a count.
    pub verbose: u8,
}

pub fn run(args: &AuditArgs) -> anyhow::Result<u8> {
    // The dependency graph is only needed for framework detection here
    // (unlike `real`, which also uses it for registry lookups) — its own
    // skip errors still get surfaced in `--json`/`-v`.
    let (graph, deps_skipped) = deps::build_graph(&args.path)?;
    let mut skip_errors: Vec<getdev_core::scan::ScanError> = deps_skipped;
    let detected = frameworks::detect(&graph, &args.path);

    // T-4-16: a broken embedded rule is fatal (release-blocking getdev bug,
    // 04-01's own load-policy decision) — `load_embedded()`'s error
    // propagates via `?`. A broken `--rules` file never reaches this path;
    // `load_user_pack` collects it instead (Pitfall 2, graceful
    // degradation).
    let embedded = rules::load_embedded()?;
    let pack = if let Some(dir) = &args.rules_dir {
        let (user_rules, load_errors) = rules::load_user_pack(dir);
        for err in &load_errors {
            eprintln!("warning: {err}");
        }
        let (merged, collisions) = rules::merge(embedded, user_rules);
        for warning in &collisions {
            eprintln!("warning: {warning}");
        }
        merged
    } else {
        embedded
    };

    let (mut findings, audit_skipped) = audit::run(
        &args.path,
        &pack,
        &detected,
        &AuditOptions {
            severity_min: args.severity_min,
        },
    )?;
    skip_errors.extend(audit_skipped);

    // `--ignore <rule-id>` merges into `[ignore] rules` so it flows through
    // the same `suppress::filter_findings` path as the config-file
    // equivalent — one filtering mechanism, not two.
    let mut cfg = args.cfg.clone();
    cfg.ignore.rules.extend(args.ignore.iter().cloned());

    let filter_outcome = suppress::filter_findings(findings, &cfg);
    findings = filter_outcome.kept;
    // Belt-and-braces with the analyzer's own floor (the analyzer already
    // drops sub-floor findings, but `--severity` is resolved after the
    // analyzer call returns in the general case — this keeps the guarantee
    // structural rather than order-dependent).
    findings.retain(|f| f.severity >= args.severity_min);

    let skipped: Vec<String> = skip_errors.iter().map(ToString::to_string).collect();

    let mut report = FindingsReport::new(
        env!("CARGO_PKG_VERSION"),
        ProjectInfo {
            path: display_path(&args.path),
            stack: Vec::new(),
        },
        findings,
    );
    report.skipped = skip_errors
        .iter()
        .map(|e| SkippedEntry {
            path: e.path().map(|p| p.display().to_string()),
            reason: e.to_string(),
        })
        .collect();

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

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
