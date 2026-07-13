//! `getdev check` — the umbrella command (docs/SPEC-COMMANDS.md `getdev
//! check`). A THIN orchestrator on top of the parse-once engine: it builds ONE
//! shared [`ScanContext`], fans it into all four analyzers (`real`, `audit`,
//! `env` detect, `review --all`), concatenates their findings into a single
//! [`FindingsReport`], computes the Ship Score from the one versioned weight
//! table in `getdev-core`, renders the normative banner, and exits per the
//! standard `--fail-on` contract. `check --json --fail-on high` is the
//! canonical CI line.
//!
//! **Parse-once (CLAUDE.md rule 5 / Phase 7 Success Criterion 1):** the shared
//! context is built exactly once (a single walk + parse); every analyzer reads
//! from it as a read-only visitor (`audit::run`, `review::run_all`,
//! `deps::build_graph_with_context`, `apisurface::collect_usages_with_context`,
//! `env::plan_from_context`) — never a second walk/parse.
//!
//! **Network (REQ-privacy):** check introduces NO new network path. The only
//! network hop is `real`'s registry lookup, reused verbatim via
//! [`crate::commands::real::collect_real_findings`] and honoring `--offline`
//! (cache-only). This module names no `getdev_registry` type and makes no
//! registry call of its own.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use getdev_core::audit::{self, AuditOptions};
use getdev_core::config::Config;
use getdev_core::deps;
use getdev_core::env::{self, EnvOptions};
use getdev_core::findings::{Finding, FindingsReport, ProjectInfo, Severity, SkippedEntry};
use getdev_core::frameworks;
use getdev_core::report::{self, ColorMode};
use getdev_core::review::{self, ReviewOptions};
use getdev_core::rules;
use getdev_core::scan::ScanContext;
use getdev_core::suppress;

use crate::commands::real;

pub struct CheckArgs {
    pub path: PathBuf,
    pub json: bool,
    pub no_color: bool,
    pub fail_on: Option<Severity>,
    /// Never hit the network; use cache only (global flag, resolved once by
    /// `main` via `config::offline_resolved`). Propagates to `real`'s registry
    /// cache-only path — the sole network surface of `check`.
    pub offline: bool,
    /// Resolved config — `[ignore]`/`[[suppress]]` filtering and the
    /// `[real]` knobs (`check_apis`, `typosquat_sensitivity`).
    pub cfg: Config,
    /// Suppress banner/summary chatter; findings still render (global flag).
    pub quiet: bool,
    /// Debug-level detail, repeatable (global flag) — shows per-file skip
    /// reasons and the versioned Ship Score weight table.
    pub verbose: u8,
}

pub fn run(args: &CheckArgs) -> anyhow::Result<u8> {
    // ONE shared parse-once context: walk + parse the project EXACTLY once,
    // then hand it to every analyzer below (there is a single walk/parse code
    // path — CLAUDE.md rule 5 / Phase 7 Success Criterion 1). `ctx.skipped`
    // carries the oversized/unreadable SOURCE skips, surfaced once at the end.
    let ctx = ScanContext::build(&args.path)?;

    let mut skip_errors: Vec<getdev_core::scan::ScanError> = Vec::new();

    // --- shared prerequisites for the graph-dependent legs (real + audit) ---
    // The dependency graph is built over the SAME context (no second walk);
    // `build_graph_with_context` returns only manifest parse skips — the
    // context's own source skips live in `ctx.skipped`, surfaced below. Both
    // `real` (registry/phantom-import verdicts) and `audit` (framework
    // detection) read this one graph, and `audit` also needs the detected
    // frameworks + the embedded pack — so these are computed ONCE up front,
    // before the parallel fan-out.
    let (graph, manifest_skipped) = deps::build_graph_with_context(&ctx, &args.path)?;
    skip_errors.extend(manifest_skipped);
    let detected = frameworks::detect(&graph, &args.path);
    let pack = rules::load_embedded()?;

    // check reports every finding it aggregates; the Ship Score already weights
    // by severity, so no display floor is applied to any leg.
    let audit_options = AuditOptions {
        severity_min: Severity::Info,
    };
    let review_options = ReviewOptions {
        severity_min: Severity::Info,
    };
    // `--fix` maps to `env --write` via the existing global path in `main`, out
    // of this default aggregation (docs/SPEC-COMMANDS.md `check` Flags) — env is
    // DETECT-only here.
    let env_options = EnvOptions::default();

    // --- fan the FOUR independent analyzer legs out over the shared context ---
    // Each leg (`real` / `audit` / `env` detect / `review --all`) is a
    // read-only visitor over the SAME shared `&ScanContext` (which is
    // `Send + Sync` — the parse-once immutability established in 07-01/02/03),
    // so they run CONCURRENTLY with rayon (CLAUDE.md's settled blocking + rayon
    // model — never async/tokio). `real` fans its own registry lookups across
    // rayon internally; nested rayon composes via work-stealing.
    //
    // DETERMINISM (CLAUDE.md "same input → same output"): thread completion
    // order must NOT affect output. Each leg produces its findings in its own
    // deterministic order; we reassemble them in a FIXED leg order below, and
    // `FindingsReport::new` then re-sorts the whole set on a TOTAL key
    // (severity → file → line → column → id → message, findings.rs IN-04) — so
    // the aggregated report is byte-identical regardless of how the threads
    // interleave.
    type LegOutput = anyhow::Result<(Vec<Finding>, Vec<getdev_core::scan::ScanError>)>;
    let real_leg = || -> LegOutput {
        // deps/registry + apis + model strings over the shared context; its
        // manifest skips were already surfaced above, so it contributes none.
        let findings = real::collect_real_findings(
            &ctx,
            &graph,
            &args.path,
            args.offline,
            &args.cfg.real.typosquat_sensitivity,
            args.cfg.real.check_apis,
        )?;
        Ok((findings, Vec::new()))
    };
    let audit_leg = || -> LegOutput {
        let (findings, skipped) = audit::run(&ctx, &pack, &detected, &audit_options)?;
        Ok((findings, skipped))
    };
    let env_leg = || -> LegOutput {
        let env_plan = env::plan_from_context(&ctx, &env_options)?;
        Ok((env::findings(&env_plan, &env_options), Vec::new()))
    };
    let review_leg = || -> LegOutput {
        // All-scope has no per-file skips of its own (they are in `ctx.skipped`).
        let (findings, _review_skipped) = review::run_all(&ctx, &review_options)?;
        Ok((findings, Vec::new()))
    };

    let ((real_out, audit_out), (env_out, review_out)) = rayon::join(
        || rayon::join(real_leg, audit_leg),
        || rayon::join(env_leg, review_leg),
    );
    let (real_findings, real_skipped) = real_out?;
    let (audit_findings, audit_skipped) = audit_out?;
    let (env_findings, env_skipped) = env_out?;
    let (review_findings, review_skipped) = review_out?;

    // Reassemble in a FIXED order (real → audit → env → review) — the same
    // concatenation the sequential version produced; the total-key sort in
    // `FindingsReport::new` makes this order immaterial to the final output,
    // but keeping it fixed keeps the pre-sort intermediate deterministic too.
    let mut findings = Vec::with_capacity(
        real_findings.len() + audit_findings.len() + env_findings.len() + review_findings.len(),
    );
    findings.extend(real_findings);
    findings.extend(audit_findings);
    findings.extend(env_findings);
    findings.extend(review_findings);
    skip_errors.extend(real_skipped);
    skip_errors.extend(audit_skipped);
    skip_errors.extend(env_skipped);
    skip_errors.extend(review_skipped);

    // The shared context's own source read/parse skips, surfaced EXACTLY once
    // (each `_with_context` entry deliberately omits them — no double-count).
    skip_errors.extend(ctx.skipped);

    // --- reuse audit.rs's tail in shape: suppress → report → score → render ---
    // check has no `--ignore`/`--severity` flags (global flags only, CLAUDE.md
    // rule 6); `[ignore]`/`[[suppress]]` from config flow through the SAME
    // `suppress::filter_findings` path every other command uses.
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
    report.skipped = skip_errors
        .iter()
        .map(|e| SkippedEntry {
            path: e.path().map(|p| p.display().to_string()),
            reason: e.to_string(),
        })
        .collect();

    // The ONE net-new report field check populates — `check` is the only
    // command that ever sets a Ship Score (every other leaves it `None`).
    report.score = Some(report::ship_score(&report.summary));

    if args.json {
        // `score` rides in the JSON envelope (docs/SPEC-FINDINGS.md).
        print!("{}", report::render_json(&report)?);
    } else {
        let color = ColorMode::resolve(args.no_color, std::io::stdout().is_terminal());
        print!("{}", report::render_terminal(&report, color));
        // Under `-v`, print the versioned Ship Score weight table (single-
        // sourced in `getdev-core` — never inlined here).
        if args.verbose > 0 {
            print!("{}", report::render_ship_score_weights());
        }
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

    // Exit code via the SAME `Summary::at_or_above(--fail-on)` comparator every
    // command uses — no bespoke check-only threshold (docs/PLAN.md §2.2).
    let failed = args
        .fail_on
        .is_some_and(|threshold| report.summary.at_or_above(threshold) > 0);
    Ok(u8::from(failed))
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
