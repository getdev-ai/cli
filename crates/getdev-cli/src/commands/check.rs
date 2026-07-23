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

use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::Context;

use getdev_core::audit::{self, AuditOptions};
use getdev_core::baseline;
use getdev_core::config::{Config, ConfigError};
use getdev_core::deps;
use getdev_core::env::{self, EnvOptions};
use getdev_core::findings::{Finding, FindingsReport, ProjectInfo, Severity, SkippedEntry};
use getdev_core::frameworks;
use getdev_core::report::{self, ColorMode};
use getdev_core::review::{self, ReviewOptions};
use getdev_core::rules;
use getdev_core::scan::ScanContext;
use getdev_core::ship;
use getdev_core::suppress;

use crate::commands::real;

/// Which baseline (if any) `check` subtracts from the current run (LOOP-03,
/// D-03). Resolved from the raw `--baseline`/`--update-baseline`/`--since`
/// flags plus `[baseline].auto` at the CLI boundary by [`resolve_baseline_mode`]
/// so [`collect`] stays CLI-arg-free — a plain enum, not clap types — and
/// Phase 15's `fix`/`guard` can drive it directly.
pub(crate) enum BaselineMode {
    /// No baseline suppression this run.
    None,
    /// The persisted `.getdev-baseline` file. `update` = also rewrite it from
    /// the current run's fingerprints (`--update-baseline`, D-09 auto-prune).
    Persisted { update: bool },
    /// Ephemeral snapshot baseline (`--since <snap-id>`) — reconstructed by
    /// materializing a `refs/getdev/` snap and recomputing its finding-set over
    /// the SAME `collect()` pipeline, forced offline (D-06).
    Since { snap_id: u32 },
}

/// An absolute, per-call-unique temp directory for a `--since` materialize,
/// removed on drop so no dir leaks across repeated `--since` runs (T-14-04 —
/// LOOP-03's loop-heavy use case makes a slow leak real). Mirrors gitx's
/// `TempIndex` RAII shape and `temp_index_path`'s pid+nanos+atomic-seq
/// absolute-path uniqueness (snap.rs:144-157). Cleanup fires on EVERY return
/// path out of the `--since` arm, including `?`-early-returns.
struct TempDest {
    path: PathBuf,
}

impl TempDest {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // pid disambiguates across processes; the atomic seq across concurrent
        // calls within this process (the coarse clock can repeat); nanos spreads
        // across runs for readability.
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            ".getdev-since-dest.{}.{nanos}.{seq}",
            std::process::id()
        ));
        TempDest { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDest {
    fn drop(&mut self) {
        // A materialize populates this dir; remove the whole tree. A never-created
        // dir (empty-tree snapshot) or an already-gone dir is fine.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Resolve the raw `check` baseline flags (+ `[baseline].auto`) into a
/// [`BaselineMode`] at the CLI boundary (D-04). Clap's `conflicts_with_all`
/// already rejects `--since` + `--baseline`/`--update-baseline` at parse time
/// (exit 2), so a `Some(since)` here is guaranteed exclusive. An explicit
/// `--baseline` against a missing file is a [`ConfigError::BaselineMissing`]
/// (exit 3, naming the file); `auto` + a missing file is a silent no-op.
pub(crate) fn resolve_baseline_mode(
    baseline: bool,
    update_baseline: bool,
    since: Option<u32>,
    cfg: &Config,
    path: &Path,
) -> anyhow::Result<BaselineMode> {
    if let Some(snap_id) = since {
        return Ok(BaselineMode::Since { snap_id });
    }
    let baseline_path = path.join(&cfg.baseline.file);
    if baseline || update_baseline {
        // Explicit `--baseline` demands the file exist; `--update-baseline`
        // alone creates it, so a missing file is only an error when the user
        // asked to READ a baseline (D-04). `--baseline --update-baseline`
        // (refresh) still requires the file since it reads-then-refreshes.
        if baseline && !baseline_path.exists() {
            return Err(ConfigError::BaselineMissing {
                path: baseline_path,
            }
            .into());
        }
        return Ok(BaselineMode::Persisted {
            update: update_baseline,
        });
    }
    // No flags: `[baseline].auto` applies the baseline iff the file exists;
    // `auto` + no file is a silent no-op, never an error (SPEC-CONFIG).
    if cfg.baseline.auto && baseline_path.exists() {
        return Ok(BaselineMode::Persisted { update: false });
    }
    Ok(BaselineMode::None)
}

pub struct CheckArgs {
    pub path: PathBuf,
    /// Resolved stdout format (global flag, D-04/D-10): human | json | agent.
    pub format: report::Format,
    /// `--min-score N` — the Ship-Score exit gate (global flag, D-01); active on
    /// `check` (which sets a score), inert elsewhere.
    pub min_score: Option<u8>,
    /// Write the full JSON report here; terminal keeps a short summary (global flag).
    pub output: Option<std::path::PathBuf>,
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
    /// Resolved baseline mode (LOOP-03) — the `--baseline`/`--update-baseline`/
    /// `--since` surface, reduced to a CLI-arg-free enum by
    /// [`resolve_baseline_mode`] at the `main` boundary.
    pub(crate) baseline_mode: BaselineMode,
}

/// The fully-aggregated, filtered, scored result of check's collection
/// pipeline — everything `run()`'s render tail consumes beyond the wire report.
/// Extracted so `fix`/`guard` (Phase 14) reuse check's ONE aggregation pipeline
/// instead of hand-copying it and drifting from its findings/score semantics
/// (research/SUMMARY.md Anti-Pattern 1: "a second aggregation pipeline").
pub(crate) struct Collected {
    /// The scored, deduped, config-suppressed report — `score` is `Some(_)` and
    /// `skipped` is populated inside [`collect`].
    pub report: FindingsReport,
    /// Config-suppressed findings, needed only for the `-v` "suppressed by
    /// config" section. `run()` derives its `skipped: Vec<String>` view from
    /// `report.skipped`, so that view is not carried here.
    pub suppressed: Vec<suppress::SuppressedFinding>,
    /// Baseline-suppression outcome (LOOP-03, D-07) — `Some` iff a baseline was
    /// active. Carries the suppressed findings + stale entries for the `-v`
    /// "suppressed by baseline" section, parallel to `suppressed`.
    pub(crate) baseline: Option<baseline::BaselineOutcome>,
}

/// Walk + parse the project EXACTLY once, fan the shared context into all four
/// analyzer legs over rayon, dedupe cross-command secrets, apply config
/// suppression, and score — returning the full [`FindingsReport`] with NO
/// render tail. Callable from `(path, cfg, offline, progress)` with no
/// `CheckArgs` and no CLI output path, so `fix`/`guard` reuse check's exact
/// aggregation instead of re-implementing it (CORE-01 SC2).
pub(crate) fn collect(
    path: &Path,
    cfg: &Config,
    offline: bool,
    baseline_mode: &BaselineMode,
    progress: &crate::progress::Progress,
) -> anyhow::Result<Collected> {
    // ONE shared parse-once context: walk + parse the project EXACTLY once,
    // then hand it to every analyzer below (there is a single walk/parse code
    // path — CLAUDE.md rule 5 / Phase 7 Success Criterion 1). `ctx.skipped`
    // carries the oversized/unreadable SOURCE skips, surfaced once at the end.
    let ctx = ScanContext::build(path)?;
    progress.phase("resolving dependencies…");

    let mut skip_errors: Vec<getdev_core::scan::ScanError> = Vec::new();

    // --- shared prerequisites for the graph-dependent legs (real + audit) ---
    // The dependency graph is built over the SAME context (no second walk);
    // `build_graph_with_context` returns only manifest parse skips — the
    // context's own source skips live in `ctx.skipped`, surfaced below. Both
    // `real` (registry/phantom-import verdicts) and `audit` (framework
    // detection) read this one graph, and `audit` also needs the detected
    // frameworks + the embedded pack — so these are computed ONCE up front,
    // before the parallel fan-out.
    let (graph, manifest_skipped) = deps::build_graph_with_context(&ctx, path)?;
    skip_errors.extend(manifest_skipped);
    let detected = frameworks::detect(&graph, path);
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
            path,
            offline,
            &cfg.real.typosquat_sensitivity,
            cfg.real.check_apis,
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

    progress.phase(&format!(
        "analyzing {} files · real · audit · env · review",
        ctx.files.len()
    ));
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
    dedupe_cross_command_secrets(&mut findings);
    skip_errors.extend(real_skipped);
    skip_errors.extend(audit_skipped);
    skip_errors.extend(env_skipped);
    skip_errors.extend(review_skipped);

    // The shared context's own source read/parse skips, surfaced EXACTLY once
    // (each `_with_context` entry deliberately omits them — no double-count).
    skip_errors.extend(ctx.skipped);

    // --- reuse audit.rs's tail in shape: suppress → report → score → render ---
    // D-10: assign the canonical `gdv1:` fingerprints in ONE batch pass over the
    // finalized, fixed-order (real→audit→env→review), deduped `Vec<Finding>` —
    // the occurrence index (D-04) needs the whole sibling set, so it cannot be
    // computed per-analyzer. This is the sole writer of `finding.fingerprint`;
    // it must run AFTER `dedupe_cross_command_secrets` and BEFORE
    // `filter_findings`, whose `[[suppress]]` branch now reads the stored field.
    getdev_core::fingerprint::assign_fingerprints(&mut findings);

    // check has no `--ignore`/`--severity` flags (global flags only, CLAUDE.md
    // rule 6); `[ignore]`/`[[suppress]]` from config flow through the SAME
    // `suppress::filter_findings` path every other command uses.
    let filter_outcome = suppress::filter_findings(findings, cfg);
    let findings = filter_outcome.kept;

    // --- baseline stage (LOOP-03, D-07): compose AFTER config suppression and
    // BEFORE FindingsReport::new/ship_score, keyed on the `gdv1:` fingerprints
    // already assigned above. Config `[ignore]`/`[[suppress]]` therefore apply
    // first (a config-suppressed finding is never written into an
    // `--update-baseline` file), and the Ship Score is computed on the
    // post-baseline surviving set (the loop's score reflects only what the
    // agent introduced). This stage reads the STORED fingerprint — it never
    // recomputes a hash (SC-4). ---
    let (findings, baseline_result) = match baseline_mode {
        BaselineMode::None => (findings, None),
        BaselineMode::Persisted { update } => {
            let baseline_path = path.join(&cfg.baseline.file);
            // Absent file → empty set (a silent no-op under `auto`, or the
            // fresh-create case under `--update-baseline` alone; explicit
            // `--baseline` against a missing file was already rejected as
            // `BaselineMissing` at the CLI boundary).
            let baseline_set = match baseline::read_baseline_capped(&baseline_path)? {
                Some(text) => baseline::parse_baseline(&text, &baseline_path)?,
                None => BTreeSet::new(),
            };
            // Capture the fingerprints of every finding PRESENT this run (the
            // set entering the baseline stage) BEFORE filtering — this is what
            // `--update-baseline` writes, so a later `--baseline` run suppresses
            // them and stale entries (absent this run) are pruned for free (D-09).
            let present: BTreeSet<String> = if *update {
                findings
                    .iter()
                    .filter_map(|f| f.fingerprint.clone())
                    .collect()
            } else {
                BTreeSet::new()
            };
            let outcome = baseline::filter_by_baseline(findings, &baseline_set);
            if *update {
                let serialized = baseline::serialize_baseline(&present, env!("CARGO_PKG_VERSION"));
                std::fs::write(&baseline_path, serialized).with_context(|| {
                    format!("failed to write baseline file {}", baseline_path.display())
                })?;
            }
            (outcome.kept.clone(), Some(outcome))
        }
        BaselineMode::Since { snap_id } => {
            // Ephemeral snap-anchored baseline (D-06): materialize the snapshot's
            // tree into a unique temp dir, recompute the finding-set over it with
            // the SAME `collect()` pipeline, and take the resulting `gdv1:`
            // fingerprint SET as the baseline. The recompute is FORCED offline
            // (deterministic, no network, no cache pollution) regardless of the
            // outer run's `--offline`, and passes `BaselineMode::None` so it never
            // recurses into a baseline. Only the fingerprint set is consumed — the
            // baseline run's report (its temp-dir-relative `file` paths) is
            // discarded, so no path rewrite is needed; fingerprint
            // temp-dir-invariance (RESEARCH Focus Area 2) makes the diff
            // apples-to-apples. The caller's already-resolved `cfg` is reused (NOT
            // re-resolved from the temp dir — Pitfall 3). A bad snap-id / non-repo
            // propagates as a `GitxError` → exit 2 (D-04: an execution error, not
            // a config error). The temp dir is RAII-cleaned on every return path.
            let dest = TempDest::new();
            getdev_gitx::snap::materialize(path, *snap_id, dest.path())?;
            let baseline_run = collect(dest.path(), cfg, true, &BaselineMode::None, progress)?;
            let baseline_set: BTreeSet<String> = baseline_run
                .report
                .findings
                .iter()
                .filter_map(|f| f.fingerprint.clone())
                .collect();
            let outcome = baseline::filter_by_baseline(findings, &baseline_set);
            (outcome.kept.clone(), Some(outcome))
        }
    };

    let mut report = FindingsReport::new(
        env!("CARGO_PKG_VERSION"),
        ProjectInfo {
            path: display_path(path),
            // B-02: populate the detected stack (reusing ship::detect_stack over
            // the SAME dependency graph the analyzer legs used — no second walk)
            // so `check --json` reports `project.stack` like `ship` does,
            // instead of an empty list. `Unknown` → `[]` (undetected).
            stack: ship::detect_stack(&graph, path)
                .identifiers()
                .iter()
                .map(|id| (*id).to_owned())
                .collect(),
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

    // LOOP-03/D-08: the `--json` `baseline` block, additive/optional — omitted
    // entirely unless a baseline was active this run (docs/SPEC-FINDINGS.md
    // `baseline` envelope row). `mode`/`file`/`snap` mirror the `-v` render
    // above; `suppressed` is the count the baseline removed. Matched jointly
    // with `baseline_mode` (never an `unreachable!`/panic) so a `None` outcome
    // — no baseline active — always yields `None`, regardless of mode.
    report.baseline = match (baseline_mode, baseline_result.as_ref()) {
        (BaselineMode::Persisted { .. }, Some(outcome)) => {
            Some(getdev_core::findings::BaselineEnvelope {
                mode: "persisted".to_owned(),
                file: Some(display_path(&path.join(&cfg.baseline.file))),
                snap: None,
                suppressed: outcome.suppressed.len(),
            })
        }
        (BaselineMode::Since { snap_id }, Some(outcome)) => {
            Some(getdev_core::findings::BaselineEnvelope {
                mode: "since".to_owned(),
                file: None,
                snap: Some(*snap_id),
                suppressed: outcome.suppressed.len(),
            })
        }
        _ => None,
    };

    Ok(Collected {
        report,
        suppressed: filter_outcome.suppressed,
        baseline: baseline_result,
    })
}

pub fn run(args: &CheckArgs) -> anyhow::Result<u8> {
    // Interactive-only "processing" spinner on stderr (auto-suppressed under
    // --json / -o / --quiet / non-TTY). stdout stays byte-clean — the spinner
    // is torn down before any report renders below.
    let show_progress =
        matches!(args.format, report::Format::Human) && !args.quiet && args.output.is_none();
    let progress =
        crate::progress::Progress::start(show_progress, args.no_color, "scanning project…");

    // The ENTIRE aggregation (parse-once → fan-out → dedupe → suppress → score)
    // lives in `collect()`; `run()` re-implements none of it (CORE-01 SC2) — it
    // is now `collect()` + render + exit.
    let Collected {
        report,
        suppressed,
        baseline,
    } = collect(
        &args.path,
        &args.cfg,
        args.offline,
        &args.baseline_mode,
        &progress,
    )?;

    // Derive the `-v` skipped-files view from the report. Each `SkippedEntry`'s
    // `reason` equals the original `ScanError::to_string()`, so this vector is
    // byte-identical to the pre-refactor local.
    let skipped: Vec<String> = report.skipped.iter().map(|s| s.reason.clone()).collect();

    // Erase the spinner line before anything renders to stdout.
    progress.finish();

    // The single-sourced exit gate (D-02/D-03): `--fail-on` (severity) OR
    // `--min-score` (Ship Score) — both the printed `GATE:` line (agent format)
    // and the process exit code below read this ONE computation, so they can
    // never disagree. `--min-score` is active here (check sets a score).
    let gate = report::evaluate_gate(&report, args.fail_on, args.min_score);

    if let Some(out_path) = args.output.as_deref() {
        // `-o` always writes the full JSON artifact regardless of `--format`
        // (D-11); machine formats (json/agent) print only the path, human prints
        // the short summary.
        super::emit_report_file(
            &report,
            out_path,
            !matches!(args.format, report::Format::Human),
            args.no_color,
        )?;
    } else {
        match args.format {
            // `score` rides in the JSON envelope (docs/SPEC-FINDINGS.md).
            report::Format::Json => print!("{}", report::render_json(&report)?),
            // The token-lean agent stream: GATE/SUMMARY/FINDINGS/NEXT-ACTIONS,
            // no human-only affordances, no ANSI (D-05).
            report::Format::Agent => print!("{}", report::render_agent(&report, &gate)),
            report::Format::Human => {
                let color = ColorMode::resolve(args.no_color, std::io::stdout().is_terminal());
                print!(
                    "{}",
                    report::render_terminal(&report, color, args.verbose > 0)
                );
                // First-run clarity (docs/SPEC-COMMANDS.md `check`): when the
                // project has no `.getdev.toml`, tell the user check ran on
                // built-in defaults and how to customize. Human render only —
                // suppressed under `--quiet`, a non-tty stdout, and CI;
                // `--json`/`--format=agent`/`-o` never reach this arm, so the
                // hint is never in a machine stream (determinism). A single stat,
                // never a config re-read; never affects the score or exit code.
                if !args.quiet
                    && std::io::stdout().is_terminal()
                    && std::env::var_os("CI").is_none()
                    && !args.path.join(".getdev.toml").exists()
                {
                    print!("{}", report::render_no_config_hint(color));
                }
                // Under `-v`, print the versioned Ship Score weight table
                // (single-sourced in `getdev-core` — never inlined here).
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
                if !suppressed.is_empty() {
                    if args.verbose > 0 {
                        println!("{} finding(s) suppressed by config:", suppressed.len());
                        for s in &suppressed {
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
                            suppressed.len()
                        );
                    }
                }
                // Baseline suppression is NEVER silent (SC-3): a count line
                // parallel to the config-suppressed one, with a per-finding
                // `id file` list under `-v`. Stale entries (baseline
                // fingerprints matching nothing this run) surface under `-v` as
                // an info note (D-09). Only rendered when a baseline was active,
                // so default/golden renders are unaffected.
                if let Some(baseline) = &baseline {
                    if !baseline.suppressed.is_empty() {
                        if args.verbose > 0 {
                            println!(
                                "{} finding(s) suppressed by baseline:",
                                baseline.suppressed.len()
                            );
                            for f in &baseline.suppressed {
                                println!("  - {} {}", f.id, f.file);
                            }
                        } else if !args.quiet {
                            println!(
                                "{} finding(s) suppressed by baseline (-v for details)",
                                baseline.suppressed.len()
                            );
                        }
                    }
                    if args.verbose > 0 && !baseline.stale.is_empty() {
                        println!(
                            "{} baseline entry(ies) matched nothing this run (stale):",
                            baseline.stale.len()
                        );
                        for fingerprint in &baseline.stale {
                            println!("  - {fingerprint}");
                        }
                    }
                }
            }
        }
    }

    // Exit code from the SAME single-sourced gate the agent `GATE:` line renders
    // (D-03) — `--fail-on` OR `--min-score`, no bespoke check-only threshold.
    Ok(u8::from(gate.failed))
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// `audit/hardcoded-secret` and `env/hardcoded-secret` are the SAME underlying
/// detection (`core::secrets`) surfaced by two commands. Standalone `audit`
/// and `env` runs keep their own view, but the check aggregate must not count
/// one secret twice — a single hardcoded key would otherwise inflate the
/// critical tally and drag the Ship Score double. Keep env's finding (it is
/// the fixable one — `getdev env --write` extracts it) and drop audit's twin
/// at the same file:line.
fn dedupe_cross_command_secrets(findings: &mut Vec<Finding>) {
    let env_secret_sites: std::collections::HashSet<(&str, Option<u32>)> = findings
        .iter()
        .filter(|f| f.id == "env/hardcoded-secret")
        .map(|f| (f.file.as_str(), f.line))
        .collect();
    if env_secret_sites.is_empty() {
        return;
    }
    let env_secret_sites: std::collections::HashSet<(String, Option<u32>)> = env_secret_sites
        .into_iter()
        .map(|(file, line)| (file.to_owned(), line))
        .collect();
    findings.retain(|f| {
        f.id != "audit/hardcoded-secret" || !env_secret_sites.contains(&(f.file.clone(), f.line))
    });
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use getdev_core::findings::{Confidence, Severity};

    fn secret_finding(id: &str, file: &str, line: u32) -> Finding {
        Finding {
            id: id.into(),
            command: id.split('/').next().unwrap_or("").into(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            file: file.into(),
            line: Some(line),
            column: None,
            end_line: None,
            seed: getdev_core::fingerprint::FingerprintSeed::default(),
            fingerprint: None,
            message: "stripe secret assigned to 'API_KEY'".into(),
            detail: None,
            remediation: None,
            suggestion: None,
            fixable: id.starts_with("env/"),
            refs: Vec::new(),
        }
    }

    #[test]
    fn audit_twin_of_an_env_secret_is_dropped_once_not_both() {
        let mut findings = vec![
            secret_finding("audit/hardcoded-secret", "app.js", 2),
            secret_finding("env/hardcoded-secret", "app.js", 2),
            // A different site only audit saw stays.
            secret_finding("audit/hardcoded-secret", "other.js", 9),
        ];
        dedupe_cross_command_secrets(&mut findings);
        let ids: Vec<(&str, &str)> = findings
            .iter()
            .map(|f| (f.id.as_str(), f.file.as_str()))
            .collect();
        assert_eq!(
            ids,
            vec![
                ("env/hardcoded-secret", "app.js"),
                ("audit/hardcoded-secret", "other.js"),
            ]
        );
    }

    fn scratch_project(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-cli-collect-ut-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // SC2: `collect()` is callable straight off the CLI output path — no
    // `assert_cmd`, no `run()`, no stdout, no network. Proves it returns the
    // fully-aggregated, deduped, scored report that `fix`/`guard` will reuse.
    #[test]
    fn collect_returns_a_scored_deduped_report_without_the_cli() {
        let dir = scratch_project("scored");
        // A hardcoded live secret yields the env/audit twin (exercising the
        // cross-command secret dedupe inside collect); the debug leftover adds a
        // review/* finding. No package.json → the `real` leg stays cache-only
        // and, being offline, never touches the network.
        std::fs::write(
            dir.join("app.js"),
            "const stripeKey = \"sk_live_ABCDEFGHIJKLMNOP01\";\n\
             console.log(\"debug\", stripeKey);\n",
        )
        .unwrap();

        // offline=true → `real` is cache-only; a disabled Progress = no spinner.
        let collected = collect(
            &dir,
            &Config::default(),
            true,
            &BaselineMode::None,
            &crate::progress::Progress::start(false, true, ""),
        )
        .unwrap();
        let report = &collected.report;

        // check is the only command that scores; a critical secret drags it
        // below a clean 100.
        let score = report.score.unwrap();
        assert!(
            score < 100,
            "a critical secret must drop the score, got {score}"
        );
        assert!(report.summary.total() > 0, "expected findings, got none");

        // The seeded secret surfaced, and the cross-command dedupe ran INSIDE
        // collect: env keeps its finding, audit's twin at the same site is gone.
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            ids.contains(&"env/hardcoded-secret"),
            "the seeded secret must surface as env/hardcoded-secret, got {ids:?}"
        );
        assert!(
            !ids.contains(&"audit/hardcoded-secret"),
            "audit's twin at the single secret site must be deduped, got {ids:?}"
        );

        // A single readable source file → no skips recorded.
        assert!(
            report.skipped.is_empty(),
            "a readable project must record no skips, got {:?}",
            report.skipped
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
