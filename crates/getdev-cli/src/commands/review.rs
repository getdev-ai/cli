//! `getdev review` — a thin clap subcommand over `core::review::run`. It
//! receives an already-resolved [`ReviewScope`] (built in `main.rs`, which is
//! the sole place `getdev_gitx::diff` is mapped to review's own input type —
//! see the module-level note in `core::review`), runs the read-only analyzer,
//! filters through the existing `suppress`/severity machinery, renders via the
//! unchanged findings renderers, and returns the exit-code contract. Mirrors
//! `commands::audit`'s tail exactly — review is fully offline and non-mutating.
//!
//! **This module imports NO registry crate type and makes no network call**
//! (REQ-privacy); it never mutates (REQ-safe-by-default; no `core::mutate`).
//! It also never invokes the git binary — all diff extraction happens in
//! `getdev-gitx` and is handed here as a resolved scope (REQ-cmd-review
//! boundary invariant).

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use getdev_core::config::Config;
use getdev_core::findings::{FindingsReport, ProjectInfo, Severity, SkippedEntry};
use getdev_core::report::{self, ColorMode};
use getdev_core::review::{self, ReviewOptions, ReviewScope};
use getdev_core::suppress;

pub struct ReviewArgs {
    pub path: PathBuf,
    pub json: bool,
    /// Write the full JSON report here; terminal keeps a short summary (global flag).
    pub output: Option<std::path::PathBuf>,
    pub no_color: bool,
    pub fail_on: Option<Severity>,
    /// The display/reporting floor. Review has no `--severity` flag or config
    /// key (its contractual scope is only the three scope selectors), so this
    /// is always [`Severity::Info`] — every `review/*` finding is reported and
    /// suppression is left to config `[ignore]`/`[[suppress]]` and `--fail-on`.
    pub severity_min: Severity,
    /// The scope resolved in `main.rs`: `--all` → [`ReviewScope::All`] (no
    /// git); otherwise a [`ReviewScope::Diff`] built from a `getdev-gitx` diff
    /// mapped to review's own input type at the CLI boundary.
    pub scope: ReviewScope,
    /// Resolved config — `[ignore]`/`[[suppress]]` filtering applies to
    /// `review/*` identically to `audit/*` (no carve-out).
    pub cfg: Config,
    /// Suppress banner/summary chatter; findings still render (global flag).
    pub quiet: bool,
    /// Debug-level detail, repeatable (global flag).
    pub verbose: u8,
}

pub fn run(args: &ReviewArgs) -> anyhow::Result<u8> {
    let opts = ReviewOptions {
        severity_min: args.severity_min,
    };
    // Parse-once for the `--all` scope (the one `check` reuses): build ONE
    // shared ScanContext (walk + parse) and pass it in — there is exactly one
    // walk/parse code path (07-02). `ctx.skipped` carries the oversized/
    // unreadable source files the shared scan pass folded aside. The diff-
    // scoped paths (`--against`/`--staged`/default) parse only their specific
    // changed files, so they keep their own targeted path.
    let (mut findings, skip_errors) = match &args.scope {
        ReviewScope::All => {
            let ctx = getdev_core::scan::ScanContext::build(&args.path)?;
            let (findings, mut skipped) = review::run_all(&ctx, &opts)?;
            skipped.extend(ctx.skipped);
            (findings, skipped)
        }
        scope => review::run(&args.path, scope, &opts)?,
    };

    // Config `[ignore]`/`[[suppress]]` flows through the same
    // `suppress::filter_findings` path used by `audit` — one filtering
    // mechanism, applied to `review/*` identically (no carve-out). Review has
    // no `--ignore` flag of its own (contractual scope = the three scope
    // selectors, CLAUDE.md rule 6), so the config is used as-is.
    let filter_outcome = suppress::filter_findings(findings, &args.cfg);
    findings = filter_outcome.kept;
    // Belt-and-braces with the analyzer's own floor — keeps the severity
    // guarantee structural rather than order-dependent (audit precedent).
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

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
