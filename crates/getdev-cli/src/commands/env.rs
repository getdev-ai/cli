use std::io::IsTerminal;
use std::path::Path;

use getdev_core::config::Config;
use getdev_core::env::{self, EnvOptions};
use getdev_core::findings::{
    AppliedInfo, Confidence, Finding, FindingsReport, ProjectInfo, Severity, SkippedEntry,
};
use getdev_core::report::{self, ColorMode};
use getdev_core::suppress;

pub struct EnvArgs {
    pub path: std::path::PathBuf,
    pub json: bool,
    pub no_color: bool,
    pub fail_on: Option<Severity>,
    pub env_file: String,
    pub write: bool,
    /// Resolved config (B2 audit fix) — `[ignore]`/`[[suppress]]` filtering.
    pub cfg: Config,
    /// Suppress banner/summary chatter; findings still render (global flag,
    /// docs/PLAN.md §2.2).
    pub quiet: bool,
    /// Debug-level detail, repeatable (global flag, docs/PLAN.md §2.2) —
    /// shows per-file skip reasons instead of just a count.
    pub verbose: u8,
}

pub fn run(args: &EnvArgs) -> anyhow::Result<u8> {
    let options = EnvOptions {
        env_file: args.env_file.clone(),
    };
    let plan = env::plan(&args.path, &options)?;
    let mut findings = env::findings(&plan, &options);

    // the env file being in git history is its own critical finding —
    // getdev never rewrites history automatically (rotation guidance instead)
    let env_committed = getdev_gitx::is_tracked(&args.path, &options.env_file);
    if env_committed {
        findings.push(env_file_committed_finding(&options.env_file));
    }

    // B2(b): `[ignore] rules`/`paths` and `[[suppress]]` actually filter now.
    let filter_outcome = suppress::filter_findings(findings, &args.cfg);
    let findings = filter_outcome.kept;

    // F4: apply before printing (never `?` here) so that on failure the
    // findings still print before the error exit — the apply error is
    // propagated only after rendering below.
    let applied_result = if args.write && !plan.entries.is_empty() {
        Some(env::apply(&args.path, &plan, &options))
    } else {
        None
    };
    let applied_ok = applied_result.as_ref().and_then(|r| r.as_ref().ok());

    let mut report = FindingsReport::new(
        env!("CARGO_PKG_VERSION"),
        ProjectInfo {
            path: display_path(&args.path),
            stack: Vec::new(),
        },
        findings,
    );
    // F4: skip-list surfaced in --json too (previously terminal-only).
    report.skipped = plan
        .skipped
        .iter()
        .map(|s| SkippedEntry {
            path: s.path().map(|p| p.display().to_string()),
            reason: s.to_string(),
        })
        .collect();
    // F4: the apply summary, surfaced as an additive optional envelope field
    // so `--json --write` stays a single valid JSON document.
    if let Some(summary) = applied_ok {
        report.applied = Some(AppliedInfo {
            vars_written: summary.vars_written.len(),
            files_rewritten: summary.files_rewritten.len(),
            env_file: options.env_file.clone(),
            env_file_created: summary.env_file_created,
            gitignore_patched: summary.gitignore_patched,
            example_file: summary.example_file.clone(),
        });
    }

    if args.json {
        print!("{}", report::render_json(&report)?);
    } else {
        let color = ColorMode::resolve(args.no_color, std::io::stdout().is_terminal());
        print!("{}", report::render_terminal(&report, color));
        if !args.quiet {
            match applied_result.as_ref() {
                Some(Ok(summary)) => {
                    println!();
                    println!(
                        "applied: {} var(s) → {} ({}), {} file(s) rewritten{}",
                        summary.vars_written.len(),
                        options.env_file,
                        if summary.env_file_created {
                            "created"
                        } else {
                            "appended"
                        },
                        summary.files_rewritten.len(),
                        if summary.gitignore_patched {
                            ", .gitignore patched"
                        } else {
                            ""
                        }
                    );
                    println!(
                        "keys documented in {} — commit that file, never {}",
                        summary.example_file, options.env_file
                    );
                }
                // F4: apply failed — say nothing extra here, the findings
                // above already printed; the error itself surfaces after
                // this block via the caller's `?`/exit-code-2 path.
                Some(Err(_)) => {}
                None if !plan.entries.is_empty() => {
                    println!();
                    println!(
                        "dry run — nothing written. {} secret(s) would move to {} (getdev env --write)",
                        plan.entries.len(),
                        options.env_file
                    );
                }
                None => {}
            }
        }
        if !plan.skipped.is_empty() {
            if args.verbose > 0 {
                println!("{} unreadable file(s) skipped:", plan.skipped.len());
                for skipped in &plan.skipped {
                    println!("  - {skipped}");
                }
            } else if !args.quiet {
                println!(
                    "{} unreadable file(s) skipped (-v for details)",
                    plan.skipped.len()
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

    // F4: the apply error is propagated only now — findings (and, for
    // --json, the full report) have already printed above.
    if let Some(Err(err)) = applied_result {
        return Err(err.into());
    }

    let failed = args
        .fail_on
        .is_some_and(|threshold| report.summary.at_or_above(threshold) > 0);
    Ok(u8::from(failed))
}

fn env_file_committed_finding(env_file: &str) -> Finding {
    Finding {
        id: "env/env-file-committed".to_owned(),
        command: "env".to_owned(),
        severity: Severity::Critical,
        confidence: Confidence::High,
        file: env_file.to_owned(),
        line: None,
        column: None,
        end_line: None,
        message: format!("{env_file} is committed to git — its secrets are in history"),
        detail: Some(
            "values in git history stay exposed even after the file is removed; \
             getdev never rewrites history automatically"
                .to_owned(),
        ),
        suggestion: Some("rotate every credential in this file, then remove it from git".to_owned()),
        remediation: Some(format!(
            "git rm --cached {env_file} && commit; rotate all keys; consider git-filter-repo for history"
        )),
        fixable: false,
        refs: vec!["https://getdev.ai/rules/env/env-file-committed".to_owned()],
        fingerprint: None,
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
