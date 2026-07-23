//! `getdev ship` — the user-facing surface over `core::ship` (07-05). It
//! detects the single Dockerfile preset for the project, runs the three
//! programmatic `ship/*` validators, and renders a per-target `SHIP.md`
//! checklist. With `--write` it generates the multi-stage `Dockerfile` +
//! `.dockerignore` + `SHIP.md` — every file routed through the ONE audited
//! [`getdev_core::mutate::apply`] path (atomic write → rollback), with the
//! multi-file [`AutoSnapHook`] firing before any mutation (mirrors
//! `commands::env`'s `plan → mutate::apply(writes, hook) → report` shape).
//!
//! **Execution boundary (REQ-privacy / CLAUDE.md):** `--run-build` is the ONE
//! and ONLY place in the entire product allowed to execute project code. It is
//! off by default, requires the explicit flag, and its single
//! `std::process::Command` (non-git) subprocess lives HERE at the CLI tier —
//! `getdev-core` spawns nothing. Default (`run_build == false`) runs no
//! subprocess at all.
//!
//! **Network:** none. **Mutates:** only with `--write`, only via `core::mutate`.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use getdev_core::config::Config;
use getdev_core::deps;
use getdev_core::findings::{Finding, FindingsReport, ProjectInfo, Severity, SkippedEntry};
use getdev_core::mutate::{self, PlannedWrite};
use getdev_core::report::{self, ColorMode};
use getdev_core::scan::ScanContext;
use getdev_core::ship::{self, ShipStack, ShipTarget};
use getdev_core::suppress;

pub struct ShipArgs {
    pub path: PathBuf,
    /// Generate `Dockerfile` + `.dockerignore` + `SHIP.md` via `core::mutate`
    /// (off by default — safe-by-default: no mutation without this flag).
    pub write: bool,
    /// `--target <t>` else `[ship] target` in config (`auto`/unset → docker).
    pub target: Option<ShipTarget>,
    /// The ONE opt-in that lets getdev execute project code (the build). Off by
    /// default; the single subprocess spawn lives in this module.
    pub run_build: bool,
    pub json: bool,
    /// Write the full JSON report here; terminal keeps a short summary (global flag).
    pub output: Option<std::path::PathBuf>,
    pub no_color: bool,
    pub fail_on: Option<Severity>,
    /// Resolved config — `[ignore]`/`[[suppress]]` filtering, `[ship] target`,
    /// and the `[snap]` knobs backing the auto-snap hook.
    pub cfg: Config,
    /// Suppress banner/summary chatter; findings still render (global flag).
    pub quiet: bool,
    /// Debug-level detail, repeatable (global flag) — per-file skip reasons.
    pub verbose: u8,
}

pub fn run(args: &ShipArgs) -> anyhow::Result<u8> {
    // Parse-once: ONE shared scan context (walk + parse), reused by the stack
    // detector and every validator below — no second walk (CLAUDE.md rule 5).
    let ctx = ScanContext::build(&args.path)?;
    let (graph, manifest_skipped) = deps::build_graph_with_context(&ctx, &args.path)?;
    let stack = ship::detect_stack(&graph, &args.path);

    // The three programmatic ship/* validators over the shared context.
    let mut findings: Vec<Finding> = Vec::new();
    findings.extend(ship::missing_env_declaration(&ctx, &args.path));
    findings.extend(ship::hardcoded_port(&ctx));
    findings.extend(ship::blocking_findings(&ctx, &args.path));

    // D-10: assign the canonical `gdv1:` fingerprints in one batch pass over the
    // finalized findings before suppression reads them (the sole writer of
    // `finding.fingerprint`, so `ship --json` emits it on every finding).
    getdev_core::fingerprint::assign_fingerprints(&mut findings);

    // `[ignore]`/`[[suppress]]` filtering — the same machinery every other
    // command routes through (one filtering mechanism, not two).
    let filter_outcome = suppress::filter_findings(findings, &args.cfg);
    let findings = filter_outcome.kept;

    // Resolve the target: flag > `[ship] target` > docker default. An `auto`
    // (or otherwise unrecognized) config value falls back to the `Docker`
    // default — the spec's auto-detected target.
    let target = args
        .target
        .or_else(|| args.cfg.ship.target.parse::<ShipTarget>().ok())
        .unwrap_or_default();

    // The per-target checklist, embedding the (kept) pre-flight findings.
    let ship_md = ship::render_ship_md(stack, target, &findings);

    // --- --write: generate files through the ONE audited mutate path ---------
    // Every generated file is a `PlannedWrite::WriteFile` handed to
    // `mutate::apply` (never a bare filesystem write) — atomic write + rollback
    // come for free, and the >1-file plan fires the AutoSnapHook before any I/O.
    let hook = if args.write && args.cfg.snap.auto_snap_before_fix {
        Some(AutoSnapHook {
            root: &args.path,
            keep: args.cfg.snap.keep,
        })
    } else {
        None
    };
    let applied_result = if args.write {
        let mut writes: Vec<PlannedWrite> = Vec::new();
        if let Some(dockerfile) = ship::render_dockerfile(stack) {
            writes.push(planned_write(args.path.join("Dockerfile"), dockerfile));
        }
        writes.push(planned_write(
            args.path.join(".dockerignore"),
            ship::render_dockerignore(stack),
        ));
        writes.push(planned_write(args.path.join("SHIP.md"), ship_md.clone()));
        Some(mutate::apply(
            writes,
            hook.as_ref()
                .map(|h| h as &dyn getdev_core::mutate::PreMutateHook),
        ))
    } else {
        None
    };
    let applied_ok = applied_result.as_ref().and_then(|r| r.as_ref().ok());

    // --- report (mirror audit.rs's read-only tail) ---------------------------
    let skipped: Vec<String> = manifest_skipped
        .iter()
        .chain(ctx.skipped.iter())
        .map(ToString::to_string)
        .collect();

    let mut report = FindingsReport::new(
        env!("CARGO_PKG_VERSION"),
        ProjectInfo {
            path: display_path(&args.path),
            stack: vec![stack.as_str().to_owned()],
        },
        findings,
    );
    report.skipped = manifest_skipped
        .iter()
        .chain(ctx.skipped.iter())
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
        print!(
            "{}",
            report::render_terminal(&report, color, args.verbose > 0)
        );
        if !args.quiet {
            println!();
            println!("stack: {} · target: {}", stack.as_str(), target.as_str());
            match applied_ok {
                Some(applied) => {
                    println!(
                        "wrote {} file(s): {}",
                        applied.files_written.len(),
                        applied
                            .files_written
                            .iter()
                            .map(|p| p
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    if stack == ShipStack::Unknown {
                        println!(
                            "note: stack not recognized — no Dockerfile generated (add a manifest so getdev can detect it)"
                        );
                    }
                }
                None => {
                    // Dry run — show the checklist getdev *would* write.
                    println!("dry run — nothing written (getdev ship --write to generate):");
                    println!();
                    print!("{ship_md}");
                }
            }
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

    // The mutate error is propagated only now — the findings (and, for --json,
    // the full report) have already printed above (env.rs F4 precedent).
    if let Some(Err(err)) = applied_result {
        return Err(err.into());
    }

    // --- --run-build: the ONE sanctioned project-code execution --------------
    // Guarded by the explicit flag; default runs NO subprocess (REQ-privacy).
    let mut build_failed = false;
    if args.run_build {
        build_failed = !run_project_build(stack, &args.path, args.quiet);
    }

    let findings_failed = args
        .fail_on
        .is_some_and(|threshold| report.summary.at_or_above(threshold) > 0);
    Ok(u8::from(findings_failed || build_failed))
}

/// A whole-file [`PlannedWrite::WriteFile`] for `path` (its `original` is the
/// current on-disk content if the file exists, else `None`). Reads are best
/// effort — an unreadable existing file is treated as absent for rollback.
fn planned_write(path: PathBuf, content: String) -> PlannedWrite {
    let original = std::fs::read_to_string(&path).ok();
    PlannedWrite::WriteFile {
        path,
        original,
        new_content: content,
    }
}

/// The ONE project-code execution point in the entire product. Spawns the
/// stack's build in `root` (never in `getdev-core`), streaming its output.
/// Returns `true` when the build succeeded (or there is nothing to build).
/// A missing build tool is reported, not fatal — it degrades to `false`.
fn run_project_build(stack: ShipStack, root: &Path, quiet: bool) -> bool {
    let (program, argv): (&str, &[&str]) = match stack {
        ShipStack::NodeNextjs | ShipStack::Node => ("npm", &["run", "build"]),
        ShipStack::Fastapi | ShipStack::Flask | ShipStack::Django => {
            ("pip", &["install", "-r", "requirements.txt"])
        }
        ShipStack::Unknown => {
            if !quiet {
                println!("--run-build: unrecognized stack — no build step to run");
            }
            return true;
        }
    };
    if !quiet {
        println!(
            "--run-build: executing `{program} {}` (the only project-code getdev ever runs)",
            argv.join(" ")
        );
    }
    match std::process::Command::new(program)
        .args(argv)
        .current_dir(root)
        .status()
    {
        Ok(status) if status.success() => {
            if !quiet {
                println!("--run-build: build succeeded");
            }
            true
        }
        Ok(status) => {
            eprintln!("--run-build: build failed ({status})");
            false
        }
        Err(err) => {
            eprintln!("--run-build: could not start `{program}`: {err}");
            false
        }
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// The concrete `PreMutateHook` backing `core::mutate`'s auto-snap seam with a
/// real `getdev-gitx` snapshot — identical to `commands::env`'s hook, only the
/// snap message differs. Before a multi-file `ship --write` mutates anything,
/// it records a deduped safety snapshot under `refs/getdev/auto/<N>` so the
/// user always has an undo point; any `GitxError` aborts the plan closed (a
/// security tool must not write multiple files with no undo path).
struct AutoSnapHook<'a> {
    root: &'a Path,
    keep: u32,
}

impl getdev_core::mutate::PreMutateHook for AutoSnapHook<'_> {
    fn before_multi_file_write(&self, _paths: &[&Path]) -> Result<(), String> {
        getdev_gitx::snap::snapshot(
            self.root,
            getdev_gitx::snap::Namespace::Auto,
            "auto: before ship --write",
            true,
            self.keep,
        )
        .map(|_outcome| ())
        .map_err(|e| e.to_string())
    }
}
