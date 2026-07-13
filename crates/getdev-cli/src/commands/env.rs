use std::collections::HashSet;
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
    /// Also extract http(s) URLs + connection strings (08-02's detection),
    /// resolved in `main.rs` as `--include-urls` flag OR `[env] include_urls`
    /// config. Threads straight into [`EnvOptions::include_urls`].
    pub include_urls: bool,
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
        // Resolved in `main.rs` (`--include-urls` flag OR `[env] include_urls`
        // config) and threaded through here to switch on 08-02's URL/DSN
        // detection.
        include_urls: args.include_urls,
    };
    let mut plan = env::plan(&args.path, &options)?;
    let mut findings = env::findings(&plan, &options);

    // CR-02: fingerprints of the per-secret findings, computed BEFORE the
    // committed-file finding is pushed. `env::findings` maps over
    // `plan.entries` directly, so this list is 1:1 with `plan.entries` and
    // in the same order — the index alignment relied on below. We reuse
    // these to gate what `--write` mutates on the exact same suppression
    // decision that hides findings from the report.
    let entry_fingerprints: Vec<String> = findings.iter().map(suppress::fingerprint).collect();

    // the env file being in git history is its own critical finding —
    // getdev never rewrites history automatically (rotation guidance instead)
    let env_committed = getdev_gitx::is_tracked(&args.path, &options.env_file);
    if env_committed {
        findings.push(env_file_committed_finding(&options.env_file));
    }

    // B2(b): `[ignore] rules`/`paths` and `[[suppress]]` actually filter now.
    let filter_outcome = suppress::filter_findings(findings, &args.cfg);

    // CR-02: suppression previously touched ONLY this display list while
    // `env::apply` ran on the full `plan.entries` — a secret the user
    // explicitly suppressed ([[suppress]] "test fixture key…") or ignored
    // ([ignore]) still got its literal rewritten and its value appended to
    // `.env`, mutating a file against explicit user intent. Gate the plan on
    // the SAME outcome: drop every entry whose finding was suppressed, so
    // detect/report and mutate agree. Identity is the finding fingerprint
    // (rule id + file + line), which suppress uses and which is 1:1 with a
    // plan entry.
    let suppressed_fingerprints: HashSet<String> = filter_outcome
        .suppressed
        .iter()
        .map(|s| suppress::fingerprint(&s.finding))
        .collect();
    let mut idx = 0usize;
    plan.entries.retain(|_| {
        // `Vec::retain` visits entries once, in order — same order as
        // `entry_fingerprints`. Keep an entry unless its finding was
        // suppressed above.
        let keep = entry_fingerprints
            .get(idx)
            .is_none_or(|fp| !suppressed_fingerprints.contains(fp));
        idx += 1;
        keep
    });

    let findings = filter_outcome.kept;

    // F4: apply before printing (never `?` here) so that on failure the
    // findings still print before the error exit — the apply error is
    // propagated only after rendering below.
    //
    // 05-05: gate a getdev-gitx-backed `AutoSnapHook` on
    // `snap.auto_snap_before_fix` (default true). When enabled, a multi-file
    // `env --write` records an invisible, deduped safety snapshot under
    // `refs/getdev/auto/<N>` BEFORE any file is mutated (D-06/D-07/D-08);
    // `core::mutate::apply` fires the hook only for multi-file plans and aborts
    // closed if the snapshot fails. When the toggle is off (or dry-run), pass
    // `None`. The hook is built into a `let` so it outlives the `apply` call.
    let hook = if args.write && args.cfg.snap.auto_snap_before_fix {
        Some(AutoSnapHook {
            root: &args.path,
            keep: args.cfg.snap.keep,
        })
    } else {
        None
    };
    let applied_result = if args.write && !plan.entries.is_empty() {
        Some(env::apply(
            &args.path,
            &plan,
            &options,
            hook.as_ref()
                .map(|h| h as &dyn getdev_core::mutate::PreMutateHook),
        ))
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
            vars_skipped_stale: summary.vars_skipped_stale.len(),
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
                    if !summary.vars_skipped_stale.is_empty() {
                        println!(
                            "{} var(s) already present in {} — not duplicated: {}",
                            summary.vars_skipped_stale.len(),
                            options.env_file,
                            summary.vars_skipped_stale.join(", ")
                        );
                    }
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

/// The concrete `PreMutateHook` that closes the Phase 2 carry-forward: it backs
/// `core::mutate`'s auto-snap seam (05-02) with a real `getdev-gitx` snapshot
/// (05-01). This is the ONLY place that imports both
/// `getdev_core::mutate::PreMutateHook` and `getdev_gitx::snap` — the
/// dependency-inversion seam that keeps `getdev-core` free of a
/// `getdev-gitx` edge.
///
/// Before a multi-file `env --write` mutates anything, `before_multi_file_write`
/// records a deduped snapshot under the `Auto` namespace
/// (`refs/getdev/auto/<N>`, D-06) so the user always has an undo point. `dedupe`
/// makes an unchanged tree a no-op (D-07) — back-to-back writes never churn the
/// auto namespace. The message records the trigger (D-08); the snapshot commit's
/// committer time supplies the timestamp, so no wall-clock string is embedded.
/// Any `GitxError` is stringified so `core::mutate` turns it into
/// `MutateError::AutoSnapFailed`, aborting the plan closed (a security tool must
/// not mutate multiple files with no undo path).
struct AutoSnapHook<'a> {
    root: &'a Path,
    keep: u32,
}

impl getdev_core::mutate::PreMutateHook for AutoSnapHook<'_> {
    fn before_multi_file_write(&self, _paths: &[&Path]) -> Result<(), String> {
        getdev_gitx::snap::snapshot(
            self.root,
            getdev_gitx::snap::Namespace::Auto,
            "auto: before env --write",
            true,
            self.keep,
        )
        .map(|_outcome| ())
        .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use getdev_core::config::Config;

    fn unique_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-env-cli-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `git init` a hermetic repo at `dir` (no network, local only) so the
    /// auto-snap has a repo to write `refs/getdev/auto/` into. `snapshot`'s own
    /// `ensure_repo` would `git init` on demand, but doing it explicitly keeps
    /// the test's intent obvious and its state deterministic.
    fn git_init(dir: &std::path::Path) {
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["init", "--quiet"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "git init failed for {}", dir.display());
    }

    /// Count the live `refs/getdev/auto/` refs in `dir` by shelling
    /// `for-each-ref` — the auto namespace `snapshot` writes into. `list` is
    /// manual-namespace-only, so the auto refs are counted directly.
    fn count_auto_refs(dir: &std::path::Path) -> usize {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["for-each-ref", "--format=%(refname)", "refs/getdev/auto/"])
            .output()
            .unwrap();
        assert!(out.status.success(), "for-each-ref failed");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count()
    }

    /// Build an `EnvArgs` for a `--write` run over `dir` with the given
    /// auto-snap toggle. Everything else mirrors the crate's convention (quiet,
    /// no color, no fail-on) so the tests assert only on filesystem/ref state.
    fn write_args(dir: &std::path::Path, auto_snap: bool) -> EnvArgs {
        let mut cfg = Config::default();
        cfg.snap.auto_snap_before_fix = auto_snap;
        EnvArgs {
            path: dir.to_path_buf(),
            json: false,
            no_color: true,
            fail_on: None,
            env_file: ".env".to_owned(),
            include_urls: false,
            write: true,
            cfg,
            quiet: true,
            verbose: 0,
        }
    }

    /// Write two secret-bearing source files so the mutation plan is multi-file
    /// (two source rewrites + the `.env`/`.gitignore` writes) — the D-07
    /// trigger that fires the auto-snap hook. Distinct values so neither is
    /// deduped away by the extractor.
    fn seed_two_secret_files(dir: &std::path::Path) {
        std::fs::write(
            dir.join("one.js"),
            "const a = \"sk_live_AAAAAAAAAAAAAAAA01\";\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("two.js"),
            "const b = \"sk_live_BBBBBBBBBBBBBBBB02\";\n",
        )
        .unwrap();
    }

    /// REQ-safe-by-default: a multi-file `env --write` with
    /// `snap.auto_snap_before_fix = true` records exactly one
    /// `refs/getdev/auto/` snapshot BEFORE mutating — the undo point the Phase 2
    /// carry-forward promised (success criterion 4).
    #[test]
    fn env_write_creates_auto_snap_before_mutation() {
        let dir = unique_dir("autosnap-on");
        git_init(&dir);
        seed_two_secret_files(&dir);

        assert_eq!(count_auto_refs(&dir), 0, "no auto ref before the run");
        run(&write_args(&dir, true)).unwrap();

        assert_eq!(
            count_auto_refs(&dir),
            1,
            "exactly one auto-snap must be recorded before the multi-file mutation"
        );
        // and the mutation still happened — the raw secrets left the source
        let one = std::fs::read_to_string(dir.join("one.js")).unwrap();
        assert!(
            one.contains("process.env"),
            "source should be rewritten after the auto-snap, got:\n{one}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Config-honored: with `snap.auto_snap_before_fix = false`, the SAME
    /// multi-file `env --write` records ZERO auto snapshots (the toggle is read
    /// at the call site, so `None` is passed to `env::apply`).
    #[test]
    fn env_write_auto_snap_disabled_by_config() {
        let dir = unique_dir("autosnap-off");
        git_init(&dir);
        seed_two_secret_files(&dir);

        run(&write_args(&dir, false)).unwrap();

        assert_eq!(
            count_auto_refs(&dir),
            0,
            "toggle off must record no auto-snap"
        );
        // the mutation still ran — the toggle only governs the safety snapshot
        let one = std::fs::read_to_string(dir.join("one.js")).unwrap();
        assert!(
            one.contains("process.env"),
            "source is still rewritten with the toggle off, got:\n{one}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// D-07 dedupe: a second immediate `env --write` must not churn the auto
    /// namespace. After the first run the secrets have already been extracted,
    /// so the second run's plan is empty — `env::apply` is never called and no
    /// second auto ref is created. The invariant the user cares about holds: the
    /// auto namespace stays at exactly one ref for back-to-back runs, never
    /// accumulating a duplicate for an unchanged tree.
    #[test]
    fn env_write_twice_dedupes_auto_snap() {
        let dir = unique_dir("autosnap-dedupe");
        git_init(&dir);
        seed_two_secret_files(&dir);

        run(&write_args(&dir, true)).unwrap();
        assert_eq!(count_auto_refs(&dir), 1, "first run records one auto-snap");

        // immediate second run: no secrets remain, so nothing to mutate and no
        // new snapshot — the auto namespace does not gain a duplicate ref.
        run(&write_args(&dir, true)).unwrap();
        assert_eq!(
            count_auto_refs(&dir),
            1,
            "back-to-back run must not add a duplicate auto ref"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SC5 spot-check: `include_urls` (the resolved `--include-urls` flag /
    /// `[env] include_urls` config) switches on 08-02's URL/DSN detection —
    /// a bare connection string is extracted to `.env` under `--write` ONLY
    /// when the gate is on. With it off, the same file is left untouched
    /// (byte-identical to secret-only behaviour).
    #[test]
    fn include_urls_flag_gates_dsn_extraction() {
        // include_urls = TRUE → the DSN is extracted.
        let on = unique_dir("include-urls-on");
        std::fs::write(
            on.join("db.js"),
            "const dbUrl = \"postgres://u:p@host:5432/db\";\n",
        )
        .unwrap();
        let mut args = write_args(&on, false);
        args.include_urls = true;
        run(&args).unwrap();
        let src = std::fs::read_to_string(on.join("db.js")).unwrap();
        assert!(
            src.contains("process.env"),
            "with --include-urls the DSN source must be rewritten, got:\n{src}"
        );
        let env_on = std::fs::read_to_string(on.join(".env")).unwrap();
        assert!(
            env_on.contains("postgres://u:p@host:5432/db"),
            "the DSN value must land in .env, got:\n{env_on}"
        );
        let _ = std::fs::remove_dir_all(&on);

        // include_urls = FALSE → the same DSN is NOT touched (no .env written).
        let off = unique_dir("include-urls-off");
        std::fs::write(
            off.join("db.js"),
            "const dbUrl = \"postgres://u:p@host:5432/db\";\n",
        )
        .unwrap();
        run(&write_args(&off, false)).unwrap();
        let src_off = std::fs::read_to_string(off.join("db.js")).unwrap();
        assert!(
            src_off.contains("\"postgres://u:p@host:5432/db\""),
            "without the gate the DSN source must be untouched, got:\n{src_off}"
        );
        assert!(
            !off.join(".env").exists(),
            "without the gate no .env should be created"
        );
        let _ = std::fs::remove_dir_all(&off);
    }

    /// CR-02 regression: a secret the user suppressed via `[ignore] paths`
    /// must be neither rewritten in source nor appended to `.env` under
    /// `--write`, while a NON-suppressed secret in the same run still is.
    /// The bug was that suppression filtered only the reported findings; the
    /// full `plan.entries` was still applied.
    #[test]
    fn write_never_mutates_a_suppressed_secret() {
        let dir = unique_dir("suppress");
        // suppressed: lives under the ignored path prefix
        std::fs::write(
            dir.join("fixture.js"),
            "const awsKey = \"AKIAFIXTUREFIXTURE01\";\n",
        )
        .unwrap();
        // reported: must still be extracted
        std::fs::write(
            dir.join("keep.js"),
            "const stripeKey = \"sk_live_KEEPKEEPKEEPKEEP01\";\n",
        )
        .unwrap();

        let mut cfg = Config::default();
        cfg.ignore.paths = vec!["fixture.js".to_owned()];

        let args = EnvArgs {
            path: dir.clone(),
            json: false,
            no_color: true,
            fail_on: None,
            env_file: ".env".to_owned(),
            include_urls: false,
            write: true,
            cfg,
            quiet: true,
            verbose: 0,
        };
        run(&args).unwrap();

        // the suppressed source is untouched — raw literal still there, no
        // env accessor injected
        let fixture = std::fs::read_to_string(dir.join("fixture.js")).unwrap();
        assert!(
            fixture.contains("\"AKIAFIXTUREFIXTURE01\""),
            "suppressed secret must not be rewritten in source, got:\n{fixture}"
        );
        assert!(
            !fixture.contains("process.env"),
            "suppressed source must not gain an env accessor, got:\n{fixture}"
        );

        // the non-suppressed source WAS rewritten
        let keep = std::fs::read_to_string(dir.join("keep.js")).unwrap();
        assert!(
            keep.contains("process.env.STRIPE_SECRET_KEY"),
            "reported secret should be extracted, got:\n{keep}"
        );

        // .env holds the reported secret's value but NOT the suppressed one's
        let env_file = std::fs::read_to_string(dir.join(".env")).unwrap();
        assert!(
            env_file.contains("sk_live_KEEPKEEPKEEPKEEP01"),
            "reported secret value should be written to .env, got:\n{env_file}"
        );
        assert!(
            !env_file.contains("AKIAFIXTUREFIXTURE01"),
            "suppressed secret value must NEVER reach .env, got:\n{env_file}"
        );
        assert!(
            !env_file.contains("AWS_ACCESS_KEY_ID"),
            "suppressed secret's var must not be written to .env, got:\n{env_file}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
