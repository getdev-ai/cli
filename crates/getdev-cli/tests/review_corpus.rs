//! Hermetic two-state corpus integration tests — the P5 exit gate
//! (ROADMAP Phase 6 Success Criterion 3, REQ-cmd-review's exit criteria):
//! on a realistic `base/` → `after/` agent-session-diff corpus, `getdev
//! review` catches **≥80%** of the seeded artifacts (recall) with a per-rule
//! sentinel **false-positive rate < 10%**.
//!
//! Unlike `real`/`audit`'s flat single-tree `corpus.rs`, review analyzes a
//! DIFF, so each corpus app carries two tree states. This harness materializes
//! each app into a throwaway git repo at test time (06-RESEARCH.md A6):
//!
//!   1. copy `<app>/base/` into a temp dir, `git init`, commit it under a
//!      hermetic `getdev` identity (global/system config blanked, so the run
//!      is deterministic regardless of the CI machine's git config);
//!   2. overlay `<app>/after/` on top of the working tree (add/replace files);
//!   3. run `getdev review --json --path <tmp>` — the default working-tree-vs-
//!      HEAD scope, so the diff *is* the `base → after` delta.
//!
//! Fully hermetic: review is network-free by construction (06-05, imports no
//! `getdev_registry` type), and this harness only ever writes to a temp dir —
//! it never mutates a fixture under `testdata/corpus/review/`. The
//! `Command::new("git")` literal lives only in this `tests/` setup code; the
//! REVIEW code path itself invokes git exclusively through `getdev-gitx`
//! (asserted by `review_cli.rs`'s boundary gate).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use serde::Deserialize;
use serde_json::Value;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/review")
}

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-review-corpus-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

#[derive(Debug, Deserialize)]
struct ExpectedCatalog {
    seeded: Vec<ExpectedFinding>,
}

#[derive(Debug, Deserialize)]
struct ExpectedFinding {
    /// Matching is by rule `id` + `file`, the stable recall criterion (a
    /// seeded artifact's exact line can shift as the corpus evolves), mirroring
    /// `corpus.rs`'s `real`/`audit` recall gate.
    id: String,
    file: String,
}

/// Run raw `git` in `dir` for test setup — global/system config blanked so the
/// harness stays hermetic regardless of the CI machine's git config, mirroring
/// `review_cli.rs`/`getdev-gitx::snap`'s discipline.
fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    StdCommand::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("git should run in tests")
}

/// Recursively copy every file under `src` into `dst` (creating parents),
/// overwriting existing files — the overlay semantics `after/` needs.
fn copy_tree(src: &Path, dst: &Path) {
    for entry in
        std::fs::read_dir(src).unwrap_or_else(|err| panic!("read {}: {err}", src.display()))
    {
        let entry = entry.expect("dir entry");
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            std::fs::create_dir_all(&to).expect("create dir");
            copy_tree(&from, &to);
        } else {
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent).expect("create parent");
            }
            std::fs::copy(&from, &to)
                .unwrap_or_else(|err| panic!("copy {} -> {}: {err}", from.display(), to.display()));
        }
    }
}

/// Materialize `<app>/base/` + `<app>/after/` into a throwaway git repo and
/// return its path (caller removes it). Commits `base/`, then overlays
/// `after/` onto the working tree so `git diff HEAD` is exactly the agent-
/// session delta. Never writes under `testdata/corpus/review/`.
fn materialize(app_dir: &Path, label: &str) -> PathBuf {
    let repo = tmp_dir(label);

    let base = app_dir.join("base");
    assert!(
        base.is_dir(),
        "corpus app {} is missing a base/ tree",
        app_dir.display()
    );
    copy_tree(&base, &repo);

    assert!(
        git(&repo, &["init", "--quiet"]).status.success(),
        "git init failed for {label}"
    );
    assert!(git(&repo, &["config", "user.name", "getdev"])
        .status
        .success());
    assert!(git(&repo, &["config", "user.email", "noreply@getdev.ai"])
        .status
        .success());
    // Deterministic default branch name irrespective of the host's
    // init.defaultBranch config (already neutralized, but explicit is safer).
    let _ = git(&repo, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    assert!(
        git(&repo, &["add", "-A"]).status.success(),
        "git add failed for {label}"
    );
    assert!(
        git(&repo, &["commit", "-q", "-m", "base"]).status.success(),
        "git commit failed for {label}"
    );

    // Overlay the agent-session delta onto the working tree.
    let after = app_dir.join("after");
    assert!(
        after.is_dir(),
        "corpus app {} is missing an after/ tree",
        app_dir.display()
    );
    copy_tree(&after, &repo);

    repo
}

/// Run `getdev review --json --path <repo>` (default working-tree-vs-HEAD
/// scope) and parse the `FindingsReport` JSON. No `--fail-on` is ever passed,
/// so a clean review of any corpus app must exit 0 — a crash or non-zero exit
/// on ONE app fails the whole gate loudly rather than being swallowed by a
/// JSON-parse panic (mirrors `corpus.rs`'s recall-gate hardening).
fn run_review(repo: &Path, label: &str) -> Value {
    let assert = getdev()
        .arg("review")
        .arg("--json")
        .arg("--path")
        .arg(repo)
        .timeout(Duration::from_secs(30))
        .assert();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let code = output.status.code();
    assert_eq!(
        code,
        Some(0),
        "getdev review crashed or exited non-zero for {label} ({}) — exit={code:?} \
         stdout={stdout} stderr={stderr}",
        repo.display(),
    );
    serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!(
            "stdout was not valid JSON ({err}) for {label} ({}): stdout={stdout} stderr={stderr}",
            repo.display(),
        )
    })
}

/// Every `review/*` finding in a parsed report.
fn review_findings(report: &Value) -> Vec<&Value> {
    report["findings"]
        .as_array()
        .expect("findings is an array")
        .iter()
        .filter(|f| f["id"].as_str().is_some_and(|id| id.starts_with("review/")))
        .collect()
}

/// A finding counts toward the false-positive budget only at warning+ severity
/// (low/medium/high/critical). An `info` finding — `review/todo-introduced`, an
/// intentional marker rather than a defect — is excluded, identical to the
/// `real`/`audit` budget in `corpus.rs`.
fn is_warning_plus(finding: &Value) -> bool {
    finding["severity"].as_str() != Some("info")
}

fn list_app_dirs(dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn seeded_apps() -> Vec<PathBuf> {
    list_app_dirs(&corpus_root().join("seeded"))
}

fn sentinel_apps() -> Vec<PathBuf> {
    list_app_dirs(&corpus_root().join("sentinels"))
}

fn app_label(app_dir: &Path) -> String {
    app_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_owned()
}

/// Every source file (JS/TS/TSX/Python) under `dir` — the false-positive-rate
/// denominator. Duplicated from `corpus.rs` (no shared test-support crate
/// exists in this workspace); `node_modules`/`site-packages` are skipped.
fn count_source_files(dir: &Path) -> usize {
    fn walk(dir: &Path, count: &mut usize) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if matches!(
                    path.file_name().and_then(|n| n.to_str()),
                    Some("node_modules" | "site-packages" | ".git")
                ) {
                    continue;
                }
                walk(&path, count);
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if matches!(
                    ext,
                    "js" | "jsx" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "tsx" | "py"
                ) {
                    *count += 1;
                }
            }
        }
    }
    let mut count = 0;
    walk(dir, &mut count);
    count
}

/// The P5 recall gate: on the two-state seeded corpus, `getdev review` catches
/// **≥80%** of the catalogued agent-debris artifacts (matched by `id` + `file`
/// against each app's `getdev-expected.json`). Recall is ≥80% rather than 100%
/// because containment-scoping legitimately misses a declaration split across
/// two hunks (06-RESEARCH.md Pattern 2's documented recall gap) — a hard 100%
/// would be an over-tight gate.
///
/// A seeded app also doubles as its own sentinel: every warning+ finding
/// OUTSIDE its catalogued `(id, file)` pairs is surfaced as a hard failure, so
/// recall cannot pass by drowning a real signal in extra false positives (the
/// `corpus.rs` D3 check, adapted to the two-state corpus).
#[test]
fn review_seeded_recall() {
    let apps = seeded_apps();
    assert!(
        apps.len() >= 6,
        "expected >= 6 seeded review apps, found {}",
        apps.len()
    );

    let mut catalogued = 0usize;
    let mut matched = 0usize;
    let mut misses = Vec::new();
    let mut unexpected = Vec::new();
    let mut per_rule_seen: BTreeMap<String, usize> = BTreeMap::new();

    for app_dir in &apps {
        let label = app_label(app_dir);
        let expected_path = app_dir.join("getdev-expected.json");
        let expected: ExpectedCatalog = serde_json::from_str(
            &std::fs::read_to_string(&expected_path)
                .unwrap_or_else(|err| panic!("read {}: {err}", expected_path.display())),
        )
        .unwrap_or_else(|err| panic!("parse {}: {err}", expected_path.display()));
        assert!(
            !expected.seeded.is_empty(),
            "{label}: getdev-expected.json has no seeded entries"
        );

        let repo = materialize(app_dir, &label);
        let report = run_review(&repo, &label);
        let findings = review_findings(&report);

        for exp in &expected.seeded {
            *per_rule_seen.entry(exp.id.clone()).or_insert(0) += 1;
            catalogued += 1;
            let hit = findings.iter().any(|f| {
                f["id"].as_str() == Some(exp.id.as_str())
                    && f["file"].as_str() == Some(exp.file.as_str())
            });
            if hit {
                matched += 1;
            } else {
                misses.push(format!("{label}: missing {} @ {}", exp.id, exp.file));
            }
        }

        let allowed: std::collections::HashSet<(&str, &str)> = expected
            .seeded
            .iter()
            .map(|exp| (exp.id.as_str(), exp.file.as_str()))
            .collect();
        for f in &findings {
            if !is_warning_plus(f) {
                continue; // info markers never count as false extras
            }
            let id = f["id"].as_str().unwrap_or("?");
            let file = f["file"].as_str().unwrap_or("?");
            if !allowed.contains(&(id, file)) {
                unexpected.push(format!(
                    "{label}: unexpected {id} @ {file} [{}] :: {}",
                    f["severity"].as_str().unwrap_or("?"),
                    f["message"].as_str().unwrap_or("?"),
                ));
            }
        }

        let _ = std::fs::remove_dir_all(&repo);
    }

    // Each of the six review/* rule ids must be seeded at least twice.
    let rule_summary: Vec<String> = per_rule_seen
        .iter()
        .map(|(id, n)| format!("  {id}: {n}"))
        .collect();
    let all_six = [
        "review/debug-leftover",
        "review/todo-introduced",
        "review/dead-code-introduced",
        "review/duplicate-helper",
        "review/commented-code-block",
        "review/orphan-file",
    ];
    for id in all_six {
        let n = per_rule_seen.get(id).copied().unwrap_or(0);
        assert!(
            n >= 2,
            "rule {id} is seeded only {n} time(s); the corpus must cover each of the six \
             review/* rules >= 2x:\n{}",
            rule_summary.join("\n")
        );
    }

    let recall = matched as f64 / catalogued.max(1) as f64;
    assert!(
        recall >= 0.80,
        "seeded recall {:.1}% is below the 80% P5 exit criterion ({matched}/{catalogued} \
         catalogued artifacts caught) -- missed findings:\n{}",
        recall * 100.0,
        misses.join("\n")
    );
    assert!(
        unexpected.is_empty(),
        "seeded apps produced warning+ findings beyond their catalogued getdev-expected.json \
         entries — recall can pass while the analyzer drowns a real signal in extra false \
         positives; if an extra finding is legitimately correct, add it to that app's catalogue \
         with a comment (never loosen this assertion):\n{}",
        unexpected.join("\n")
    );
}

/// The P5 false-positive gate: across every SENTINEL app's materialized after-
/// state, each `review/*` rule's warning+ false-positive rate — that rule's
/// finding count ÷ the total number of source files scanned across the whole
/// sentinel set — must stay under **10%** (the P5 budget, looser than
/// `audit`/`real`'s 5% per the ROADMAP, reflecting review's heuristic
/// detectors). Computed PER RULE ID, never a diluted aggregate across rules
/// (the `corpus.rs` D3 methodology). Info-severity findings are excluded.
///
/// Each sentinel's `after/` is a legitimate change targeting a specific FP-
/// guard class locked in 06-03/06-04 (string-reference widening, framework-
/// entry exemption, decorator exemption, prose/JSDoc, sibling-import) — so a
/// regression in any guard resurfaces here as a rule breaching the budget.
#[test]
fn review_fp_budget() {
    let apps = sentinel_apps();
    assert!(
        apps.len() >= 4,
        "expected >= 4 sentinel review apps, found {}",
        apps.len()
    );

    let mut total_files = 0usize;
    let mut per_rule_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut offenders = Vec::new();

    for app_dir in &apps {
        let label = app_label(app_dir);
        let repo = materialize(app_dir, &label);
        let report = run_review(&repo, &label);
        let findings = review_findings(&report);
        total_files += count_source_files(&repo);

        for f in &findings {
            let id = f["id"].as_str().unwrap_or("?").to_owned();
            let counted = is_warning_plus(f);
            if counted {
                *per_rule_counts.entry(id.clone()).or_insert(0) += 1;
            }
            offenders.push(format!(
                "{label}: {id} [{}/{}]{} {}:{} :: {}",
                f["severity"].as_str().unwrap_or("?"),
                f["confidence"].as_str().unwrap_or("?"),
                if counted {
                    ""
                } else {
                    " (info — excluded from the budget)"
                },
                f["file"].as_str().unwrap_or("?"),
                f["line"]
                    .as_u64()
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                f["message"].as_str().unwrap_or("?"),
            ));
        }

        let _ = std::fs::remove_dir_all(&repo);
    }

    let denom = total_files.max(1) as f64;
    let mut table = Vec::new();
    let mut failures = Vec::new();
    for (rule_id, count) in &per_rule_counts {
        let rate = *count as f64 / denom;
        table.push(format!(
            "  {rule_id}: {count}/{total_files} files = {:.1}%",
            rate * 100.0
        ));
        if rate >= 0.10 {
            failures.push(format!(
                "{rule_id}: {:.1}% ({count}/{total_files} files) >= the 10% budget",
                rate * 100.0
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "per-rule sentinel false-positive rate exceeds the 10% P5 budget:\n{}\n\n\
         per-rule breakdown ({total_files} source files scanned across {} sentinels):\n{}\n\n\
         every finding:\n{}",
        failures.join("\n"),
        apps.len(),
        table.join("\n"),
        offenders.join("\n")
    );
}
