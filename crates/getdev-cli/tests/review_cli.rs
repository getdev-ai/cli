//! Hermetic integration tests for `getdev review` (assert_cmd) — the three
//! scope selectors (`--against`/`--staged`/`--all`), the exit-code contract,
//! config-driven suppression of `review/*`, and the non-repo clean-exit path,
//! all proven end-to-end against REAL temp git repos.
//!
//! Every git call here uses the `.args([...])` array API with global/system
//! config blanked and a fixed `getdev`/`noreply@getdev.ai` author identity, so
//! `git commit` never fails on a machine with no global git identity and the
//! setup stays deterministic (snap_lifecycle.rs precedent). Nothing here mutates
//! a checked-in fixture — every repo is built fresh under `std::env::temp_dir()`.
//!
//! `getdev review` is fully offline and never invokes git outside `getdev-gitx`;
//! the boundary invariants are asserted as static grep gates at the bottom of
//! this file. The `Command::new("git")` literal below lives only in `tests/`,
//! which the `src/`-scoped boundary gate deliberately excludes — no
//! self-invalidation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use assert_cmd::Command;

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-cli-review-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Run raw `git` in `dir` for test setup — global/system config blanked so the
/// harness is hermetic regardless of the CI machine's git identity.
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

/// A fresh repo with a hermetic identity and no commits yet.
fn init_repo(label: &str) -> PathBuf {
    let dir = tmp_dir(label);
    assert!(git(&dir, &["init", "--quiet"]).status.success());
    assert!(git(&dir, &["config", "user.name", "getdev"])
        .status
        .success());
    assert!(git(&dir, &["config", "user.email", "noreply@getdev.ai"])
        .status
        .success());
    dir
}

fn write(dir: &Path, rel: &str, content: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

fn commit_all(dir: &Path, message: &str) {
    assert!(git(dir, &["add", "-A"]).status.success());
    assert!(git(dir, &["commit", "-q", "-m", message]).status.success());
}

/// Parse `getdev review --json` stdout into the findings array.
fn findings_of(stdout: &str) -> Vec<serde_json::Value> {
    let report: serde_json::Value = serde_json::from_str(stdout)
        .unwrap_or_else(|err| panic!("stdout was not valid JSON ({err}): {stdout}"));
    report["findings"].as_array().cloned().unwrap_or_default()
}

fn has_finding(findings: &[serde_json::Value], id: &str, file: &str) -> bool {
    findings.iter().any(|f| f["id"] == id && f["file"] == file)
}

/// A base source file with no debug leftover, committed clean.
const CLEAN_JS: &str = "export function add(a, b) {\n  return a + b;\n}\n";
/// The same file plus an introduced `console.log` debug leftover on a NEW line.
const DIRTY_JS: &str = "export function add(a, b) {\n  return a + b;\n}\nconsole.log(\"debug\");\n";

/// Test 1: default scope reports `review/debug-leftover` on an introduced line,
/// and NOT on unchanged pre-existing lines (introduced-scope proof, end-to-end).
#[test]
fn default_scope_reports_review_findings() {
    let dir = init_repo("default");
    write(&dir, "app.js", CLEAN_JS);
    commit_all(&dir, "init");
    // Introduce a debug leftover in the working tree (uncommitted).
    write(&dir, "app.js", DIRTY_JS);

    let assert = getdev()
        .arg("review")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .assert();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let findings = findings_of(&stdout);

    assert!(
        has_finding(&findings, "review/debug-leftover", "app.js"),
        "expected a review/debug-leftover finding on the introduced line, got: {stdout}"
    );
    // The finding must be on line 4 (the introduced line), never the unchanged
    // function body — introduced-scope enforced end-to-end.
    let debug = findings
        .iter()
        .find(|f| f["id"] == "review/debug-leftover")
        .unwrap();
    assert_eq!(
        debug["line"], 4,
        "the finding must be scoped to the introduced line, got: {stdout}"
    );
}

/// D-14 #5 wire population: EVERY finding in `review --json` carries a
/// populated `gdv1:` fingerprint. `review` runs `assign_fingerprints` before
/// `filter_findings` (11-05); this per-command guard proves the standalone
/// `review` diff path stays fingerprinted (RESEARCH Pitfall 1). Mirrors
/// `audit_cli.rs`'s tracer proof.
#[test]
fn review_json_populates_gdv1_fingerprint_on_every_finding() {
    let dir = init_repo("gdv1-wire");
    write(&dir, "app.js", CLEAN_JS);
    commit_all(&dir, "init");
    // Introduce a debug leftover so the default scope reports a finding.
    write(&dir, "app.js", DIRTY_JS);

    let assert = getdev()
        .arg("review")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .assert();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let findings = findings_of(&stdout);
    assert!(
        !findings.is_empty(),
        "expected at least one review finding to assert on, got: {stdout}"
    );
    assert!(
        findings.iter().all(|f| f["fingerprint"]
            .as_str()
            .is_some_and(|fp| fp.starts_with("gdv1:"))),
        "every review --json finding must carry a gdv1: fingerprint, got: {stdout}"
    );
}

/// Test 2: `--against <ref>` reports findings introduced since the ref (working
/// tree vs the ref — Open Q1 LOCKED).
#[test]
fn against_ref_scope() {
    let dir = init_repo("against");
    write(&dir, "app.js", CLEAN_JS);
    commit_all(&dir, "rev1");
    // A second clean revision so HEAD~1 exists and is itself clean.
    write(&dir, "other.js", "export const x = 1;\n");
    commit_all(&dir, "rev2");
    // Now introduce a debug leftover in the working tree.
    write(&dir, "app.js", DIRTY_JS);

    let assert = getdev()
        .arg("review")
        .arg("--against")
        .arg("HEAD~1")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .assert();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let findings = findings_of(&stdout);

    assert!(
        has_finding(&findings, "review/debug-leftover", "app.js"),
        "expected review/debug-leftover introduced since HEAD~1, got: {stdout}"
    );
}

/// Test 3: `--staged` reads the REAL index (Pitfall 1) — a staged-only debug
/// leftover is reported.
#[test]
fn staged_scope() {
    let dir = init_repo("staged");
    write(&dir, "app.js", CLEAN_JS);
    commit_all(&dir, "init");
    // Stage the dirty change (index has the leftover; working tree matches).
    write(&dir, "app.js", DIRTY_JS);
    assert!(git(&dir, &["add", "app.js"]).status.success());

    let assert = getdev()
        .arg("review")
        .arg("--staged")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .assert();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let findings = findings_of(&stdout);

    assert!(
        has_finding(&findings, "review/debug-leftover", "app.js"),
        "expected --staged to read the real index and report the staged leftover, got: {stdout}"
    );
}

/// Test 4: `--all` reports whole-tree findings regardless of any diff — the
/// walker-synthesized full range, no git dependency.
#[test]
fn all_scope() {
    let dir = init_repo("all");
    // Commit the leftover so there is NO diff vs HEAD — only `--all` finds it.
    write(&dir, "app.js", DIRTY_JS);
    commit_all(&dir, "committed with leftover");

    // Sanity: default scope (working tree vs HEAD) has no diff → no findings.
    let default_assert = getdev()
        .arg("review")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .assert();
    let default_stdout = String::from_utf8_lossy(&default_assert.get_output().stdout).to_string();
    assert!(
        findings_of(&default_stdout).is_empty(),
        "default scope must report nothing when the leftover is fully committed, got: {default_stdout}"
    );

    // `--all` treats the whole tree as introduced → the leftover is reported.
    let all_assert = getdev()
        .arg("review")
        .arg("--all")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .assert();
    let all_stdout = String::from_utf8_lossy(&all_assert.get_output().stdout).to_string();
    assert!(
        has_finding(&findings_of(&all_stdout), "review/debug-leftover", "app.js"),
        "--all must report the whole-tree leftover with no diff, got: {all_stdout}"
    );
}

/// Test 5: `getdev review` in a non-git folder prints a clean report and exits
/// 0 — review never `git init`s (unlike snap).
#[test]
fn no_repo_is_clean_exit_zero() {
    let dir = tmp_dir("no-repo");
    // A debug leftover exists, but there is no repo → no diff → clean.
    write(&dir, "app.js", DIRTY_JS);
    assert!(
        !dir.join(".git").exists(),
        "the scratch dir must not be a git repo"
    );

    let assert = getdev()
        .arg("review")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .assert()
        .code(0);
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        findings_of(&stdout).is_empty(),
        "a non-repo has no diff, so review reports nothing and exits 0, got: {stdout}"
    );
}

/// Test 6: config `[ignore]` suppresses a `review/*` rule identically to
/// `audit/*` — review participates in the generic suppression path, no carve-out
/// (06-RESEARCH Open Q3 LOCKED). Review has no `--ignore` flag of its own (its
/// contractual scope is the three scope selectors), so suppression is proven via
/// the config file — the same `suppress::filter_findings` mechanism.
#[test]
fn ignore_suppresses_review_rule() {
    let dir = init_repo("ignore");
    write(&dir, "app.js", CLEAN_JS);
    commit_all(&dir, "init");
    write(&dir, "app.js", DIRTY_JS);
    // Config-driven suppression of the review rule.
    write(
        &dir,
        ".getdev.toml",
        "[ignore]\nrules = [\"review/debug-leftover\"]\n",
    );

    let assert = getdev()
        .arg("review")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .assert();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let findings = findings_of(&stdout);

    assert!(
        findings.iter().all(|f| f["id"] != "review/debug-leftover"),
        "config [ignore] must suppress the review rule (no carve-out), got: {stdout}"
    );
}

/// Test 7: exit-code contract — a medium `review/debug-leftover` with
/// `--fail-on medium` exits 1; `--fail-on high` exits 0.
#[test]
fn fail_on_sets_exit_one() {
    let dir = init_repo("fail-on");
    write(&dir, "app.js", CLEAN_JS);
    commit_all(&dir, "init");
    write(&dir, "app.js", DIRTY_JS);

    // A bare run always exits 0 regardless of findings.
    getdev()
        .arg("review")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .assert()
        .code(0);

    // The leftover is medium → --fail-on medium exits 1.
    getdev()
        .arg("review")
        .arg("--fail-on")
        .arg("medium")
        .arg("--path")
        .arg(&dir)
        .assert()
        .code(1);

    // No high/critical finding → --fail-on high exits 0.
    getdev()
        .arg("review")
        .arg("--fail-on")
        .arg("high")
        .arg("--path")
        .arg(&dir)
        .assert()
        .code(0);
}

/// `getdev review --help` exposes exactly the three sanctioned scope flags (plus
/// inherited globals) — no review-specific flag beyond `--against`/`--staged`/
/// `--all` (CLAUDE.md rule 6 / docs/PLAN.md §2.3).
#[test]
fn help_lists_exactly_the_three_scope_flags() {
    let assert = getdev().arg("review").arg("--help").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(stdout.contains("--against"));
    assert!(stdout.contains("--staged"));
    assert!(stdout.contains("--all"));
    // review must never accept audit's or real's own flags (a scope leak would
    // be a CLAUDE.md rule 6 violation).
    assert!(!stdout.contains("--severity"));
    assert!(!stdout.contains("--rules"));
    assert!(!stdout.contains("--deps-only"));
}

/// Test 8: `--against`/`--staged`/`--all` are mutually exclusive — clap rejects
/// any pair at parse time (never runs the analyzer twice / ambiguously).
#[test]
fn scope_flags_are_mutually_exclusive() {
    getdev()
        .arg("review")
        .arg("--staged")
        .arg("--all")
        .assert()
        .failure();
    getdev()
        .arg("review")
        .arg("--against")
        .arg("HEAD")
        .arg("--staged")
        .assert()
        .failure();
    getdev()
        .arg("review")
        .arg("--against")
        .arg("HEAD")
        .arg("--all")
        .assert()
        .failure();
}

/// Boundary invariant (T-06-14): no direct git-binary invocation in the review
/// command or `core::review` — all diff work routes through `getdev-gitx`. The
/// gate is scoped to `src/` so this test file's own `Command::new("git")` (used
/// only for repo setup) is excluded.
#[test]
fn git_binary_is_never_invoked_from_review_source() {
    let root = repo_root();
    assert_no_match(
        &root.join("crates/getdev-cli/src/commands/review.rs"),
        "Command::new(\"git\")",
    );
    assert_dir_no_match(
        &root.join("crates/getdev-core/src/review"),
        "Command::new(\"git\")",
    );
}

/// Boundary invariant: the review command imports no registry crate type (no
/// network) and `core::review` likewise stays network-free.
#[test]
fn review_source_is_network_free() {
    let root = repo_root();
    assert_no_match(
        &root.join("crates/getdev-cli/src/commands/review.rs"),
        "getdev_registry",
    );
    assert_dir_no_match(
        &root.join("crates/getdev-core/src/review"),
        "getdev_registry",
    );
}

/// The workspace root — `CARGO_MANIFEST_DIR` is `crates/getdev-cli`, so go up two.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above the cli crate")
        .to_path_buf()
}

fn assert_no_match(file: &Path, needle: &str) {
    let contents = std::fs::read_to_string(file)
        .unwrap_or_else(|err| panic!("read {} failed: {err}", file.display()));
    assert!(
        !contents.contains(needle),
        "{} must not contain `{needle}`",
        file.display()
    );
}

fn assert_dir_no_match(dir: &Path, needle: &str) {
    for entry in std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read_dir {} failed: {err}", dir.display()))
    {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") {
            assert_no_match(&path, needle);
        }
    }
}
