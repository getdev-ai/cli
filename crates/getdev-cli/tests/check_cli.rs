//! Hermetic integration tests for `getdev check` (assert_cmd). Every
//! invocation sets `GETDEV_OFFLINE=1` and points `GETDEV_CACHE_DIR` at a
//! seeded scratch directory — zero live network egress (docs/TESTING.md "no
//! network in CI"). These prove: the four-analyzer fan-in over ONE shared
//! ScanContext, the Ship Score in the JSON envelope, the `--json --fail-on
//! high` exit-code contract, the `--offline` no-network guarantee, and that
//! the score is exactly the versioned severity-weight formula.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use getdev_registry::{Cache, Ecosystem, Existence};
use serde_json::Value;

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-cli-check-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Run `getdev check --json --offline` over `dir` with `cache_dir` seeded,
/// returning the parsed report and the process exit code. Extra args (e.g.
/// `--fail-on high`) are appended.
fn run_check_json(dir: &Path, cache_dir: &Path, extra: &[&str]) -> (Value, i32) {
    let mut cmd = getdev();
    cmd.env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", cache_dir)
        // hermetic git — `env`'s committed-file check and any gitx path must
        // never read the developer's real global/system git config.
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .arg("check")
        .arg("--offline")
        .arg("--json")
        .arg("--path")
        .arg(dir);
    for a in extra {
        cmd.arg(a);
    }
    let output = cmd.assert().get_output().clone();
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout was not valid JSON ({err}): {stdout}"));
    (report, code)
}

fn finding_ids(report: &Value) -> Vec<String> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// The four-analyzer fan-in: one project seeding a finding per analyzer family
/// (a nonexistent dep for `real`, a hardcoded secret for `audit`/`env`, a
/// debug leftover for `review`) yields ONE scored report whose findings carry
/// the `real/`, `audit/`+`env/`, and `review/` prefixes — proof the single
/// shared ScanContext feeds every analyzer.
#[test]
fn check_json_aggregates_four_analyzers() {
    let dir = tmp_dir("aggregate");
    let cache_dir = dir.join("cache");

    // real: a declared package seeded Missing → real/nonexistent-package.
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"t","dependencies":{"totally-fake-pkg-xyz":"^1.0.0"}}"#,
    )
    .unwrap();
    // audit + env: a hardcoded live secret. review: a debug leftover.
    std::fs::write(
        dir.join("app.js"),
        "const stripeKey = \"sk_live_ABCDEFGHIJKLMNOP01\";\n\
         console.log(\"debug\", stripeKey);\n",
    )
    .unwrap();

    let cache = Cache::open_at(&cache_dir).unwrap();
    cache
        .put_existence(Ecosystem::Npm, "totally-fake-pkg-xyz", Existence::Missing)
        .unwrap();
    drop(cache);

    let (report, code) = run_check_json(&dir, &cache_dir, &[]);

    // score is present — `check` is the only command that sets it.
    assert!(
        report["score"].is_u64(),
        "check --json must carry a Ship Score, got: {report}"
    );
    // no --fail-on given → exit 0 regardless of severity.
    assert_eq!(code, 0, "no --fail-on must exit 0");

    let ids = finding_ids(&report);
    let prefix = |p: &str| ids.iter().any(|id| id.starts_with(p));
    assert!(prefix("real/"), "expected a real/* finding, got {ids:?}");
    assert!(
        prefix("audit/") || prefix("env/"),
        "expected an audit/* or env/* secret finding, got {ids:?}"
    );
    assert!(
        prefix("review/"),
        "expected a review/* finding, got {ids:?}"
    );
    assert!(
        ids.iter().any(|id| id == "real/nonexistent-package"),
        "the seeded Missing package must surface, got {ids:?}"
    );

    // B-02: `check --json` populates `project.stack` (it used to be an empty
    // list even when `ship` detected the stack on the same tree). A project
    // with a `package.json` detects at least `node`.
    let stack: Vec<String> = report["project"]["stack"]
        .as_array()
        .expect("project.stack must be an array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(
        stack.iter().any(|s| s == "node"),
        "check --json must report the detected stack (expected 'node'), got {stack:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The `--json --fail-on high` exit-code contract (docs/PLAN.md §2.2): a
/// project with a finding at/above `high` exits 1; a project with only
/// sub-`high` findings exits 0; a malformed config exits 3. All via the shared
/// `Summary::at_or_above` comparator — no bespoke check-only threshold.
#[test]
fn fail_on_high_exit_contract() {
    // (1) a critical secret → at_or_above(high) > 0 → exit 1.
    let hi = tmp_dir("failon-high");
    let hi_cache = hi.join("cache");
    std::fs::write(
        hi.join("app.js"),
        "const stripeKey = \"sk_live_ABCDEFGHIJKLMNOP01\";\n",
    )
    .unwrap();
    let (_report, code) = run_check_json(&hi, &hi_cache, &["--fail-on", "high"]);
    assert_eq!(
        code, 1,
        "a critical finding with --fail-on high must exit 1"
    );

    // (2) only a sub-high finding (an INFO-level TODO marker) → exit 0.
    let lo = tmp_dir("failon-low");
    let lo_cache = lo.join("cache");
    std::fs::write(lo.join("app.js"), "// TODO: finish this later\n").unwrap();
    let (report, code) = run_check_json(&lo, &lo_cache, &["--fail-on", "high"]);
    assert_eq!(
        code, 0,
        "a project with no >=high findings must exit 0, got: {report}"
    );

    // (3) a malformed .getdev.toml → config error → exit 3.
    let bad = tmp_dir("failon-badcfg");
    let bad_cache = bad.join("cache");
    std::fs::write(bad.join("app.js"), "const x = 1;\n").unwrap();
    std::fs::write(bad.join(".getdev.toml"), "this = = not valid toml\n").unwrap();
    let output = getdev()
        .env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", &bad_cache)
        .arg("check")
        .arg("--offline")
        .arg("--json")
        .arg("--fail-on")
        .arg("high")
        .arg("--path")
        .arg(&bad)
        .assert()
        .get_output()
        .clone();
    assert_eq!(
        output.status.code().unwrap_or(-1),
        3,
        "a malformed config must exit 3 (docs/PLAN.md §2.2)"
    );

    let _ = std::fs::remove_dir_all(&hi);
    let _ = std::fs::remove_dir_all(&lo);
    let _ = std::fs::remove_dir_all(&bad);
}

/// `--offline` completes cache-only with zero network egress and still
/// produces a scored report — proof `check` adds no new network path and
/// honors `--offline` (an UNSEEDED package resolves Inconclusive, never a
/// fabricated finding). The `GETDEV_OFFLINE=1` harness makes any registry HTTP
/// a hard error, so a clean exit is itself the no-egress proof.
#[test]
fn offline_no_network() {
    let dir = tmp_dir("offline");
    let cache_dir = dir.join("cache");
    // A declared package with NO cache seed at all — under --offline it must
    // resolve Inconclusive (no network to confirm), never Missing.
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"t","dependencies":{"some-uncached-pkg-xyz":"^1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("app.js"), "const x = 1;\n").unwrap();

    let (report, code) = run_check_json(&dir, &cache_dir, &[]);
    assert_eq!(code, 0, "offline check on a clean-ish project exits 0");
    assert!(report["score"].is_u64(), "offline check still scores");
    let ids = finding_ids(&report);
    assert!(
        !ids.iter().any(|id| id == "real/nonexistent-package"),
        "an uncached package under --offline must NOT fabricate real/nonexistent-package, got {ids:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// End-to-end cross-check of Task 1's formula: the JSON `score` equals
/// `100 − (25·critical + 10·high + 4·medium + 1·low)` floored at 0, computed
/// from the report's own summary — the versioned weights, proven through the
/// whole command.
#[test]
fn score_reflects_severity_weights() {
    let dir = tmp_dir("score");
    let cache_dir = dir.join("cache");
    // A single hardcoded secret → exactly ONE critical in the aggregate:
    // audit/hardcoded-secret and env/hardcoded-secret are the same underlying
    // detection, and check dedupes audit's twin in favor of env's fixable
    // finding (one secret must never dent the Ship Score twice).
    std::fs::write(
        dir.join("app.js"),
        "const stripeKey = \"sk_live_ABCDEFGHIJKLMNOP01\";\n",
    )
    .unwrap();

    let (report, _code) = run_check_json(&dir, &cache_dir, &[]);
    let summary = &report["summary"];
    let count = |k: &str| summary[k].as_i64().unwrap_or(0);
    let deduction =
        25 * count("critical") + 10 * count("high") + 4 * count("medium") + count("low");
    let expected = (100 - deduction).clamp(0, 100);
    let score = report["score"].as_i64().unwrap();
    assert_eq!(
        score, expected,
        "score must equal the versioned weight formula; summary={summary}"
    );
    // the secret is counted ONCE, and the survivor is env's fixable finding.
    assert_eq!(
        count("critical"),
        1,
        "one hardcoded secret must yield exactly one critical after the audit/env dedupe, got {summary}"
    );
    let ids = finding_ids(&report);
    assert!(
        ids.iter().any(|id| id == "env/hardcoded-secret"),
        "the kept finding is env's fixable one, got {ids:?}"
    );
    assert!(
        !ids.iter().any(|id| id == "audit/hardcoded-secret"),
        "audit's twin of the same secret must be deduped, got {ids:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// D-14 #5 wire population: EVERY finding in `check --json` carries a populated
/// `gdv1:` fingerprint. `check` runs `assign_fingerprints` on the aggregate
/// real→audit→env→review vector before `filter_findings` (11-05); this is the
/// per-command regression guard that the batch pass never silently skips the
/// aggregate seam (RESEARCH Pitfall 1). Mirrors `audit_cli.rs`'s tracer proof.
#[test]
fn check_json_populates_gdv1_fingerprint_on_every_finding() {
    let dir = tmp_dir("gdv1-wire");
    let cache_dir = dir.join("cache");
    // A hardcoded secret + a debug leftover — seeds findings across the
    // audit/env and review families so the "every finding" quantifier is not
    // vacuously true over a single analyzer.
    std::fs::write(
        dir.join("app.js"),
        "const stripeKey = \"sk_live_ABCDEFGHIJKLMNOP01\";\n\
         console.log(\"debug\", stripeKey);\n",
    )
    .unwrap();

    let (report, _code) = run_check_json(&dir, &cache_dir, &[]);
    let findings = report["findings"].as_array().unwrap();
    assert!(
        !findings.is_empty(),
        "expected at least one finding to assert on, got: {report}"
    );
    assert!(
        findings.iter().all(|f| f["fingerprint"]
            .as_str()
            .is_some_and(|fp| fp.starts_with("gdv1:"))),
        "every check --json finding must carry a gdv1: fingerprint, got: {report}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The first-run no-config hint (docs/SPEC-COMMANDS.md `check`) is NEVER part of
/// the machine-readable output: a config-less project run under `--json` must
/// yield clean JSON with no `using built-in defaults …` line (determinism — the
/// hint lives only in the human render). The human render additionally gates the
/// hint on a TTY stdout, so under a piped `assert_cmd` stdout it is suppressed
/// there too; the renderer's positive path is unit-tested in `core::report`.
#[test]
fn no_config_hint_is_absent_from_machine_output() {
    let dir = tmp_dir("no-config-hint");
    let cache_dir = dir.join("cache");
    // A minimal source file, and crucially NO .getdev.toml — the condition that
    // arms the hint on the human path.
    std::fs::write(dir.join("app.js"), "const x = 1;\n").unwrap();
    assert!(
        !dir.join(".getdev.toml").exists(),
        "this test requires a config-less project"
    );

    // --json: the hint must never appear in the JSON envelope.
    let mut cmd = getdev();
    let json_out = cmd
        .env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .args(["check", "--offline", "--json", "--path"])
        .arg(&dir)
        .assert()
        .success()
        .get_output()
        .clone();
    let json_stdout = String::from_utf8_lossy(&json_out.stdout);
    assert!(
        !json_stdout.contains("using built-in defaults"),
        "the no-config hint must never appear under --json, got:\n{json_stdout}"
    );

    // Plain (human) render over a piped stdout: the hint is TTY-gated, so it is
    // suppressed here as well — stdout stays clean for pipes/CI.
    let mut cmd = getdev();
    let human_out = cmd
        .env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .args(["check", "--offline", "--no-color", "--path"])
        .arg(&dir)
        .assert()
        .success()
        .get_output()
        .clone();
    let human_stdout = String::from_utf8_lossy(&human_out.stdout);
    assert!(
        !human_stdout.contains("using built-in defaults"),
        "the hint is TTY-gated and must be suppressed on a piped stdout, got:\n{human_stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---- LOOP-01 / LOOP-02 (12-03): --min-score gate + --format=agent -----------

/// Seed a scratch project with a hardcoded live secret (critical) plus a debug
/// leftover (medium) so `check` yields a multi-finding, well-below-100 Ship
/// Score — the representative fixture for the gate and agent-format tests.
fn seed_multi_finding_project(dir: &Path) {
    std::fs::write(
        dir.join("app.js"),
        "const stripeKey = \"sk_live_ABCDEFGHIJKLMNOP01\";\n\
         console.log(\"debug\", stripeKey);\n",
    )
    .unwrap();
}

/// Run `getdev check` over `dir` returning RAW stdout + exit code (no forced
/// `--json`, so `--format=agent`/`--min-score` can be exercised). Hermetic:
/// offline + seeded cache + nulled git config, like `run_check_json`.
fn run_check_raw(dir: &Path, cache_dir: &Path, extra: &[&str]) -> (String, i32) {
    let mut cmd = getdev();
    cmd.env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", cache_dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .arg("check")
        .arg("--offline")
        .arg("--no-color")
        .arg("--path")
        .arg(dir);
    for a in extra {
        cmd.arg(a);
    }
    let output = cmd.assert().get_output().clone();
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    (stdout, code)
}

/// SC1 / D-01/D-02: `--min-score` shares exit code `1` with `--fail-on` — a
/// score below the floor exits `1`; a score at/above it exits `0`.
#[test]
fn min_score_gate_shares_exit_code_one() {
    let dir = tmp_dir("min-score-gate");
    let cache = dir.join("cache");
    seed_multi_finding_project(&dir);

    // The critical secret drags the Ship Score well below 100.
    let (_out, fail_code) = run_check_raw(&dir, &cache, &["--min-score", "100", "--quiet"]);
    assert_eq!(
        fail_code, 1,
        "score < --min-score must exit 1 (shared with --fail-on)"
    );

    let (_out, pass_code) = run_check_raw(&dir, &cache, &["--min-score", "1", "--quiet"]);
    assert_eq!(pass_code, 0, "score >= --min-score must exit 0");
}

/// D-02: the two gates compose OR-to-fail / AND-to-pass — either tripping fails,
/// both passing succeeds.
#[test]
fn min_score_and_fail_on_compose_or_to_fail() {
    // Dirty project: a critical secret → a critical finding AND a sub-100 score.
    let dirty = tmp_dir("gate-dirty");
    let dcache = dirty.join("cache");
    seed_multi_finding_project(&dirty);
    // fail-on critical is MET (min-score 0 passes) → 1 (the severity gate trips).
    let (_o, c_sev) = run_check_raw(
        &dirty,
        &dcache,
        &["--fail-on", "critical", "--min-score", "0", "--quiet"],
    );
    assert_eq!(
        c_sev, 1,
        "a met --fail-on trips the OR gate even if score passes"
    );
    // score gate trips (min 100) while fail-on critical is also met → 1.
    let (_o, c_both) = run_check_raw(
        &dirty,
        &dcache,
        &["--fail-on", "low", "--min-score", "100", "--quiet"],
    );
    assert_eq!(c_both, 1, "both gates tripping → 1");

    // Clean project: no findings, score 100 → both gates pass → 0.
    let clean = tmp_dir("gate-clean");
    let ccache = clean.join("cache");
    std::fs::write(clean.join("ok.js"), "export const x = 1;\n").unwrap();
    let (_o, c_pass) = run_check_raw(
        &clean,
        &ccache,
        &["--fail-on", "critical", "--min-score", "0", "--quiet"],
    );
    assert_eq!(c_pass, 0, "both gates passing → 0 (AND-to-pass)");
}

/// SC2 / D-05..D-08: `--format=agent` emits the documented
/// GATE/SUMMARY/FINDINGS/NEXT-ACTIONS shape with the `gdv1:` fingerprint, is
/// ANSI-free, and leaks no raw secret value.
#[test]
fn format_agent_emits_the_documented_shape_no_ansi_no_secret() {
    let dir = tmp_dir("agent-shape");
    let cache = dir.join("cache");
    seed_multi_finding_project(&dir);
    let (out, _code) = run_check_raw(&dir, &cache, &["--format", "agent"]);
    assert!(
        out.starts_with("GATE: "),
        "agent output starts with GATE:\n{out}"
    );
    assert!(
        out.contains("\nSUMMARY: "),
        "agent output carries SUMMARY:\n{out}"
    );
    assert!(
        out.contains("\nFINDINGS:\n"),
        "agent output carries FINDINGS:\n{out}"
    );
    assert!(
        out.contains("NEXT ACTIONS:"),
        "agent output carries NEXT ACTIONS:\n{out}"
    );
    assert!(
        out.contains("gdv1:"),
        "agent finding lines carry the gdv1: fingerprint:\n{out}"
    );
    assert!(
        !out.contains('\u{1b}'),
        "agent output must be ANSI-free:\n{out}"
    );
    assert!(
        !out.contains("sk_live_ABCDEFGHIJKLMNOP01"),
        "the raw secret value must never appear in agent output:\n{out}"
    );
}

/// SC3 / D-09: the agent render is measured strictly smaller than the JSON
/// render on the same representative project — a real byte comparison.
#[test]
fn format_agent_is_smaller_than_json_measured() {
    let dir = tmp_dir("agent-smaller");
    let cache = dir.join("cache");
    seed_multi_finding_project(&dir);
    let (agent_out, _a) = run_check_raw(&dir, &cache, &["--format", "agent"]);
    let (json_out, _j) = run_check_raw(&dir, &cache, &["--format", "json"]);
    assert!(
        agent_out.len() < json_out.len(),
        "agent stdout ({} bytes) must be strictly smaller than json stdout ({} bytes) — SC3",
        agent_out.len(),
        json_out.len()
    );
}
