//! Hermetic integration test for `getdev check` baseline suppression (LOOP-03,
//! SC-2). Mirrors `check_cli.rs`'s harness: every invocation forces
//! `GETDEV_OFFLINE=1`, points `GETDEV_CACHE_DIR` at a throwaway dir, and
//! neutralizes global/system git config — zero live network egress
//! (docs/TESTING.md "no network in CI").
//!
//! The one round-trip this file proves end-to-end: a scratch project with one
//! detectable finding — `check` reports it; `check --update-baseline` writes a
//! sorted `gdv1:` `.getdev-baseline`; a second `check --baseline` no longer
//! reports it (fingerprint-keyed suppression on unchanged content).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-cli-baseline-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// The set of `--since` materialize temp dirs currently under the system temp
/// dir (named `.getdev-since-dest.<pid>.<nanos>.<seq>` by `check.rs`'s
/// `TempDest`). Used to prove a `check --since` invocation leaks none: the child
/// process's `Drop` runs before it exits, so no NEW entry may remain after the
/// command returns (T-14-04 no-leak).
fn since_dest_dirs() -> std::collections::BTreeSet<PathBuf> {
    let mut set = std::collections::BTreeSet::new();
    if let Ok(rd) = std::fs::read_dir(std::env::temp_dir()) {
        for entry in rd.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(".getdev-since-dest.")
            {
                set.insert(entry.path());
            }
        }
    }
    set
}

/// Run `getdev snap -m base --path <dir>` (hermetic git), returning the exit
/// code. The first snap in a fresh dir is id 1.
fn run_snap(dir: &Path) -> i32 {
    let output = getdev()
        .env("GETDEV_OFFLINE", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .arg("snap")
        .arg("-m")
        .arg("base")
        .arg("--path")
        .arg(dir)
        .assert()
        .get_output()
        .clone();
    output.status.code().unwrap_or(-1)
}

/// Run `getdev check --offline --format=agent` over `dir` (cache seeded at
/// `cache_dir`), returning stdout and the exit code. Extra args are appended.
fn run_check_agent(dir: &Path, cache_dir: &Path, extra: &[&str]) -> (String, i32) {
    let mut cmd = getdev();
    cmd.env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", cache_dir)
        // hermetic git — never read the developer's real global/system config.
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .arg("check")
        .arg("--offline")
        .arg("--format=agent")
        .arg("--path")
        .arg(dir);
    for a in extra {
        cmd.arg(a);
    }
    let output = cmd.assert().get_output().clone();
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    (stdout, code)
}

/// Run `getdev check --offline --json` over `dir` (cache seeded at
/// `cache_dir`), returning stdout, stderr, and the exit code. Extra args are
/// appended — used by the Task-3 exit-code/exclusivity/determinism suite.
fn run_check_json(dir: &Path, cache_dir: &Path, extra: &[&str]) -> (String, String, i32) {
    let mut cmd = getdev();
    cmd.env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", cache_dir)
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
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (stdout, stderr, code)
}

/// SC-2 persisted round-trip: `--update-baseline` writes the file, a later
/// `--baseline` suppresses the previously-seen finding on unchanged content.
#[test]
fn persisted_baseline_round_trip_suppresses_a_previously_seen_finding() {
    let dir = tmp_dir("round-trip");
    let cache_dir = dir.join("cache");

    // A hardcoded live secret → env/hardcoded-secret (offline, no network); the
    // debug leftover adds a review/* finding. No package.json → `real` is
    // cache-only. This mirrors check_cli.rs's seeded project.
    std::fs::write(
        dir.join("app.js"),
        "const stripeKey = \"sk_live_ABCDEFGHIJKLMNOP01\";\n\
         console.log(\"debug\", stripeKey);\n",
    )
    .unwrap();

    // 1) Un-baselined run: the secret finding is present in FINDINGS.
    let (before, code) = run_check_agent(&dir, &cache_dir, &[]);
    assert_eq!(code, 0, "no --fail-on must exit 0");
    assert!(
        before.contains("env/hardcoded-secret"),
        "the seeded secret must surface un-baselined, got:\n{before}"
    );

    // 2) `--update-baseline` writes a sorted gdv1: file; the finding still shows
    //    this run (it is `kept`, only recorded for the NEXT run to suppress).
    let baseline_path = dir.join(".getdev-baseline");
    assert!(
        !baseline_path.exists(),
        "no baseline file should exist before --update-baseline"
    );
    let (during, code) = run_check_agent(&dir, &cache_dir, &["--update-baseline"]);
    assert_eq!(code, 0, "--update-baseline must exit 0");
    assert!(
        during.contains("env/hardcoded-secret"),
        "the finding is still reported on the run that WRITES the baseline"
    );
    assert!(
        baseline_path.exists(),
        "--update-baseline must write the .getdev-baseline file"
    );
    let baseline_body = std::fs::read_to_string(&baseline_path).unwrap();
    assert!(
        baseline_body.contains("gdv1:"),
        "the baseline file must contain gdv1: fingerprints, got:\n{baseline_body}"
    );
    assert!(
        baseline_body.starts_with("# getdev baseline v1"),
        "the baseline file must carry the committable header, got:\n{baseline_body}"
    );

    // 3) `--baseline` reads the file and suppresses the finding on unchanged
    //    content — it must be ABSENT from FINDINGS now (present un-baselined,
    //    gone under --baseline: fingerprint-keyed suppression, SC-2).
    let (after, code) = run_check_agent(&dir, &cache_dir, &["--baseline"]);
    assert_eq!(code, 0, "--baseline must exit 0");
    assert!(
        !after.contains("env/hardcoded-secret"),
        "the baselined finding must be suppressed under --baseline, got:\n{after}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// CR-01 regression: `--update-baseline` alone must NEVER apply suppression to
/// the current run — even when a `.getdev-baseline` file ALREADY exists with the
/// finding's fingerprint. Suppression is exclusively `--baseline`'s job
/// (docs/SPEC-COMMANDS.md / SPEC-CONFIG.md). Before the fix, a second
/// `--update-baseline` run silently suppressed everything the first run recorded
/// — masking real findings from the report, the Ship Score, AND the `--fail-on`
/// gate (a critical secret went from exit 1 to exit 0).
#[test]
fn update_baseline_alone_never_suppresses_even_with_a_preexisting_file() {
    let dir = tmp_dir("update-no-suppress");
    let cache_dir = dir.join("cache");
    std::fs::write(
        dir.join("app.js"),
        "const stripeKey = \"sk_live_ABCDEFGHIJKLMNOP01\";\n",
    )
    .unwrap();

    // 1) First `--update-baseline`: writes the file, the finding still shows.
    let (first, _c1) = run_check_agent(&dir, &cache_dir, &["--update-baseline"]);
    assert!(
        first.contains("env/hardcoded-secret"),
        "1st --update-baseline must report the finding, got:\n{first}"
    );
    let baseline_path = dir.join(".getdev-baseline");
    assert!(
        std::fs::read_to_string(&baseline_path)
            .unwrap()
            .contains("gdv1:"),
        "the first --update-baseline must have recorded the fingerprint"
    );

    // 2) SECOND `--update-baseline`, file now present WITH the fingerprint: the
    //    finding MUST STILL show (write-only, never suppresses) — this is the
    //    exact case the CR-01 bug silently suppressed.
    let (second, _c2) = run_check_agent(&dir, &cache_dir, &["--update-baseline"]);
    assert!(
        second.contains("env/hardcoded-secret"),
        "CR-01: --update-baseline alone must NOT suppress a pre-recorded finding, got:\n{second}"
    );

    // 3) The `--fail-on critical` gate must still TRIP under `--update-baseline`
    //    (the critical secret is real and unsuppressed) — never silently pass.
    let (_o, _e, gate_code) = run_check_json(
        &dir,
        &cache_dir,
        &["--update-baseline", "--fail-on", "critical"],
    );
    assert_eq!(
        gate_code, 1,
        "CR-01: --update-baseline must not mask a critical finding from --fail-on (want exit 1)"
    );

    // 4) Contrast — `--baseline` DOES suppress it (the file holds the fingerprint).
    let (baselined, _c) = run_check_agent(&dir, &cache_dir, &["--baseline"]);
    assert!(
        !baselined.contains("env/hardcoded-secret"),
        "--baseline (the suppression flag) must still suppress, got:\n{baselined}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// SC-1 ephemeral round-trip: snap a project, introduce a NEW finding, then
/// `check --since <snap-id>` surfaces ONLY the new finding — the pre-existing
/// one (present in the materialized snapshot) is suppressed. Also asserts the
/// materialize temp dir is cleaned up (no leak, T-14-04).
#[test]
fn since_snapshot_surfaces_only_newly_introduced_findings_and_leaks_no_temp_dir() {
    // The cache lives OUTSIDE the scanned project so the live scan never sees it.
    let dir = tmp_dir("since-round-trip");
    let cache_dir = tmp_dir("since-cache");

    // A pre-existing secret finding, captured by the snapshot below.
    std::fs::write(
        dir.join("app.js"),
        "const stripeKey = \"sk_live_ABCDEFGHIJKLMNOP01\";\n",
    )
    .unwrap();

    // snap #1 — materialize-able baseline of the project as it is now (app.js).
    // `snapshot()` uses `add -A` into a throwaway index, so app.js is captured
    // even though it is untracked; the user's HEAD/index are never touched.
    assert_eq!(run_snap(&dir), 0, "getdev snap must exit 0");

    // Introduce a NEW finding in a NEW file AFTER the snapshot — a distinct
    // secret in a distinct file → a distinct gdv1: fingerprint.
    std::fs::write(
        dir.join("feature.js"),
        "const otherKey = \"sk_live_ZZZZZZZZZZZZZZZZ99\";\n",
    )
    .unwrap();

    // Baseline (un-since) sanity: BOTH files' findings are present.
    let (plain, code) = run_check_agent(&dir, &cache_dir, &[]);
    assert_eq!(code, 0, "no --fail-on must exit 0");
    assert!(
        plain.contains("app.js") && plain.contains("feature.js"),
        "un-baselined, both files' findings must surface, got:\n{plain}"
    );

    let before = since_dest_dirs();

    // `--since 1`: the materialized snap #1 (app.js only) is the baseline, so the
    // app.js finding is suppressed and ONLY feature.js's new finding surfaces.
    let (after, code) = run_check_agent(&dir, &cache_dir, &["--since", "1"]);
    assert_eq!(code, 0, "--since must exit 0 when below the fail threshold");
    assert!(
        after.contains("feature.js"),
        "the newly-introduced finding must surface under --since, got:\n{after}"
    );
    assert!(
        !after.contains("app.js"),
        "the pre-existing (snapshot) finding must be suppressed under --since, got:\n{after}"
    );

    // No-leak: the child process's TempDest::drop ran before it exited, so no
    // NEW `.getdev-since-dest.*` dir may remain.
    let leaked: Vec<_> = since_dest_dirs().difference(&before).cloned().collect();
    assert!(
        leaked.is_empty(),
        "check --since must leave no materialize temp dir behind, leaked: {leaked:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&cache_dir).ok();
}

/// D-04: an explicit `--baseline` against a missing `.getdev-baseline` file is
/// a config error (exit 3), and the message names the file and points the
/// user at `--update-baseline` (docs/SPEC-CONFIG.md "the message names the
/// file and points at `--update-baseline`").
#[test]
fn explicit_baseline_against_a_missing_file_is_exit_3_naming_the_file_and_update_baseline() {
    let dir = tmp_dir("missing-baseline");
    let cache_dir = dir.join("cache");
    std::fs::write(dir.join("app.js"), "console.log(\"hi\");\n").unwrap();

    let baseline_path = dir.join(".getdev-baseline");
    assert!(!baseline_path.exists(), "precondition: no baseline file");

    let mut cmd = getdev();
    let output = cmd
        .env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .arg("check")
        .arg("--offline")
        .arg("--baseline")
        .arg("--path")
        .arg(&dir)
        .assert()
        .get_output()
        .clone();
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        code, 3,
        "--baseline against a missing file must be a config error (exit 3), got {code}, stderr:\n{stderr}"
    );
    assert!(
        stderr.contains(".getdev-baseline"),
        "the error must name the baseline file, got:\n{stderr}"
    );
    assert!(
        stderr.contains("--update-baseline"),
        "the error must point at --update-baseline, got:\n{stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// D-01: a `.getdev-baseline` file with a non-`gdv1:` line is rejected as
/// malformed — exit 3, mirroring a malformed `.getdev.toml`.
#[test]
fn malformed_baseline_file_is_exit_3() {
    let dir = tmp_dir("malformed-baseline");
    let cache_dir = dir.join("cache");
    std::fs::write(dir.join("app.js"), "console.log(\"hi\");\n").unwrap();
    std::fs::write(
        dir.join(".getdev-baseline"),
        "# getdev baseline v1\nnot-a-fingerprint\n",
    )
    .unwrap();

    let mut cmd = getdev();
    let output = cmd
        .env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .arg("check")
        .arg("--offline")
        .arg("--baseline")
        .arg("--path")
        .arg(&dir)
        .assert()
        .get_output()
        .clone();
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        code, 3,
        "a malformed .getdev-baseline must be a config error (exit 3), got {code}, stderr:\n{stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// D-04 exclusivity: `--since` + `--baseline` in one invocation is a clap
/// usage error (exit 2), mirroring `cli_global_flags.rs`'s
/// `quiet_and_verbose_together_is_rejected_with_exact_clap_usage_exit_code`.
#[test]
fn since_and_baseline_together_is_a_clap_conflict_exit_2() {
    let dir = tmp_dir("since-baseline-conflict");
    let assert = getdev()
        .env("GETDEV_OFFLINE", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .arg("check")
        .arg("--offline")
        .arg("--since")
        .arg("1")
        .arg("--baseline")
        .arg("--path")
        .arg(&dir)
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 2,
        "--since + --baseline must be a clap usage-error conflict (exit 2), got {code}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// D-04 exclusivity: `--since` + `--update-baseline` in one invocation is
/// also a clap usage error (exit 2) — a snapshot baseline is ephemeral and is
/// never a source for the persisted file.
#[test]
fn since_and_update_baseline_together_is_a_clap_conflict_exit_2() {
    let dir = tmp_dir("since-update-baseline-conflict");
    let assert = getdev()
        .env("GETDEV_OFFLINE", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .arg("check")
        .arg("--offline")
        .arg("--since")
        .arg("1")
        .arg("--update-baseline")
        .arg("--path")
        .arg(&dir)
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 2,
        "--since + --update-baseline must be a clap usage-error conflict (exit 2), got {code}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// SC-3/determinism: a plain `check --json` with NO baseline flags omits the
/// `baseline` key entirely (additive/optional, docs/SPEC-FINDINGS.md) — the
/// default `--json` shape is byte-unchanged by this phase.
#[test]
fn plain_json_with_no_baseline_flags_omits_the_baseline_key() {
    let dir = tmp_dir("no-baseline-json");
    let cache_dir = dir.join("cache");
    std::fs::write(
        dir.join("app.js"),
        "const stripeKey = \"sk_live_ABCDEFGHIJKLMNOP01\";\n",
    )
    .unwrap();

    let (stdout, _stderr, code) = run_check_json(&dir, &cache_dir, &[]);
    assert_eq!(code, 0, "no --fail-on must exit 0");
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("check --json must emit valid JSON");
    assert!(
        json.get("baseline").is_none(),
        "a run with no baseline flags must omit the `baseline` key entirely, got:\n{stdout}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Count `findings[].id` entries starting with `review/` in a `check --json`
/// stdout body.
fn count_review_findings(json_stdout: &str) -> usize {
    let json: serde_json::Value =
        serde_json::from_str(json_stdout).expect("check --json must emit valid JSON");
    json["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter(|f| f["id"].as_str().is_some_and(|id| id.starts_with("review/")))
        .count()
}

/// The phase's raison d'etre (SC-1/SC-2 applied to the real FP class):
/// `review/*` "Introduced X" rules fire whole-repo without a diff — an
/// unbaselined `check` reports many of them, and the SAME `check --baseline`
/// (after `--update-baseline`) over UNCHANGED content reports ZERO. Two
/// unreferenced source files are a deterministic `review/orphan-file`
/// generator (no relative import anywhere targets them, and neither path
/// matches an entry-point/test/config exemption glob).
#[test]
fn whole_repo_noise_review_findings_are_suppressed_to_zero_by_the_baseline() {
    let dir = tmp_dir("whole-repo-noise");
    let cache_dir = dir.join("cache");
    std::fs::create_dir_all(dir.join("src")).unwrap();
    // Neither file is imported anywhere, and neither path matches an
    // EXEMPT_PATH_GLOBS entry (index/main/app/server/*.config./scripts/**/
    // tests) — both fire `review/orphan-file` under `check`'s whole-repo
    // (`review --all`) scan, which treats every file as "introduced"
    // (is_new_file = true, review/mod.rs::review_file_from_scanned).
    std::fs::write(
        dir.join("src/orphan-helper-one.js"),
        "export function helperOne() {\n  return 1;\n}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("src/orphan-helper-two.js"),
        "export function helperTwo() {\n  return 2;\n}\n",
    )
    .unwrap();

    // 1) Unbaselined: many review/* "Introduced ..." findings (N >= 2).
    let (before, _stderr, code) = run_check_json(&dir, &cache_dir, &[]);
    assert_eq!(code, 0, "no --fail-on must exit 0");
    let unbaselined_review_count = count_review_findings(&before);
    assert!(
        unbaselined_review_count >= 2,
        "an unbaselined whole-repo check must report >= 2 review/* findings, got {unbaselined_review_count}:\n{before}"
    );

    // 2) `--update-baseline` writes the fingerprints of the current run.
    let (_during, _stderr, code) = run_check_json(&dir, &cache_dir, &["--update-baseline"]);
    assert_eq!(code, 0, "--update-baseline must exit 0");
    assert!(
        dir.join(".getdev-baseline").exists(),
        "--update-baseline must write the .getdev-baseline file"
    );

    // 3) `--baseline` over the SAME unchanged project: zero review/* findings.
    let (after, _stderr, code) = run_check_json(&dir, &cache_dir, &["--baseline"]);
    assert_eq!(code, 0, "--baseline must exit 0");
    let baselined_review_count = count_review_findings(&after);
    assert_eq!(
        baselined_review_count, 0,
        "check --baseline over unchanged content must suppress every review/* finding to zero, got {baselined_review_count}:\n{after}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// SC-4 at the CLI level: a reformat (blank lines inserted ABOVE a baselined
/// finding, shifting its line number without changing its content) keeps the
/// finding suppressed — the baseline FILTER reads the stored, line-independent
/// `gdv1:` token, never the line number. Composes the CLI surface (this test)
/// with the already-proven core property (`baseline.rs`'s
/// `occurrence_index_shift_is_documented_not_a_baseline_bug` /
/// `fingerprint.rs`'s temp-dir-invariance anchor).
#[test]
fn reformat_above_a_baselined_finding_stays_suppressed() {
    let dir = tmp_dir("reformat-stays-suppressed");
    let cache_dir = dir.join("cache");

    // One detectable finding: a hardcoded live secret, line 1.
    std::fs::write(
        dir.join("app.js"),
        "const stripeKey = \"sk_live_ABCDEFGHIJKLMNOP01\";\n",
    )
    .unwrap();

    // `--update-baseline` writes the baseline over the original layout.
    let (baseline_run, _stderr, code) = run_check_json(&dir, &cache_dir, &["--update-baseline"]);
    assert_eq!(code, 0, "--update-baseline must exit 0");
    assert!(
        baseline_run.contains("env/hardcoded-secret"),
        "the finding must be reported on the run that writes the baseline, got:\n{baseline_run}"
    );

    // Reformat: insert blank lines ABOVE the finding, shifting its line number
    // (1 -> 6) without changing the matched content.
    std::fs::write(
        dir.join("app.js"),
        "\n\n\n\n\nconst stripeKey = \"sk_live_ABCDEFGHIJKLMNOP01\";\n",
    )
    .unwrap();

    // `--baseline` over the reformatted file: still suppressed.
    let (after, _stderr, code) = run_check_json(&dir, &cache_dir, &["--baseline"]);
    assert_eq!(code, 0, "--baseline must exit 0");
    assert!(
        !after.contains("env/hardcoded-secret"),
        "a reformat above a baselined finding must keep it suppressed (fingerprint-keyed, not line-keyed), got:\n{after}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
