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
