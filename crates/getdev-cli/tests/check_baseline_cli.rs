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
