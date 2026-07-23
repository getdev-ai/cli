//! Hermetic integration test for `getdev env --json` (assert_cmd) — the D-14 #5
//! wire-population + D-05 secret-non-leak contract for the one secret-bearing
//! command. `env --json` (dry-run, no `--write`) must carry a `gdv1:`
//! fingerprint on every finding while the raw secret value NEVER reaches the
//! wire — only the one-way digest (SPEC-FINDINGS Invariant 2). The secret
//! literals are assembled from concatenated pieces in the test so the absence
//! assertion is not self-defeating (no full secret token appears in this source
//! to match against). `getdev env` is fully offline; `GETDEV_OFFLINE=1` +
//! `GETDEV_CACHE_DIR` keep the harness hermetic regardless of the CI machine.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use assert_cmd::Command;

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-cli-env-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// D-14 #5 + D-05: `getdev env --json` (dry run) populates a `gdv1:`
/// fingerprint on every finding while never emitting the raw secret value.
/// Two DISTINCT secrets on ONE line additionally prove per-secret fingerprint
/// differentiation on the wire — the identity seed for an `env` hardcoded-secret
/// finding IS the raw secret value, so distinct secrets differentiate
/// intrinsically even when they share a line (the 05-REVIEW same-line collision
/// closure, D-14 #2).
#[test]
fn env_json_populates_gdv1_fingerprint_without_leaking_the_secret() {
    let dir = tmp_dir("gdv1-wire");
    // Two distinct stripe-live-shaped secrets built from pieces on ONE line —
    // no full secret token appears literally in this test source, so the
    // absence assertions below cannot match themselves.
    let secret_a = format!("sk_live_{}{}", "AAAAAAAA", "ALPHABODY0123456789");
    let secret_b = format!("sk_live_{}{}", "BBBBBBBB", "BETABODY09876543210");
    std::fs::write(
        dir.join("pay.js"),
        format!("const a = \"{secret_a}\"; const b = \"{secret_b}\";\n"),
    )
    .unwrap();

    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("env")
        .arg("--json")
        .assert();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout was not valid JSON ({err}): {stdout}"));
    let findings = report["findings"].as_array().unwrap();

    // (a) every finding carries a populated gdv1: fingerprint.
    assert!(
        !findings.is_empty(),
        "expected at least one secret finding to assert on, got: {stdout}"
    );
    assert!(
        findings.iter().all(|f| f["fingerprint"]
            .as_str()
            .is_some_and(|fp| fp.starts_with("gdv1:"))),
        "every env --json finding must carry a gdv1: fingerprint, got: {stdout}"
    );

    // (b) neither raw secret value — nor its distinctive body — ever appears in
    // the serialized output (D-05 / SPEC-FINDINGS Invariant 2). `--json` must be
    // safe to attach to public CI logs.
    assert!(
        !stdout.contains(&secret_a),
        "raw secret A leaked into --json output"
    );
    assert!(
        !stdout.contains(&secret_b),
        "raw secret B leaked into --json output"
    );
    assert!(
        !stdout.contains("ALPHABODY0123456789"),
        "secret A body leaked into --json output"
    );
    assert!(
        !stdout.contains("BETABODY09876543210"),
        "secret B body leaked into --json output"
    );

    // D-14 #2: the two distinct same-line secrets must carry DISTINCT gdv1:
    // fingerprints (the seed is the raw secret value — identity differs
    // intrinsically, never collapsing two secrets onto one line-keyed token).
    let secret_fps: Vec<&str> = findings
        .iter()
        .filter(|f| f["id"] == "env/hardcoded-secret")
        .filter_map(|f| f["fingerprint"].as_str())
        .collect();
    assert!(
        secret_fps.len() >= 2,
        "expected two hardcoded-secret findings on the one line, got: {stdout}"
    );
    assert_ne!(
        secret_fps[0], secret_fps[1],
        "two distinct same-line secrets must carry distinct gdv1: fingerprints, got: {stdout}"
    );
}
