//! `getdev doctor` integration tests (assert_cmd) — REQ-cmd-doctor.
//!
//! Hermetic: `--offline` is passed on every invocation and `GETDEV_CACHE_DIR`
//! always points at a scratch directory, so these tests never touch the
//! real `~/.getdev` cache or the network (docs/TESTING.md "no network in
//! CI").

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use assert_cmd::Command;

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-cli-doctor-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    dir
}

#[test]
fn offline_doctor_makes_zero_network_calls_and_passes_on_a_healthy_env() {
    let dir = tmp_dir("healthy");
    let cache_dir = dir.join("cache");
    let assert = getdev()
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .arg("doctor")
        .arg("--offline")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        stdout.contains("version check skipped (--offline)"),
        "expected the version row to show Skipped under --offline, got:\n{stdout}"
    );
    assert!(
        stdout.contains("registry reachability skipped (--offline)"),
        "expected the reachability row to show Skipped under --offline, got:\n{stdout}"
    );
}

#[test]
fn a_404_from_github_releases_is_not_exercised_offline_but_cache_absent_is_still_a_pass() {
    // NoReleasesYet only differs from Skipped when a live GitHub call is
    // made (out of scope for a hermetic test); this test instead pins down
    // the adjacent contract that doctor never hard-fails just because the
    // cache hasn't been created yet.
    let dir = tmp_dir("cache-absent");
    let cache_dir = dir.join("cache-does-not-exist");
    getdev()
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .arg("doctor")
        .arg("--offline")
        .assert()
        .success();
}

#[test]
fn offline_fix_clears_a_corrupt_cache_and_the_follow_up_run_passes() {
    let dir = tmp_dir("corrupt");
    let cache_dir = dir.join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    // A garbage "cache.sqlite3" fails SQLite's header check the moment
    // doctor opens it (verified: `PRAGMA journal_mode=WAL` on a non-DB file
    // returns "file is not a database").
    std::fs::write(cache_dir.join("cache.sqlite3"), b"not a real sqlite file").unwrap();

    // First run: the corrupt cache is a failing check, and --fix is not
    // passed, so doctor must exit non-zero.
    getdev()
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .arg("doctor")
        .arg("--offline")
        .assert()
        .failure();

    // --fix clears exactly the cache directory.
    getdev()
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .arg("doctor")
        .arg("--offline")
        .arg("--fix")
        .assert()
        .success();

    // Follow-up run reports the cache healthy again.
    let assert = getdev()
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .arg("doctor")
        .arg("--offline")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        stdout.contains("cache") && stdout.contains("healthy")
            || stdout.contains("not yet created"),
        "expected a healthy/absent cache row after --fix, got:\n{stdout}"
    );
}

#[test]
fn fix_with_an_already_healthy_cache_is_a_no_op_and_still_passes() {
    let dir = tmp_dir("healthy-fix-noop");
    let cache_dir = dir.join("cache");
    // Create a healthy cache first (a plain doctor run creates nothing by
    // itself — open the cache the same way getdev-registry's own tests do).
    getdev_registry_precreate(&cache_dir);

    getdev()
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .arg("doctor")
        .arg("--offline")
        .arg("--fix")
        .assert()
        .success();
}

#[test]
fn doctor_survives_a_malformed_config_and_reports_it_as_a_failed_row() {
    // B3 regression: a malformed `.getdev.toml` must not kill doctor before
    // it can diagnose anything — every other command exits 3 on a
    // ConfigError, but doctor resolves config leniently and continues its
    // other checks, reporting the parse failure as a failed row instead.
    let dir = tmp_dir("malformed-config");
    std::fs::create_dir_all(&dir).unwrap();
    let cache_dir = dir.join("cache");
    std::fs::write(dir.join(".getdev.toml"), "[check]\nfail_onn = \"high\"\n").unwrap();

    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .arg("doctor")
        .arg("--offline")
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 1,
        "F3(c): a malformed config surfaced as a failed doctor check row is an unhealthy-\
         environment exit (1), not the config-resolution hard exit (3) — doctor never dies \
         before reporting it, and a health-check failure is distinct from a genuine execution \
         error (2)"
    );
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        stdout.contains("FAIL") && stdout.contains("config:"),
        "expected a failed config row in doctor's output, got:\n{stdout}"
    );
    // doctor still ran its other checks (grammar rows) despite the broken config.
    assert!(
        stdout.contains("grammar javascript"),
        "expected doctor to continue past the config check, got:\n{stdout}"
    );
}

#[test]
fn fix_refuses_to_delete_a_cache_dir_with_unexpected_contents() {
    // F3(b): --fix must only ever delete a directory that actually looks
    // like a getdev cache — a misconfigured GETDEV_CACHE_DIR pointing at an
    // unrelated directory (that also happens to contain a corrupt/garbage
    // "cache.sqlite3") must be refused, not silently wiped.
    let dir = tmp_dir("unexpected-contents");
    let cache_dir = dir.join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::write(cache_dir.join("cache.sqlite3"), b"not a real sqlite file").unwrap();
    std::fs::write(
        cache_dir.join("important-user-data.txt"),
        b"do not delete me",
    )
    .unwrap();

    let assert = getdev()
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .arg("doctor")
        .arg("--offline")
        .arg("--fix")
        .assert()
        .failure();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        stdout.contains("refusing"),
        "expected doctor to refuse the --fix, got:\n{stdout}"
    );
    assert!(
        cache_dir.join("important-user-data.txt").exists(),
        "doctor must never delete a directory with unexpected contents"
    );
    assert!(
        cache_dir.join("cache.sqlite3").exists(),
        "doctor must never delete a directory with unexpected contents"
    );
}

fn getdev_registry_precreate(dir: &std::path::Path) {
    // Exercise the same public API doctor.rs itself uses to open/create the
    // cache, keeping this test decoupled from getdev-registry's private
    // file-naming details.
    getdev_registry::Cache::open_at(dir).expect("open_at should create a healthy cache");
}
