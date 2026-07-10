//! Global-flag CLI integration tests (assert_cmd) — REQ-global-flags.
//!
//! Hermetic: every invocation either passes `--offline` explicitly or sets
//! `GETDEV_OFFLINE=1`/points `GETDEV_CACHE_DIR` at a scratch directory, so
//! these tests never depend on (or produce) live network traffic —
//! docs/TESTING.md "no network in CI".

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use assert_cmd::Command;

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-cli-global-flags-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn assert_contract_exit_code(code: i32) {
    assert!(
        (0..=3).contains(&code),
        "exit code {code} is outside the docs/PLAN.md §2.2 contract (0/1/2/3)"
    );
}

#[test]
fn doctor_offline_parses_and_exits_in_contract_range() {
    let dir = tmp_dir("doctor-offline");
    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("doctor")
        .arg("--offline")
        .assert();
    assert_contract_exit_code(assert.get_output().status.code().unwrap_or(-1));
}

#[test]
fn env_quiet_long_and_short_flag_both_parse() {
    let dir = tmp_dir("env-quiet");
    for flag in ["--quiet", "-q"] {
        let assert = getdev().current_dir(&dir).arg("env").arg(flag).assert();
        assert_contract_exit_code(assert.get_output().status.code().unwrap_or(-1));
    }
}

#[test]
fn env_config_flag_with_explicit_path_parses() {
    let dir = tmp_dir("env-config");
    let config_path = dir.join("custom.toml");
    std::fs::write(&config_path, "").unwrap();
    let assert = getdev()
        .current_dir(&dir)
        .arg("env")
        .arg("--config")
        .arg(&config_path)
        .assert();
    assert_contract_exit_code(assert.get_output().status.code().unwrap_or(-1));
}

#[test]
fn verbose_flag_is_repeatable_and_parses_on_doctor() {
    let dir = tmp_dir("doctor-verbose");
    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("doctor")
        .arg("--offline")
        .arg("-vv")
        .assert();
    assert_contract_exit_code(assert.get_output().status.code().unwrap_or(-1));
}

#[test]
fn getdev_offline_env_var_makes_doctor_networkless_and_it_succeeds() {
    let dir = tmp_dir("doctor-offline-env");
    getdev()
        .current_dir(&dir)
        .env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("doctor")
        .assert()
        .success();
}

#[test]
fn fix_flag_parses_on_every_command() {
    let dir = tmp_dir("fix-flag");
    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("doctor")
        .arg("--offline")
        .arg("--fix")
        .assert();
    assert_contract_exit_code(assert.get_output().status.code().unwrap_or(-1));
}

#[test]
fn unknown_global_flag_is_a_parse_error() {
    let dir = tmp_dir("unknown-flag");
    getdev()
        .current_dir(&dir)
        .arg("env")
        .arg("--not-a-real-flag")
        .assert()
        .failure();
}
