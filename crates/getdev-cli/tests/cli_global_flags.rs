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

/// B4: `--json`/`--no-color`/`--path`/`--fail-on` are now true globals, not
/// per-command duplicates on `env`/`real` — `doctor` must accept them too.
#[test]
fn doctor_accepts_the_flags_that_used_to_be_env_real_only() {
    let dir = tmp_dir("doctor-lifted-flags");
    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("doctor")
        .arg("--offline")
        .arg("--json")
        .arg("--no-color")
        .arg("--path")
        .arg(&dir)
        .assert();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(code, 0, "a healthy offline doctor run must exit 0");
}

/// B4: doctor's `--json` output is a small stable pass/fail shape, not the
/// findings schema (doctor has no findings).
#[test]
fn doctor_json_is_valid_json_with_the_stable_check_table_shape() {
    let dir = tmp_dir("doctor-json-shape");
    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("doctor")
        .arg("--offline")
        .arg("--json")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("doctor --json did not print valid JSON: {err}\n{stdout}"));
    assert!(value["ok"].as_bool().unwrap());
    assert!(value["checks"].as_array().unwrap().iter().any(|c| c["name"]
        .as_str()
        .unwrap()
        .starts_with("version check skipped")));
    for check in value["checks"].as_array().unwrap() {
        assert!(check["name"].is_string());
        assert!(check["ok"].is_boolean());
    }
}

/// B4: `--quiet`/`-q` and `--verbose`/`-v` are mutually exclusive.
#[test]
fn quiet_and_verbose_together_is_rejected_with_exact_clap_usage_exit_code() {
    let dir = tmp_dir("quiet-verbose-conflict");
    let assert = getdev()
        .current_dir(&dir)
        .arg("doctor")
        .arg("--offline")
        .arg("--quiet")
        .arg("--verbose")
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 2,
        "clap usage errors (arg conflicts) exit 2, matching the docs/PLAN.md §2.2 \
         'execution error' code — got {code}"
    );
}

/// B4: `--fail-on` accepts `critical|high|medium|low` only; `info` is
/// rejected at parse time (info-level findings never fail a run).
#[test]
fn fail_on_info_is_rejected_at_parse_time_with_exact_clap_usage_exit_code() {
    let dir = tmp_dir("fail-on-info-rejected");
    let assert = getdev()
        .current_dir(&dir)
        .arg("env")
        .arg("--fail-on")
        .arg("info")
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 2,
        "a rejected --fail-on value is a clap usage error, exit 2 — got {code}"
    );
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("info"),
        "expected the rejection message to name the rejected value, got:\n{stderr}"
    );
}

/// B5: global `--fix` on `env` behaves exactly like `--write` — env's
/// findings are all fixable, but `--fix` used to be silently ignored.
#[test]
fn env_fix_flag_writes_exactly_like_write_flag() {
    let dir = tmp_dir("env-fix-writes");
    std::fs::write(
        dir.join("pay.js"),
        "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
    )
    .unwrap();

    getdev()
        .current_dir(&dir)
        .arg("env")
        .arg("--fix")
        .assert()
        .success();

    let env_file = std::fs::read_to_string(dir.join(".env")).unwrap_or_else(|err| {
        panic!("expected --fix to write .env exactly like --write would: {err}")
    });
    assert!(env_file.contains("STRIPE_SECRET_KEY"));
}

/// B2(a): `[env] env_file` feeds `EnvOptions` when `--env-file` wasn't
/// explicitly passed.
#[test]
fn env_file_from_config_is_honored_when_flag_is_absent() {
    let dir = tmp_dir("env-file-from-config");
    std::fs::write(
        dir.join("pay.js"),
        "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
    )
    .unwrap();
    std::fs::write(
        dir.join(".getdev.toml"),
        "[env]\nenv_file = \"secrets.env\"\n",
    )
    .unwrap();

    getdev()
        .current_dir(&dir)
        .arg("env")
        .arg("--write")
        .assert()
        .success();

    assert!(
        dir.join("secrets.env").exists(),
        "expected [env] env_file = \"secrets.env\" from config to be honored"
    );
    assert!(
        !dir.join(".env").exists(),
        "the default .env must not be written when config names a different file"
    );
}

/// B2(a): an explicit `--env-file` flag still overrides config (flags >
/// config, docs/SPEC-CONFIG.md precedence).
#[test]
fn env_file_flag_overrides_config() {
    let dir = tmp_dir("env-file-flag-overrides-config");
    std::fs::write(
        dir.join("pay.js"),
        "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
    )
    .unwrap();
    std::fs::write(
        dir.join(".getdev.toml"),
        "[env]\nenv_file = \"secrets.env\"\n",
    )
    .unwrap();

    getdev()
        .current_dir(&dir)
        .arg("env")
        .arg("--write")
        .arg("--env-file")
        .arg("from-flag.env")
        .assert()
        .success();

    assert!(dir.join("from-flag.env").exists());
    assert!(!dir.join("secrets.env").exists());
}

/// B2(b): `[ignore] rules` actually drops matching findings now.
#[test]
fn ignore_rules_in_config_drops_matching_findings() {
    let dir = tmp_dir("ignore-rules");
    std::fs::write(
        dir.join("pay.js"),
        "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
    )
    .unwrap();
    std::fs::write(
        dir.join(".getdev.toml"),
        "[ignore]\nrules = [\"env/hardcoded-secret\"]\n",
    )
    .unwrap();

    let assert = getdev().current_dir(&dir).arg("env").arg("--json").assert();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert!(
        findings.iter().all(|f| f["id"] != "env/hardcoded-secret"),
        "[ignore] rules must drop matching findings, got: {stdout}"
    );
}

/// B2(b): `[ignore] paths` prefix-matches and drops findings under it.
#[test]
fn ignore_paths_in_config_drops_findings_under_the_prefix() {
    let dir = tmp_dir("ignore-paths");
    std::fs::create_dir_all(dir.join("vendor")).unwrap();
    std::fs::write(
        dir.join("vendor").join("lib.js"),
        "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
    )
    .unwrap();
    std::fs::write(
        dir.join(".getdev.toml"),
        "[ignore]\npaths = [\"vendor/\"]\n",
    )
    .unwrap();

    let assert = getdev().current_dir(&dir).arg("env").arg("--json").assert();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert!(
        findings.is_empty(),
        "[ignore] paths = [\"vendor/\"] must drop the only finding, got: {stdout}"
    );
}

/// B4: `--fail-on` still accepts every value the spec allows.
#[test]
fn fail_on_accepts_every_contractual_severity() {
    for severity in ["critical", "high", "medium", "low"] {
        let dir = tmp_dir(&format!("fail-on-{severity}"));
        let assert = getdev()
            .current_dir(&dir)
            .env("GETDEV_CACHE_DIR", dir.join("cache"))
            .arg("env")
            .arg("--fail-on")
            .arg(severity)
            .assert();
        let code = assert.get_output().status.code().unwrap();
        assert!(
            (0..=1).contains(&code),
            "a valid --fail-on={severity} on a clean scratch dir should parse and run \
             (exit 0 or 1), got {code}"
        );
    }
}
