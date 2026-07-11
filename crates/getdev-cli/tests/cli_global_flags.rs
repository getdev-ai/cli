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

/// D1: every test in this file asserts its EXACT expected exit code —
/// `assert_contract_exit_code(0..=3)` (deleted) used to accept the entire
/// docs/PLAN.md §2.2 contract range, so a test using it would still pass
/// with the flag it claims to cover deleted outright (clap's unknown-flag
/// parse error is exit 2, inside the same accepted range). Each helper
/// below pins the one code that scenario must produce.

#[test]
fn doctor_offline_on_a_healthy_scratch_dir_exits_0() {
    let dir = tmp_dir("doctor-offline");
    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("doctor")
        .arg("--offline")
        .assert();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(code, 0, "a healthy offline doctor run must exit exactly 0");
}

#[test]
fn env_quiet_long_and_short_flag_both_exit_0_on_a_clean_scratch_dir() {
    let dir = tmp_dir("env-quiet");
    for flag in ["--quiet", "-q"] {
        let assert = getdev()
            .current_dir(&dir)
            .env("GETDEV_CACHE_DIR", dir.join("cache"))
            .arg("env")
            .arg(flag)
            .assert();
        let code = assert.get_output().status.code().unwrap();
        assert_eq!(
            code, 0,
            "env {flag} on a clean scratch dir (no findings, no --fail-on) must exit exactly 0"
        );
    }
}

#[test]
fn env_config_flag_with_explicit_valid_path_exits_0() {
    let dir = tmp_dir("env-config");
    let config_path = dir.join("custom.toml");
    std::fs::write(&config_path, "").unwrap();
    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("env")
        .arg("--config")
        .arg(&config_path)
        .assert();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 0,
        "env --config <valid empty toml> on a clean scratch dir must exit exactly 0"
    );
}

#[test]
fn verbose_flag_is_repeatable_and_exits_0_on_doctor() {
    let dir = tmp_dir("doctor-verbose");
    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("doctor")
        .arg("--offline")
        .arg("-vv")
        .assert();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 0,
        "doctor --offline -vv on a healthy env must exit exactly 0"
    );
}

/// D1: `--config` pointing at a file that does not exist on disk must hit
/// the config-resolution hard exit (3), not silently fall through to a
/// clean run.
#[test]
fn config_flag_pointing_at_a_missing_file_exits_3() {
    let dir = tmp_dir("config-missing");
    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("env")
        .arg("--config")
        .arg(dir.join("does-not-exist.toml"))
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 3,
        "a --config path that does not exist must be a config-resolution error (exit 3)"
    );
}

/// D1: `--config` pointing at a syntactically malformed TOML file must also
/// hit the config-resolution hard exit (3).
#[test]
fn config_flag_pointing_at_a_malformed_file_exits_3() {
    let dir = tmp_dir("config-malformed");
    let config_path = dir.join("bad.toml");
    std::fs::write(&config_path, "not = [valid\n").unwrap();
    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("env")
        .arg("--config")
        .arg(&config_path)
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 3,
        "a syntactically malformed --config file must be a config-resolution error (exit 3)"
    );
}

/// D1: a `--fail-on` threshold that a real finding actually meets/exceeds
/// must exit exactly 1 — the finding-threshold-hit exit code, distinct from
/// both a clean run (0) and any error path (2/3).
#[test]
fn fail_on_hit_on_env_exits_1() {
    let dir = tmp_dir("fail-on-hit");
    std::fs::write(
        dir.join("pay.js"),
        "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
    )
    .unwrap();

    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("env")
        .arg("--fail-on")
        .arg("low")
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 1,
        "a --fail-on threshold met by a real finding (critical secret >= low) must exit exactly 1"
    );
}

/// D1: `--quiet` must actually suppress doctor's `getdev {version}` banner
/// line — not just happen to still return a passing exit code. Assert on
/// stdout content, not code alone.
#[test]
fn quiet_flag_suppresses_the_doctor_banner_in_stdout() {
    let dir = tmp_dir("quiet-suppresses-banner");

    let loud = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache-loud"))
        .arg("doctor")
        .arg("--offline")
        .assert()
        .success();
    let loud_stdout = String::from_utf8_lossy(&loud.get_output().stdout).to_string();
    assert!(
        loud_stdout.starts_with("getdev "),
        "expected the default (non-quiet) run to print the version banner first, got:\n{loud_stdout}"
    );

    let quiet = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache-quiet"))
        .arg("doctor")
        .arg("--offline")
        .arg("--quiet")
        .assert()
        .success();
    let quiet_stdout = String::from_utf8_lossy(&quiet.get_output().stdout).to_string();
    assert!(
        !quiet_stdout.contains("getdev 0.") && !quiet_stdout.starts_with("getdev "),
        "expected --quiet to suppress the 'getdev {{version}}' banner line, got:\n{quiet_stdout}"
    );
    assert!(
        quiet_stdout.contains("all checks passed"),
        "expected --quiet to still print the check rows/summary, got:\n{quiet_stdout}"
    );
}

/// D1: `--verbose` must add real per-file skip detail to env's terminal
/// output, not just a bare count — assert the exact unreadable-file reason
/// text appears only under `-v`.
#[cfg(unix)]
#[test]
fn verbose_flag_adds_skip_detail_to_env_terminal_output() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("verbose-skip-detail");
    let unreadable = dir.join("broken.js");
    std::fs::write(&unreadable, "const x = 1;\n").unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();

    let quiet_run = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache-no-v"))
        .arg("env")
        .assert()
        .success();
    let quiet_stdout = String::from_utf8_lossy(&quiet_run.get_output().stdout).to_string();
    assert!(
        quiet_stdout.contains("1 unreadable file(s) skipped (-v for details)"),
        "expected the bare skip count without -v, got:\n{quiet_stdout}"
    );
    assert!(!quiet_stdout.contains("broken.js"));

    let verbose_run = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache-v"))
        .arg("env")
        .arg("-v")
        .assert()
        .success();

    let _ = std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644));

    let verbose_stdout = String::from_utf8_lossy(&verbose_run.get_output().stdout).to_string();
    assert!(
        verbose_stdout.contains("1 unreadable file(s) skipped:"),
        "expected the detailed skip header under -v, got:\n{verbose_stdout}"
    );
    assert!(
        verbose_stdout.contains("broken.js"),
        "expected -v to name the actual skipped file, got:\n{verbose_stdout}"
    );
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
fn fix_flag_on_doctor_with_no_cache_yet_exits_0() {
    let dir = tmp_dir("fix-flag");
    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("doctor")
        .arg("--offline")
        .arg("--fix")
        .assert();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 0,
        "doctor --offline --fix against a not-yet-created cache must exit exactly 0"
    );
}

/// D1: an unrecognized flag is a clap usage error — exit exactly 2, not
/// merely "some failure code in 1..=3".
#[test]
fn unknown_global_flag_is_a_parse_error_exit_2() {
    let dir = tmp_dir("unknown-flag");
    let assert = getdev()
        .current_dir(&dir)
        .arg("env")
        .arg("--not-a-real-flag")
        .assert()
        .failure();
    let code = assert.get_output().status.code().unwrap();
    assert_eq!(
        code, 2,
        "an unrecognized flag must be a clap parse error (exit 2)"
    );
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

/// F4: `env --json --write` is a single valid JSON document that includes
/// an additive `applied` object describing what was written.
#[test]
fn env_json_write_includes_an_applied_object() {
    let dir = tmp_dir("json-write-applied");
    std::fs::write(
        dir.join("pay.js"),
        "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
    )
    .unwrap();

    let assert = getdev()
        .current_dir(&dir)
        .arg("env")
        .arg("--write")
        .arg("--json")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("env --write --json did not print valid JSON: {err}\n{stdout}")
    });
    assert!(!report["findings"].as_array().unwrap().is_empty());
    let applied = &report["applied"];
    assert_eq!(applied["vars_written"].as_u64().unwrap(), 1);
    assert_eq!(applied["files_rewritten"].as_u64().unwrap(), 1);
    assert_eq!(applied["env_file"].as_str().unwrap(), ".env");
    assert!(applied["env_file_created"].as_bool().unwrap());
}

/// F4: a dry run (no `--write`) must never include the `applied` key at all
/// (optional field, omitted when absent — not `null`).
#[test]
fn env_json_dry_run_omits_the_applied_key() {
    let dir = tmp_dir("json-dry-run-no-applied");
    std::fs::write(
        dir.join("pay.js"),
        "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
    )
    .unwrap();

    let assert = getdev().current_dir(&dir).arg("env").arg("--json").assert();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        report.get("applied").is_none(),
        "applied must be omitted (not null) on a dry run, got: {stdout}"
    );
}

/// F4: when `apply` fails mid-write, the findings must still print before
/// the error exit — not silently swallowed by an early `?`. The scratch dir
/// itself (not the source file, which must stay readable for `plan` to find
/// the finding in the first place) is made read-only so `mutate`'s
/// temp-file-then-rename write deterministically fails.
#[cfg(unix)]
#[test]
fn env_apply_error_still_prints_findings_before_exiting() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("apply-error-prints-findings");
    std::fs::write(
        dir.join("pay.js"),
        "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
    )
    .unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    let assert = getdev()
        .current_dir(&dir)
        .arg("env")
        .arg("--write")
        .arg("--json")
        .assert()
        .failure();

    // restore permissions so the scratch dir can be cleaned up
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));

    let code = assert.get_output().status.code().unwrap();
    assert_eq!(code, 2, "an apply I/O error is an execution error (2)");
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("findings must still print as valid JSON on an apply error: {err}\n{stdout}")
    });
    assert!(
        !report["findings"].as_array().unwrap().is_empty(),
        "expected the findings to have printed despite the apply failure, got: {stdout}"
    );
    assert!(report.get("applied").is_none());
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("error:"),
        "expected an error message on stderr, got: {stderr}"
    );
}

/// F4: `--json` includes a `skipped` array for unreadable files (previously
/// terminal-only, under `-v`).
#[cfg(unix)]
#[test]
fn env_json_includes_skipped_array_for_unreadable_files() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("json-skipped-array");
    let unreadable = dir.join("broken.js");
    std::fs::write(&unreadable, "const x = 1;\n").unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();

    let assert = getdev().current_dir(&dir).arg("env").arg("--json").assert();

    let _ = std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644));

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let skipped = report["skipped"].as_array().unwrap();
    assert!(
        !skipped.is_empty(),
        "expected the unreadable file to appear in the skipped array, got: {stdout}"
    );
    assert!(skipped[0]["reason"].is_string());
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
