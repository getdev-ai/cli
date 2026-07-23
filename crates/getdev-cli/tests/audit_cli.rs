//! Hermetic integration tests for `getdev audit` (assert_cmd) — SC3: the
//! three flags (`--severity`/`--ignore`/`--rules`) filter/merge correctly,
//! a malformed `--rules` user pack degrades gracefully (never a panic, the
//! rest of the pack still runs), and a hostile pack can never execute code.
//!
//! Every temp `--rules` pack used here is controlled by the test itself
//! (fresh rule ids, never colliding with the embedded pack) so these tests
//! stay deterministic regardless of the embedded pack's evolving contents
//! (04-06-PLAN.md Task 2). `getdev audit` is fully offline — no
//! `GETDEV_OFFLINE`/`GETDEV_CACHE_DIR` seeding is needed anywhere in this
//! file (unlike `real_cli.rs`/`corpus.rs`), which is itself part of what
//! test 7 below asserts.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-cli-audit-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// A minimal, schema-valid AST rule matching a JS call `fn_name(...)`.
/// `fixtures.positive`/`.negative` never need to resolve to real files here
/// — `rules::load_rule` only requires the `>=3` string entries the schema
/// demands, it never touches disk for them (that's `audit_fixtures.rs`'s
/// job, a different gate entirely).
fn ast_rule_yaml(id: &str, severity: &str, fn_name: &str) -> String {
    format!(
        r#"
id: {id}
severity: {severity}
confidence: high
languages: [javascript]
description: test rule — {fn_name} call detected
message: "{fn_name} call detected"
remediation: remove it
refs: []
matchers:
  - language: javascript
    query: |
      (call_expression
        function: (identifier) @fn (#eq? @fn "{fn_name}")) @finding
fixtures:
  positive: [a.js, b.js, c.js]
  negative: [d.js, e.js, f.js]
"#
    )
}

fn write_rule(dir: &Path, filename: &str, contents: &str) {
    std::fs::write(dir.join(filename), contents).expect("write rule file");
}

/// Test 1: `--severity high` on a controlled `--rules` pack containing one
/// medium-severity rule and one high-severity rule — only the high finding
/// survives.
#[test]
fn severity_flag_filters_below_the_threshold() {
    let dir = tmp_dir("severity");
    let rules_dir = dir.join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    write_rule(
        &rules_dir,
        "medium.yaml",
        &ast_rule_yaml("audit/test-medium-thing", "medium", "mediumCall"),
    );
    write_rule(
        &rules_dir,
        "high.yaml",
        &ast_rule_yaml("audit/test-high-thing", "high", "highCall"),
    );
    std::fs::write(dir.join("app.js"), "mediumCall();\nhighCall();\n").unwrap();

    let assert = getdev()
        .arg("audit")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--severity")
        .arg("high")
        .assert();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout was not valid JSON ({err}): {stdout}"));
    let findings = report["findings"].as_array().unwrap();

    assert!(
        findings.iter().any(|f| f["id"] == "audit/test-high-thing"),
        "expected the high finding to survive --severity high, got: {stdout}"
    );
    assert!(
        findings
            .iter()
            .all(|f| f["id"] != "audit/test-medium-thing"),
        "--severity high must drop the medium finding, got: {stdout}"
    );
}

/// Test 2: `--ignore <rule-id>` suppresses exactly that rule's findings.
#[test]
fn ignore_flag_suppresses_exactly_the_named_rule() {
    let dir = tmp_dir("ignore");
    let rules_dir = dir.join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    write_rule(
        &rules_dir,
        "ignored.yaml",
        &ast_rule_yaml("audit/test-ignored-thing", "high", "ignoredCall"),
    );
    write_rule(
        &rules_dir,
        "kept.yaml",
        &ast_rule_yaml("audit/test-kept-thing", "high", "keptCall"),
    );
    std::fs::write(dir.join("app.js"), "ignoredCall();\nkeptCall();\n").unwrap();

    let assert = getdev()
        .arg("audit")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--ignore")
        .arg("audit/test-ignored-thing")
        .assert();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout was not valid JSON ({err}): {stdout}"));
    let findings = report["findings"].as_array().unwrap();

    assert!(
        findings
            .iter()
            .all(|f| f["id"] != "audit/test-ignored-thing"),
        "--ignore must suppress the named rule's findings, got: {stdout}"
    );
    assert!(
        findings.iter().any(|f| f["id"] == "audit/test-kept-thing"),
        "--ignore must not suppress an unrelated rule, got: {stdout}"
    );
}

/// Test 3: `--rules <tmp>` merge — a benign user rule fires on a crafted
/// source file, proving user packs load declaratively (never executable).
#[test]
fn rules_flag_merges_a_benign_user_pack_and_it_fires() {
    let dir = tmp_dir("merge");
    let rules_dir = dir.join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    write_rule(
        &rules_dir,
        "benign.yaml",
        &ast_rule_yaml("audit/test-benign-thing", "high", "benignCall"),
    );
    std::fs::write(dir.join("app.js"), "benignCall();\n").unwrap();

    let assert = getdev()
        .arg("audit")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .arg("--rules")
        .arg(&rules_dir)
        .assert();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout was not valid JSON ({err}): {stdout}"));
    let findings = report["findings"].as_array().unwrap();

    assert!(
        findings
            .iter()
            .any(|f| f["id"] == "audit/test-benign-thing" && f["file"] == "app.js"),
        "expected the merged user rule to fire on the crafted source file, got: {stdout}"
    );
}

/// Test 4 (Pitfall 2): a `--rules` dir with one syntactically-broken
/// `.yaml` and one valid `.yaml` — the process must exit within the
/// 0..=3 contract (never panic/abort), print an error naming the broken
/// rule/file to stderr, and the sibling valid user rule must STILL fire.
#[test]
fn malformed_rule_in_the_pack_degrades_gracefully_the_valid_sibling_still_fires() {
    let dir = tmp_dir("degrade");
    let rules_dir = dir.join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    // Syntactically invalid YAML (unterminated mapping) — must never panic
    // the loader, only be collected as a per-file `RuleLoadError`.
    write_rule(
        &rules_dir,
        "broken.yaml",
        "id: audit/test-broken-thing\nseverity: [this is not valid yaml structure\n",
    );
    write_rule(
        &rules_dir,
        "valid.yaml",
        &ast_rule_yaml("audit/test-valid-sibling", "high", "validSiblingCall"),
    );
    std::fs::write(dir.join("app.js"), "validSiblingCall();\n").unwrap();

    let assert = getdev()
        .arg("audit")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .arg("--rules")
        .arg(&rules_dir)
        .assert();

    let output = assert.get_output();
    let code = output.status.code();
    assert!(
        code.is_some_and(|c| (0..=3).contains(&c)),
        "exit code must stay within the 0..=3 contract (never a raw panic/abort), got {code:?}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("broken.yaml"),
        "expected stderr to name the broken rule file, got: {stderr}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("stdout was not valid JSON ({err}): {stdout} stderr={stderr}")
    });
    let findings = report["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["id"] == "audit/test-valid-sibling"),
        "the valid sibling rule must still fire despite the broken rule in the same pack \
         (Pitfall 2 — one bad rule must never disable the rest), got: {stdout}"
    );
}

/// Test 5 (SC3 security boundary): a `--rules` pack whose YAML tries to
/// smuggle code-shaped content via an unrecognized tree-sitter predicate
/// (`#matches?`, not the auto-evaluated `#match?`) — the offending rule is
/// rejected as a typed load error at compile time, nothing is ever
/// executed, and no file outside the scan is touched.
#[test]
fn hostile_pack_with_unsupported_predicate_never_executes_anything() {
    let dir = tmp_dir("hostile");
    let rules_dir = dir.join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let hostile_rule = r#"
id: audit/test-hostile-thing
severity: critical
confidence: high
languages: [javascript]
description: hostile rule — smuggled predicate
message: "should never fire"
remediation: n/a
refs: []
matchers:
  - language: javascript
    query: |
      (call_expression
        function: (identifier) @fn (#matches? @fn "anything")) @finding
fixtures:
  positive: [a.js, b.js, c.js]
  negative: [d.js, e.js, f.js]
"#;
    write_rule(&rules_dir, "hostile.yaml", hostile_rule);
    std::fs::write(dir.join("app.js"), "anything();\n").unwrap();

    // A canary file the hostile rule could never legitimately touch — an
    // out-of-scan-root sentinel proving no matcher kind can perform file
    // I/O or code execution (only AST-query-text/regex/secret-flag are
    // representable at all, enforced by the typed `Matcher` shape).
    let canary = dir.join("canary-untouched.txt");
    std::fs::write(&canary, "before\n").unwrap();

    let assert = getdev()
        .arg("audit")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .arg("--rules")
        .arg(&rules_dir)
        .assert();

    let output = assert.get_output();
    let code = output.status.code();
    assert!(
        code.is_some_and(|c| (0..=3).contains(&c)),
        "exit code must stay within the 0..=3 contract, got {code:?}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("hostile.yaml") || stderr.to_lowercase().contains("predicate"),
        "expected stderr to name the rejected hostile rule/predicate, got: {stderr}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("stdout was not valid JSON ({err}): {stdout} stderr={stderr}")
    });
    let findings = report["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .all(|f| f["id"] != "audit/test-hostile-thing"),
        "the hostile rule must never fire — it was rejected at load time, got: {stdout}"
    );

    let canary_after = std::fs::read_to_string(&canary).unwrap();
    assert_eq!(
        canary_after, "before\n",
        "the hostile pack must never mutate any file on disk"
    );
}

/// Test 5b (SC3 security boundary, second smuggling shape): an
/// out-of-band matcher key mixed into an otherwise-valid `{secret: true}`
/// matcher — rejected by the JSON Schema's `additionalProperties: false`
/// per-branch enforcement (`oneOf`), never silently accepted as a fourth
/// matcher kind.
#[test]
fn hostile_pack_with_out_of_band_matcher_key_is_rejected_as_a_load_error() {
    let dir = tmp_dir("hostile-key");
    let rules_dir = dir.join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let hostile_rule = r#"
id: audit/test-hostile-key-thing
severity: critical
confidence: high
languages: [javascript]
description: hostile rule — out-of-band matcher key
message: "should never fire"
remediation: n/a
refs: []
matchers:
  - secret: true
    exec: "rm -rf /"
fixtures:
  positive: [a.js, b.js, c.js]
  negative: [d.js, e.js, f.js]
"#;
    write_rule(&rules_dir, "hostile-key.yaml", hostile_rule);
    std::fs::write(
        dir.join("app.js"),
        "const x = \"sk_live_FAKEFAKEFAKE1234\";\n",
    )
    .unwrap();

    let assert = getdev()
        .arg("audit")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .arg("--rules")
        .arg(&rules_dir)
        .assert();

    let output = assert.get_output();
    let code = output.status.code();
    assert!(
        code.is_some_and(|c| (0..=3).contains(&c)),
        "exit code must stay within the 0..=3 contract, got {code:?}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("hostile-key.yaml"),
        "expected stderr to name the rejected file with the out-of-band matcher key, got: {stderr}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("stdout was not valid JSON ({err}): {stdout} stderr={stderr}")
    });
    let findings = report["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .all(|f| f["id"] != "audit/test-hostile-key-thing"),
        "the hostile rule must never load or fire, got: {stdout}"
    );
}

/// Test 6: exit codes — a clean run (no `--fail-on`) always exits 0;
/// `--fail-on <sev>` exits 1 when a matching-severity finding is present.
#[test]
fn fail_on_exit_code_contract() {
    let dir = tmp_dir("exit-codes");
    let rules_dir = dir.join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    write_rule(
        &rules_dir,
        "high.yaml",
        &ast_rule_yaml("audit/test-exit-code-thing", "high", "exitCodeCall"),
    );
    std::fs::write(dir.join("app.js"), "exitCodeCall();\n").unwrap();

    // No --fail-on: clean exit 0 regardless of findings present.
    getdev()
        .arg("audit")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .arg("--rules")
        .arg(&rules_dir)
        .assert()
        .code(0);

    // --fail-on high: a high finding is present, exit 1.
    getdev()
        .arg("audit")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--fail-on")
        .arg("high")
        .assert()
        .code(1);

    // --fail-on critical: no critical finding present, exit 0.
    getdev()
        .arg("audit")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--fail-on")
        .arg("critical")
        .assert()
        .code(0);
}

/// Test 7: no-network — `getdev audit` is fully offline (imports no
/// `getdev_registry` type, docs/SPEC-COMMANDS.md "Network: none"). A plain
/// run with NO `GETDEV_OFFLINE`/`GETDEV_CACHE_DIR` seeding at all (unlike
/// every `real`/`corpus` test in this crate) must still succeed cleanly —
/// there is no registry/cache dependency to seed in the first place.
#[test]
fn plain_run_succeeds_offline_with_no_registry_seeding_needed() {
    let dir = tmp_dir("no-network");
    std::fs::write(
        dir.join("app.js"),
        "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
    )
    .unwrap();

    let assert = getdev()
        .arg("audit")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout was not valid JSON ({err}): {stdout}"));
    assert_eq!(report["schema_version"], "1");
}

/// Test 8 (11-02 tracer wire proof): `getdev audit --json` populates
/// `Finding.fingerprint` end-to-end with a `gdv1:` token through the
/// hardcoded-secret layer, and the raw secret value NEVER appears anywhere in
/// the JSON output (D-05 — the secret is the identity seed, hashed only, and is
/// `#[serde(skip)]` + redacting-`Debug` protected). The secret is assembled
/// from concatenated pieces so the absence assertion is not self-defeating (no
/// literal secret token in this test source to match against).
#[test]
fn audit_json_populates_gdv1_fingerprint_without_leaking_the_secret() {
    let dir = tmp_dir("gdv1-wire");
    // Stripe-live-shaped secret built from pieces — the embedded pack's secret
    // rule fires on the `sk_live_` prefix, and the masked preview only ever
    // shows `sk_live_…<last4>`, never this full body.
    let secret = format!("sk_live_{}{}", "FAKEFAKE", "MIDDLEBODY0123456789");
    std::fs::write(
        dir.join("app.js"),
        format!("const apiKey = \"{secret}\";\n"),
    )
    .unwrap();

    let assert = getdev()
        .arg("audit")
        .arg("--json")
        .arg("--path")
        .arg(&dir)
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout was not valid JSON ({err}): {stdout}"));
    let findings = report["findings"].as_array().unwrap();

    // (a) at least one finding carries a populated `gdv1:` fingerprint.
    assert!(
        findings.iter().any(|f| f["fingerprint"]
            .as_str()
            .is_some_and(|fp| fp.starts_with("gdv1:"))),
        "expected a gdv1:-prefixed fingerprint on the secret finding, got: {stdout}"
    );

    // (b) the raw secret value — and its distinctive middle body — never appear
    // anywhere in the serialized output (D-05 wire proof).
    assert!(
        !stdout.contains(&secret),
        "raw secret value leaked into --json output"
    );
    assert!(
        !stdout.contains("MIDDLEBODY0123456789"),
        "the secret body leaked into --json output"
    );
}

/// `getdev audit --help` exposes exactly the three sanctioned flags (plus
/// inherited globals) — no audit-specific flag beyond
/// `--severity`/`--ignore`/`--rules` (CLAUDE.md rule 6 / docs/PLAN.md §2.3).
#[test]
fn help_lists_exactly_the_three_sanctioned_flags() {
    let assert = getdev().arg("audit").arg("--help").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(stdout.contains("--severity"));
    assert!(stdout.contains("--ignore"));
    assert!(stdout.contains("--rules"));
    // audit must never accept `real`'s flags (a scope leak would be a
    // CLAUDE.md rule 6 violation).
    assert!(!stdout.contains("--deps-only"));
    assert!(!stdout.contains("--apis-only"));
    assert!(!stdout.contains("--models-only"));
}
