//! P1 exit-gate tests for `env --write` (docs/ROADMAP.md P1 criteria):
//! zero broken rewrites — the project must still parse after apply — and
//! the pipeline must be idempotent (second run finds nothing).

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use getdev_core::env::{self, EnvOptions};
use getdev_core::scan;

const JS_BEFORE: &str = r#"const stripeKey = "sk_live_FAKEFAKEFAKE1234";
const config = {
  apiKey: "sk-ant-FAKEFAKEFAKEFAKEFAKEFAKE1234",
};

export function charge() {
  return stripeKey;
}
"#;

const PY_BEFORE: &str = r#"#!/usr/bin/env python3
"""Payment helper module."""

aws_key = "AKIAFAKEFAKEFAKEFAKE"


def region():
    return "eu-west-1"
"#;

fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("getdev-apply-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pay.js"), JS_BEFORE).unwrap();
    std::fs::write(dir.join("cloud.py"), PY_BEFORE).unwrap();
    dir
}

#[test]
fn apply_rewrites_extracts_and_stays_parseable() {
    let dir = project("full");
    let options = EnvOptions::default();

    let plan = env::plan(&dir, &options).unwrap();
    assert_eq!(plan.entries.len(), 3);
    let summary = env::apply(&dir, &plan, &options).unwrap();
    assert_eq!(summary.vars_written.len(), 3);
    assert_eq!(summary.files_rewritten.len(), 2);
    assert!(summary.env_file_created);
    assert!(summary.gitignore_patched);

    // sources: secrets gone, accessors in place
    let js = std::fs::read_to_string(dir.join("pay.js")).unwrap();
    assert!(!js.contains("sk_live_"), "raw secret left in source:\n{js}");
    assert!(!js.contains("sk-ant-"));
    assert!(js.contains("const stripeKey = process.env.STRIPE_SECRET_KEY;"));
    assert!(js.contains("apiKey: process.env.ANTHROPIC_API_KEY,"));

    let py = std::fs::read_to_string(dir.join("cloud.py")).unwrap();
    assert!(!py.contains("AKIA"));
    assert!(py.contains("aws_key = os.environ[\"AWS_ACCESS_KEY_ID\"]"));
    // import inserted after shebang + docstring, exactly once
    assert_eq!(py.matches("import os").count(), 1);
    let docstring_pos = py.find("\"\"\"Payment").unwrap();
    let import_pos = py.find("import os").unwrap();
    assert!(
        import_pos > docstring_pos,
        "import os must come after the module docstring:\n{py}"
    );

    // ZERO BROKEN REWRITES: both files still parse without syntax errors
    let (scans, skipped) = scan::scan_path(&dir).unwrap();
    assert!(skipped.is_empty());
    assert_eq!(scans.len(), 2);
    for file in &scans {
        assert!(
            !file.has_syntax_errors,
            "{} broken after --write",
            file.path.display()
        );
    }

    // .env holds the values; .env.example holds keys only
    let env_file = std::fs::read_to_string(dir.join(".env")).unwrap();
    assert!(env_file.contains("STRIPE_SECRET_KEY=sk_live_FAKEFAKEFAKE1234"));
    assert!(env_file.contains("AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKEFAKE"));
    let example = std::fs::read_to_string(dir.join(".env.example")).unwrap();
    assert!(example.contains("STRIPE_SECRET_KEY=\n"));
    assert!(!example.contains("FAKE"), "values leaked into .env.example");

    // .gitignore covers the env file
    let gitignore = std::fs::read_to_string(dir.join(".gitignore")).unwrap();
    assert!(gitignore.lines().any(|l| l.trim() == ".env"));

    // IDEMPOTENT: a second run finds nothing (the .env file itself is not
    // scanned — it has no supported extension)
    let second = env::plan(&dir, &options).unwrap();
    assert!(
        second.entries.is_empty(),
        "second run still finds: {:?}",
        second
            .entries
            .iter()
            .map(|e| &e.var_name)
            .collect::<Vec<_>>()
    );
}

#[test]
fn apply_appends_without_clobbering_existing_env_files() {
    let dir = project("append");
    std::fs::write(dir.join(".env"), "EXISTING=1\n").unwrap();
    std::fs::write(dir.join(".gitignore"), "node_modules/\n.env\n").unwrap();
    let options = EnvOptions::default();

    let plan = env::plan(&dir, &options).unwrap();
    let summary = env::apply(&dir, &plan, &options).unwrap();

    let env_file = std::fs::read_to_string(dir.join(".env")).unwrap();
    assert!(
        env_file.starts_with("EXISTING=1\n"),
        "existing .env clobbered"
    );
    assert!(!summary.env_file_created);
    assert!(!summary.gitignore_patched, ".env already ignored");
    let gitignore = std::fs::read_to_string(dir.join(".gitignore")).unwrap();
    assert_eq!(gitignore.matches(".env").count(), 1);
}

/// C9 regression: a key can appear in `.env` between `plan()` and `apply()`
/// — edited externally, or a second `getdev env --write` racing this one.
/// The planned var must be skipped (not duplicated), reported in
/// `vars_skipped_stale`, and every other planned var still applied normally.
#[test]
fn env_key_added_between_plan_and_apply_is_not_duplicated() {
    let dir = project("staleenv");
    let options = EnvOptions::default();

    let plan = env::plan(&dir, &options).unwrap();
    assert_eq!(plan.entries.len(), 3);
    assert!(plan
        .entries
        .iter()
        .any(|e| e.var_name == "STRIPE_SECRET_KEY"));

    // simulate the race: STRIPE_SECRET_KEY lands in .env, with a DIFFERENT
    // value than getdev's plan, after plan() already ran.
    std::fs::write(
        dir.join(".env"),
        "STRIPE_SECRET_KEY=already-set-by-someone-else\n",
    )
    .unwrap();

    let summary = env::apply(&dir, &plan, &options).unwrap();
    assert_eq!(
        summary.vars_skipped_stale,
        vec!["STRIPE_SECRET_KEY".to_owned()]
    );
    assert_eq!(summary.vars_written.len(), 2);

    let env_file = std::fs::read_to_string(dir.join(".env")).unwrap();
    assert_eq!(
        env_file.matches("STRIPE_SECRET_KEY=").count(),
        1,
        "STRIPE_SECRET_KEY must not be duplicated:\n{env_file}"
    );
    assert!(env_file.contains("STRIPE_SECRET_KEY=already-set-by-someone-else"));
    // the other two planned vars still got appended normally
    assert!(env_file.contains("ANTHROPIC_API_KEY="));
    assert!(env_file.contains("AWS_ACCESS_KEY_ID="));
}

#[test]
fn stale_plan_is_rejected_and_nothing_is_written() {
    let dir = project("stale");
    let options = EnvOptions::default();
    let plan = env::plan(&dir, &options).unwrap();

    // file changes between plan and apply
    std::fs::write(dir.join("pay.js"), "const x = 1;\n").unwrap();

    let err = env::apply(&dir, &plan, &options).unwrap_err();
    assert!(err.to_string().contains("changed since the plan"));
    assert!(!dir.join(".env").exists(), "stale apply must write nothing");
}
