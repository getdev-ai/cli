//! Fixture gate for the env secret-detection pack (docs/TESTING.md):
//! every positive fixture must yield at least one finding, every negative
//! fixture exactly zero, and raw values must never surface.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use getdev_core::env::{self, EnvOptions};

fn fixtures(subdir: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/fixtures/env")
        .join(subdir)
}

#[test]
fn every_positive_fixture_fires() {
    let dir = fixtures("positive");
    let plan = env::plan(&dir, &EnvOptions::default()).unwrap();
    assert!(plan.skipped.is_empty());

    let mut files_with_hits: Vec<&str> = plan.entries.iter().map(|e| e.file.as_str()).collect();
    files_with_hits.sort_unstable();
    files_with_hits.dedup();

    let mut fixture_files: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    fixture_files.sort();

    assert_eq!(
        files_with_hits, fixture_files,
        "every positive fixture file must produce at least one finding"
    );
    // llm_client.ts seeds two secrets
    assert!(plan.entries.len() > fixture_files.len());
}

#[test]
fn no_negative_fixture_fires() {
    let plan = env::plan(&fixtures("negative"), &EnvOptions::default()).unwrap();
    let details: Vec<String> = plan
        .entries
        .iter()
        .map(|e| format!("{}:{} {}", e.file, e.line, e.var_name))
        .collect();
    assert!(
        plan.entries.is_empty(),
        "negative fixtures fired: {details:?}"
    );
}

#[test]
fn findings_json_never_contains_raw_values() {
    let options = EnvOptions::default();
    let plan = env::plan(&fixtures("positive"), &options).unwrap();
    let findings = env::findings(&plan, &options);
    let json = serde_json::to_string(&findings).unwrap();
    for leaked in ["FAKEFAKEFAKEFAKE", "9fQ4cA2e78bZ1dY6fX3aP5cV0e9K4mW7"] {
        assert!(
            !json.contains(leaked),
            "raw secret '{leaked}' leaked into findings JSON"
        );
    }
}
