//! Fixture gate for the LLM model-string matcher (docs/TESTING.md): every
//! positive fixture must be flagged as an unknown model string, every
//! negative fixture must never fire — mirrors `env_fixtures.rs`'s pattern.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use getdev_core::models::ModelMatcher;
use getdev_core::scan;

fn fixtures(subdir: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/fixtures/models")
        .join(subdir)
}

#[test]
fn every_positive_fixture_is_flagged() {
    let matcher = ModelMatcher::embedded().unwrap();
    let dir = fixtures("positive");
    let (assignments, skipped) = scan::collect_string_assignments(&dir).unwrap();
    assert!(skipped.is_empty());
    assert!(
        assignments.len() >= 3,
        "expected at least 3 positive fixture assignments, found {}",
        assignments.len()
    );
    for assignment in &assignments {
        let verdict = matcher.classify_model(&assignment.value, &assignment.name);
        assert!(
            verdict.is_some(),
            "expected '{}' ({}) in {:?} to be flagged as an unknown model string",
            assignment.value,
            assignment.name,
            assignment.path
        );
    }
}

#[test]
fn no_negative_fixture_is_flagged() {
    let matcher = ModelMatcher::embedded().unwrap();
    let dir = fixtures("negative");
    let (assignments, skipped) = scan::collect_string_assignments(&dir).unwrap();
    assert!(skipped.is_empty());
    assert!(
        assignments.len() >= 3,
        "expected at least 3 negative fixture assignments, found {}",
        assignments.len()
    );
    for assignment in &assignments {
        let verdict = matcher.classify_model(&assignment.value, &assignment.name);
        assert!(
            verdict.is_none(),
            "expected '{}' ({}) in {:?} to NOT be flagged",
            assignment.value,
            assignment.name,
            assignment.path
        );
    }
}

#[test]
fn embedded_dataset_parses_and_has_no_hallucinated_families() {
    // rules/models.json's family-prefix list is human-approved (checkpoint,
    // 03-05-PLAN.md) — this pins down that a prior session's hallucinated
    // "claude-mythos-" family never sneaks back in.
    let matcher = ModelMatcher::embedded().unwrap();
    assert!(matcher
        .classify_model("claude-mythos-7", "model_name")
        .is_some());
}
