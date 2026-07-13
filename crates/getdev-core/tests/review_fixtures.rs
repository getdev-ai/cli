//! Data-driven fixture gate for the `rules/review/*.yaml` DECLARATIVE pack
//! (mirrors `audit_fixtures.rs`, driving `review::run` in `ReviewScope::All`
//! mode over `testdata/fixtures/review/`).
//!
//! Auto-discovers rules from `rules::load_embedded_review()` — no hardcoded
//! rule-id list — so a future declarative review rule is validated by this
//! gate without editing it. Findings are filtered by `f.id == rule.id`, so a
//! programmatic detector firing on a fixture (once 06-03/06-04 land) can never
//! break this declarative gate.
//!
//! The four PROGRAMMATIC review detectors do NOT use these declarative
//! `fixtures:` blocks — their inputs are unit-test files in their own modules
//! (see `testdata/fixtures/review/README.md`).

#![allow(clippy::unwrap_used)]

use std::collections::HashSet;
use std::path::PathBuf;

use getdev_core::review::{self, ReviewOptions, ReviewScope};
use getdev_core::rules;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/fixtures/review")
}

/// Every declarative review rule's every positive fixture must produce a
/// finding for THAT rule id (All mode ⇒ the whole file is introduced, so the
/// overlap filter passes).
#[test]
fn every_positive_fixture_fires() {
    let pack = rules::load_embedded_review().unwrap();
    let root = fixtures_root();

    let (findings, skipped) =
        review::run(&root, &ReviewScope::All, &ReviewOptions::default()).unwrap();
    assert!(skipped.is_empty(), "fixtures were skipped: {skipped:?}");

    for rule in &pack.rules {
        let hit_files: HashSet<&str> = findings
            .iter()
            .filter(|f| f.id == rule.id)
            .map(|f| f.file.as_str())
            .collect();

        for positive in &rule.fixtures.positive {
            assert!(
                hit_files.contains(positive.as_str()),
                "rule {}: positive fixture {positive} produced no finding for that rule id",
                rule.id
            );
        }
    }
}

/// No declarative review rule's negative fixture may produce a finding for
/// THAT rule id — including `todo-introduced`'s `todo_in_string` (marker in a
/// string, not a comment — the AST comment match must stay silent) and
/// `debug-leftover`'s bare-`print` exclusion.
#[test]
fn no_negative_fixture_fires() {
    let pack = rules::load_embedded_review().unwrap();
    let root = fixtures_root();

    let (findings, _skipped) =
        review::run(&root, &ReviewScope::All, &ReviewOptions::default()).unwrap();

    for rule in &pack.rules {
        for negative in &rule.fixtures.negative {
            let fired = findings
                .iter()
                .any(|f| f.id == rule.id && f.file == *negative);
            assert!(
                !fired,
                "rule {}: negative fixture {negative} produced a finding",
                rule.id
            );
        }
    }
}

/// CLAUDE.md hard rule 3 / SPEC-RULES: every declarative review rule declares
/// ≥3 positive + ≥3 negative fixtures AND accumulates ≥3 positive fixture
/// MATCHES (mirrors `audit_fixtures.rs`'s coverage floor).
#[test]
fn coverage_every_rule_meets_the_three_plus_three_fixture_floor() {
    let pack = rules::load_embedded_review().unwrap();
    let root = fixtures_root();

    let (findings, _skipped) =
        review::run(&root, &ReviewScope::All, &ReviewOptions::default()).unwrap();

    for rule in &pack.rules {
        assert!(
            rule.fixtures.positive.len() >= 3,
            "rule {}: fewer than 3 declared positive fixtures",
            rule.id
        );
        assert!(
            rule.fixtures.negative.len() >= 3,
            "rule {}: fewer than 3 declared negative fixtures",
            rule.id
        );

        let matches = findings
            .iter()
            .filter(|f| f.id == rule.id)
            .map(|f| f.file.as_str())
            .collect::<HashSet<_>>()
            .len();
        assert!(
            matches >= 3,
            "rule {}: fewer than 3 positive fixture matches ({matches})",
            rule.id
        );
    }
}
