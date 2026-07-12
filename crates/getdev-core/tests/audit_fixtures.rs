//! Data-driven fixture gate for the `rules/audit/*.yaml` pack (mirrors
//! `env_fixtures.rs`'s table-driven pattern, SC1/SC4, 04-VALIDATION.md).
//!
//! This file auto-discovers rules from `rules::load_embedded()` — it
//! contains NO hardcoded rule-id list — so 04-03/04/05 (the plans that
//! actually author `rules/audit/*.yaml`) are validated by this gate without
//! ever editing it. Against the current, still-empty embedded pack (only
//! `rules/audit/schema.json` exists so far — 04-01/04-02 scope), every test
//! below is trivially green: the assertions quantify over whatever rules
//! exist, and start enforcing the moment a rule lands.
//!
//! Fixture path convention (established here, binding for every rule
//! authored later): a rule's `fixtures.positive`/`fixtures.negative` YAML
//! entries are paths relative to `testdata/fixtures/audit/` (e.g.
//! `positive/hardcoded_secret_stripe.js`), matching how `audit::run`'s
//! returned `Finding.file` is computed when `root` is that same directory.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use getdev_core::audit::{self, AuditOptions};
use getdev_core::frameworks::DetectedFrameworks;
use getdev_core::rules::{self, Framework, Matcher, Rule};

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/fixtures/audit")
}

/// A `DetectedFrameworks` with every framework `rule` declares forced
/// present — framework-scoped rules must be exercised by this gate exactly
/// as they'd fire in a project that actually has the framework (SC2).
fn frameworks_for(rule: &Rule) -> DetectedFrameworks {
    let mut frameworks = DetectedFrameworks::default();
    for framework in &rule.frameworks {
        match framework {
            Framework::Express => frameworks.express = true,
            Framework::Nextjs => frameworks.nextjs_api = true,
            Framework::Fastapi => frameworks.fastapi = true,
            Framework::Flask => frameworks.flask = true,
        }
    }
    frameworks
}

#[test]
fn every_positive_fixture_fires() {
    let pack = rules::load_embedded().unwrap();
    let root = fixtures_root();

    for rule in &pack.rules {
        let frameworks = frameworks_for(rule);
        let (findings, skipped) =
            audit::run(&root, &pack, &frameworks, &AuditOptions::default()).unwrap();
        assert!(
            skipped.is_empty(),
            "rule {}: fixtures were skipped: {skipped:?}",
            rule.id
        );

        let hit_files: std::collections::HashSet<&str> = findings
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

#[test]
fn no_negative_fixture_fires() {
    let pack = rules::load_embedded().unwrap();
    let root = fixtures_root();

    for rule in &pack.rules {
        let frameworks = frameworks_for(rule);
        let (findings, _skipped) =
            audit::run(&root, &pack, &frameworks, &AuditOptions::default()).unwrap();

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

/// CLAUDE.md hard rule 3 / SC4: every shipped rule declares >= 3 positive
/// and >= 3 negative fixtures, AND accumulates >= 3 positive fixture
/// MATCHES (not just "some file fired") — the per-rule check
/// `every_positive_fixture_fires` above cannot express, mirroring
/// `env_fixtures.rs`'s `every_secret_pattern_has_at_least_three_positive_matches`.
/// Named so `cargo test -p getdev-core --test audit_fixtures -- coverage`
/// selects it.
#[test]
fn coverage_every_rule_meets_the_three_plus_three_fixture_floor() {
    let pack = rules::load_embedded().unwrap();
    let root = fixtures_root();

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

        let frameworks = frameworks_for(rule);
        let (findings, _skipped) =
            audit::run(&root, &pack, &frameworks, &AuditOptions::default()).unwrap();
        let matches = findings.iter().filter(|f| f.id == rule.id).count();
        assert!(
            matches >= 3,
            "rule {}: fewer than 3 positive fixture matches ({matches})",
            rule.id
        );
    }
}

/// Pitfall 6: for every rule wrapping the secret matcher, its positive
/// fixtures' raw file content must never leak verbatim into the findings
/// JSON — `audit/hardcoded-secret`'s own precise masking behavior is
/// additionally unit-tested directly in `audit.rs`; this is the coarser,
/// data-driven safety net exercised against the real shipped fixtures.
#[test]
fn findings_json_never_contains_raw_fixture_content() {
    let pack = rules::load_embedded().unwrap();
    let root = fixtures_root();

    for rule in &pack.rules {
        let has_secret_matcher = rule.matchers.iter().any(|m| matches!(m, Matcher::Secret));
        if !has_secret_matcher {
            continue;
        }

        let frameworks = frameworks_for(rule);
        let (findings, _skipped) =
            audit::run(&root, &pack, &frameworks, &AuditOptions::default()).unwrap();
        let json = serde_json::to_string(&findings).unwrap();

        for positive in &rule.fixtures.positive {
            let Ok(raw) = std::fs::read_to_string(root.join(positive)) else {
                continue;
            };
            let trimmed = raw.trim();
            assert!(
                trimmed.is_empty() || !json.contains(trimmed),
                "rule {}: positive fixture {positive}'s raw content leaked verbatim into findings JSON",
                rule.id
            );
        }
    }
}
