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
use getdev_core::rules::{self, Framework, Matcher, Rule, RulePack};
use getdev_core::scan::Lang;

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

/// Isolate a single AST matcher into its own one-matcher `RulePack`: keep
/// the rule's id/severity/frameworks/path_glob (so scanning + gating behave
/// exactly as in the full pack) but replace `matchers` with just this one
/// entry. `rules::merge` into an empty pack compiles the query into the
/// returned pack's `query_cache` — the same public path `--rules` uses — so
/// the matcher's query is exercised STANDALONE, never merged with its
/// same-language siblings.
fn single_matcher_pack(rule: &Rule, language: Lang, query: &str) -> (RulePack, Vec<String>) {
    let synthetic = Rule {
        id: rule.id.clone(),
        severity: rule.severity,
        confidence: rule.confidence,
        languages: vec![language],
        frameworks: rule.frameworks.clone(),
        path_glob: rule.path_glob.clone(),
        description: rule.description.clone(),
        message: rule.message.clone(),
        remediation: rule.remediation.clone(),
        refs: rule.refs.clone(),
        matchers: vec![Matcher::Ast {
            language,
            query: query.to_owned(),
        }],
        fixtures: rule.fixtures.clone(),
    };
    rules::merge(RulePack::new(), vec![synthetic])
}

/// STRUCTURAL gate (the e3e2c19 lesson): `every_positive_fixture_fires` and
/// `coverage_…` only prove that SOME finding fires per fixture / that a rule
/// accumulates >= 3 hits — neither can see a rule that ships an AST matcher
/// NO fixture ever exercises. That is exactly how e3e2c19 (and its 7-rule
/// blast radius) slipped the net: a silently-dropped/broken matcher whose
/// twin is in no fixture stays green.
///
/// This test compiles EACH AST matcher standalone (per language, isolated
/// from its same-language siblings via `single_matcher_pack`) and asserts at
/// least one of that rule's positive fixtures OF THAT LANGUAGE triggers THAT
/// matcher. If any AST matcher is unexercised, the test FAILS naming the
/// rule, matcher index, language, and query — so a future rule author cannot
/// ship an untested (and possibly broken) matcher. A genuinely unexercisable
/// matcher must be reported and fixtured, never silenced by weakening this
/// gate.
#[test]
fn every_ast_matcher_has_an_exercising_positive_fixture() {
    let pack = rules::load_embedded().unwrap();
    let root = fixtures_root();

    let mut unexercised: Vec<String> = Vec::new();

    for rule in &pack.rules {
        let frameworks = frameworks_for(rule);
        for (matcher_index, matcher) in rule.matchers.iter().enumerate() {
            let Matcher::Ast { language, query } = matcher else {
                continue;
            };

            let (single_pack, warnings) = single_matcher_pack(rule, *language, query);
            assert!(
                warnings.is_empty(),
                "rule {} matcher #{matcher_index}: standalone compile warned: {warnings:?}",
                rule.id
            );

            let (findings, skipped) =
                audit::run(&root, &single_pack, &frameworks, &AuditOptions::default()).unwrap();
            assert!(
                skipped.is_empty(),
                "rule {} matcher #{matcher_index}: fixtures were skipped: {skipped:?}",
                rule.id
            );

            // A positive fixture "of this language" that produced a finding
            // for this rule id. Because the isolated pack holds only this one
            // language matcher, any positive that fires necessarily exercised
            // THIS matcher.
            let exercised = rule.fixtures.positive.iter().any(|positive| {
                Lang::from_path(std::path::Path::new(positive)) == Some(*language)
                    && findings
                        .iter()
                        .any(|f| f.id == rule.id && f.file == *positive)
            });

            if !exercised {
                unexercised.push(format!(
                    "rule {} matcher #{matcher_index} (language {language:?}) has no positive \
                     fixture of that language that triggers it — query:\n{query}",
                    rule.id
                ));
            }
        }
    }

    assert!(
        unexercised.is_empty(),
        "{} AST matcher(s) ship with no exercising positive fixture (add one, or report a \
         genuinely unexercisable matcher — do NOT weaken this gate):\n\n{}",
        unexercised.len(),
        unexercised.join("\n\n")
    );
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
