//! Fixture gate for the env secret-detection pack (docs/TESTING.md):
//! every positive fixture must yield at least one finding, every negative
//! fixture exactly zero, and raw values must never surface.

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::path::PathBuf;

use getdev_core::env::{self, EnvOptions};
use getdev_core::secrets::SecretPatterns;

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

/// C5/CLAUDE.md hard rule 3: every pattern shipped in
/// rules/env/secrets.yaml must have >= 3 positive fixture MATCHES (not just
/// one file that happens to fire) in testdata/fixtures/env/positive/. This
/// is the per-rule check the file-level `every_positive_fixture_fires`
/// above cannot express — a single fixture file can satisfy that test while
/// covering only one of a pattern's several distinct key shapes.
#[test]
fn every_secret_pattern_has_at_least_three_positive_matches() {
    let plan = env::plan(&fixtures("positive"), &EnvOptions::default()).unwrap();

    let mut counts: HashMap<String, usize> = HashMap::new();
    for entry in &plan.entries {
        *counts.entry(entry.secret.pattern_id.clone()).or_insert(0) += 1;
    }

    let patterns = SecretPatterns::embedded().unwrap();
    let mut under_covered = Vec::new();
    for pattern in patterns.patterns() {
        let count = counts.get(pattern.id.as_str()).copied().unwrap_or(0);
        if count < 3 {
            under_covered.push(format!("{} ({count} match(es))", pattern.id));
        }
    }

    assert!(
        under_covered.is_empty(),
        "patterns with fewer than 3 positive fixture matches: {under_covered:?}"
    );
}

/// C5/CLAUDE.md hard rule 3, negative half: every pattern's near-miss
/// fixtures actually land on the pattern they're guarding — a value that
/// coincidentally contains a DIFFERENT provider's substring wouldn't prove
/// anything about the pattern under test. This asserts the full negative
/// corpus produces zero entropy-fallback hits too (the blanket
/// `no_negative_fixture_fires` above already covers zero-total; this
/// documents *why* per-pattern negative coverage matters: every negative
/// fixture file is paired 1:1 with a positive `providers_*` file above by
/// naming convention).
#[test]
fn negative_fixtures_cover_every_provider_pairing() {
    let positive_providers = [
        "providers_stripe.js",
        "providers_aws.py",
        "providers_github.ts",
        "providers_llm.ts",
        "providers_google.js",
        "providers_slack_sendgrid_twilio.js",
        "providers_npm.js",
        "providers_supabase.ts",
        "providers_private_key.py",
    ];
    let negative_dir = fixtures("negative");
    for positive_file in positive_providers {
        let stem = positive_file.rsplit_once('.').unwrap().0;
        let has_pairing = std::fs::read_dir(&negative_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{stem}_neg"))
            });
        assert!(
            has_pairing,
            "positive/{positive_file} has no matching negative/{stem}_neg.* fixture"
        );
    }
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
