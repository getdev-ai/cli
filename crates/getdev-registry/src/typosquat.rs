//! Typosquat scoring over embedded top-N popularity snapshots
//! (docs/PLAN.md §2.3 `real/typosquat-suspect`): a name is a suspect when
//! ANY of — near-name (Damerau-Levenshtein <= 2 of a top-N package),
//! low download count, or created < 90 days ago — fires.
//!
//! Dataset provenance (Assumptions A2/A3 in 03-RESEARCH.md — license must be
//! confirmed before embedding, recorded here and in the plan SUMMARY):
//! - `rules/real/npm-top-10k.json`: `wooorm/npm-high-impact`
//!   (<https://github.com/wooorm/npm-high-impact>), MIT license. Confirmed
//!   directly against the repo's `license` file at implementation time.
//! - `rules/real/pypi-top-5k.json`: `Robert-96/top-pypi-packages`
//!   (<https://github.com/Robert-96/top-pypi-packages>), MIT license,
//!   confirmed via the GitHub Licenses API. This wraps (and re-publishes
//!   under its own MIT grant) `hugovk/top-pypi-packages`' monthly PyPI
//!   download ranking; `hugovk/top-pypi-packages` itself carries no
//!   explicit LICENSE file, so the un-licensed upstream repo was not vendored
//!   directly (03-RESEARCH.md Assumption A3) — Robert-96's MIT-licensed,
//!   API-enriched republish was used instead. It contains 4,999 entries
//!   (audit E5) — the file is named `-5k`, not `-15k`, to match that count
//!   honestly rather than overstate typosquat recall. See the plan SUMMARY
//!   for the full licensing note.

use serde::Deserialize;

use crate::client::Ecosystem;

const NPM_DATASET_JSON: &str = include_str!("../data/npm-top-10k.json");
const PYPI_DATASET_JSON: &str = include_str!("../data/pypi-top-5k.json");

/// Near-name reason fires when the Damerau-Levenshtein distance to the
/// nearest top-N package is in `1..=NEAR_NAME_MAX_DISTANCE`.
const NEAR_NAME_MAX_DISTANCE: usize = 2;
/// E1 DoS guard: above this length, near-name scoring (an O(candidates *
/// name_len * candidate_len) Damerau-Levenshtein pass over the whole
/// dataset) is skipped entirely. No legitimate npm/PyPI package name
/// approaches this length; a multi-MB name in a hostile manifest is a
/// resource-exhaustion attempt, not a typo. Exact-membership (`==`)
/// checking still runs regardless of length — it's a cheap length-gated
/// string compare, not the scoring pass.
const MAX_NAME_LEN_FOR_NEAR_NAME_SCORING: usize = 128;
/// npm last-week download count below this is "low downloads"
/// (documented heuristic threshold — surfaced in the finding `detail` per
/// FP policy §9.2, not hidden).
const LOW_DOWNLOADS_THRESHOLD: u64 = 1000;
/// A package created less than this many seconds ago is "new"
/// (90 days, docs/PLAN.md §2.3).
const NEW_PACKAGE_MAX_AGE_SECS: i64 = 90 * 24 * 3600;

#[derive(Debug, thiserror::Error)]
pub enum DatasetError {
    #[error("invalid top-package dataset: {0}")]
    Parse(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatasetFile {
    #[allow(dead_code)]
    version: u32,
    #[allow(dead_code)]
    ecosystem: String,
    #[allow(dead_code)]
    source: String,
    #[allow(dead_code)]
    license: String,
    #[allow(dead_code)]
    refresh: String,
    packages: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TyposquatReason {
    NearName,
    LowDownloads,
    NewPackage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TyposquatHit {
    pub nearest: String,
    pub distance: usize,
    pub reasons: Vec<TyposquatReason>,
}

#[derive(Debug)]
pub struct Datasets {
    npm: Vec<String>,
    pypi: Vec<String>,
}

impl Datasets {
    /// Load the embedded top-N snapshots. A malformed embedded pack is a
    /// release-blocking bug (mirrors `SecretPatterns::embedded()`), never a
    /// panic — the CLI reports it as a typed error.
    pub fn embedded() -> Result<Self, DatasetError> {
        let npm: DatasetFile = serde_json::from_str(NPM_DATASET_JSON)?;
        let pypi: DatasetFile = serde_json::from_str(PYPI_DATASET_JSON)?;
        Ok(Self {
            npm: npm.packages,
            pypi: pypi.packages,
        })
    }

    fn for_ecosystem(&self, eco: Ecosystem) -> &[String] {
        match eco {
            Ecosystem::Npm => &self.npm,
            Ecosystem::Pypi => &self.pypi,
        }
    }
}

/// `[real].typosquat_sensitivity` (docs/SPEC-CONFIG.md: `"strict" | "normal"
/// | "off"`) — B2 audit fix: the config key existed but nothing read it.
/// `Off` skips the typosquat check entirely (never returns a hit); `Strict`
/// widens the near-name distance threshold to catch more lookalikes at the
/// cost of more false positives; `Normal` is the existing/default behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    Strict,
    Normal,
    Off,
}

impl Sensitivity {
    /// Unrecognized strings fall back to `Normal` — validating the config
    /// value itself is not this fix's scope; a typo here degrades
    /// gracefully to the pre-existing behavior rather than erroring.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw {
            "strict" => Self::Strict,
            "off" => Self::Off,
            _ => Self::Normal,
        }
    }

    fn near_name_max_distance(self) -> usize {
        match self {
            Self::Strict => NEAR_NAME_MAX_DISTANCE + 1,
            Self::Normal => NEAR_NAME_MAX_DISTANCE,
            Self::Off => 0,
        }
    }
}

/// Scores one package name against the embedded dataset plus its own
/// registry-derived downloads/creation-date, at the default (`Normal`)
/// sensitivity. Returns `None` when no reason fires (the common case — most
/// dependencies are legitimate).
pub fn score(
    datasets: &Datasets,
    eco: Ecosystem,
    name: &str,
    downloads: Option<u64>,
    created_at: Option<i64>,
    now: i64,
) -> Option<TyposquatHit> {
    score_with_sensitivity(
        datasets,
        eco,
        name,
        downloads,
        created_at,
        now,
        Sensitivity::Normal,
    )
}

/// `score`, but with `[real].typosquat_sensitivity` pass-through (B2).
#[allow(clippy::too_many_arguments)]
pub fn score_with_sensitivity(
    datasets: &Datasets,
    eco: Ecosystem,
    name: &str,
    downloads: Option<u64>,
    created_at: Option<i64>,
    now: i64,
    sensitivity: Sensitivity,
) -> Option<TyposquatHit> {
    if sensitivity == Sensitivity::Off {
        return None;
    }

    // E2: self-normalize PyPI names (PEP 503) before dataset/cache use — a
    // caller that forgot to normalize (or normalized only for the URL, not
    // for typosquat scoring) must not see `Django` flagged as a near-name
    // typo of `django`. npm names pass through unchanged (already
    // canonical; scoped names' `/` is not touched by PEP 503 rules).
    let normalized_name;
    let name: &str = match eco {
        Ecosystem::Pypi => {
            normalized_name = crate::client::normalize_pep503(name);
            &normalized_name
        }
        Ecosystem::Npm => name,
    };

    let candidates = datasets.for_ecosystem(eco);
    let mut reasons = Vec::new();
    let mut nearest = String::new();
    let mut nearest_distance = usize::MAX;

    // E1: the exact-membership check is a cheap length-gated `==` (never a
    // scoring pass) and always runs, even for a pathological input — but the
    // Damerau-Levenshtein scoring loop below is skipped entirely above
    // `MAX_NAME_LEN_FOR_NEAR_NAME_SCORING`.
    let is_exact_top_n = candidates.iter().any(|c| c == name);
    if !is_exact_top_n && name.chars().count() <= MAX_NAME_LEN_FOR_NEAR_NAME_SCORING {
        let max_distance = sensitivity.near_name_max_distance();
        let name_len = name.chars().count();
        for candidate in candidates {
            // E1: a per-candidate length-diff prune — Damerau-Levenshtein
            // distance is always >= the absolute length difference, so any
            // candidate whose length differs from `name` by more than
            // `max_distance` can never be a near-name hit; skip the O(n*m)
            // comparison entirely for it.
            let candidate_len = candidate.chars().count();
            let len_diff = (name_len as isize - candidate_len as isize).unsigned_abs();
            if len_diff > max_distance {
                continue;
            }
            let distance = strsim::damerau_levenshtein(name, candidate);
            if distance < nearest_distance {
                nearest_distance = distance;
                nearest.clone_from(candidate);
            }
        }
        if (1..=max_distance).contains(&nearest_distance) {
            reasons.push(TyposquatReason::NearName);
        }
    }

    if let Some(downloads) = downloads {
        if downloads < LOW_DOWNLOADS_THRESHOLD {
            reasons.push(TyposquatReason::LowDownloads);
        }
    }

    if let Some(created_at) = created_at {
        if now - created_at < NEW_PACKAGE_MAX_AGE_SECS {
            reasons.push(TyposquatReason::NewPackage);
        }
    }

    if reasons.is_empty() {
        return None;
    }

    Some(TyposquatHit {
        nearest,
        distance: if nearest_distance == usize::MAX {
            0
        } else {
            nearest_distance
        },
        reasons,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn embedded_datasets_parse_and_are_non_empty() {
        let datasets = Datasets::embedded().unwrap();
        assert!(!datasets.npm.is_empty());
        assert!(!datasets.pypi.is_empty());
        assert!(datasets.npm.contains(&"left-pad".to_owned()));
        assert!(datasets.pypi.contains(&"requests".to_owned()));
    }

    #[test]
    fn near_name_typo_at_distance_1_is_flagged() {
        let datasets = Datasets::embedded().unwrap();
        // A single adjacent-transposition typo of "requests" (verified via
        // strsim: damerau_levenshtein("reqeusts", "requests") == 1).
        assert_eq!(strsim::damerau_levenshtein("reqeusts", "requests"), 1);
        let hit = score(&datasets, Ecosystem::Pypi, "reqeusts", None, None, 0).unwrap();
        assert!(hit.reasons.contains(&TyposquatReason::NearName));
        assert_eq!(hit.nearest, "requests");
        assert_eq!(hit.distance, 1);
    }

    #[test]
    fn near_name_typo_at_distance_2_is_flagged() {
        let datasets = Datasets::embedded().unwrap();
        // Two edits away from "requests" (verified via strsim).
        assert_eq!(strsim::damerau_levenshtein("reqeustz", "requests"), 2);
        let hit = score(&datasets, Ecosystem::Pypi, "reqeustz", None, None, 0).unwrap();
        assert!(hit.reasons.contains(&TyposquatReason::NearName));
        assert_eq!(hit.nearest, "requests");
        assert_eq!(hit.distance, 2);
    }

    #[test]
    fn exact_top_n_name_is_never_its_own_typosquat() {
        let datasets = Datasets::embedded().unwrap();
        assert!(score(&datasets, Ecosystem::Pypi, "requests", None, None, 0).is_none());
        assert!(score(&datasets, Ecosystem::Npm, "left-pad", None, None, 0).is_none());
    }

    #[test]
    fn low_downloads_reason_fires_independent_of_name_distance() {
        let datasets = Datasets::embedded().unwrap();
        let hit = score(
            &datasets,
            Ecosystem::Npm,
            "some-totally-unrelated-name-xyz",
            Some(3),
            None,
            0,
        )
        .unwrap();
        assert_eq!(hit.reasons, vec![TyposquatReason::LowDownloads]);
    }

    #[test]
    fn new_package_reason_fires_independent_of_name_distance() {
        let datasets = Datasets::embedded().unwrap();
        let now = 10_000_000;
        let hit = score(
            &datasets,
            Ecosystem::Npm,
            "some-totally-unrelated-name-xyz",
            None,
            Some(now - 1000),
            now,
        )
        .unwrap();
        assert_eq!(hit.reasons, vec![TyposquatReason::NewPackage]);
    }

    #[test]
    fn no_reason_fires_for_a_boring_legitimate_package() {
        let datasets = Datasets::embedded().unwrap();
        let now = 10_000_000_000;
        assert!(score(
            &datasets,
            Ecosystem::Npm,
            "some-totally-unrelated-name-xyz",
            Some(50_000),
            Some(now - NEW_PACKAGE_MAX_AGE_SECS - 1),
            now,
        )
        .is_none());
    }

    // --- E1: DoS guard -----------------------------------------------

    #[test]
    fn a_multi_megabyte_name_returns_quickly_with_no_near_name_hit() {
        let datasets = Datasets::embedded().unwrap();
        // 1MB name: if the length cap didn't short-circuit the scoring
        // loop, this would run a full Damerau-Levenshtein pass against
        // every dataset entry (thousands of O(n*m) comparisons against a
        // ~1_000_000-char string) — a CPU/memory DoS via a hostile
        // manifest. The test's only real assertion is that this returns at
        // all (no panic, no hang); the `None` also documents that a
        // pathological name is never treated as a near-name hit.
        let huge_name = "a".repeat(1_000_000);
        let hit = score(&datasets, Ecosystem::Npm, &huge_name, None, None, 0);
        assert!(hit.is_none());
    }

    #[test]
    fn length_pruning_preserves_existing_near_name_hits() {
        let datasets = Datasets::embedded().unwrap();
        // Regression guard for the E1 per-candidate length-diff prune:
        // these are the same fixtures as the pre-existing distance-1/2
        // tests above — they must still fire after pruning is introduced.
        let hit = score(&datasets, Ecosystem::Pypi, "reqeusts", None, None, 0).unwrap();
        assert!(hit.reasons.contains(&TyposquatReason::NearName));
        assert_eq!(hit.nearest, "requests");
        assert_eq!(hit.distance, 1);

        let hit = score(&datasets, Ecosystem::Pypi, "reqeustz", None, None, 0).unwrap();
        assert!(hit.reasons.contains(&TyposquatReason::NearName));
        assert_eq!(hit.nearest, "requests");
        assert_eq!(hit.distance, 2);
    }

    #[test]
    fn a_name_at_exactly_the_length_cap_still_scores_normally() {
        let datasets = Datasets::embedded().unwrap();
        // A name at (not over) MAX_NAME_LEN_FOR_NEAR_NAME_SCORING is a
        // boundary case that must still be scored — only names strictly
        // over the cap are skipped.
        let mut name = "reqeusts".to_owned();
        name.push_str(&"x".repeat(MAX_NAME_LEN_FOR_NEAR_NAME_SCORING - name.len()));
        assert_eq!(name.chars().count(), MAX_NAME_LEN_FOR_NEAR_NAME_SCORING);
        // Far from every dataset entry (padded with 'x'), so no NearName
        // hit is expected — but the exact-membership `is_none()` shape
        // proves the scoring path ran (rather than being skipped by the
        // length cap) without needing a private-field assertion.
        assert!(score(&datasets, Ecosystem::Pypi, &name, None, None, 0).is_none());
    }

    // --- E2: self-normalization ---------------------------------------

    #[test]
    fn pypi_typosquat_scoring_self_normalizes_pep503() {
        let datasets = Datasets::embedded().unwrap();
        // `typing_extensions` (underscore form) must not be flagged as a
        // near-name typo of the dataset's canonical `typing-extensions`
        // entry — without self-normalization the two are 1 edit apart
        // (`_` vs `-`) and would false-positive as NearName.
        assert!(datasets.pypi.contains(&"typing-extensions".to_owned()));
        assert!(score(
            &datasets,
            Ecosystem::Pypi,
            "typing_extensions",
            None,
            None,
            0
        )
        .is_none());

        // Case variance must collapse the same way (`Django` == `django`).
        assert!(score(&datasets, Ecosystem::Pypi, "Django", None, None, 0).is_none());
    }
}
