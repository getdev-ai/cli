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
//! - `rules/real/pypi-top-15k.json`: `Robert-96/top-pypi-packages`
//!   (<https://github.com/Robert-96/top-pypi-packages>), MIT license,
//!   confirmed via the GitHub Licenses API. This wraps (and re-publishes
//!   under its own MIT grant) `hugovk/top-pypi-packages`' monthly PyPI
//!   download ranking; `hugovk/top-pypi-packages` itself carries no
//!   explicit LICENSE file, so the un-licensed upstream repo was not vendored
//!   directly (03-RESEARCH.md Assumption A3) — Robert-96's MIT-licensed,
//!   API-enriched republish (~5k packages) was used instead. See the plan
//!   SUMMARY for the full licensing note, including the resulting package
//!   count being smaller than the `-15k` filename suggests.

use serde::Deserialize;

use crate::client::Ecosystem;

const NPM_DATASET_JSON: &str = include_str!("../../../rules/real/npm-top-10k.json");
const PYPI_DATASET_JSON: &str = include_str!("../../../rules/real/pypi-top-15k.json");

/// Near-name reason fires when the Damerau-Levenshtein distance to the
/// nearest top-N package is in `1..=NEAR_NAME_MAX_DISTANCE`.
const NEAR_NAME_MAX_DISTANCE: usize = 2;
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

/// Scores one package name against the embedded dataset plus its own
/// registry-derived downloads/creation-date. Returns `None` when no reason
/// fires (the common case — most dependencies are legitimate).
pub fn score(
    datasets: &Datasets,
    eco: Ecosystem,
    name: &str,
    downloads: Option<u64>,
    created_at: Option<i64>,
    now: i64,
) -> Option<TyposquatHit> {
    let candidates = datasets.for_ecosystem(eco);
    let mut reasons = Vec::new();
    let mut nearest = String::new();
    let mut nearest_distance = usize::MAX;

    let is_exact_top_n = candidates.iter().any(|c| c == name);
    if !is_exact_top_n {
        for candidate in candidates {
            let distance = strsim::damerau_levenshtein(name, candidate);
            if distance < nearest_distance {
                nearest_distance = distance;
                nearest.clone_from(candidate);
            }
        }
        if (1..=NEAR_NAME_MAX_DISTANCE).contains(&nearest_distance) {
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
}
