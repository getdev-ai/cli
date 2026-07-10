//! Integration tests for typosquat scoring against the real embedded
//! datasets, through the public API only.
#![allow(clippy::unwrap_used)]

use getdev_registry::typosquat::score;
use getdev_registry::{Datasets, Ecosystem};

#[test]
fn embedded_datasets_load_and_parse() {
    let datasets = Datasets::embedded();
    assert!(
        datasets.is_ok(),
        "embedded top-N datasets must parse: {datasets:?}"
    );
}

#[test]
fn near_name_within_distance_2_yields_a_hit() {
    let datasets = Datasets::embedded().unwrap();
    assert_eq!(strsim_distance("reqeusts", "requests"), 1);
    let hit = score(&datasets, Ecosystem::Pypi, "reqeusts", None, None, 0);
    assert!(hit.is_some());

    assert_eq!(strsim_distance("reqeustz", "requests"), 2);
    let hit = score(&datasets, Ecosystem::Pypi, "reqeustz", None, None, 0);
    assert!(hit.is_some());
}

#[test]
fn exact_top_n_package_is_not_flagged_as_its_own_typosquat() {
    let datasets = Datasets::embedded().unwrap();
    assert!(score(&datasets, Ecosystem::Pypi, "requests", None, None, 0).is_none());
}

fn strsim_distance(a: &str, b: &str) -> usize {
    strsim::damerau_levenshtein(a, b)
}
