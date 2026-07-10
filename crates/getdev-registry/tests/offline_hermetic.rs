//! Hard, executable proof of REQ-privacy: under `--offline`, `verify_full`
//! never reaches the network. The `Fetcher` here panics if called at all —
//! not just "returns an error" — so any regression that lets an offline
//! path fall through to the network fails the test suite loudly.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use getdev_registry::{
    Cache, Datasets, Ecosystem, Existence, FetchOutcome, Fetcher, RegistryClient, RegistryError,
};

struct PanicFetcher;

impl Fetcher for PanicFetcher {
    fn get(&self, url: &str, _accept: Option<&str>) -> Result<FetchOutcome, RegistryError> {
        panic!("PanicFetcher must never be called under --offline: {url}");
    }
}

fn temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "getdev-registry-offline-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

#[test]
fn verify_full_under_offline_never_touches_the_panicking_fetcher() {
    let cache = Cache::open_at(&temp_dir("verify-full")).unwrap();
    cache
        .put_existence(Ecosystem::Npm, "left-pad", Existence::Found)
        .unwrap();
    cache
        .put_metadata(Ecosystem::Npm, "left-pad", Some(1_000_000), Some(100))
        .unwrap();

    let datasets = Datasets::embedded().unwrap();
    let client = RegistryClient::with_fetcher(Box::new(PanicFetcher), true);
    assert!(client.is_offline());

    let verdict = client
        .verify_full(&cache, &datasets, Ecosystem::Npm, "left-pad")
        .unwrap();
    assert_eq!(verdict.existence, Existence::Found);
    assert_eq!(verdict.downloads, Some(1_000_000));
    assert_eq!(verdict.created_at, Some(100));
}

#[test]
fn verify_full_under_offline_with_an_uncached_package_is_inconclusive_not_missing() {
    let cache = Cache::open_at(&temp_dir("verify-full-miss")).unwrap();
    let datasets = Datasets::embedded().unwrap();
    let client = RegistryClient::with_fetcher(Box::new(PanicFetcher), true);

    let verdict = client
        .verify_full(&cache, &datasets, Ecosystem::Npm, "never-seen-before-xyz")
        .unwrap();
    assert_eq!(verdict.existence, Existence::Inconclusive);
    assert_eq!(verdict.downloads, None);
    assert_eq!(verdict.created_at, None);
}

#[test]
fn env_offline_flag_also_short_circuits_existence_and_metadata() {
    // GETDEV_OFFLINE=1 is honored by resolve_offline(); this test exercises
    // the `offline: true` constructor path directly (see client.rs's test
    // module doc-comment for why the env var itself is not mutated here —
    // this crate forbids unsafe_code and env::set_var requires it on this
    // toolchain).
    let client = RegistryClient::with_fetcher(Box::new(PanicFetcher), true);
    assert!(matches!(
        client.existence(Ecosystem::Pypi, "requests"),
        Err(RegistryError::Offline { .. })
    ));
    assert!(matches!(
        client.metadata(Ecosystem::Pypi, "requests"),
        Err(RegistryError::Offline { .. })
    ));
}
