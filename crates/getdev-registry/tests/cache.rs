//! Integration tests for the SQLite cache + `RegistryClient::verify`'s
//! cache-first path, exercised entirely through the public API against a
//! temp directory — never the real `~/.getdev` (docs/TESTING.md).
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use getdev_registry::{
    Cache, Ecosystem, Existence, FetchOutcome, Fetcher, RegistryClient, RegistryError,
};

fn temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "getdev-registry-cache-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

/// A `Fetcher` that panics if ever called — the same "hard, executable
/// proof" pattern used by `tests/offline_hermetic.rs`.
struct PanicFetcher;

impl Fetcher for PanicFetcher {
    fn get(&self, url: &str, _accept: Option<&str>) -> Result<FetchOutcome, RegistryError> {
        panic!("PanicFetcher must never be called: {url}");
    }
}

#[test]
fn existence_put_and_get_round_trip() {
    let cache = Cache::open_at(&temp_dir("existence")).unwrap();
    assert_eq!(
        cache.get_existence(Ecosystem::Npm, "left-pad").unwrap(),
        None
    );

    cache
        .put_existence(Ecosystem::Npm, "left-pad", Existence::Found)
        .unwrap();
    assert_eq!(
        cache.get_existence(Ecosystem::Npm, "left-pad").unwrap(),
        Some(Existence::Found)
    );
}

#[test]
fn metadata_put_and_get_round_trip() {
    let cache = Cache::open_at(&temp_dir("metadata")).unwrap();
    assert_eq!(
        cache.get_metadata(Ecosystem::Npm, "left-pad").unwrap(),
        None
    );

    cache
        .put_metadata(Ecosystem::Npm, "left-pad", Some(42), Some(1_000))
        .unwrap();
    assert_eq!(
        cache.get_metadata(Ecosystem::Npm, "left-pad").unwrap(),
        Some((Some(42), Some(1_000)))
    );
}

#[test]
fn offline_cache_miss_is_inconclusive_never_missing() {
    let cache = Cache::open_at(&temp_dir("offline-miss")).unwrap();
    let fetcher = PanicFetcher;
    let client = RegistryClient::with_fetcher(Box::new(fetcher), true);

    let existence = client
        .verify(&cache, Ecosystem::Npm, "totally-unseeded-package")
        .unwrap();
    assert_eq!(
        existence,
        Existence::Inconclusive,
        "offline + cache-miss must never fabricate Missing"
    );
}

#[test]
fn offline_client_reads_a_seeded_row_with_zero_fetcher_calls() {
    let cache = Cache::open_at(&temp_dir("offline-seeded")).unwrap();
    cache
        .put_existence(Ecosystem::Npm, "left-pad", Existence::Found)
        .unwrap();

    let fetcher = PanicFetcher;
    let client = RegistryClient::with_fetcher(Box::new(fetcher), true);

    let existence = client.verify(&cache, Ecosystem::Npm, "left-pad").unwrap();
    assert_eq!(existence, Existence::Found);
}
