//! Hermetic tests for `RegistryClient::existence`/`metadata`: a
//! `RecordingFetcher` stand-in for the network (docs/TESTING.md "no network
//! in CI") returns canned outcomes captured from the live npm/PyPI response
//! shapes verified in 03-RESEARCH.md. No test here ever touches the network.
#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use std::path::PathBuf;

use getdev_registry::{
    encode_scoped, normalize_pep503, Cache, Datasets, Ecosystem, Existence, FetchOutcome, Fetcher,
    RegistryClient, RegistryError,
};

fn temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "getdev-registry-client-hermetic-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

enum Canned {
    Status(u16, &'static str),
    TransportError,
}

/// Pops one canned response per call, in order. The call counter is a
/// shared `Arc` so the test can keep reading it after the `Box<dyn Fetcher>`
/// (and the `RecordingFetcher` inside it) has been moved into the client —
/// the executable proof that an offline client never reaches `Fetcher`.
struct RecordingFetcher {
    calls: Arc<AtomicUsize>,
    queue: Mutex<VecDeque<Canned>>,
}

impl RecordingFetcher {
    fn new(responses: Vec<Canned>) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Self {
            calls: Arc::clone(&calls),
            queue: Mutex::new(responses.into()),
        };
        (fetcher, calls)
    }
}

impl Fetcher for RecordingFetcher {
    fn get(&self, url: &str, _accept: Option<&str>) -> Result<FetchOutcome, RegistryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let next = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front();
        match next {
            Some(Canned::Status(status, body)) => Ok(FetchOutcome {
                status,
                body: body.as_bytes().to_vec(),
            }),
            Some(Canned::TransportError) => Err(RegistryError::Http {
                url: url.to_owned(),
                message: "simulated transport failure".to_owned(),
            }),
            None => panic!("RecordingFetcher queue exhausted for {url}"),
        }
    }
}

// Verified live this session (03-RESEARCH.md "Verified npm existence"):
// GET https://registry.npmjs.org/left-pad -> 200 with an abbreviated body.
const NPM_ABBREVIATED_FOUND: &str = r#"{"name":"left-pad","dist-tags":{"latest":"1.3.0"}}"#;

#[test]
fn npm_200_maps_to_found() {
    let (fetcher, _calls) = RecordingFetcher::new(vec![Canned::Status(200, NPM_ABBREVIATED_FOUND)]);
    let client = RegistryClient::with_fetcher(Box::new(fetcher), false);
    assert_eq!(
        client.existence(Ecosystem::Npm, "left-pad").unwrap(),
        Existence::Found
    );
}

#[test]
fn npm_404_maps_to_missing_and_is_never_retried() {
    let (fetcher, calls) = RecordingFetcher::new(vec![Canned::Status(404, "")]);
    let client = RegistryClient::with_fetcher(Box::new(fetcher), false);
    assert_eq!(
        client
            .existence(Ecosystem::Npm, "this-package-does-not-exist-xyz")
            .unwrap(),
        Existence::Missing
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a 404 is authoritative and must not be retried"
    );
}

#[test]
fn pypi_200_maps_to_found() {
    let (fetcher, _calls) =
        RecordingFetcher::new(vec![Canned::Status(200, r#"{"info":{"name":"requests"}}"#)]);
    let client = RegistryClient::with_fetcher(Box::new(fetcher), false);
    assert_eq!(
        client.existence(Ecosystem::Pypi, "requests").unwrap(),
        Existence::Found
    );
}

#[test]
fn repeated_500_exhausts_retries_and_maps_to_inconclusive_never_missing() {
    let (fetcher, calls) = RecordingFetcher::new(vec![
        Canned::Status(500, ""),
        Canned::Status(500, ""),
        Canned::Status(500, ""),
    ]);
    let client = RegistryClient::with_fetcher(Box::new(fetcher), false);
    assert_eq!(
        client.existence(Ecosystem::Npm, "left-pad").unwrap(),
        Existence::Inconclusive
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3, "at most 3 attempts");
}

#[test]
fn repeated_transport_error_exhausts_retries_and_maps_to_inconclusive_never_missing() {
    let (fetcher, calls) = RecordingFetcher::new(vec![
        Canned::TransportError,
        Canned::TransportError,
        Canned::TransportError,
    ]);
    let client = RegistryClient::with_fetcher(Box::new(fetcher), false);
    assert_eq!(
        client.existence(Ecosystem::Pypi, "requests").unwrap(),
        Existence::Inconclusive
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3, "at most 3 attempts");
}

#[test]
fn a_single_500_is_retried_and_can_still_succeed() {
    let (fetcher, calls) = RecordingFetcher::new(vec![
        Canned::Status(500, ""),
        Canned::Status(200, NPM_ABBREVIATED_FOUND),
    ]);
    let client = RegistryClient::with_fetcher(Box::new(fetcher), false);
    assert_eq!(
        client.existence(Ecosystem::Npm, "left-pad").unwrap(),
        Existence::Found
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn offline_client_makes_zero_fetcher_calls() {
    let (fetcher, calls) = RecordingFetcher::new(vec![]);
    let client = RegistryClient::with_fetcher(Box::new(fetcher), true);
    assert!(client.is_offline());

    assert!(matches!(
        client.existence(Ecosystem::Npm, "left-pad"),
        Err(RegistryError::Offline { .. })
    ));
    assert!(matches!(
        client.metadata(Ecosystem::Npm, "left-pad"),
        Err(RegistryError::Offline { .. })
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "offline must short-circuit before any Fetcher call"
    );
}

#[test]
fn scoped_encoding_and_pep503_normalization() {
    assert_eq!(encode_scoped("@babel/core"), "@babel%2fcore");
    assert_eq!(normalize_pep503("Typing_Extensions"), "typing-extensions");
}

// --- E6: skip metadata fetches for a Missing/Inconclusive package --------

#[test]
fn verify_full_skips_metadata_fetches_for_a_missing_package() {
    // Only ONE canned response: the existence 404. If `verify_full` still
    // fetched npm downloads/full-doc for a Missing package (the pre-E6
    // behavior), the RecordingFetcher's queue would be exhausted and panic.
    let (fetcher, calls) = RecordingFetcher::new(vec![Canned::Status(404, "")]);
    let client = RegistryClient::with_fetcher(Box::new(fetcher), false);
    let cache = Cache::open_at(&temp_dir("e6-missing")).unwrap();
    let datasets = Datasets::embedded().unwrap();

    let verdict = client
        .verify_full(
            &cache,
            &datasets,
            Ecosystem::Npm,
            "this-package-does-not-exist-xyz",
        )
        .unwrap();
    assert_eq!(verdict.existence, Existence::Missing);
    assert_eq!(verdict.downloads, None);
    assert_eq!(verdict.created_at, None);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "E6: metadata must not be fetched for a Missing package"
    );
}

#[test]
fn verify_full_skips_metadata_fetches_for_an_inconclusive_package() {
    // 3 canned 500s exhaust existence's own retries (Inconclusive); if
    // `verify_full` still went on to fetch metadata, the queue would be
    // exhausted and the RecordingFetcher would panic.
    let (fetcher, calls) = RecordingFetcher::new(vec![
        Canned::Status(500, ""),
        Canned::Status(500, ""),
        Canned::Status(500, ""),
    ]);
    let client = RegistryClient::with_fetcher(Box::new(fetcher), false);
    let cache = Cache::open_at(&temp_dir("e6-inconclusive")).unwrap();
    let datasets = Datasets::embedded().unwrap();

    let verdict = client
        .verify_full(&cache, &datasets, Ecosystem::Npm, "left-pad")
        .unwrap();
    assert_eq!(verdict.existence, Existence::Inconclusive);
    assert_eq!(verdict.downloads, None);
    assert_eq!(verdict.created_at, None);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "E6: metadata must not be fetched for an Inconclusive package"
    );
}
