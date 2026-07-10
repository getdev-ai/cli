#![forbid(unsafe_code)]
//! npm and PyPI registry clients with a local SQLite cache.
//!
//! This is the ONLY crate in the workspace permitted to make network calls
//! (blocking `reqwest` + `rustls`; permitted destinations: npm registry,
//! PyPI — docs/ARCHITECTURE.md "Network boundary rule"). `--offline` /
//! `GETDEV_OFFLINE=1` is provably networkless: see
//! [`client::resolve_offline`] and `tests/offline_hermetic.rs`.

pub mod cache;
pub mod client;
pub mod typosquat;

pub use cache::{Cache, CacheError};
pub use client::{
    encode_scoped, normalize_pep503, resolve_offline, Ecosystem, Existence, FetchOutcome, Fetcher,
    RegistryClient, RegistryError, RegistryVerdict,
};
pub use typosquat::{DatasetError, Datasets, TyposquatHit, TyposquatReason};
