//! npm + PyPI existence/metadata client.
//!
//! `getdev-registry` is the ONLY crate in the workspace permitted to make
//! network calls (docs/ARCHITECTURE.md "Network boundary rule"). The actual
//! network transport is behind the [`Fetcher`] trait so every code path here
//! is testable without touching the network (docs/TESTING.md "no network in
//! CI"). `--offline`/`GETDEV_OFFLINE=1` short-circuits before `Fetcher` is
//! ever invoked — see [`resolve_offline`].

use std::io::Read;
use std::time::Duration;

use serde::Deserialize;

use crate::cache::CacheError;

/// Hard cap on a registry response body, mitigating an oversized/malformed
/// response from a compromised or DNS-hijacked registry mirror (DoS —
/// 03-RESEARCH.md Security Domain, T-3-02).
const BODY_CAP_BYTES: u64 = 2 * 1024 * 1024;
const REQUEST_TIMEOUT_SECS: u64 = 5;
const MAX_ATTEMPTS: u32 = 3;

/// npm's abbreviated-metadata `Accept` header — cuts the response from
/// potentially tens of MB down to a few KB (03-RESEARCH.md Pitfall 2).
const NPM_EXISTENCE_ACCEPT: &str =
    "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Npm,
    Pypi,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existence {
    Found,
    Missing,
    /// Network failure, timeout, or a non-200/404 status. NEVER treated as
    /// `Missing` — a 5xx/timeout is not proof a package does not exist
    /// (03-RESEARCH.md Anti-Patterns).
    Inconclusive,
}

#[derive(Debug, Clone)]
pub struct RegistryVerdict {
    pub existence: Existence,
    pub downloads: Option<u64>,
    pub created_at: Option<i64>,
    pub typosquat: Option<crate::typosquat::TyposquatHit>,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("http request to {url} failed: {message}")]
    Http { url: String, message: String },
    #[error("response body from {url} exceeded the {limit}-byte cap")]
    Body { url: String, limit: u64 },
    #[error("failed to decode response from {url}: {source}")]
    Decode {
        url: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("offline mode: no network call permitted for {url}")]
    Offline { url: String },
    #[error("failed to build http client: {message}")]
    Client { message: String },
    #[error("retries exhausted for {url}")]
    Exhausted { url: String },
    #[error(transparent)]
    Cache(#[from] CacheError),
}

/// The bytes and status of one GET response — the network seam every test in
/// this crate substitutes with a fixture instead of a live/mock server.
#[derive(Debug, Clone)]
pub struct FetchOutcome {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Dependency-injected "fetch bytes for a URL" seam (03-RESEARCH.md Wave 0
/// Gaps, "Hermetic Testing note", approach (a)). Real network I/O lives only
/// in [`ReqwestFetcher`]; tests substitute fixtures or panicking/counting
/// stand-ins.
pub trait Fetcher: Send + Sync {
    fn get(&self, url: &str, accept: Option<&str>) -> Result<FetchOutcome, RegistryError>;
}

/// The real, network-touching [`Fetcher`]. Fixed hosts only, no redirects, a
/// 5s hard timeout, and a capped body read (03-RESEARCH.md Security Domain).
pub struct ReqwestFetcher {
    client: reqwest::blocking::Client,
}

impl ReqwestFetcher {
    pub fn new() -> Result<Self, RegistryError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .user_agent(format!("getdev/{}", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|source| RegistryError::Client {
                message: source.to_string(),
            })?;
        Ok(Self { client })
    }
}

impl Fetcher for ReqwestFetcher {
    fn get(&self, url: &str, accept: Option<&str>) -> Result<FetchOutcome, RegistryError> {
        let mut request = self.client.get(url);
        if let Some(accept) = accept {
            request = request.header(reqwest::header::ACCEPT, accept);
        }
        let response = request.send().map_err(|source| RegistryError::Http {
            url: url.to_owned(),
            message: source.to_string(),
        })?;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        response
            .take(BODY_CAP_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|source| RegistryError::Http {
                url: url.to_owned(),
                message: source.to_string(),
            })?;
        if body.len() as u64 > BODY_CAP_BYTES {
            return Err(RegistryError::Body {
                url: url.to_owned(),
                limit: BODY_CAP_BYTES,
            });
        }
        Ok(FetchOutcome { status, body })
    }
}

#[derive(Debug, Deserialize)]
struct NpmDownloads {
    downloads: u64,
}

#[derive(Debug, Deserialize)]
struct NpmFullDoc {
    #[serde(default)]
    time: Option<NpmTime>,
}

#[derive(Debug, Deserialize)]
struct NpmTime {
    created: Option<String>,
}

/// Whether the client should behave as if `--offline`/`GETDEV_OFFLINE=1` was
/// passed. `flag` is the CLI/config value; the environment variable always
/// wins when set (test/CI override, matches `GETDEV_CACHE_DIR`'s precedent).
pub fn resolve_offline(flag: bool) -> bool {
    flag || std::env::var_os("GETDEV_OFFLINE").is_some()
}

/// npm scoped packages (`@scope/name`) contain a literal `/`; encode it
/// defensively (03-RESEARCH.md Pattern 2).
pub fn encode_scoped(name: &str) -> String {
    name.replacen('/', "%2f", 1)
}

/// PEP 503 normalization: lowercase; runs of `-`/`_`/`.` collapse to one
/// `-`. Must run once, before the cache key is built (03-RESEARCH.md
/// Pitfall 3) — `Django`/`django`/`DJANGO` must share one cache row.
pub fn normalize_pep503(name: &str) -> String {
    let mut out = String::new();
    let mut last_was_sep = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !last_was_sep {
                out.push('-');
                last_was_sep = true;
            }
        } else {
            out.push(c.to_ascii_lowercase());
            last_was_sep = false;
        }
    }
    out
}

fn existence_url(eco: Ecosystem, name: &str) -> String {
    match eco {
        Ecosystem::Npm => format!("https://registry.npmjs.org/{}", encode_scoped(name)),
        Ecosystem::Pypi => format!("https://pypi.org/pypi/{}/json", normalize_pep503(name)),
    }
}

fn backoff(attempt: u32) -> Duration {
    match attempt {
        1 => Duration::from_millis(200),
        2 => Duration::from_millis(400),
        _ => Duration::from_millis(800),
    }
}

/// Reject unknown/malformed shapes gracefully rather than `Value`-walking
/// and assuming a field is present (03-RESEARCH.md V5 Input Validation).
fn parse_json<T: serde::de::DeserializeOwned>(url: &str, body: &[u8]) -> Result<T, RegistryError> {
    serde_json::from_slice(body).map_err(|source| RegistryError::Decode {
        url: url.to_owned(),
        source,
    })
}

pub struct RegistryClient {
    fetcher: Box<dyn Fetcher>,
    offline: bool,
}

impl RegistryClient {
    /// Build a client backed by the real network [`ReqwestFetcher`].
    pub fn new(offline: bool) -> Result<Self, RegistryError> {
        let fetcher = Box::new(ReqwestFetcher::new()?);
        Ok(Self::with_fetcher(fetcher, offline))
    }

    /// Build a client over an injected [`Fetcher`] — the hermetic-test seam.
    pub fn with_fetcher(fetcher: Box<dyn Fetcher>, offline: bool) -> Self {
        Self {
            fetcher,
            offline: resolve_offline(offline),
        }
    }

    pub fn is_offline(&self) -> bool {
        self.offline
    }

    /// At most [`MAX_ATTEMPTS`] attempts with 200/400/800ms backoff, retried
    /// only on transport error or a 5xx status. A 404 is authoritative and
    /// is returned immediately, never retried.
    fn get_with_retry(
        &self,
        url: &str,
        accept: Option<&str>,
    ) -> Result<FetchOutcome, RegistryError> {
        let mut last_err: Option<RegistryError> = None;
        for attempt in 1..=MAX_ATTEMPTS {
            match self.fetcher.get(url, accept) {
                Ok(outcome) => {
                    if (500..=599).contains(&outcome.status) && attempt < MAX_ATTEMPTS {
                        std::thread::sleep(backoff(attempt));
                        continue;
                    }
                    return Ok(outcome);
                }
                Err(err) => {
                    last_err = Some(err);
                    if attempt < MAX_ATTEMPTS {
                        std::thread::sleep(backoff(attempt));
                        continue;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| RegistryError::Exhausted {
            url: url.to_owned(),
        }))
    }

    /// npm: GET the abbreviated-metadata endpoint; PyPI: GET the JSON API.
    /// 200 => Found, 404 => Missing, anything else (incl. transport
    /// error/timeout, retries exhausted) => Inconclusive — NEVER Missing.
    pub fn existence(&self, eco: Ecosystem, name: &str) -> Result<Existence, RegistryError> {
        let url = existence_url(eco, name);
        if self.offline {
            return Err(RegistryError::Offline { url });
        }
        let accept = match eco {
            Ecosystem::Npm => Some(NPM_EXISTENCE_ACCEPT),
            Ecosystem::Pypi => None,
        };
        match self.get_with_retry(&url, accept) {
            Ok(outcome) => Ok(match outcome.status {
                200 => Existence::Found,
                404 => Existence::Missing,
                _ => Existence::Inconclusive,
            }),
            Err(_) => Ok(Existence::Inconclusive),
        }
    }

    /// npm: last-week download count + full-doc `time.created`. PyPI: no
    /// download/creation-date endpoint exists in v0.1 — record `None`,
    /// never fabricate a value (03-RESEARCH.md "Code Examples").
    pub fn metadata(
        &self,
        eco: Ecosystem,
        name: &str,
    ) -> Result<crate::cache::Metadata, RegistryError> {
        if self.offline {
            return Err(RegistryError::Offline {
                url: existence_url(eco, name),
            });
        }
        match eco {
            Ecosystem::Npm => Ok(self.npm_metadata(name)),
            Ecosystem::Pypi => Ok((None, None)),
        }
    }

    fn npm_metadata(&self, name: &str) -> crate::cache::Metadata {
        let encoded = encode_scoped(name);
        (self.npm_downloads(&encoded), self.npm_created_at(&encoded))
    }

    fn npm_downloads(&self, encoded: &str) -> Option<u64> {
        let url = format!("https://api.npmjs.org/downloads/point/last-week/{encoded}");
        let outcome = self.get_with_retry(&url, None).ok()?;
        if outcome.status != 200 {
            return None;
        }
        parse_json::<NpmDownloads>(&url, &outcome.body)
            .ok()
            .map(|d| d.downloads)
    }

    fn npm_created_at(&self, encoded: &str) -> Option<i64> {
        let url = format!("https://registry.npmjs.org/{encoded}");
        let outcome = self.get_with_retry(&url, None).ok()?;
        if outcome.status != 200 {
            return None;
        }
        parse_json::<NpmFullDoc>(&url, &outcome.body)
            .ok()?
            .time?
            .created
            .and_then(|created| parse_iso8601_utc(&created))
    }

    /// Cache-first existence check (`getdev real`'s primary entry point).
    /// A cache hit returns immediately; on a miss while offline, returns
    /// `Inconclusive` (a network lookup cannot be confirmed, so it is never
    /// fabricated as `Missing`); otherwise fetches, validates, and
    /// write-throughs the result.
    pub fn verify(
        &self,
        cache: &crate::cache::Cache,
        eco: Ecosystem,
        name: &str,
    ) -> Result<Existence, RegistryError> {
        if let Some(existence) = cache.get_existence(eco, name)? {
            return Ok(existence);
        }
        if self.offline {
            return Ok(Existence::Inconclusive);
        }
        let existence = self.existence(eco, name)?;
        cache.put_existence(eco, name, existence)?;
        Ok(existence)
    }

    /// Full verdict assembly: existence + downloads + created_at +
    /// typosquat, in one cache-aware call (rayon-parallelizable by the CLI
    /// caller, 03-05).
    pub fn verify_full(
        &self,
        cache: &crate::cache::Cache,
        datasets: &crate::typosquat::Datasets,
        eco: Ecosystem,
        name: &str,
    ) -> Result<RegistryVerdict, RegistryError> {
        self.verify_full_with_sensitivity(
            cache,
            datasets,
            eco,
            name,
            crate::typosquat::Sensitivity::Normal,
        )
    }

    /// `verify_full`, but with `[real].typosquat_sensitivity` pass-through
    /// (B2 audit fix — the config key existed but nothing read it).
    pub fn verify_full_with_sensitivity(
        &self,
        cache: &crate::cache::Cache,
        datasets: &crate::typosquat::Datasets,
        eco: Ecosystem,
        name: &str,
        sensitivity: crate::typosquat::Sensitivity,
    ) -> Result<RegistryVerdict, RegistryError> {
        let existence = self.verify(cache, eco, name)?;
        let (downloads, created_at) = self.cached_metadata(cache, eco, name)?;
        let now = now_unix();
        let typosquat = crate::typosquat::score_with_sensitivity(
            datasets,
            eco,
            name,
            downloads,
            created_at,
            now,
            sensitivity,
        );
        Ok(RegistryVerdict {
            existence,
            downloads,
            created_at,
            typosquat,
        })
    }

    fn cached_metadata(
        &self,
        cache: &crate::cache::Cache,
        eco: Ecosystem,
        name: &str,
    ) -> Result<crate::cache::Metadata, RegistryError> {
        if let Some(cached) = cache.get_metadata(eco, name)? {
            return Ok(cached);
        }
        if self.offline {
            return Ok((None, None));
        }
        let (downloads, created_at) = self.metadata(eco, name)?;
        cache.put_metadata(eco, name, downloads, created_at)?;
        Ok((downloads, created_at))
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Days since the Unix epoch for a proleptic-Gregorian civil date, via
/// Howard Hinnant's `days_from_civil` algorithm. No external date crate is
/// in the approved dependency set for this phase, and npm's `time.created`
/// field is a fixed, well-known UTC ISO-8601 shape — hand-rolling this one
/// conversion is lower-risk than adding a new dependency for it.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 }); // [0, 11]
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Parses a UTC ISO-8601 timestamp of the shape npm's registry emits
/// (`2014-03-14T09:09:20.762Z`) into Unix seconds. Any other shape (missing
/// `Z`, non-UTC offset, malformed component) returns `None` rather than
/// panicking — untrusted third-party network input.
fn parse_iso8601_utc(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut date_parts = date.split('-');
    let y: i64 = date_parts.next()?.parse().ok()?;
    let m: u32 = date_parts.next()?.parse().ok()?;
    let d: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() {
        return None;
    }
    let time_main = time.split('.').next()?;
    let mut time_parts = time_main.split(':');
    let hh: i64 = time_parts.next()?.parse().ok()?;
    let mm: i64 = time_parts.next()?.parse().ok()?;
    let ss: i64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() {
        return None;
    }
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let days = days_from_civil(y, m, d);
    Some(days * 86400 + hh * 3600 + mm * 60 + ss)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn scoped_names_are_percent_encoded() {
        assert_eq!(encode_scoped("@babel/core"), "@babel%2fcore");
        assert_eq!(encode_scoped("left-pad"), "left-pad");
    }

    #[test]
    fn pep503_normalization_collapses_separators_and_lowercases() {
        assert_eq!(normalize_pep503("Typing_Extensions"), "typing-extensions");
        assert_eq!(normalize_pep503("Django"), "django");
        assert_eq!(normalize_pep503("a..b__c--d"), "a-b-c-d");
    }

    #[test]
    fn iso8601_parses_npm_shape() {
        // Verified live this session (03-RESEARCH.md): left-pad's
        // time.created == "2014-03-14T09:09:20.762Z"
        assert_eq!(
            parse_iso8601_utc("2014-03-14T09:09:20.762Z"),
            Some(1_394_788_160)
        );
        assert_eq!(parse_iso8601_utc("not-a-date"), None);
        assert_eq!(parse_iso8601_utc("2014-03-14T09:09:20+02:00"), None);
    }

    #[test]
    fn offline_resolver_honors_flag() {
        assert!(resolve_offline(true));
        // The `GETDEV_OFFLINE` env-var branch is a single `var_os` read
        // (see the function above); it is set at the CI-job level per
        // docs/TESTING.md, not via `std::env::set_var` in test code, which
        // is `unsafe` as of this toolchain and this crate forbids
        // `unsafe_code` workspace-wide (DEC-11).
    }
}
