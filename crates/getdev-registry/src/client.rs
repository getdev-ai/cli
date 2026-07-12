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

/// Percent-encodes `name` for safe inclusion as a single URL path segment.
/// E4: the whole name is encoded (a query/fragment-inclusive allow-list —
/// only RFC 3986 unreserved characters plus `@` for npm scopes pass
/// through unencoded), not just the scoped `/` the old implementation
/// special-cased. A name containing `?`/`#` previously truncated the
/// request path silently instead of being treated as a literal (untrusted)
/// package name; every non-allow-listed byte, including `/`, `?`, and `#`,
/// is now percent-encoded.
pub fn encode_scoped(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for byte in name.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'@' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02x}")),
        }
    }
    out
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

/// E2: self-normalizes the incoming name for PyPI (PEP 503) before it is
/// used as a cache key or dataset-lookup key — `verify`/`cached_metadata`
/// each call this at their own entry point so the crate enforces its own
/// documented invariant (`Django`/`django`/`DJANGO` share one cache row)
/// instead of trusting every caller to have already normalized. npm names
/// pass through unchanged — already canonical, and PEP 503's rules don't
/// apply to them.
fn self_normalize(eco: Ecosystem, name: &str) -> String {
    match eco {
        Ecosystem::Npm => name.to_owned(),
        Ecosystem::Pypi => normalize_pep503(name),
    }
}

fn existence_url(eco: Ecosystem, name: &str) -> String {
    match eco {
        Ecosystem::Npm => format!("https://registry.npmjs.org/{}", encode_scoped(name)),
        // E4: PEP 503-normalize first, then percent-encode the result — a
        // name containing `?`/`#` after normalization (normalization only
        // touches case/`-_.` separators) must still land in the URL as a
        // literal, encoded path segment rather than truncating/redirecting
        // the request.
        Ecosystem::Pypi => format!(
            "https://pypi.org/pypi/{}/json",
            encode_scoped(&normalize_pep503(name))
        ),
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
    /// `None` only when constructed offline via [`RegistryClient::new`] (E3)
    /// — every offline call path is gated before ever reaching
    /// [`RegistryClient::get_with_retry`], so this is never dereferenced
    /// while `offline` is `true`. `with_fetcher` (the test seam) always
    /// stores `Some`, matching its pre-E3 behavior exactly.
    fetcher: Option<Box<dyn Fetcher>>,
    offline: bool,
}

impl RegistryClient {
    /// Build a client backed by the real network [`ReqwestFetcher`] — unless
    /// `offline` resolves `true`, in which case NO [`ReqwestFetcher`] (and
    /// therefore no `reqwest::blocking::Client`/TLS setup) is constructed at
    /// all (E3): an offline run has no use for it, and every offline call
    /// path was already gated before ever reaching the fetcher.
    pub fn new(offline: bool) -> Result<Self, RegistryError> {
        let offline = resolve_offline(offline);
        let fetcher = if offline {
            None
        } else {
            Some(Box::new(ReqwestFetcher::new()?) as Box<dyn Fetcher>)
        };
        Ok(Self { fetcher, offline })
    }

    /// Build a client over an injected [`Fetcher`] — the hermetic-test seam.
    /// Always stores `Some(fetcher)` regardless of `offline`, so tests can
    /// assert an offline client never *calls* the injected fetcher (see
    /// `tests/offline_hermetic.rs`'s `PanicFetcher`) without needing `new`'s
    /// no-construction behavior.
    pub fn with_fetcher(fetcher: Box<dyn Fetcher>, offline: bool) -> Self {
        Self {
            fetcher: Some(fetcher),
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
        // E3: defensive fallback — every call site gates on `self.offline`
        // before reaching here, so `fetcher` is always `Some` in practice;
        // this returns the same `Offline` error the gated call sites would
        // have returned rather than panicking, should that invariant ever
        // slip.
        let Some(fetcher) = self.fetcher.as_deref() else {
            return Err(RegistryError::Offline {
                url: url.to_owned(),
            });
        };
        let mut last_err: Option<RegistryError> = None;
        for attempt in 1..=MAX_ATTEMPTS {
            match fetcher.get(url, accept) {
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
        // E2: self-normalize before the cache key is built — see
        // `self_normalize`'s doc-comment.
        let name = &self_normalize(eco, name);
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
        // E6: a Missing/Inconclusive package gets no downloads/full-doc
        // fetch — there's nothing useful to fetch for a package that either
        // doesn't exist or whose existence couldn't even be confirmed, and
        // fetching anyway wastes a request (and, for npm, two: downloads +
        // full-doc).
        let (downloads, created_at) = if existence == Existence::Found {
            self.cached_metadata(cache, eco, name)?
        } else {
            (None, None)
        };
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
        // E2: self-normalize before the cache key is built — see
        // `self_normalize`'s doc-comment.
        let name = &self_normalize(eco, name);
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
    // IN-02: reject impossible calendar dates (Feb 30, Apr 31, ...) rather
    // than letting `days_from_civil` compute a nonsense day for them —
    // untrusted npm `time.created` feeding the NewPackage typosquat
    // heuristic must not be skewed by a hijacked-mirror out-of-range day.
    if d < 1 || d > days_in_month(y, m)? {
        return None;
    }
    let days = days_from_civil(y, m, d);
    Some(days * 86400 + hh * 3600 + mm * 60 + ss)
}

/// Number of days in a proleptic-Gregorian month, or `None` for an
/// out-of-range month (subsumes the old `1..=12` guard).
fn days_in_month(year: i64, month: u32) -> Option<u32> {
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return None,
    };
    Some(days)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
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
    fn iso8601_rejects_impossible_calendar_dates() {
        // IN-02: an out-of-range day-of-month must be rejected, not fed to
        // days_from_civil (which would compute a nonsense date).
        assert_eq!(parse_iso8601_utc("2024-02-30T00:00:00.000Z"), None); // Feb 30
        assert_eq!(parse_iso8601_utc("2023-02-29T00:00:00.000Z"), None); // non-leap Feb 29
        assert_eq!(parse_iso8601_utc("2024-04-31T00:00:00.000Z"), None); // Apr 31
        assert_eq!(parse_iso8601_utc("2024-00-10T00:00:00.000Z"), None); // month 0
        assert_eq!(parse_iso8601_utc("2024-13-10T00:00:00.000Z"), None); // month 13
        assert_eq!(parse_iso8601_utc("2024-01-00T00:00:00.000Z"), None); // day 0
                                                                         // Valid boundary dates must still parse.
        assert!(parse_iso8601_utc("2024-02-29T00:00:00.000Z").is_some()); // leap Feb 29
        assert!(parse_iso8601_utc("2024-01-31T00:00:00.000Z").is_some());
        assert!(parse_iso8601_utc("2000-02-29T00:00:00.000Z").is_some()); // 2000 is leap
        assert!(parse_iso8601_utc("1900-02-29T00:00:00.000Z").is_none()); // 1900 is not
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

    // --- E4: full-name percent-encoding ---------------------------------

    #[test]
    fn full_name_percent_encoding_covers_query_and_fragment_chars() {
        // A `?`/`#` in a name must never reach the built URL as a literal —
        // the old scoped-slash-only `encode_scoped` silently truncated the
        // request path at the first of either.
        assert_eq!(encode_scoped("evil?x=1#y"), "evil%3fx%3d1%23y");

        let npm_url = existence_url(Ecosystem::Npm, "evil?x=1#y");
        assert!(npm_url.contains("%3f"), "expected encoded '?': {npm_url}");
        assert!(npm_url.contains("%23"), "expected encoded '#': {npm_url}");
        assert!(!npm_url.contains('?'), "raw '?' leaked into: {npm_url}");
        assert!(!npm_url.contains('#'), "raw '#' leaked into: {npm_url}");

        let pypi_url = existence_url(Ecosystem::Pypi, "evil?x=1#y");
        assert!(pypi_url.contains("%3f"), "expected encoded '?': {pypi_url}");
        assert!(pypi_url.contains("%23"), "expected encoded '#': {pypi_url}");
        assert!(!pypi_url.contains('?'), "raw '?' leaked into: {pypi_url}");
        assert!(!pypi_url.contains('#'), "raw '#' leaked into: {pypi_url}");
    }

    // --- E2: self-normalization ------------------------------------------

    fn temp_cache_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "getdev-registry-client-test-{label}-{}-{}",
            std::process::id(),
            now_unix()
        ))
    }

    #[test]
    fn verify_self_normalizes_pypi_name_so_case_variants_share_one_cache_row() {
        let cache = crate::cache::Cache::open_at(&temp_cache_dir("pep503-cache-key")).unwrap();
        // Seed the cache under the normalized key only, exactly as a prior
        // `verify` call for the canonical spelling would have.
        cache
            .put_existence(Ecosystem::Pypi, "django", Existence::Found)
            .unwrap();

        let client = RegistryClient::with_fetcher(
            Box::new(NeverCalledFetcher),
            true, // offline: a cache hit must short-circuit before this matters
        );

        // Without E2's self-normalization, "Django" would miss the
        // "django"-keyed cache row and fall through to (offline)
        // Inconclusive instead of the cached Found.
        assert_eq!(
            client.verify(&cache, Ecosystem::Pypi, "Django").unwrap(),
            Existence::Found
        );
    }

    struct NeverCalledFetcher;
    impl Fetcher for NeverCalledFetcher {
        fn get(&self, url: &str, _accept: Option<&str>) -> Result<FetchOutcome, RegistryError> {
            panic!("must never be called: {url}");
        }
    }

    // --- E3: offline construction builds no fetcher -----------------------

    #[test]
    fn new_offline_succeeds_and_stays_cache_only() {
        // Proves `RegistryClient::new(true)` works with no live network/TLS
        // dependency having been initialized: construction succeeds, and a
        // cache-miss `verify` under offline resolves Inconclusive (never
        // fabricated as Missing) without needing a `Fetcher` at all.
        let client = RegistryClient::new(true).unwrap();
        assert!(client.is_offline());

        let cache = crate::cache::Cache::open_at(&temp_cache_dir("new-offline")).unwrap();
        let existence = client
            .verify(&cache, Ecosystem::Npm, "never-cached-before-xyz")
            .unwrap();
        assert_eq!(existence, Existence::Inconclusive);
    }
}
