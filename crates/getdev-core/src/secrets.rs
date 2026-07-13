//! Secret classification: provider patterns (data — rules/env/secrets.yaml)
//! plus a Shannon-entropy fallback. Shared by `env` (P1) and `audit` (P3).
//!
//! Invariant (docs/SPEC-FINDINGS.md): raw secret values never leave this
//! module except through [`mask`].

use regex::Regex;
use serde::Deserialize;

use crate::findings::{Confidence, Severity};

const EMBEDDED_PATTERNS: &str = include_str!("../../../rules/env/secrets.yaml");

/// Minimum length + entropy (bits/char) for the generic fallback, which also
/// requires a secret-suggesting identifier name.
const ENTROPY_MIN_LEN: usize = 20;
const ENTROPY_MIN_BITS: f64 = 3.5;

#[derive(Debug, thiserror::Error)]
pub enum PatternError {
    #[error("invalid secret pattern pack: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("invalid regex in secret pattern '{id}': {source}")]
    Regex {
        id: String,
        #[source]
        source: Box<regex::Error>,
    },
}

#[derive(Debug, Deserialize)]
struct PatternFile {
    #[allow(dead_code)]
    version: u32,
    patterns: Vec<RawPattern>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPattern {
    id: String,
    provider: String,
    env_key: String,
    severity: Severity,
    prefix: String,
    regex: String,
}

#[derive(Debug)]
pub struct SecretPattern {
    pub id: String,
    pub provider: String,
    pub env_key: String,
    pub severity: Severity,
    pub prefix: String,
    regex: Regex,
}

/// C4/03-REVIEW.md — **structural note on match order:** `classify` below
/// walks `patterns` in the order they were loaded and returns the FIRST
/// regex match (first-match-wins). That order is exactly the order
/// patterns appear in `rules/env/secrets.yaml`, which means correctness
/// for any two patterns whose bodies can overlap (e.g. `sk-ant-…` matches
/// BOTH the `anthropic-api-key` and `openai-api-key` regexes — the OpenAI
/// pattern's `sk-` prefix is a strict subset of Anthropic's `sk-ant-`)
/// depends entirely on YAML file order, not on any code-level
/// disambiguation. Reordering `secrets.yaml` can silently change which
/// provider a key classifies as. `anthropic_before_openai_ordering_is_pinned`
/// below is the regression test guarding this; the corresponding note lives
/// in `secrets.yaml` next to the two patterns.
#[derive(Debug)]
pub struct SecretPatterns {
    patterns: Vec<SecretPattern>,
}

/// A classified secret. Holds no value data beyond the masked preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMatch {
    /// pattern id, or "entropy" for the generic fallback
    pub pattern_id: String,
    pub provider: String,
    /// suggested environment variable name (provider default; `env::plan`
    /// may override from the identifier)
    pub env_key: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub masked: String,
}

impl SecretPatterns {
    /// Load the embedded pattern pack. Compile errors are release-blocking
    /// bugs (the pack ships in the binary), surfaced as typed errors so the
    /// CLI reports them instead of panicking.
    pub fn embedded() -> Result<Self, PatternError> {
        Self::parse(EMBEDDED_PATTERNS)
    }

    /// The loaded pattern set, in file order (the order `classify` tries
    /// them — see the first-match-wins note above). Exposed read-only so
    /// callers (the C5 fixture-coverage test) can enumerate every shipped
    /// pattern id without duplicating the YAML.
    pub fn patterns(&self) -> &[SecretPattern] {
        &self.patterns
    }

    pub fn parse(yaml: &str) -> Result<Self, PatternError> {
        let file: PatternFile = serde_yaml::from_str(yaml)?;
        let mut patterns = Vec::with_capacity(file.patterns.len());
        for raw in file.patterns {
            let regex = Regex::new(&raw.regex).map_err(|source| PatternError::Regex {
                id: raw.id.clone(),
                source: Box::new(source),
            })?;
            patterns.push(SecretPattern {
                id: raw.id,
                provider: raw.provider,
                env_key: raw.env_key,
                severity: raw.severity,
                prefix: raw.prefix,
                regex,
            });
        }
        Ok(Self { patterns })
    }

    /// Classify a string literal's contents. `identifier` is the variable /
    /// property name it is assigned to (used by the entropy fallback and to
    /// reject placeholders).
    ///
    /// C7/03-REVIEW.md: a known provider pattern (an exact-format match on
    /// the vendor's own key shape) wins even if the literal's body happens
    /// to contain a placeholder-looking substring like `xxxx`/`todo` — a
    /// real live key with a randomly-generated body that happens to
    /// contain those four characters in sequence is a false negative we
    /// cannot afford. The placeholder screen only protects the entropy
    /// fallback, where there is no vendor-format signal to trust and a
    /// placeholder-shaped string is the dominant false-positive source.
    pub fn classify(&self, value: &str, identifier: &str) -> Option<SecretMatch> {
        for pattern in &self.patterns {
            if pattern.regex.is_match(value) {
                return Some(SecretMatch {
                    pattern_id: pattern.id.clone(),
                    provider: pattern.provider.clone(),
                    env_key: pattern.env_key.clone(),
                    severity: pattern.severity,
                    confidence: Confidence::High,
                    masked: mask(value, &pattern.prefix),
                });
            }
        }
        // generic fallback: random-looking value assigned to a secret-ish
        // name — no vendor format to anchor on, so the placeholder screen
        // applies here only.
        if !looks_like_placeholder(value)
            && !is_known_non_secret(value)
            && identifier_suggests_secret(identifier)
            && value.len() >= ENTROPY_MIN_LEN
            && !value.contains(char::is_whitespace)
            && shannon_entropy(value) >= ENTROPY_MIN_BITS
        {
            return Some(SecretMatch {
                pattern_id: "entropy".to_owned(),
                provider: "generic".to_owned(),
                env_key: String::new(), // env::plan derives from identifier
                severity: Severity::High,
                confidence: Confidence::Medium,
                masked: mask(value, ""),
            });
        }
        None
    }
}

/// Masked preview per docs/SPEC-FINDINGS.md: `sk_live_…9f2a`. Keeps the
/// pattern's stable prefix (or the first 3 chars) and the last 4; everything
/// else is elided. Short values are fully elided.
///
/// C8/03-REVIEW.md: the guard against head+tail overlapping (or elided
/// content shrinking to nothing) must scale with the actual `head` used —
/// a long pattern prefix (e.g. `github_pat_`, 11 chars) plus the 4-char
/// tail can equal-or-exceed the value length well above the old flat `< 12`
/// floor, which was sized only for the no-prefix 3-char-head case and left
/// long-prefix patterns unguarded.
pub fn mask(value: &str, prefix: &str) -> String {
    let value = value.trim();
    let chars: Vec<char> = value.chars().collect();
    let head: String = if !prefix.is_empty() && value.starts_with(prefix) {
        prefix.to_owned()
    } else if !prefix.is_empty() {
        // IN-03/02-env-REVIEW.md: the declared `prefix` isn't a literal
        // prefix of THIS value — e.g. an `ASIA…` STS key against the AWS
        // pattern, whose regex matches `AKIA|ASIA` but whose declared prefix
        // is only `AKIA`. Falling back to a generic 3-char head (`ASI…`)
        // drops the recognisable provider marker. Keep a head of the same
        // length as the declared prefix so `ASIA…` still reads as AWS; the
        // overlap guard below still fully elides short values, so this never
        // reveals more of the secret body than the prefix path would.
        chars.iter().take(prefix.chars().count()).collect()
    } else {
        chars.iter().take(3).collect()
    };
    if head.chars().count() + 4 >= chars.len() {
        return "…".to_owned();
    }
    let tail: String = chars[chars.len().saturating_sub(4)..].iter().collect();
    format!("{head}…{tail}")
}

/// Connection-string / DSN schemes whose `scheme://…` shape is a database or
/// message-broker endpoint. With `env --include-urls` these are extracted even
/// without embedded credentials — the endpoint is deployment config that
/// belongs in `.env`. A credentialed member additionally masks its userinfo.
const DSN_SCHEMES: &[&str] = &[
    "postgres",
    "postgresql",
    "mysql",
    "mysqlx",
    "mariadb",
    "redis",
    "rediss",
    "mongodb",
    "mongodb+srv",
    "amqp",
    "amqps",
];

/// Deterministic URL / connection-string classifier for `env --include-urls`
/// (docs/SPEC-COMMANDS.md §env). Pure, no network, a single bounded
/// left-to-right scan (no regex, so no catastrophic backtracking — T-08-06).
/// Returns a [`SecretMatch`] reusing the secret pipeline's shape so the env
/// plan + `env/hardcoded-secret` finding path stay unchanged; `env_key` is
/// left empty so [`crate::env::plan`] derives the var name from the identifier
/// (mirroring the entropy fallback).
///
/// Fires on:
///   - any `scheme://user[:pass]@host…` embedding credentials — a credentialed
///     DSN, or a userinfo-token URL like a Sentry `https://<key>@sentry.io/…`
///     DSN → high severity, credential masked ([`mask_url_credential`]);
///   - a known DSN scheme (`postgres://`, `redis://`, `mongodb+srv://`, …) with
///     a host, even without credentials → deployment config;
///   - a plain `http(s)://host/…` URL → deployment config.
///
/// Rejects (the negative-fixture FP posture): scheme-less values (relative
/// paths), bare schemes with no host, and any non-http/non-DSN scheme that
/// carries no embedded credential. Import specifiers and commented-out URLs
/// never reach here — the string-assignment walk only yields real assignment
/// RHS literals.
pub fn classify_url(value: &str) -> Option<SecretMatch> {
    let value = value.trim();
    let (scheme, rest) = value.split_once("://")?;
    // RFC-3986 scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
    let mut scheme_chars = scheme.chars();
    if !scheme_chars.next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    if !scheme_chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
        return None;
    }
    let scheme_l = scheme.to_ascii_lowercase();

    // authority runs up to the first path / query / fragment delimiter
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    // a host must be present — rejects a bare `scheme://` with no authority
    let host = host_port.split(':').next().unwrap_or("");
    if host.is_empty() {
        return None;
    }

    let has_credential = userinfo.is_some_and(|u| !u.is_empty());
    let is_http = scheme_l == "http" || scheme_l == "https";
    let is_dsn = DSN_SCHEMES.contains(&scheme_l.as_str());

    if has_credential {
        // a credentialed URL/DSN carries a secret in its userinfo — never
        // print it raw; mask the credential (T-08-04).
        Some(SecretMatch {
            pattern_id: "connection-string".to_owned(),
            provider: "url".to_owned(),
            env_key: String::new(),
            severity: Severity::High,
            confidence: Confidence::High,
            masked: mask_url_credential(value),
        })
    } else if is_dsn {
        // a DSN endpoint without embedded credentials — deployment config
        Some(SecretMatch {
            pattern_id: "connection-string".to_owned(),
            provider: "url".to_owned(),
            env_key: String::new(),
            severity: Severity::Low,
            confidence: Confidence::Medium,
            masked: value.to_owned(),
        })
    } else if is_http {
        // a plain public http(s) URL — deployment config, no secret
        Some(SecretMatch {
            pattern_id: "url".to_owned(),
            provider: "url".to_owned(),
            env_key: String::new(),
            severity: Severity::Low,
            confidence: Confidence::Medium,
            masked: value.to_owned(),
        })
    } else {
        None
    }
}

/// Mask the credential embedded in a `scheme://user[:pass]@host…` value so a
/// finding can name the endpoint without ever printing the secret userinfo
/// (T-08-04). The password (and a bare userinfo token) is elided; the scheme,
/// host, and path stay visible — they are deployment config, not secrets. A
/// value with no userinfo is returned unchanged.
pub fn mask_url_credential(value: &str) -> String {
    let value = value.trim();
    let Some((scheme, rest)) = value.split_once("://") else {
        return value.to_owned();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let tail = &rest[authority_end..];
    let Some((userinfo, host_port)) = authority.rsplit_once('@') else {
        return value.to_owned();
    };
    let masked_userinfo = match userinfo.split_once(':') {
        // `user:pass` → keep the username, elide the password
        Some((user, _pass)) => format!("{user}:…"),
        // a bare userinfo token (e.g. a Sentry DSN key) → elide entirely
        None => "…".to_owned(),
    };
    format!("{scheme}://{masked_userinfo}@{host_port}{tail}")
}

pub fn identifier_suggests_secret(identifier: &str) -> bool {
    let lower = identifier.to_lowercase();
    [
        "secret",
        "token",
        "key",
        "passw",
        "credential",
        "auth",
        "api",
    ]
    .iter()
    .any(|hint| lower.contains(hint))
}

/// Values that look like credentials but are not secrets by design:
/// test-mode keys and publishable (client-side) keys. They must never fire —
/// flagging them would train users to ignore real findings (FP policy §9.2).
fn is_known_non_secret(value: &str) -> bool {
    [
        "sk_test_",
        "rk_test_",
        "pk_test_",
        "pk_live_",
        "whsec_test_",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

fn looks_like_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    [
        "example",
        "your-",
        "your_",
        "changeme",
        "change-me",
        "placeholder",
        "dummy",
        "xxxx",
        "<",
        "todo",
        "insert-",
        "fixme",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

#[allow(clippy::cast_precision_loss)]
pub fn shannon_entropy(value: &str) -> f64 {
    let len = value.chars().count();
    if len == 0 {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in value.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    counts
        .values()
        .map(|&count| {
            let p = count as f64 / len as f64;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn patterns() -> SecretPatterns {
        SecretPatterns::embedded().unwrap()
    }

    #[test]
    fn embedded_pack_compiles() {
        assert!(patterns().patterns.len() >= 10);
    }

    /// C4 regression: `sk-ant-…` matches BOTH the anthropic-api-key regex
    /// and the openai-api-key regex (openai's `sk-` prefix is a strict
    /// subset of anthropic's `sk-ant-`). Correctness depends entirely on
    /// anthropic-api-key appearing before openai-api-key in
    /// rules/env/secrets.yaml (first-match-wins) — this pins that ordering
    /// so a future edit that reorders the YAML fails loudly here instead of
    /// silently misclassifying every Anthropic key as OpenAI.
    #[test]
    fn anthropic_before_openai_ordering_is_pinned() {
        let m = patterns()
            .classify("sk-ant-FAKEFAKEFAKEFAKEFAKEFAKE1234", "apiKey")
            .unwrap();
        assert_eq!(m.provider, "anthropic");
        assert_eq!(m.pattern_id, "anthropic-api-key");
        assert_eq!(m.env_key, "ANTHROPIC_API_KEY");
    }

    #[test]
    fn classifies_provider_keys() {
        let m = patterns()
            .classify("sk_live_FAKEFAKEFAKE1234", "stripeKey")
            .unwrap();
        assert_eq!(m.provider, "stripe");
        assert_eq!(m.env_key, "STRIPE_SECRET_KEY");
        assert_eq!(m.severity, Severity::Critical);
        assert_eq!(m.confidence, Confidence::High);
        assert_eq!(m.masked, "sk_live_…1234");
        assert!(!m.masked.contains("FAKEFAKE"));

        let aws = patterns().classify("AKIAFAKEFAKEFAKEFAKE", "x").unwrap();
        assert_eq!(aws.env_key, "AWS_ACCESS_KEY_ID");
    }

    #[test]
    fn test_keys_and_placeholders_do_not_fire() {
        let p = patterns();
        assert!(p
            .classify("sk_test_FAKEFAKEFAKE1234", "stripeKey")
            .is_none());
        assert!(p.classify("YOUR-STRIPE-KEY-HERE", "stripeKey").is_none());
        assert!(p
            .classify("sk_live_example_key_123456", "stripeKey")
            .is_none());
        assert!(p.classify("<insert key>", "apiKey").is_none());
    }

    /// C7 regression: a provider-pattern match wins even when the literal's
    /// body happens to contain a placeholder-looking substring like `xxxx`
    /// — the placeholder screen must only guard the entropy fallback, not
    /// gate provider patterns ahead of them.
    #[test]
    fn provider_pattern_wins_over_placeholder_screen() {
        let m = patterns()
            .classify("sk_live_FAKExxxxFAKE1234", "stripeKey")
            .unwrap();
        assert_eq!(m.provider, "stripe");
        assert_eq!(m.pattern_id, "stripe-live-secret-key");

        // "TODO" inside the body of an otherwise well-formed AWS key
        // (must stay uppercase — the AWS pattern only allows [0-9A-Z])
        let aws = patterns().classify("AKIAFAKETODOFAKEFAKE", "x").unwrap();
        assert_eq!(aws.provider, "aws");
    }

    #[test]
    fn entropy_fallback_requires_secretish_identifier() {
        let p = patterns();
        let random = "9fQ4cA2e78bZ1dY6fX3aP5cV0e9K";
        let hit = p.classify(random, "api_token").unwrap();
        assert_eq!(hit.pattern_id, "entropy");
        assert_eq!(hit.confidence, Confidence::Medium);
        // same value, non-secret identifier → silent
        assert!(p.classify(random, "request_id").is_none());
        // low-entropy value, secret identifier → silent
        assert!(p
            .classify("aaaaaaaaaaaaaaaaaaaaaaaa", "api_token")
            .is_none());
    }

    /// C8 regression: when `prefix_len + 4 >= value_len` the mask must fall
    /// back to fully-elided `…` rather than emitting a head/tail pair that
    /// overlaps (or reveals more of the value than intended, e.g. a
    /// `head…tail` where `head` and `tail` share characters).
    #[test]
    fn mask_falls_back_when_prefix_plus_tail_would_overlap() {
        // "github_pat_" is 11 chars; value is exactly 15 chars total, so
        // prefix_len(11) + 4 == 15 >= len(15) — must fall back.
        assert_eq!(mask("github_pat_ABCD", "github_pat_"), "…");
        // one char longer clears the guard and masks normally.
        assert_eq!(mask("github_pat_ABCDE", "github_pat_"), "github_pat_…BCDE");
        // no-prefix path: head defaults to 3 chars, so the boundary is at
        // len == 7 (3 + 4).
        assert_eq!(mask("abcdefg", ""), "…");
        assert_eq!(mask("abcdefgh", ""), "abc…efgh");
    }

    /// IN-03 regression: an `ASIA…` STS key matches the AWS regex
    /// (`AKIA|ASIA`) but not its declared `AKIA` prefix. The masked preview
    /// must keep a provider-recognisable `ASIA…` head (prefix-length), not a
    /// generic 3-char `ASI…` head — while still never revealing the middle.
    #[test]
    fn mask_keeps_provider_head_for_alternate_prefix() {
        let m = patterns().classify("ASIAFAKEFAKEFAKEFAKE", "x").unwrap();
        assert_eq!(m.provider, "aws");
        assert_eq!(m.masked, "ASIA…FAKE");
        assert!(!m.masked.contains("FAKEFAKE"), "middle must stay elided");
        // direct: prefix-length head when value doesn't start with the prefix
        assert_eq!(mask("ASIAFAKEFAKEFAKEFAKE", "AKIA"), "ASIA…FAKE");
        // a short alternate-prefix value still fully elides (guard holds)
        assert_eq!(mask("ASIAFAKE", "AKIA"), "…");
    }

    #[test]
    fn mask_never_leaks_middle() {
        assert_eq!(
            mask("sk_live_FAKEFAKEFAKE9f2a", "sk_live_"),
            "sk_live_…9f2a"
        );
        assert_eq!(mask("abcdefghijklmnop", ""), "abc…mnop");
        assert_eq!(mask("short", ""), "…");
    }

    #[test]
    fn classify_url_detects_plain_http() {
        let m = classify_url("https://api.example.com/v1").unwrap();
        assert_eq!(m.provider, "url");
        assert_eq!(m.pattern_id, "url");
        assert_eq!(m.severity, Severity::Low);
        assert!(m.env_key.is_empty(), "env_key derived from identifier");
        // no credential → nothing to hide, endpoint stays visible
        assert_eq!(m.masked, "https://api.example.com/v1");
    }

    #[test]
    fn classify_url_detects_credentialless_dsn() {
        let m = classify_url("redis://cache.internal:6379/0").unwrap();
        assert_eq!(m.provider, "url");
        assert_eq!(m.pattern_id, "connection-string");
        assert_eq!(m.severity, Severity::Low);
    }

    /// T-08-04: a credentialed DSN must be classified high severity and its
    /// password must never appear in the masked preview.
    #[test]
    fn classify_url_masks_credentialed_dsn() {
        let raw = "postgres://admin:s3cr3tP@ss@db.example.com:5432/app";
        let m = classify_url(raw).unwrap();
        assert_eq!(m.provider, "url");
        assert_eq!(m.pattern_id, "connection-string");
        assert_eq!(m.severity, Severity::High);
        assert_eq!(m.confidence, Confidence::High);
        assert!(
            !m.masked.contains("s3cr3tP"),
            "password leaked into mask: {}",
            m.masked
        );
        // username + host stay visible; password elided (rsplit on the last @)
        assert_eq!(m.masked, "postgres://admin:…@db.example.com:5432/app");
    }

    /// A Sentry-style DSN embeds its key as a bare userinfo token — elide it
    /// whole (no colon → no username to keep).
    #[test]
    fn classify_url_masks_userinfo_token() {
        let raw = "https://abc123deadbeef@o123.ingest.sentry.io/456";
        let m = classify_url(raw).unwrap();
        assert_eq!(m.severity, Severity::High);
        assert!(!m.masked.contains("abc123deadbeef"), "{}", m.masked);
        assert_eq!(m.masked, "https://…@o123.ingest.sentry.io/456");
    }

    #[test]
    fn classify_url_rejects_relative_paths_and_bare_schemes() {
        // no scheme (relative filesystem path) → not a URL
        assert!(classify_url("./config/settings.json").is_none());
        assert!(classify_url("../secrets/prod.pem").is_none());
        assert!(classify_url("config/app.yaml").is_none());
        // scheme with no host → rejected
        assert!(classify_url("https://").is_none());
        assert!(classify_url("postgres://").is_none());
        // an unknown scheme with no credential is not extracted
        assert!(classify_url("file:///etc/hosts").is_none());
        assert!(classify_url("custom://plain-host").is_none());
        // not even a URL shape
        assert!(classify_url("just a sentence").is_none());
    }

    /// An unknown scheme that DOES embed a credential is still secret-bearing
    /// and must be caught + masked.
    #[test]
    fn classify_url_catches_credentialed_unknown_scheme() {
        let m = classify_url("ftp://user:hunter2@files.example.com/x").unwrap();
        assert_eq!(m.severity, Severity::High);
        assert!(!m.masked.contains("hunter2"), "{}", m.masked);
    }

    #[test]
    fn mask_url_credential_passthrough_without_userinfo() {
        // nothing to mask — returned unchanged
        assert_eq!(
            mask_url_credential("https://api.example.com/v1"),
            "https://api.example.com/v1"
        );
        assert_eq!(mask_url_credential("not-a-url"), "not-a-url");
    }
}
