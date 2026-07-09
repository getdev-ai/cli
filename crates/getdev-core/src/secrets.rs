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
    pub fn classify(&self, value: &str, identifier: &str) -> Option<SecretMatch> {
        if looks_like_placeholder(value) {
            return None;
        }
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
        // generic fallback: random-looking value assigned to a secret-ish name
        if !is_known_non_secret(value)
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
pub fn mask(value: &str, prefix: &str) -> String {
    let value = value.trim();
    if value.len() < 12 {
        return "…".to_owned();
    }
    let head: String = if !prefix.is_empty() && value.starts_with(prefix) {
        prefix.to_owned()
    } else {
        value.chars().take(3).collect()
    };
    let tail: String = {
        let chars: Vec<char> = value.chars().collect();
        chars[chars.len().saturating_sub(4)..].iter().collect()
    };
    format!("{head}…{tail}")
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

    #[test]
    fn mask_never_leaks_middle() {
        assert_eq!(
            mask("sk_live_FAKEFAKEFAKE9f2a", "sk_live_"),
            "sk_live_…9f2a"
        );
        assert_eq!(mask("abcdefghijklmnop", ""), "abc…mnop");
        assert_eq!(mask("short", ""), "…");
    }
}
