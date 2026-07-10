//! LLM model-string matcher: flags model-looking literals at model call
//! sites that match no known vendor family prefix. Deliberately
//! freshness-tolerant (03-RESEARCH.md Pitfall 1) — matches by vendor family
//! PREFIX, not exact model ID, so a newly released dated model ID from a
//! known vendor family never false-positives; only a whole new/hallucinated
//! vendor family or a garbled string is flagged.
//!
//! Embedded dataset: `rules/models.json` (families + call-site identifier
//! names) — mirrors `SecretPatterns::embedded()`'s `include_str!` + serde
//! pattern (crate::secrets).

use serde::Deserialize;

const EMBEDDED_MODELS: &str = include_str!("../../../rules/models.json");

#[derive(Debug, thiserror::Error)]
pub enum ModelsError {
    #[error("invalid models dataset: {0}")]
    Parse(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelsFile {
    #[allow(dead_code)]
    version: u32,
    families: Vec<String>,
    call_sites: Vec<String>,
}

/// Vendor family-prefix model-string matcher.
#[derive(Debug)]
pub struct ModelMatcher {
    families: Vec<String>,
    call_sites: Vec<String>,
}

/// An unrecognized model-looking literal found at a model call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelVerdict {
    pub literal: String,
    /// Reserved for a future "did you mean" hint; always `None` in v0.1 —
    /// no local, network-free evidence source names a specific nearest
    /// family (docs/PLAN.md §2.3 model-string mechanics).
    pub nearest_family: Option<String>,
}

impl ModelMatcher {
    /// Load the embedded family-prefix dataset (`rules/models.json`). A
    /// malformed embedded pack is a release-blocking bug, surfaced as a
    /// typed error rather than a panic (mirrors `SecretPatterns::embedded`).
    pub fn embedded() -> Result<Self, ModelsError> {
        Self::parse(EMBEDDED_MODELS)
    }

    pub fn parse(json: &str) -> Result<Self, ModelsError> {
        let file: ModelsFile = serde_json::from_str(json)?;
        Ok(Self {
            families: file.families,
            call_sites: file.call_sites,
        })
    }

    /// Classify a string literal found at `identifier_context` (the
    /// variable/property/parameter name it is assigned to). Returns `Some`
    /// only when ALL of: `identifier_context` is a known model call-site
    /// name, `literal` looks like a model id, and `literal` starts with
    /// none of the known vendor family prefixes — deliberately
    /// freshness-tolerant (03-RESEARCH.md Pitfall 1): a brand-new dated ID
    /// from a *known* family never fires, only a whole unrecognized family
    /// or a garbled string does.
    pub fn classify_model(&self, literal: &str, identifier_context: &str) -> Option<ModelVerdict> {
        let at_call_site = self
            .call_sites
            .iter()
            .any(|site| site.eq_ignore_ascii_case(identifier_context));
        if !at_call_site || !looks_like_model_id(literal) {
            return None;
        }
        let known_family = self
            .families
            .iter()
            .any(|family| literal.starts_with(family.as_str()));
        if known_family {
            return None;
        }
        Some(ModelVerdict {
            literal: literal.to_owned(),
            nearest_family: None,
        })
    }
}

/// Heuristic model-id shape: lowercase ASCII alphanumerics plus `-`/`.`,
/// containing at least one hyphen or digit. Rules out plain English words
/// at a model call site (e.g. `"production"`) from firing a wall of false
/// positives — the literal must actually *look* like a model identifier.
fn looks_like_model_id(literal: &str) -> bool {
    if literal.is_empty() {
        return false;
    }
    let valid_chars = literal
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.');
    valid_chars && (literal.contains('-') || literal.chars().any(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn matcher() -> ModelMatcher {
        ModelMatcher::embedded().unwrap()
    }

    #[test]
    fn embedded_pack_compiles_and_is_non_empty() {
        let m = matcher();
        assert!(!m.families.is_empty());
        assert!(!m.call_sites.is_empty());
    }

    #[test]
    fn known_family_models_at_a_model_call_site_are_never_flagged() {
        let m = matcher();
        assert!(m.classify_model("claude-sonnet-4-6", "model").is_none());
        assert!(m.classify_model("gpt-5.4", "model").is_none());
        assert!(m.classify_model("gemini-2.0-flash", "model").is_none());
    }

    #[test]
    fn known_family_prefix_is_freshness_tolerant_to_unseen_dated_ids() {
        let m = matcher();
        // a not-yet-released dated Claude ID under a KNOWN family prefix
        // must never false-positive (matches by family, not exact ID)
        assert!(m
            .classify_model("claude-sonnet-9-does-not-exist", "model")
            .is_none());
    }

    #[test]
    fn unknown_family_at_a_model_call_site_is_flagged() {
        let m = matcher();
        let verdict = m
            .classify_model("gpt5-turbo-hallucinated", "model")
            .unwrap();
        assert_eq!(verdict.literal, "gpt5-turbo-hallucinated");
    }

    #[test]
    fn model_looking_string_outside_a_model_call_site_is_never_flagged() {
        let m = matcher();
        assert!(m
            .classify_model("gpt5-turbo-hallucinated", "description")
            .is_none());
    }

    #[test]
    fn no_hallucinated_mythos_family_is_ever_recognized() {
        // Regression guard: a prior session hallucinated a "claude-mythos-"
        // family that does not exist at Anthropic — must always flag.
        let m = matcher();
        assert!(m.classify_model("claude-mythos-7", "model_name").is_some());
        assert!(!m.families.iter().any(|f| f.contains("mythos")));
    }
}
