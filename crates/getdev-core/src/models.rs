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

const EMBEDDED_MODELS: &str = include_str!("../rules/models.json");

#[derive(Debug, thiserror::Error)]
pub enum ModelsError {
    #[error("invalid models dataset: {0}")]
    Parse(#[from] serde_json::Error),
    /// An empty or whitespace-only `families`/`call_sites` entry — WR-04
    /// (03-REVIEW.md P2). An empty family prefix would make
    /// `literal.starts_with("")` match every literal, silently disabling all
    /// `real/unknown-model-string` detection. A bad embedded dataset row is
    /// release-blocking (mirrors `Datasets::embedded`), never a match-all.
    #[error("invalid models dataset: `{0}` contains an empty or whitespace-only entry")]
    EmptyEntry(&'static str),
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
        reject_empty_entries("families", &file.families)?;
        reject_empty_entries("call_sites", &file.call_sites)?;
        Ok(Self {
            families: file.families,
            call_sites: file.call_sites,
        })
    }

    /// Classify a string literal found at `identifier_context` (the
    /// variable/property/parameter name it is assigned to). Returns `Some`
    /// only when ALL of: `identifier_context` is a known model call-site
    /// name, `literal` looks like a model id, and `literal` matches none of
    /// the known vendor family entries — deliberately freshness-tolerant
    /// (03-RESEARCH.md Pitfall 1): a brand-new dated ID from a *known*
    /// family never fires, only a whole unrecognized family or a garbled
    /// string does.
    ///
    /// A family entry matches a literal when the literal EQUALS the entry
    /// exactly OR the literal starts with it (A9, 03-REVIEW.md). Entries may
    /// or may not carry a trailing hyphen: hyphenated entries (`"o1-"`) only
    /// match dashed continuations, while bare stems (`"o1"`) also cover the
    /// bare id itself (`model: "o1"`) — `starts_with` already subsumes the
    /// equality case, so both are checked via one `starts_with` scan.
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
            .any(|family| literal == family.as_str() || literal.starts_with(family.as_str()));
        if known_family {
            return None;
        }
        Some(ModelVerdict {
            literal: literal.to_owned(),
            nearest_family: None,
        })
    }
}

/// WR-04 (03-REVIEW.md P2): a dataset entry that is empty or whitespace-only
/// is rejected at load. An empty family prefix would make
/// `literal.starts_with("")` true for every literal — silently disabling all
/// unknown-model detection while tests stay green — so a stray blank row in
/// the release-refreshed `rules/models.json` fails loudly instead.
fn reject_empty_entries(field: &'static str, entries: &[String]) -> Result<(), ModelsError> {
    if entries.iter().any(|entry| entry.trim().is_empty()) {
        return Err(ModelsError::EmptyEntry(field));
    }
    Ok(())
}

/// Heuristic model-id shape: lowercase ASCII alphanumerics plus `-`/`.`/`:`,
/// containing at least one hyphen or digit. Rules out plain English words
/// at a model call site (e.g. `"production"`) from firing a wall of false
/// positives — the literal must actually *look* like a model identifier.
///
/// `:` is tolerated alongside `.` (A9) so Bedrock-form ids
/// (`"anthropic.claude-3-5-sonnet-20241022-v2:0"`) reach the known-family
/// check instead of being rejected on shape alone — the family gate, not
/// the charset, is what must decide whether such a literal is flagged.
fn looks_like_model_id(literal: &str) -> bool {
    if literal.is_empty() {
        return false;
    }
    let valid_chars = literal
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.' || c == ':');
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
    fn empty_family_entry_is_rejected_at_load() {
        // WR-04 (P2): an empty family prefix would make starts_with("") match
        // every literal, silently disabling ALL unknown-model detection — it
        // must fail loudly at parse instead.
        let err =
            ModelMatcher::parse(r#"{"version":1,"families":["gpt-",""],"call_sites":["model"]}"#)
                .unwrap_err();
        assert!(matches!(err, ModelsError::EmptyEntry("families")));
    }

    #[test]
    fn whitespace_only_family_entry_is_rejected_at_load() {
        let err = ModelMatcher::parse(r#"{"version":1,"families":["  "],"call_sites":["model"]}"#)
            .unwrap_err();
        assert!(matches!(err, ModelsError::EmptyEntry("families")));
    }

    #[test]
    fn empty_call_site_entry_is_rejected_at_load() {
        let err = ModelMatcher::parse(r#"{"version":1,"families":["gpt-"],"call_sites":[""]}"#)
            .unwrap_err();
        assert!(matches!(err, ModelsError::EmptyEntry("call_sites")));
    }

    #[test]
    fn a_blank_family_row_never_disables_unknown_model_detection() {
        // The failure mode WR-04 guards: had the empty family been accepted,
        // this hallucinated family would be silently swallowed. Rejecting at
        // load means `embedded()`/`parse` never yields a match-all matcher.
        assert!(ModelMatcher::parse(
            r#"{"version":1,"families":["claude-",""],"call_sites":["model"]}"#
        )
        .is_err());
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

    /// A9 — bare (non-hyphenated) ids from a known family must never flag,
    /// but a numerically adjacent *unrelated* family (o9, no matching
    /// entry) still must.
    #[test]
    fn bare_family_stems_are_recognized_without_a_trailing_hyphen() {
        let m = matcher();
        assert!(m.classify_model("o1", "model").is_none());
        assert!(m.classify_model("o1-preview", "model").is_none());
        assert!(m.classify_model("o3", "model_id").is_none());
        assert!(m.classify_model("o4", "modelId").is_none());
        assert!(m.classify_model("o9-mini", "model").is_some());
    }

    /// A9 — families added by the freshness-gated checkpoint update
    /// (03-REVIEW.md): non-chat model families (embeddings/audio/image) and
    /// newer vendor lines must never flag.
    #[test]
    fn newly_added_families_are_recognized() {
        let m = matcher();
        assert!(m
            .classify_model("text-embedding-3-large", "model")
            .is_none());
        assert!(m.classify_model("whisper-1", "model").is_none());
        assert!(m.classify_model("chatgpt-4o-latest", "model").is_none());
        assert!(m.classify_model("gemma-2-27b", "model").is_none());
        assert!(m.classify_model("qwen-2.5-72b", "model").is_none());
    }

    /// A9 — Bedrock-form ids (`vendor.family-...:version`) must reach the
    /// known-family check rather than being rejected on charset alone; the
    /// dotted/colon-suffixed form of a known Anthropic family must never
    /// flag.
    #[test]
    fn bedrock_form_known_family_id_is_never_flagged() {
        let m = matcher();
        assert!(m
            .classify_model("anthropic.claude-3-5-sonnet-20241022-v2:0", "model_id")
            .is_none());
    }

    /// F6 — documented residual FP class: an ORM-style `model:` key whose
    /// value happens to look like a model id (hyphen + version suffix)
    /// still flags at medium/medium once it reaches a model call site
    /// name. This is an accepted trade-off (03-REVIEW.md F6): the family
    /// gate protects every real model id from ANY known vendor, so the only
    /// remaining false-positive surface is a non-model field that happens
    /// to share a call-site identifier name (`model`) AND happens to look
    /// like a dashed/versioned id — narrow, and always emits a
    /// human-readable "matches no known vendor family" detail rather than
    /// staying silent, so it is a documented trade-off, not a silent bug.
    #[test]
    fn orm_style_model_field_collision_is_a_documented_medium_medium_finding() {
        let m = matcher();
        let verdict = m.classify_model("user-profile-v2", "model").unwrap();

        let finding = crate::real::unknown_model_finding(&verdict, "app/models.py", Some(12));
        assert_eq!(finding.severity, crate::findings::Severity::Medium);
        assert_eq!(finding.confidence, crate::findings::Confidence::Medium);
        assert!(finding
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("no vendor family prefix"));
    }
}
