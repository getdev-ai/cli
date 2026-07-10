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
    #[allow(dead_code)]
    families: Vec<String>,
    #[allow(dead_code)]
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

    /// TODO(RED): stubbed to always return `None` — the failing fixture
    /// gate (`tests/models_fixtures.rs`) documents the required behavior;
    /// the GREEN commit implements the real family-prefix + call-site +
    /// model-id-shape classification.
    pub fn classify_model(&self, _literal: &str, _identifier_context: &str) -> Option<ModelVerdict> {
        None
    }
}
