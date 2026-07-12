//! JSON Schema validation for rule YAML — the friendly, multi-error layer
//! that runs BEFORE typed serde deserialization (see [`super::load_rule`]).
//! Belt-and-braces with typed `#[serde(deny_unknown_fields)]`: the schema
//! catches shape/enum/`oneOf` violations with a human-readable, ALL-errors
//! message (04-RESEARCH.md's "Alternatives Considered" — friendlier for a
//! community `--rules` contributor than serde's fail-fast single error);
//! the typed struct downstream is what the rest of the engine actually
//! programs against.

use jsonschema::Validator;
use std::sync::OnceLock;

use super::RuleLoadError;

/// The JSON Schema every rule YAML (embedded and `--rules`-supplied)
/// validates against. Normative shape: docs/SPEC-RULES.md.
const SCHEMA_JSON: &str = include_str!("../../../../rules/audit/schema.json");

/// Compile the embedded schema exactly once per process. A malformed
/// embedded schema (a getdev release bug, not user-controlled content) is
/// still surfaced as a typed [`RuleLoadError`] rather than a panic
/// (CLAUDE.md rule 1 — no unwrap/expect/panic anywhere in this crate,
/// release-blocking-ness is enforced by CI catching the first rule load,
/// not by aborting the process).
fn compiled_schema() -> Result<&'static Validator, RuleLoadError> {
    static SCHEMA: OnceLock<Result<Validator, String>> = OnceLock::new();
    let result = SCHEMA.get_or_init(|| {
        let value: serde_json::Value = serde_json::from_str(SCHEMA_JSON).map_err(|source| {
            format!("embedded rules/audit/schema.json is not valid JSON: {source}")
        })?;
        jsonschema::validator_for(&value).map_err(|source| {
            format!("embedded rules/audit/schema.json is not a valid JSON Schema: {source}")
        })
    });
    match result {
        Ok(validator) => Ok(validator),
        Err(message) => Err(RuleLoadError::Schema {
            origin: "rules/audit/schema.json".to_owned(),
            rule_id: "<schema>".to_owned(),
            message: message.clone(),
        }),
    }
}

/// Validate `value` (a rule YAML already normalized to `serde_json::Value`)
/// against the embedded JSON Schema. Collects EVERY violation into one
/// error message (`iter_errors`, not `validate`'s single-error path) so a
/// rule with two problems (e.g. a bad `severity` AND a matcher entry
/// combining `query`+`text_pattern`) is reported in one pass.
pub(super) fn validate_schema(
    value: &serde_json::Value,
    origin: &str,
) -> Result<(), RuleLoadError> {
    let validator = compiled_schema()?;
    let messages: Vec<String> = validator
        .iter_errors(value)
        .map(|err| err.to_string())
        .collect();
    if messages.is_empty() {
        return Ok(());
    }
    let rule_id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<unknown>")
        .to_owned();
    Err(RuleLoadError::Schema {
        origin: origin.to_owned(),
        rule_id,
        message: messages.join("; "),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use serde_json::json;

    #[test]
    fn valid_rule_passes_schema() {
        let value = json!({
            "id": "audit/cors-wildcard",
            "severity": "high",
            "confidence": "high",
            "languages": ["javascript"],
            "description": "CORS wildcard",
            "message": "CORS allows any origin",
            "remediation": "Restrict origins.",
            "refs": ["https://getdev.ai/rules/audit/cors-wildcard"],
            "matchers": [{"language": "javascript", "query": "(call_expression) @c"}],
            "fixtures": {
                "positive": ["a.js", "b.js", "c.js"],
                "negative": ["d.js", "e.js", "f.js"]
            }
        });
        assert!(validate_schema(&value, "test").is_ok());
    }

    /// Task 1 behavior: a schema violation is reported with EVERY error,
    /// not just the first — this rule has both a bad `severity` AND a
    /// matcher combining `query`+`text_pattern` (violates `oneOf`).
    #[test]
    fn schema_reports_every_violation_not_just_the_first() {
        let value = json!({
            "id": "audit/broken-rule",
            "severity": "bogus",
            "confidence": "high",
            "languages": ["javascript"],
            "description": "x",
            "message": "x",
            "remediation": "x",
            "refs": [],
            "matchers": [{"language": "javascript", "query": "(x) @c", "text_pattern": "y"}],
            "fixtures": {
                "positive": ["a.js", "b.js", "c.js"],
                "negative": ["d.js", "e.js", "f.js"]
            }
        });
        let err = validate_schema(&value, "test").unwrap_err();
        let RuleLoadError::Schema {
            message, rule_id, ..
        } = &err
        else {
            panic!("expected Schema error, got {err:?}");
        };
        assert_eq!(rule_id, "audit/broken-rule");
        // the `;`-joined message proves BOTH violations were collected
        // (our own join separator between `iter_errors` entries) — not
        // just the first one `validate()` would have stopped at.
        assert!(
            message.matches(';').count() >= 1,
            "expected multiple joined violations, got: {message}"
        );
    }
}
