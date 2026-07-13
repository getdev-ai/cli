//! The declarative rule engine — `core::rules`. Rule packs (embedded and
//! `--rules`-supplied) are YAML data, never code (CLAUDE.md rule 7 /
//! DECISIONS.md DEC-03): this module's only matcher primitives are
//! tree-sitter query text, a whole-file regex, and the `core::secrets`
//! classifier — no eval, no shell-out, no file-write matcher kind exists.
//!
//! Load pipeline (`load_rule`): raw YAML -> `serde_json::Value` -> JSON
//! Schema validation (`schema::validate_schema`, friendly multi-error) ->
//! typed `serde` deserialization (`#[serde(deny_unknown_fields)]`, the
//! second safety net) -> a non-empty-matchers check. Two distinct load
//! policies sit on top of `load_rule` (04-RESEARCH.md Pitfall 2): the
//! embedded pack ([`load_embedded`]) treats ANY error as fatal — a broken
//! shipped rule is a release-blocking getdev bug; a user `--rules <dir>`
//! pack ([`load_user_pack`]) collects one error per broken rule file and
//! keeps loading the rest — never a panic, never a silently-dropped pack.
//!
//! Normative spec: docs/SPEC-RULES.md.

mod query_cache;
mod schema;
mod text_regex;

pub use query_cache::QueryCache;
pub use text_regex::CompiledTextMatcher;

use std::path::Path;

use include_dir::{include_dir, Dir};
use serde::Deserialize;

use crate::findings::{Confidence, Severity};
use crate::scan::Lang;

/// The shipped `rules/audit/*.yaml` pack, embedded at compile time.
/// `schema.json` (and anything else that isn't `.yaml`) is skipped by
/// [`load_embedded`], not by this embedding itself.
static EMBEDDED_RULES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../../rules/audit");

/// The shipped `rules/review/*.yaml` pack, embedded at compile time — a
/// SECOND `Dir`, independent of [`EMBEDDED_RULES`] (06-RESEARCH.md Open Q2,
/// LOCKED). Keeping the two packs siloed means an `audit` invocation never
/// silently compiles `review/*` queries it never runs (and vice versa), and
/// each command's pack stays independently testable. Loaded via
/// [`load_embedded_review`].
static EMBEDDED_REVIEW_RULES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../../rules/review");

/// Every way a rule pack load can fail. Always carries `origin` (the
/// source file/description this error came from) so a multi-rule pack load
/// can report exactly which file was the problem.
#[derive(Debug, thiserror::Error)]
pub enum RuleLoadError {
    #[error("{origin}: invalid rule YAML: {message}")]
    Yaml { origin: String, message: String },

    #[error("{origin}: rule '{rule_id}' failed schema validation: {message}")]
    Schema {
        origin: String,
        rule_id: String,
        message: String,
    },

    #[error("{origin}: rule '{rule_id}' has an empty matchers list — a rule with zero matchers can never fire")]
    EmptyMatchers { origin: String, rule_id: String },

    #[error("{origin}: rule '{rule_id}': invalid tree-sitter query for language {lang}: {source}")]
    QueryCompile {
        origin: String,
        rule_id: String,
        lang: String,
        #[source]
        source: Box<getdev_grammars::tree_sitter::QueryError>,
    },

    #[error("{origin}: rule '{rule_id}': query uses unsupported predicate(s): {names}")]
    UnsupportedPredicate {
        origin: String,
        rule_id: String,
        names: String,
    },

    #[error("{origin}: rule '{rule_id}': invalid regex in text-regex matcher: {source}")]
    BadRegex {
        origin: String,
        rule_id: String,
        #[source]
        source: regex::Error,
    },

    #[error("{origin}: rule '{rule_id}': invalid glob pattern: {source}")]
    BadGlob {
        origin: String,
        rule_id: String,
        #[source]
        source: globset::Error,
    },
}

/// Optional project-level framework gate (docs/SPEC-RULES.md `frameworks`
/// field), parallel to `languages`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Framework {
    Express,
    Nextjs,
    Fastapi,
    Flask,
}

/// A rule's `≥3 positive + ≥3 negative` fixture file lists
/// (docs/SPEC-RULES.md "Fixture requirements").
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixtures {
    pub positive: Vec<String>,
    pub negative: Vec<String>,
}

/// One matcher entry: exactly one of the three declarative matcher kinds
/// (docs/SPEC-RULES.md "Predicate support" / matchers row). The JSON Schema
/// (`rules/audit/schema.json`, `oneOf` + `additionalProperties: false` per
/// branch) rejects any entry mixing fields from more than one kind before
/// this type is ever constructed — this `Deserialize` impl still validates
/// defensively rather than assuming that guarantee holds.
#[derive(Debug, Clone)]
pub enum Matcher {
    /// `{language, query}` — a tree-sitter AST query.
    Ast { language: Lang, query: String },
    /// `{file_glob, text_pattern}` — a whole-file regex, no grammar.
    TextRegex {
        file_glob: String,
        text_pattern: String,
    },
    /// `{secret: true}` — wraps `core::secrets`'s classifier.
    Secret,
}

impl<'de> Deserialize<'de> for Matcher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let Some(obj) = value.as_object() else {
            return Err(serde::de::Error::custom("matcher entry must be an object"));
        };
        let has_ast = obj.contains_key("language") || obj.contains_key("query");
        let has_text = obj.contains_key("file_glob") || obj.contains_key("text_pattern");
        let has_secret = obj.contains_key("secret");

        match (has_ast, has_text, has_secret) {
            (true, false, false) => {
                #[derive(Deserialize)]
                struct Raw {
                    language: Lang,
                    query: String,
                }
                let raw: Raw = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                Ok(Matcher::Ast {
                    language: raw.language,
                    query: raw.query,
                })
            }
            (false, true, false) => {
                #[derive(Deserialize)]
                struct Raw {
                    file_glob: String,
                    text_pattern: String,
                }
                let raw: Raw = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                Ok(Matcher::TextRegex {
                    file_glob: raw.file_glob,
                    text_pattern: raw.text_pattern,
                })
            }
            (false, false, true) => {
                #[derive(Deserialize)]
                struct Raw {
                    secret: bool,
                }
                let raw: Raw = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                if !raw.secret {
                    return Err(serde::de::Error::custom(
                        "matcher entry 'secret' must be `true`",
                    ));
                }
                Ok(Matcher::Secret)
            }
            _ => Err(serde::de::Error::custom(
                "matcher entry must be exactly one of: {language, query} | {file_glob, text_pattern} | {secret: true}",
            )),
        }
    }
}

/// A single declarative rule (docs/SPEC-RULES.md field reference).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub languages: Vec<Lang>,
    #[serde(default)]
    pub frameworks: Vec<Framework>,
    #[serde(default)]
    pub path_glob: Vec<String>,
    pub description: String,
    pub message: String,
    pub remediation: String,
    pub refs: Vec<String>,
    pub matchers: Vec<Matcher>,
    pub fixtures: Fixtures,
}

/// A loaded, load-time-validated rule pack: every AST matcher's query is
/// compiled and cached in `query_cache`; text-regex matchers were validated
/// to compile during load (`compile_rule`) but are re-derived by callers at
/// scan time (`core::audit`, a later phase) rather than persisted here.
#[derive(Default)]
pub struct RulePack {
    pub rules: Vec<Rule>,
    pub query_cache: QueryCache,
}

impl RulePack {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Parse, schema-validate, and typed-deserialize one rule YAML document.
/// Does NOT compile its matchers (query/regex/glob compilation is
/// `compile_rule`'s job, layered on top by both loader policies below).
fn load_rule(raw: &str, origin: &str) -> Result<Rule, RuleLoadError> {
    let yaml_value: serde_yaml::Value =
        serde_yaml::from_str(raw).map_err(|source| RuleLoadError::Yaml {
            origin: origin.to_owned(),
            message: source.to_string(),
        })?;
    let value: serde_json::Value =
        serde_json::to_value(&yaml_value).map_err(|source| RuleLoadError::Yaml {
            origin: origin.to_owned(),
            message: format!("failed to normalize YAML to a JSON-compatible structure: {source}"),
        })?;

    schema::validate_schema(&value, origin)?;

    let rule: Rule = serde_json::from_value(value).map_err(|source| RuleLoadError::Yaml {
        origin: origin.to_owned(),
        message: source.to_string(),
    })?;

    if rule.matchers.is_empty() {
        return Err(RuleLoadError::EmptyMatchers {
            origin: origin.to_owned(),
            rule_id: rule.id,
        });
    }

    Ok(rule)
}

/// Compile every matcher in `rule` into `cache` (AST matchers) or validate
/// it compiles (text-regex matchers — the compiled matcher itself is not
/// persisted here; `Secret` matchers wrap `core::secrets` and need no
/// compilation step at all). 04-RESEARCH.md Pitfall 7: this is called ONCE
/// per rule at load time, never per scanned file.
pub(crate) fn compile_rule(
    cache: &mut QueryCache,
    rule: &Rule,
    origin: &str,
) -> Result<(), RuleLoadError> {
    // Validate every `path_glob` entry compiles — mirroring the text-regex
    // `file_glob` path (`CompiledTextMatcher::compile`). Without this, an
    // invalid user glob is silently accepted at load and, because a builder
    // that dropped every bad pattern yields an empty `GlobSet` (matches
    // nothing), silently DISABLES the whole rule at scan time (WR-02): the
    // worst failure for a security scanner — a false all-clear. A bad glob
    // must be a typed per-rule load error (fatal for the embedded pack,
    // collected for `--rules`), exactly like `BadRegex`/`BadGlob` already are
    // for text matchers.
    for pattern in &rule.path_glob {
        globset::Glob::new(pattern).map_err(|source| RuleLoadError::BadGlob {
            origin: origin.to_owned(),
            rule_id: rule.id.clone(),
            source,
        })?;
    }

    // Combine all AST matchers that share a language into ONE multi-pattern
    // query string (tree-sitter supports many patterns per query). The
    // `QueryCache` is keyed by `(Lang, rule_id)` — exactly one query per
    // pair — so without this merge a rule declaring several same-language
    // AST matchers would silently keep only its FIRST pattern: every later
    // same-language matcher hits the `contains_key` fast-path in
    // `QueryCache::compile` and is dropped. Order is preserved so a rule's
    // patterns compile in author order. `TextRegex`/`Secret` matchers are
    // unaffected (validated/handled per entry, never AST-cached).
    let mut combined: Vec<(Lang, String)> = Vec::new();
    for matcher in &rule.matchers {
        match matcher {
            Matcher::Ast { language, query } => {
                if let Some((_, acc)) = combined.iter_mut().find(|(lang, _)| lang == language) {
                    acc.push('\n');
                    acc.push_str(query);
                } else {
                    combined.push((*language, query.clone()));
                }
            }
            Matcher::TextRegex {
                file_glob,
                text_pattern,
            } => {
                CompiledTextMatcher::compile(&rule.id, origin, file_glob, text_pattern)?;
            }
            Matcher::Secret => {}
        }
    }
    for (language, query) in &combined {
        cache.compile(*language, &rule.id, origin, query)?;
    }
    Ok(())
}

/// Load, validate, and compile the shipped `rules/audit/*.yaml` pack.
/// Skips `schema.json` and any non-`.yaml` file. ANY error here is fatal
/// (04-RESEARCH.md Pitfall 2): a broken embedded rule is a release-blocking
/// getdev bug, caught by CI on the first rule load, never a partial/silent
/// pack.
///
/// # Errors
/// Returns the first `RuleLoadError` encountered (YAML/schema violation,
/// empty matchers, or a compile failure) — never panics.
pub fn load_embedded() -> Result<RulePack, RuleLoadError> {
    load_embedded_dir(&EMBEDDED_RULES)
}

/// Load, validate, and compile the shipped `rules/review/*.yaml` pack — the
/// `review` command's counterpart to [`load_embedded`], reading the SECOND
/// embedded `EMBEDDED_REVIEW_RULES` `Dir` (06-RESEARCH.md Open Q2, LOCKED).
/// Same fatal-on-any-error policy as [`load_embedded`].
///
/// # Errors
/// Returns the first `RuleLoadError` encountered — never panics.
pub fn load_embedded_review() -> Result<RulePack, RuleLoadError> {
    load_embedded_dir(&EMBEDDED_REVIEW_RULES)
}

/// Shared body for both embedded-pack loaders: walk one `Dir<'static>`'s
/// `.yaml` files (skipping `schema.json` and anything else), parse + validate
/// + compile each, ANY error fatal.
fn load_embedded_dir(dir: &Dir<'static>) -> Result<RulePack, RuleLoadError> {
    let mut pack = RulePack::new();
    for file in dir.files() {
        let path = file.path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("yaml") {
            continue;
        }
        let origin = path.display().to_string();
        let raw = file.contents_utf8().ok_or_else(|| RuleLoadError::Yaml {
            origin: origin.clone(),
            message: "embedded rule file is not valid UTF-8".to_owned(),
        })?;
        let rule = load_rule(raw, &origin)?;
        compile_rule(&mut pack.query_cache, &rule, &origin)?;
        pack.rules.push(rule);
    }
    Ok(pack)
}

/// Load a user-supplied `--rules <dir>` pack: walk `*.yaml` files directly
/// under `dir`, parse+validate+compile each independently. A broken rule
/// file is skipped and its error collected in the second return value — the
/// rest of the pack still loads (04-RESEARCH.md Pitfall 2, CLAUDE.md rule
/// 1: never panic on user-controlled content).
#[must_use]
pub fn load_user_pack(dir: &Path) -> (Vec<Rule>, Vec<RuleLoadError>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(source) => {
            errors.push(RuleLoadError::Yaml {
                origin: dir.display().to_string(),
                message: format!("failed to read rules directory: {source}"),
            });
            return (rules, errors);
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("yaml") {
            continue;
        }
        let origin = path.display().to_string();
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(source) => {
                errors.push(RuleLoadError::Yaml {
                    origin,
                    message: format!("failed to read: {source}"),
                });
                continue;
            }
        };
        match load_rule(&raw, &origin) {
            Ok(rule) => {
                let mut scratch_cache = QueryCache::new();
                match compile_rule(&mut scratch_cache, &rule, &origin) {
                    Ok(()) => rules.push(rule),
                    Err(err) => errors.push(err),
                }
            }
            Err(err) => errors.push(err),
        }
    }

    (rules, errors)
}

/// Merge a user `--rules` pack into the embedded pack: a user rule whose
/// `id` matches an embedded rule's `id` overrides that rule entirely, never
/// silently ambiguous (docs/SPEC-RULES.md "Pack merge & collisions"). One
/// warning string is returned per collision.
#[must_use]
pub fn merge(mut embedded: RulePack, user: Vec<Rule>) -> (RulePack, Vec<String>) {
    let mut warnings = Vec::new();
    for rule in user {
        // A user rule overrides an embedded rule of the same id ENTIRELY
        // (docs/SPEC-RULES.md). Evict any cached queries for this id FIRST —
        // otherwise the already-present fast-path in `QueryCache::compile`
        // keeps the stale embedded query and the override's replacement query
        // is never compiled (BL-01), so the embedded pattern would run under
        // the user's metadata.
        embedded.query_cache.remove_rule(&rule.id);
        // Re-insert into the embedded cache so the merged pack's queries are
        // actually usable. `load_user_pack` already validated this rule
        // compiles (into a scratch cache), and compilation is pure/
        // deterministic, so a failure here "can't happen" on that path — but
        // now that BL-01's fix has EVICTED any colliding embedded query
        // first, a swallowed error would leave the rule AST-dead with no
        // diagnostic (IN-05). Surface it as a warning instead of `.ok()`, so
        // a recompile failure is visible rather than a silent no-op.
        if let Err(err) = compile_rule(&mut embedded.query_cache, &rule, "user-pack") {
            warnings.push(format!(
                "rule '{}': failed to recompile on merge (its AST matchers will not fire): {err}",
                rule.id
            ));
        }

        if let Some(existing) = embedded.rules.iter().position(|r| r.id == rule.id) {
            warnings.push(format!(
                "rule '{}': user pack overrides embedded rule of the same id",
                rule.id
            ));
            embedded.rules[existing] = rule;
        } else {
            embedded.rules.push(rule);
        }
    }
    (embedded, warnings)
}

/// Manual `Deserialize` for [`crate::scan::Lang`] (a local type — no orphan
/// rule concern) so rule YAML's `language`/`languages` fields parse
/// directly into it, matching `Lang`'s own `Display` spelling
/// (docs/SPEC-RULES.md: `javascript`\|`typescript`\|`tsx`\|`python`).
impl<'de> Deserialize<'de> for Lang {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "javascript" => Ok(Self::JavaScript),
            "typescript" => Ok(Self::TypeScript),
            "tsx" => Ok(Self::Tsx),
            "python" => Ok(Self::Python),
            other => Err(serde::de::Error::custom(format!(
                "unknown language '{other}' (expected javascript|typescript|tsx|python)"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const VALID_RULE_YAML: &str = r#"
id: audit/cors-wildcard
severity: high
confidence: high
languages: [javascript]
description: CORS configured with wildcard origin
message: "CORS allows any origin ('*')"
remediation: Restrict allowed origins.
refs:
  - https://getdev.ai/rules/audit/cors-wildcard
matchers:
  - language: javascript
    query: |
      (call_expression
        function: (identifier) @fn (#eq? @fn "cors")) @call
fixtures:
  positive: [a.js, b.js, c.js]
  negative: [d.js, e.js, f.js]
"#;

    /// Task 1 behavior: a valid rule round-trips through schema validation
    /// then typed serde into a `Rule` with a non-empty `matchers`.
    #[test]
    fn valid_rule_round_trips() {
        let rule = load_rule(VALID_RULE_YAML, "test").unwrap();
        assert_eq!(rule.id, "audit/cors-wildcard");
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.confidence, Confidence::High);
        assert_eq!(rule.languages, vec![Lang::JavaScript]);
        assert!(!rule.matchers.is_empty());
        assert!(matches!(rule.matchers[0], Matcher::Ast { .. }));
    }

    /// Task 1 behavior: an unknown top-level key is rejected via
    /// `deny_unknown_fields`, classified as `RuleLoadError::Yaml`.
    #[test]
    fn unknown_top_level_key_is_a_yaml_error() {
        let yaml = VALID_RULE_YAML.replace("severity: high", "severity: high\nbogus_field: 1");
        let err = load_rule(&yaml, "test").unwrap_err();
        assert!(matches!(err, RuleLoadError::Yaml { .. }));
    }

    /// Task 1 behavior: a schema violation (bad `severity` enum value) is
    /// `RuleLoadError::Schema`.
    #[test]
    fn invalid_severity_is_a_schema_error() {
        let yaml = VALID_RULE_YAML.replace("severity: high", "severity: bogus");
        let err = load_rule(&yaml, "test").unwrap_err();
        assert!(matches!(err, RuleLoadError::Schema { .. }));
    }

    /// Task 1 behavior: a matcher entry with BOTH `query` and
    /// `text_pattern` violates the schema's `oneOf`.
    #[test]
    fn matcher_with_both_query_and_text_pattern_is_rejected() {
        let yaml = VALID_RULE_YAML.replace(
            "  - language: javascript\n    query: |\n      (call_expression\n        function: (identifier) @fn (#eq? @fn \"cors\")) @call\n",
            "  - language: javascript\n    query: \"(x) @c\"\n    text_pattern: \"y\"\n",
        );
        let err = load_rule(&yaml, "test").unwrap_err();
        assert!(matches!(err, RuleLoadError::Schema { .. }));
    }

    /// Task 1 behavior: an empty `matchers` list is `EmptyMatchers`.
    #[test]
    fn empty_matchers_list_is_rejected() {
        let yaml = r#"
id: audit/cors-wildcard
severity: high
confidence: high
languages: [javascript]
description: CORS configured with wildcard origin
message: "CORS allows any origin ('*')"
remediation: Restrict allowed origins.
refs: []
matchers: []
fixtures:
  positive: [a.js, b.js, c.js]
  negative: [d.js, e.js, f.js]
"#;
        let err = load_rule(yaml, "test").unwrap_err();
        assert!(matches!(err, RuleLoadError::EmptyMatchers { .. }));
    }

    #[test]
    fn secret_matcher_round_trips() {
        let yaml = r#"
id: audit/hardcoded-secret
severity: critical
confidence: high
languages: [javascript, python]
description: Hardcoded secret literal
message: Hardcoded secret detected
remediation: Move to an environment variable.
refs: []
matchers:
  - secret: true
fixtures:
  positive: [a.js, b.js, c.js]
  negative: [d.js, e.js, f.js]
"#;
        let rule = load_rule(yaml, "test").unwrap();
        assert!(matches!(rule.matchers[0], Matcher::Secret));
    }

    #[test]
    fn text_regex_matcher_round_trips() {
        let yaml = r#"
id: audit/firebase-open-rules
severity: high
confidence: medium
languages: [javascript]
description: Firebase rules file allows open read/write
message: Firebase rules allow unauthenticated access
remediation: Restrict the rule to authenticated requests.
refs: []
matchers:
  - file_glob: "**/*.rules"
    text_pattern: "allow read, write: if true"
fixtures:
  positive: [a.rules, b.rules, c.rules]
  negative: [d.rules, e.rules, f.rules]
"#;
        let rule = load_rule(yaml, "test").unwrap();
        assert!(matches!(rule.matchers[0], Matcher::TextRegex { .. }));
    }

    /// Task 2 behavior: `load_embedded` succeeds without error against the
    /// real, on-disk `rules/audit/` directory (currently only `schema.json`
    /// — later plans in this phase add the shipped `.yaml` rules; this test
    /// only pins that an empty-of-rules pack is not itself an error).
    #[test]
    fn load_embedded_succeeds() {
        // `load_embedded()` returning `Ok` at all (not panicking, not
        // erroring on the schema.json-only directory) is the assertion.
        let _pack = load_embedded().unwrap();
    }

    /// Task 2 behavior (rules::load_error): a user pack with one valid and
    /// one broken rule file returns exactly one Rule and one
    /// RuleLoadError, never panics, and does not drop the good rule.
    #[test]
    fn load_error_user_pack_skips_broken_rule_keeps_the_rest() {
        let dir = tempdir();
        std::fs::write(dir.join("good.yaml"), VALID_RULE_YAML).unwrap();
        std::fs::write(
            dir.join("broken.yaml"),
            "id: audit/broken\nseverity: bogus\n",
        )
        .unwrap();

        let (rules, errors) = load_user_pack(&dir);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "audit/cors-wildcard");
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn load_error_user_pack_broken_query_is_collected_not_fatal() {
        let dir = tempdir();
        let broken_query_yaml = VALID_RULE_YAML.replace(
            "function: (identifier) @fn (#eq? @fn \"cors\")) @call",
            "function: (identifier",
        );
        std::fs::write(dir.join("broken.yaml"), broken_query_yaml).unwrap();
        std::fs::write(
            dir.join("good.yaml"),
            VALID_RULE_YAML.replace("audit/cors-wildcard", "audit/other-rule"),
        )
        .unwrap();

        let (rules, errors) = load_user_pack(&dir);
        assert_eq!(rules.len(), 1);
        assert_eq!(errors.len(), 1);
        assert!(matches!(errors[0], RuleLoadError::QueryCompile { .. }));
    }

    /// WR-02: an invalid `path_glob` entry is a typed `BadGlob` load error,
    /// not a silently-accepted rule that matches nothing at scan time.
    #[test]
    fn invalid_path_glob_is_a_bad_glob_load_error() {
        let yaml = VALID_RULE_YAML.replace(
            "languages: [javascript]",
            "languages: [javascript]\npath_glob: [\"src/**/*.{ts\"]",
        );
        let rule = load_rule(&yaml, "test").unwrap();
        let mut cache = QueryCache::new();
        let err = compile_rule(&mut cache, &rule, "test").unwrap_err();
        assert!(
            matches!(err, RuleLoadError::BadGlob { .. }),
            "expected BadGlob, got {err:?}"
        );
    }

    /// WR-02: a bad `path_glob` in a `--rules` file is collected per-file
    /// (never fatal to the pack), just like a bad AST query.
    #[test]
    fn user_pack_bad_path_glob_is_collected_not_fatal() {
        let dir = tempdir();
        let bad = VALID_RULE_YAML.replace(
            "languages: [javascript]",
            "languages: [javascript]\npath_glob: [\"[\"]",
        );
        std::fs::write(dir.join("bad.yaml"), bad).unwrap();
        std::fs::write(
            dir.join("good.yaml"),
            VALID_RULE_YAML.replace("audit/cors-wildcard", "audit/other-rule"),
        )
        .unwrap();

        let (rules, errors) = load_user_pack(&dir);
        assert_eq!(rules.len(), 1);
        assert_eq!(errors.len(), 1);
        assert!(matches!(errors[0], RuleLoadError::BadGlob { .. }));
    }

    /// WR-02: the shipped embedded pack (which uses `path_glob`, e.g.
    /// missing-auth-middleware) still loads clean under the new validation.
    #[test]
    fn embedded_pack_path_globs_all_compile() {
        let _pack = load_embedded().unwrap();
    }

    #[test]
    fn merge_user_rule_overrides_embedded_rule_of_same_id() {
        let embedded_rule = load_rule(VALID_RULE_YAML, "embedded").unwrap();
        let mut embedded_pack = RulePack::new();
        compile_rule(&mut embedded_pack.query_cache, &embedded_rule, "embedded").unwrap();
        embedded_pack.rules.push(embedded_rule);

        let user_rule = load_rule(
            &VALID_RULE_YAML.replace("severity: high", "severity: critical"),
            "user",
        )
        .unwrap();

        let (merged, warnings) = merge(embedded_pack, vec![user_rule]);
        assert_eq!(merged.rules.len(), 1);
        assert_eq!(merged.rules[0].severity, Severity::Critical);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn merge_new_user_rule_is_added_without_warning() {
        let embedded_pack = RulePack::new();
        let user_rule = load_rule(VALID_RULE_YAML, "user").unwrap();
        let (merged, warnings) = merge(embedded_pack, vec![user_rule]);
        assert_eq!(merged.rules.len(), 1);
        assert!(warnings.is_empty());
    }

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-rules-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
