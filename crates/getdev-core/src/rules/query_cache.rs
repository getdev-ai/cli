//! Compiled `tree_sitter::Query` cache, keyed by `(Lang, rule_id)` — each
//! rule's query compiles exactly ONCE per invocation regardless of how many
//! files of that language the audit run scans (docs/PLAN.md §3.5 perf
//! budget; 04-RESEARCH.md Architecture Pattern 1).
//!
//! Query predicate evaluation (`#eq?`/`#match?`/`#any-of?`/etc.) is handled
//! automatically by the vendored `tree-sitter` Rust binding inside
//! `QueryCursor::matches()` — this module writes NO custom predicate
//! evaluator. It only rejects, at compile time, any predicate name outside
//! the auto-evaluated set (04-RESEARCH.md Pattern 2) so an unrecognized
//! predicate is a clean load error, never a silently-unconditional match.

use std::collections::HashMap;

use getdev_grammars::tree_sitter::Query;

use crate::scan::Lang;

use super::RuleLoadError;

/// The exhaustive set of tree-sitter predicate names the Rust binding
/// auto-evaluates inside `QueryCursor::matches()` (verified against the
/// vendored `tree-sitter-0.25.10` binding source — see docs/SPEC-RULES.md
/// "Predicate support"). Names here are the raw operator text as the
/// binding parses it: WITHOUT the leading `#`, WITH the trailing `?`.
const AUTO_EVALUATED_PREDICATES: &[&str] = &[
    "eq?",
    "not-eq?",
    "any-eq?",
    "any-not-eq?",
    "match?",
    "not-match?",
    "any-match?",
    "any-not-match?",
    "is?",
    "is-not?",
    "any-of?",
    "not-any-of?",
];

/// `HashMap<(Lang, rule_id), Query>` — one compiled query per `(language,
/// rule)` pair, reused across every file of that language.
#[derive(Default)]
pub struct QueryCache {
    queries: HashMap<(Lang, String), Query>,
}

impl QueryCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compile `query_src` for `lang` under `rule_id` and insert it into the
    /// cache if not already present (requesting the same key twice never
    /// recompiles). Rejects the query if it uses any predicate outside
    /// [`AUTO_EVALUATED_PREDICATES`] — checked AFTER compiling (so the
    /// specific unsupported name can be reported) and BEFORE inserting into
    /// the cache, so an unrecognized predicate is never cached as if it
    /// were valid.
    pub fn compile(
        &mut self,
        lang: Lang,
        rule_id: &str,
        origin: &str,
        query_src: &str,
    ) -> Result<(), RuleLoadError> {
        let key = (lang, rule_id.to_owned());
        if self.queries.contains_key(&key) {
            return Ok(());
        }

        let query = Query::new(&lang.language(), query_src).map_err(|source| {
            RuleLoadError::QueryCompile {
                origin: origin.to_owned(),
                rule_id: rule_id.to_owned(),
                lang: lang.to_string(),
                source: Box::new(source),
            }
        })?;

        let mut unsupported: Vec<String> = Vec::new();
        for pattern_index in 0..query.pattern_count() {
            for predicate in query.general_predicates(pattern_index) {
                let name = predicate.operator.as_ref();
                if !AUTO_EVALUATED_PREDICATES.contains(&name) {
                    unsupported.push(format!("#{name}"));
                }
            }
        }
        if !unsupported.is_empty() {
            unsupported.sort();
            unsupported.dedup();
            return Err(RuleLoadError::UnsupportedPredicate {
                origin: origin.to_owned(),
                rule_id: rule_id.to_owned(),
                names: unsupported.join(", "),
            });
        }

        self.queries.insert(key, query);
        Ok(())
    }

    /// The compiled query for `(lang, rule_id)`, if it has been compiled.
    #[must_use]
    pub fn get(&self, lang: Lang, rule_id: &str) -> Option<&Query> {
        self.queries.get(&(lang, rule_id.to_owned()))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.queries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const VALID_QUERY: &str =
        "(call_expression function: (identifier) @fn (#eq? @fn \"cors\")) @call";

    #[test]
    fn compiles_and_caches_one_query_per_lang_rule_pair() {
        let mut cache = QueryCache::new();
        cache
            .compile(Lang::JavaScript, "audit/cors-wildcard", "test", VALID_QUERY)
            .unwrap();
        assert_eq!(cache.len(), 1);
        assert!(cache.get(Lang::JavaScript, "audit/cors-wildcard").is_some());

        // requesting the same key again does not insert a second entry
        cache
            .compile(Lang::JavaScript, "audit/cors-wildcard", "test", VALID_QUERY)
            .unwrap();
        assert_eq!(cache.len(), 1);
    }

    /// Task 2 behavior: `#matches?` (a typo — not `#match?`) is not in the
    /// auto-evaluated set and must be rejected, naming the predicate.
    #[test]
    fn unrecognized_predicate_is_rejected() {
        let mut cache = QueryCache::new();
        let query = "(call_expression function: (identifier) @fn (#matches? @fn \"x\")) @call";
        let err = cache
            .compile(Lang::JavaScript, "audit/bad", "test", query)
            .unwrap_err();
        let RuleLoadError::UnsupportedPredicate { names, .. } = &err else {
            panic!("expected UnsupportedPredicate, got {err:?}");
        };
        assert!(names.contains("matches?"), "names was: {names}");
        assert_eq!(cache.len(), 0, "a rejected query must never be cached");
    }

    /// Task 2 behavior: a syntactically invalid query is a clean
    /// `QueryCompile` error, never a panic.
    #[test]
    fn malformed_query_is_a_clean_error_not_a_panic() {
        let mut cache = QueryCache::new();
        let err = cache
            .compile(Lang::JavaScript, "audit/bad", "test", "(call_expression")
            .unwrap_err();
        assert!(matches!(err, RuleLoadError::QueryCompile { .. }));
    }
}
