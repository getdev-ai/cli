//! `review/dead-code-introduced` detector — newly introduced named
//! declarations with zero references anywhere in the tree.
//!
//! ## Algorithm (06-RESEARCH.md Pitfall 5 — the phase's highest-FP-risk rule)
//! This is ZERO-REFERENCE detection, NOT reachability / call-graph analysis
//! (Anti-Pattern — a real call graph is out of scope for v0.1 determinism and
//! blows the <2s budget). Once across all [`ReviewFile`]s a whole-project
//! REFERENCE INDEX is built: every identifier token's occurrence count, plus
//! every string literal's text. For each INTRODUCED named declaration
//! (`super::is_introduced_declaration` containment — the WHOLE declaration is
//! inside the added ranges), the rule fires only when the symbol name has zero
//! references outside its own definition site.
//!
//! ## False-positive guards (Pitfall 5, all LOCKED — FP < 10% is the harder gate)
//!  - the reference search WIDENS to plain string-literal occurrences of the
//!    name (catches route-registration-by-name / dynamic dispatch);
//!  - decorator-registered handlers (a `decorated_definition` ancestor, or a
//!    `decorator` child) are exempt — the framework calls them, not source;
//!  - framework entry-point path conventions (`pages/**`, Next.js app-router
//!    `page`/`layout`/`route`, Django `urls.py`/`views.py`) are exempt;
//!  - test files are exempt (a helper used only by tests is not debris).
//!
//! Confidence is `medium` (never `high`, given reference-search limits) and
//! every finding carries a caveat `detail` naming the heuristic (SPEC-RULES).
//!
//! This file is the ONLY thing 06-03 rewrites for this rule; `review/mod.rs`
//! is never touched (Wave 3 stays parallel with 06-04).

use std::collections::HashMap;

use getdev_grammars::tree_sitter::{Node, Query, QueryCursor};
use globset::{Glob, GlobSet, GlobSetBuilder};
use streaming_iterator::StreamingIterator;

use super::{is_introduced_declaration, ReviewFile};
use crate::findings::{Confidence, Finding, Severity};
use crate::scan::Lang;

/// Framework-entry-point and test-file path conventions whose declarations are
/// exempt from dead-code detection (Pitfall 5(b), LOCKED). A file matching any
/// of these is skipped whole — its exports are framework-router / test
/// consumed, not textually referenced.
const EXEMPT_PATH_GLOBS: &[&str] = &[
    // Next.js file-based routers (both `pages/` and `app/`).
    "pages/**",
    "**/pages/**",
    "app/**/page.*",
    "app/**/layout.*",
    "app/**/route.*",
    "**/app/**/page.*",
    "**/app/**/layout.*",
    "**/app/**/route.*",
    // Django URL/view registration modules.
    "urls.py",
    "views.py",
    "**/urls.py",
    "**/views.py",
    // Test files — a helper used only by tests is not debris.
    "**/*.test.*",
    "**/*.spec.*",
    "*.test.*",
    "*.spec.*",
    "**/tests/**",
    "**/test_*.py",
    "**/*_test.py",
];

/// Detect introduced dead code — introduced named declarations with zero
/// textual references anywhere in the project.
pub(crate) fn detect(files: &[ReviewFile]) -> Vec<Finding> {
    let index = ReferenceIndex::build(files);
    let exemptions = compile_exemptions();

    // Compile the declaration query once per language, not once per file (the
    // per-file recompile was an O(files) cost inside the `< 2 s` perf budget).
    let mut query_cache: Vec<(Lang, Query)> = Vec::new();

    let mut findings = Vec::new();
    for file in files {
        // FP guard: framework-entry / test files are exempt whole.
        if path_is_exempt(exemptions.as_ref(), &file.rel) {
            continue;
        }
        if !query_cache.iter().any(|(l, _)| *l == file.lang) {
            let Ok(q) = Query::new(&file.lang.language(), declaration_query(file.lang)) else {
                continue;
            };
            query_cache.push((file.lang, q));
        }
        let Some(query) = query_cache
            .iter()
            .find(|(l, _)| *l == file.lang)
            .map(|(_, q)| q)
        else {
            continue;
        };
        let bytes = file.source.as_bytes();
        for decl in named_declarations(query, file.tree.root_node(), bytes) {
            let span = (decl.start_line, decl.end_line);
            if !is_introduced_declaration(span, &file.added_ranges) {
                continue;
            }
            // FP guard: decorator-registered handlers.
            if has_decorator(decl.node) {
                continue;
            }
            if index.is_referenced(&decl.name) {
                continue;
            }
            findings.push(deadcode_finding(&file.rel, &decl));
        }
    }

    findings
}

/// Whole-project reference index: identifier occurrence counts plus the raw
/// text of every string literal (widened reference search, Pitfall 5(a)).
///
/// String literals are accumulated into a SINGLE newline-joined blob rather
/// than a `Vec<String>`: the widened check is a substring search, and doing it
/// per-declaration over a `Vec` is `O(declarations × string-literals)` — a
/// quadratic blow-up that is invisible on a small diff but dominates
/// `ReviewScope::All` on a large repo (every declaration is "introduced", so
/// every one runs the string scan). Joining once turns each declaration's
/// widened check into a single `str::contains` over the blob (memchr-optimized
/// first-byte scan), keeping `review --all` inside the `< 2 s` perf budget
/// (docs/PLAN.md §3.5). The separator is `\n`, which can never appear inside an
/// identifier name, so no name can spuriously match across two adjacent
/// literals' boundary — the substring semantics of the original per-literal
/// check are preserved exactly.
struct ReferenceIndex {
    ident_counts: HashMap<String, usize>,
    string_blob: String,
}

impl ReferenceIndex {
    fn build(files: &[ReviewFile]) -> Self {
        let mut index = Self {
            ident_counts: HashMap::new(),
            string_blob: String::new(),
        };
        for file in files {
            collect_references(file.tree.root_node(), file.source.as_bytes(), &mut index);
        }
        index
    }

    /// A name is "referenced" when it appears as an identifier anywhere OTHER
    /// than its single defining occurrence, OR its text occurs inside any
    /// string literal (route-registration-by-name / dynamic dispatch).
    fn is_referenced(&self, name: &str) -> bool {
        // Subtract the one defining occurrence of the declaration's own name.
        let external = self
            .ident_counts
            .get(name)
            .copied()
            .unwrap_or(0)
            .saturating_sub(1);
        if external > 0 {
            return true;
        }
        self.string_blob.contains(name)
    }
}

/// Walk a whole tree, accumulating identifier occurrence counts and string
/// literal texts into `index`.
fn collect_references(node: Node<'_>, bytes: &[u8], index: &mut ReferenceIndex) {
    let kind = node.kind();
    match kind {
        "identifier"
        | "property_identifier"
        | "shorthand_property_identifier"
        | "shorthand_property_identifier_pattern"
        | "type_identifier" => {
            if let Ok(text) = node.utf8_text(bytes) {
                *index.ident_counts.entry(text.to_owned()).or_default() += 1;
            }
            return;
        }
        "string" => {
            if let Ok(text) = node.utf8_text(bytes) {
                index.string_blob.push_str(text);
                index.string_blob.push('\n');
            }
            return;
        }
        // A template string is BOTH a string blob (its literal parts) AND may
        // interpolate identifier references (`${handler()}`) — record its text
        // and still descend so interpolated references are counted.
        "template_string" => {
            if let Ok(text) = node.utf8_text(bytes) {
                index.string_blob.push_str(text);
                index.string_blob.push('\n');
            }
        }
        _ => {}
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_references(child, bytes, index);
        }
    }
}

/// One introduced named declaration candidate.
struct Declaration<'tree> {
    name: String,
    node: Node<'tree>,
    line: u32,
    column: u32,
    start_line: u32,
    end_line: u32,
}

/// Query for named declarations whose zero-reference-ness is meaningful:
/// functions, classes, and top-level names bound to a function value.
fn declaration_query(lang: Lang) -> &'static str {
    match lang {
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => {
            "(function_declaration name: (identifier) @name) @decl\n\
             (class_declaration name: (_) @name) @decl\n\
             (variable_declarator name: (identifier) @name value: (arrow_function)) @decl\n\
             (variable_declarator name: (identifier) @name value: (function_expression)) @decl"
        }
        Lang::Python => {
            "(function_definition name: (identifier) @name) @decl\n\
             (class_definition name: (identifier) @name) @decl"
        }
    }
}

/// Run the declaration query, returning each `(name, decl-span)` pair.
fn named_declarations<'tree>(
    query: &Query,
    root: Node<'tree>,
    bytes: &[u8],
) -> Vec<Declaration<'tree>> {
    let name_idx = query.capture_index_for_name("name");
    let decl_idx = query.capture_index_for_name("decl");
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(query, root, bytes);
    let mut out = Vec::new();
    while let Some(m) = matches.next() {
        let mut name_node = None;
        let mut decl_node = None;
        for capture in m.captures {
            if Some(capture.index) == name_idx {
                name_node = Some(capture.node);
            } else if Some(capture.index) == decl_idx {
                decl_node = Some(capture.node);
            }
        }
        let (Some(name_node), Some(decl_node)) = (name_node, decl_node) else {
            continue;
        };
        let Ok(name) = name_node.utf8_text(bytes) else {
            continue;
        };
        let name_pos = name_node.start_position();
        let decl_start = decl_node.start_position();
        let decl_end = decl_node.end_position();
        out.push(Declaration {
            name: name.to_owned(),
            node: decl_node,
            line: u32::try_from(name_pos.row)
                .unwrap_or(u32::MAX)
                .saturating_add(1),
            column: u32::try_from(name_pos.column)
                .unwrap_or(u32::MAX)
                .saturating_add(1),
            start_line: u32::try_from(decl_start.row)
                .unwrap_or(u32::MAX)
                .saturating_add(1),
            end_line: u32::try_from(decl_end.row)
                .unwrap_or(u32::MAX)
                .saturating_add(1),
        });
    }
    out
}

/// True when `node` is decorator-registered — either it has a
/// `decorated_definition` ancestor (Python) or a direct `decorator` child
/// (JS/TS class/method decorators). Decorated symbols are framework-registered,
/// not called by name (Pitfall 5(b)).
fn has_decorator(node: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(n) = current {
        if n.kind() == "decorated_definition" {
            return true;
        }
        current = n.parent();
    }
    for i in 0..node.child_count() {
        if node.child(i).is_some_and(|c| c.kind() == "decorator") {
            return true;
        }
    }
    false
}

/// Compile the [`EXEMPT_PATH_GLOBS`] set once per invocation, mirroring
/// `audit`'s `path_glob` compilation. A malformed pattern is skipped rather
/// than aborting (defensive — CLAUDE.md rule 1).
fn compile_exemptions() -> Option<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in EXEMPT_PATH_GLOBS {
        if let Ok(glob) = Glob::new(pattern) {
            builder.add(glob);
        }
    }
    builder.build().ok()
}

fn path_is_exempt(globs: Option<&GlobSet>, rel: &str) -> bool {
    globs.is_some_and(|set| set.is_match(rel))
}

/// Build the `review/dead-code-introduced` finding with the mandatory caveat
/// `detail` (SPEC-RULES heuristic-detail requirement — confidence != high).
fn deadcode_finding(rel: &str, decl: &Declaration<'_>) -> Finding {
    Finding {
        id: "review/dead-code-introduced".to_owned(),
        command: "review".to_owned(),
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        file: rel.to_owned(),
        line: Some(decl.line),
        column: Some(decl.column),
        end_line: Some(decl.end_line),
        message: format!(
            "Introduced '{}' has no references in the project",
            decl.name
        ),
        detail: Some(
            "no textual reference found; may be a new public API or framework entry point \
             (zero-reference heuristic, not call-graph analysis; confidence: medium)"
                .to_owned(),
        ),
        suggestion: None,
        remediation: Some(
            "remove the unused declaration, or reference/export it if it is a new public API"
                .to_owned(),
        ),
        fixable: false,
        refs: vec!["https://getdev.ai/rules/review/dead-code-introduced".to_owned()],
        fingerprint: None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use getdev_grammars::tree_sitter::Parser;

    fn review_file(
        rel: &str,
        lang: Lang,
        source: &str,
        added_ranges: Vec<(u32, u32)>,
        is_new_file: bool,
    ) -> ReviewFile {
        let mut parser = Parser::new();
        parser.set_language(&lang.language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        ReviewFile {
            rel: rel.to_owned(),
            lang,
            source: source.to_owned(),
            tree,
            added_ranges,
            is_new_file,
        }
    }

    #[test]
    fn introduced_unreferenced_function_fires() {
        let src = "function unusedHelper() {\n  return 1;\n}\n";
        let file = review_file("src/util.js", Lang::JavaScript, src, vec![(1, 3)], true);
        let findings = detect(&[file]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "review/dead-code-introduced");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].confidence, Confidence::Medium);
        assert!(
            findings[0].detail.as_ref().is_some_and(|d| !d.is_empty()),
            "must carry a non-empty caveat detail"
        );
    }

    #[test]
    fn reference_by_name_in_a_string_literal_is_not_dead() {
        // The function is introduced but its NAME appears in a string literal
        // elsewhere (route-registration-by-name) — the widened reference
        // search (Pitfall 5(a)) must suppress the finding.
        let src = "function unusedHelper() {\n  return 1;\n}\n\
                   const routes = { path: \"unusedHelper\" };\n";
        let file = review_file("src/util.js", Lang::JavaScript, src, vec![(1, 3)], true);
        assert!(
            detect(&[file]).is_empty(),
            "a string-literal occurrence of the name must count as a reference"
        );
    }

    #[test]
    fn python_decorator_registered_handler_is_exempt() {
        let src = "@app.route(\"/x\")\ndef handler():\n    return 1\n";
        let file = review_file("service.py", Lang::Python, src, vec![(1, 3)], true);
        assert!(
            detect(&[file]).is_empty(),
            "a decorator-registered handler must be exempt"
        );
    }

    #[test]
    fn framework_entry_point_file_is_exempt() {
        let src = "function Page() {\n  return 1;\n}\n";
        let file = review_file("pages/index.js", Lang::JavaScript, src, vec![(1, 3)], true);
        assert!(
            detect(&[file]).is_empty(),
            "a declaration under pages/ must be exempt (framework entry point)"
        );
    }

    #[test]
    fn pre_existing_unreferenced_function_is_gated_out() {
        // Same unreferenced function, but its span is NOT inside any added
        // range — the introduced-gate must suppress it.
        let src = "function unusedHelper() {\n  return 1;\n}\n";
        let file = review_file("src/util.js", Lang::JavaScript, src, vec![], false);
        assert!(
            detect(&[file]).is_empty(),
            "a pre-existing (non-introduced) function must produce zero findings"
        );
    }
}
