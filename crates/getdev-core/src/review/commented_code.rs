//! `review/commented-code-block` detector — an INTRODUCED comment run of >=3
//! lines whose stripped body re-parses as CODE (zero ERROR/MISSING nodes AND
//! at least one "code-shaped" node kind), excluding JSDoc and license headers.
//!
//! ## Algorithm (06-RESEARCH.md Pitfall 4 — the phase's second-highest FP-risk rule)
//! For each already-parsed [`ReviewFile`] we walk its `(comment)` nodes,
//! coalesce ADJACENT line comments (and each block comment) into a comment
//! RUN, then apply — in order — the cheap gates before the expensive re-parse:
//!  1. min-length: the run must span >= 3 source lines;
//!  2. introduced-scope OVERLAP (`super::is_introduced_line`): at least one of
//!     the run's lines is inside an added range (a commented-out block is
//!     either newly added or it isn't a candidate — Pattern 2 line policy);
//!  3. JSDoc exemption: a `/**`-prefixed block is documentation, never code;
//!  4. license-header guard: a run within the first ~20 lines containing
//!     case-insensitive `copyright`/`license`/`spdx` is a header, not debris.
//!
//! ## "Parses as code" discriminator (Pitfall 4 / A4, LOCKED — BOTH required)
//! tree-sitter's error recovery is permissive enough that short prose can
//! parse with zero ERROR nodes, so "no ERROR nodes" ALONE is not sufficient.
//! The run's markers are stripped, the recovered text is CAPPED at
//! [`MAX_SCAN_FILE_BYTES`] (an enormous comment block is a DoS surface exactly
//! like a whole-file read — T-06-11), then RE-PARSED with the file's own
//! grammar. This is a fresh parse of a DIFFERENT input (the stripped comment
//! text), not a second parse of the file — CLAUDE.md rule 5 (never re-parse
//! the same file) is honored. The finding fires only when the snippet has ZERO
//! ERROR and ZERO MISSING nodes AND contains >= 1 code-shaped node kind
//! (call/assignment/if/for/while/function/class/import/export) — a shape plain
//! prose essentially never produces, which is what keeps FP < 10%.
//!
//! This file is the ONLY thing 06-04 rewrites for this rule; `review/mod.rs`
//! is never touched (Wave 3 stays parallel with 06-03).

use getdev_grammars::tree_sitter::{Node, Parser};

use super::{is_introduced_line, ReviewFile};
use crate::findings::{Confidence, Finding, Severity};
use crate::scan::{Lang, MAX_SCAN_FILE_BYTES};

/// Node kinds that mark a re-parsed snippet as "code-shaped" across the JS/TS
/// and Python grammars (Pitfall 4 / A4). Presence of ANY of these (with zero
/// ERROR/MISSING nodes) is the second half of the LOCKED discriminator; plain
/// prose essentially never yields one.
const CODE_SHAPED_KINDS: &[&str] = &[
    // calls
    "call_expression",
    "call",
    // assignments / bindings
    "assignment_expression",
    "variable_declarator",
    "assignment",
    // control flow
    "if_statement",
    "for_statement",
    "while_statement",
    // definitions
    "function_declaration",
    "function_definition",
    "class_declaration",
    "class_definition",
    // module boundaries
    "import_statement",
    "export_statement",
    "import_from_statement",
];

/// Minimum number of source lines a comment run must span to be a candidate
/// (spec: ">=3 lines parsing as code").
const MIN_RUN_LINES: usize = 3;

/// A license-header guard only applies to runs starting within this many
/// leading lines of the file (0-based row).
const LICENSE_HEADER_MAX_ROW: usize = 20;

/// Detect introduced commented-out code blocks. Fires on an introduced
/// comment run of three or more lines whose stripped body re-parses as code;
/// stays quiet on prose, JSDoc, license headers, short runs, and pre-existing
/// runs.
pub(crate) fn detect(files: &[ReviewFile]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in files {
        let comments = collect_comments(file);
        for run in coalesce_runs(&comments) {
            if let Some(finding) = evaluate_run(file, &run) {
                findings.push(finding);
            }
        }
    }
    findings
}

/// One `(comment)` node reduced to what the detector needs.
struct Comment {
    /// 0-based first row.
    start_row: usize,
    /// 0-based last row (a line comment's start == end; a block spans rows).
    end_row: usize,
    /// `/* ... */` (JS) vs `//`/`#` line comment.
    is_block: bool,
    /// The raw comment text, markers included.
    text: String,
}

/// A coalesced comment RUN — the candidate unit.
struct Run {
    /// 0-based first row of the run.
    first_row: usize,
    /// 0-based last row of the run.
    last_row: usize,
    /// `true` when the run is a single `/**`-prefixed JSDoc block.
    is_jsdoc: bool,
    /// Marker-stripped inner text, ready to re-parse.
    stripped: String,
    /// Lowercased raw text, for the license-header scan.
    raw_lower: String,
}

/// Walk the already-parsed tree, collecting every `(comment)` node in source
/// order (then sorted defensively by start row so coalescing is robust to any
/// visitation quirk).
fn collect_comments(file: &ReviewFile) -> Vec<Comment> {
    let bytes = file.source.as_bytes();
    let mut out = Vec::new();
    walk_comments(file.tree.root_node(), bytes, &mut out);
    out.sort_by_key(|c| c.start_row);
    out
}

fn walk_comments(node: Node<'_>, bytes: &[u8], out: &mut Vec<Comment>) {
    if node.kind() == "comment" {
        if let Ok(text) = node.utf8_text(bytes) {
            let start = node.start_position();
            let end = node.end_position();
            out.push(Comment {
                start_row: start.row,
                end_row: end.row,
                is_block: text.trim_start().starts_with("/*"),
                text: text.to_owned(),
            });
        }
        return;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            walk_comments(child, bytes, out);
        }
    }
}

/// Group comments into runs: consecutive line comments on adjacent rows
/// coalesce; each block comment is its own run and never merges with a
/// neighbor.
fn coalesce_runs(comments: &[Comment]) -> Vec<Run> {
    let mut runs = Vec::new();
    let mut i = 0;
    while i < comments.len() {
        if comments[i].is_block {
            runs.push(run_from_block(&comments[i]));
            i += 1;
            continue;
        }
        let start = i;
        let mut end = i;
        while end + 1 < comments.len()
            && !comments[end + 1].is_block
            && comments[end + 1].start_row == comments[end].end_row + 1
        {
            end += 1;
        }
        runs.push(run_from_line_comments(&comments[start..=end]));
        i = end + 1;
    }
    runs
}

fn run_from_block(comment: &Comment) -> Run {
    Run {
        first_row: comment.start_row,
        last_row: comment.end_row,
        is_jsdoc: comment.text.trim_start().starts_with("/**"),
        stripped: strip_block(&comment.text),
        raw_lower: comment.text.to_lowercase(),
    }
}

fn run_from_line_comments(comments: &[Comment]) -> Run {
    let first_row = comments.first().map_or(0, |c| c.start_row);
    let last_row = comments.last().map_or(first_row, |c| c.end_row);
    let stripped = comments
        .iter()
        .map(|c| strip_line(&c.text))
        .collect::<Vec<_>>()
        .join("\n");
    let raw_lower = comments
        .iter()
        .map(|c| c.text.as_str())
        .collect::<String>()
        .to_lowercase();
    Run {
        first_row,
        last_row,
        is_jsdoc: false,
        stripped,
        raw_lower,
    }
}

/// Strip a single line comment's leading `//` or `#` marker, preserving the
/// code's own inner indentation so the re-parse sees valid nesting.
fn strip_line(text: &str) -> &str {
    let trimmed = text.trim_start();
    if let Some(rest) = trimmed.strip_prefix("//") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix('#') {
        rest
    } else {
        trimmed
    }
}

/// Strip a block comment's `/* ... */` fence, then drop each inner line's
/// leading `*` continuation marker (common in wrapped block comments).
fn strip_block(text: &str) -> String {
    let inner = text.trim();
    let inner = inner.strip_prefix("/*").unwrap_or(inner);
    let inner = inner.strip_suffix("*/").unwrap_or(inner);
    inner
        .lines()
        .map(|line| {
            let line = line.trim_start();
            line.strip_prefix('*').unwrap_or(line)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Apply every gate to a run and emit a finding when it is introduced,
/// long enough, not JSDoc/license, and re-parses as code.
fn evaluate_run(file: &ReviewFile, run: &Run) -> Option<Finding> {
    if run.last_row.saturating_sub(run.first_row) + 1 < MIN_RUN_LINES {
        return None;
    }
    let first_line = u32::try_from(run.first_row)
        .unwrap_or(u32::MAX)
        .saturating_add(1);
    let last_line = u32::try_from(run.last_row)
        .unwrap_or(u32::MAX)
        .saturating_add(1);
    if !(first_line..=last_line).any(|line| is_introduced_line(line, &file.added_ranges)) {
        return None;
    }
    if run.is_jsdoc {
        return None;
    }
    if run.first_row < LICENSE_HEADER_MAX_ROW && contains_license_marker(&run.raw_lower) {
        return None;
    }
    if !parses_as_code(file.lang, &run.stripped) {
        return None;
    }
    Some(commented_code_finding(&file.rel, first_line, &run.stripped))
}

/// Case-insensitive license-header sentinel scan (input is already lowercased).
fn contains_license_marker(raw_lower: &str) -> bool {
    raw_lower.contains("copyright") || raw_lower.contains("license") || raw_lower.contains("spdx")
}

/// The LOCKED discriminator: cap the stripped text at [`MAX_SCAN_FILE_BYTES`]
/// (never re-parse an unbounded substring — T-06-11), re-parse with `lang`'s
/// grammar, and require BOTH zero ERROR/MISSING nodes AND >= 1 code-shaped
/// node kind. A failed re-parse yields `false` (treated as "not code"), never
/// a panic (T-06-13).
fn parses_as_code(lang: Lang, snippet: &str) -> bool {
    // Size cap applied to the stripped comment text BEFORE `parser.parse`
    // (F7 discipline extended to substrings — Anti-Pattern: never re-parse an
    // unbounded string just because it is not a full-file read).
    if snippet.len() as u64 > MAX_SCAN_FILE_BYTES {
        return false;
    }
    let mut parser = Parser::new();
    if parser.set_language(&lang.language()).is_err() {
        return false;
    }
    let Some(tree) = parser.parse(snippet, None) else {
        return false;
    };
    let mut clean = true;
    let mut code_shaped = false;
    inspect_snippet(tree.root_node(), &mut clean, &mut code_shaped);
    clean && code_shaped
}

/// Recursively check a re-parsed snippet for ERROR/MISSING nodes and the
/// presence of any code-shaped node kind.
fn inspect_snippet(node: Node<'_>, clean: &mut bool, code_shaped: &mut bool) {
    if node.is_error() || node.is_missing() {
        *clean = false;
    }
    if CODE_SHAPED_KINDS.contains(&node.kind()) {
        *code_shaped = true;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            inspect_snippet(child, clean, code_shaped);
        }
    }
}

/// Build the `review/commented-code-block` finding with the mandatory caveat
/// `detail` (SPEC-RULES heuristic-detail requirement — confidence != high).
fn commented_code_finding(rel: &str, line: u32, matched_text: &str) -> Finding {
    Finding {
        id: "review/commented-code-block".to_owned(),
        command: "review".to_owned(),
        severity: Severity::Low,
        confidence: Confidence::Medium,
        file: rel.to_owned(),
        line: Some(line),
        column: None,
        end_line: None,
        message: "Introduced comment block re-parses as commented-out code".to_owned(),
        detail: Some(
            "a >=3-line comment run parses as code (zero parse errors and a code-shaped node), \
             not prose/JSDoc/license; likely leftover commented-out code \
             (heuristic; confidence: medium)"
                .to_owned(),
        ),
        suggestion: None,
        remediation: Some(
            "delete the commented-out code, or restore it if it is still needed".to_owned(),
        ),
        fixable: false,
        refs: vec!["https://getdev.ai/rules/review/commented-code-block".to_owned()],
        // D-01 (Shape 2, coalesced multi-comment run — no single tree-sitter
        // node): anchor on a synthetic `comment_run` kind + the already-
        // computed marker-stripped run text; the batch pass normalizes it.
        seed: crate::fingerprint::FingerprintSeed {
            node_kind: "comment_run",
            matched_text: matched_text.to_owned(),
        },
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
            is_new_file: true,
        }
    }

    #[test]
    fn introduced_commented_out_code_block_fires() {
        // Three adjacent `//` lines that reconstruct a valid `if` + call.
        let src = "// if (x) {\n//   doThing();\n// }\n";
        let file = review_file("src/app.js", Lang::JavaScript, src, vec![(1, 3)]);
        let findings = detect(&[file]);
        assert_eq!(findings.len(), 1, "commented-out code block must fire");
        assert_eq!(findings[0].id, "review/commented-code-block");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].confidence, Confidence::Medium);
        assert_eq!(findings[0].line, Some(1));
        assert!(
            findings[0].detail.as_ref().is_some_and(|d| !d.is_empty()),
            "must carry a non-empty caveat detail"
        );
    }

    #[test]
    fn introduced_prose_comment_does_not_fire() {
        // Ordinary explanatory prose: zero code-shaped nodes (and parse errors)
        // — the dual discriminator must suppress it.
        let src = "// this fixes the thing\n// because reasons here\n// see the ticket\n";
        let file = review_file("src/app.js", Lang::JavaScript, src, vec![(1, 3)]);
        assert!(
            detect(&[file]).is_empty(),
            "prose comments must not be flagged as commented-out code"
        );
    }

    #[test]
    fn jsdoc_block_with_code_like_text_is_exempt() {
        // A `/**` block whose body reads like code must still be exempt
        // (documentation, not commented-out code).
        let src = "/**\n * const x = doThing();\n * if (y) { run(); }\n */\nfunction f() {}\n";
        let file = review_file("src/app.js", Lang::JavaScript, src, vec![(1, 4)]);
        assert!(
            detect(&[file]).is_empty(),
            "a /** JSDoc block must be exempt even when its text parses as code"
        );
    }

    #[test]
    fn license_header_is_exempt() {
        // Constructed to PARSE AS CODE (assignment + call) so this asserts the
        // license guard fires BEFORE the re-parse — a real header would also be
        // suppressed by the code-shaped check, which would not isolate the guard.
        let src = "// const license = readLicense();\n// applyLicense(license);\n// done();\n";
        let file = review_file("src/app.js", Lang::JavaScript, src, vec![(1, 3)]);
        assert!(
            detect(&[file]).is_empty(),
            "a license-word header in the first lines must be exempt even if it parses as code"
        );
    }

    #[test]
    fn commented_code_outside_added_ranges_is_gated_out() {
        // Same code-shaped run as the positive case, but no line is introduced.
        let src = "// if (x) {\n//   doThing();\n// }\n";
        let file = review_file("src/app.js", Lang::JavaScript, src, vec![]);
        assert!(
            detect(&[file]).is_empty(),
            "a pre-existing commented-out block must produce zero findings"
        );
    }

    #[test]
    fn two_line_commented_block_is_below_min() {
        let src = "// doThing();\n// run();\n";
        let file = review_file("src/app.js", Lang::JavaScript, src, vec![(1, 2)]);
        assert!(
            detect(&[file]).is_empty(),
            "a 2-line run is below the >=3-line minimum"
        );
    }

    #[test]
    fn python_commented_out_code_block_fires() {
        // Cross-language coverage: three `#` lines reconstructing a Python `if`.
        let src = "# if x:\n#     do_thing()\n# else:\n#     run()\n";
        let file = review_file("svc.py", Lang::Python, src, vec![(1, 4)]);
        let findings = detect(&[file]);
        assert_eq!(findings.len(), 1, "python commented-out code must fire");
        assert_eq!(findings[0].id, "review/commented-code-block");
    }
}
