//! `core::review` — the read-only analyzer that turns a set of changed
//! files (working-tree diff, from `getdev-gitx::diff`) into `Vec<Finding>`,
//! scoping every rule to *introduced* content only.
//!
//! Mirrors `core::audit::run`'s file-outer/rule-inner shape: every candidate
//! file is parsed at most ONCE per invocation (CLAUDE.md rule 5 / Pitfall 0
//! — parse-once is honored WITHIN review's own invocation; there is no shared
//! cross-command `ScanContext` yet, that is a Phase 7 deliverable). Imports
//! NO getdev-registry type and NO network code (REQ-privacy); never mutates
//! and never touches the shared mutate engine (REQ-safe-by-default).
//!
//! ## Two consumption policies (06-RESEARCH.md Pattern 2)
//! The single hardest design problem this analyzer solves is scoping every
//! rule to introduced lines. `core::rules`/`core::audit` have no concept of
//! "only match within these line ranges"; review adds it as an analyzer-level
//! post-filter over the SAME per-file `added_ranges`, in two flavors:
//! - [`is_introduced_declaration`] — CONTAINMENT (whole node span inside an
//!   added range), for declaration-level programmatic rules.
//! - [`is_introduced_line`] — OVERLAP (a single line intersects an added
//!   range), for line-level rules (`debug-leftover`, `todo-introduced`).
//!
//! ## Architecture note — review defines its OWN input struct
//! docs/ARCHITECTURE.md fixes the crate-dependency direction: `getdev-core`
//! depends only on `getdev-grammars`, so it may NOT depend on `getdev-gitx`.
//! Review therefore defines its own [`ReviewChangedFile`] /
//! [`ReviewChangeStatus`] input types here; the CLI (06-05) maps
//! `getdev_gitx::diff::ChangedFile` -> [`ReviewChangedFile`] at the boundary
//! (the plan's stated fallback when the `core -> gitx` edge is forbidden).

mod commented_code;
mod deadcode;
mod fingerprint;
mod orphan;

use std::path::Path;

use getdev_grammars::tree_sitter::{Node, Parser, Tree};

use crate::deps::relative_display;
use crate::findings::{Confidence, Finding, Severity};
use crate::rules::{self, RuleLoadError};
use crate::scan::{project_walker, read_source_capped, Lang, ScanError};

/// How a changed file relates to the base state — review's own copy of
/// `getdev_gitx::diff::ChangeStatus` (see the module-level architecture
/// note). The CLI maps between them at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewChangeStatus {
    /// The file did not exist in the base (new / untracked file).
    Added,
    /// The file existed and its content changed.
    Modified,
    /// The file existed in the base and is gone now (no added lines).
    Deleted,
}

/// One changed file plus the 1-based inclusive line ranges it introduced —
/// review's own copy of `getdev_gitx::diff::ChangedFile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewChangedFile {
    /// Project-relative path, forward slashes.
    pub path: String,
    /// Add / modify / delete classification.
    pub status: ReviewChangeStatus,
    /// 1-based inclusive added line ranges, in file order. Empty for a
    /// deleted / binary / mode-only change.
    pub added_ranges: Vec<(u32, u32)>,
}

/// Which files to review, and what "introduced" means for them.
pub enum ReviewScope {
    /// The changed-file set from a git diff (06-01's `changed_files`, mapped
    /// to [`ReviewChangedFile`] by the CLI). Each file's `added_ranges`
    /// scope every rule to its introduced content.
    Diff(Vec<ReviewChangedFile>),
    /// Whole tree, not just the diff: every source file the walker finds is
    /// treated as fully introduced (`added_ranges = [(1, EOF)]`), no git
    /// involved (06-RESEARCH.md Pattern 3, LOCKED — the `check --all`
    /// contract Phase 7 consumes).
    All,
}

/// The severity floor applied after findings are produced. `--ignore` /
/// `--rules` are CLI-tier concerns (docs/PLAN.md §2.3); this engine only
/// knows the severity floor, mirroring `audit::AuditOptions`.
#[derive(Debug, Clone, Copy)]
pub struct ReviewOptions {
    pub severity_min: Severity,
}

impl Default for ReviewOptions {
    fn default() -> Self {
        Self {
            severity_min: Severity::Info,
        }
    }
}

/// Fatal engine-level failures only — the embedded `rules/review/*` pack
/// failing to load/compile, or a grammar/query mismatch. A per-file
/// read/parse/size problem is never fatal (collected in the second return
/// value of [`run`]), mirroring `audit::AuditError`.
#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    #[error(transparent)]
    Scan(#[from] ScanError),
    #[error(transparent)]
    Rules(#[from] RuleLoadError),
}

/// One candidate file, parsed exactly once. Shared, read-only, by the
/// declarative path and every programmatic detector — so a file is parsed
/// once per invocation, never once per rule.
pub(crate) struct ReviewFile {
    /// Project-relative path, forward slashes.
    pub rel: String,
    pub lang: Lang,
    pub source: String,
    pub tree: Tree,
    /// 1-based inclusive introduced line ranges for this file.
    pub added_ranges: Vec<(u32, u32)>,
    /// `true` for an Added file (Diff scope) or any file under `All`.
    /// Consumed by the dead-code / orphan detectors in 06-03/06-04 — unused
    /// by the 06-02 spine, so allow the otherwise-dead field until then.
    #[allow(dead_code)]
    pub is_new_file: bool,
}

/// Run every `review/*` rule over the changed-file set in `scope`, scoping
/// each to introduced content, producing schema-conformant [`Finding`]s
/// (`command: "review"`). Findings below `opts.severity_min` are dropped
/// before returning.
///
/// # Errors
/// Returns [`ReviewError`] only for fatal engine conditions (the embedded
/// review pack failing to load/compile, or a grammar/query mismatch) — never
/// for a single unreadable/oversized project file, which is collected in the
/// second return value instead.
pub fn run(
    root: &Path,
    scope: &ReviewScope,
    opts: &ReviewOptions,
) -> Result<(Vec<Finding>, Vec<ScanError>), ReviewError> {
    // The SECOND embedded pack (rules/review/*), independent of audit's — so
    // audit never silently compiles review queries it never runs, and vice
    // versa (06-RESEARCH.md Open Q2, LOCKED).
    let pack = rules::load_embedded_review()?;

    let (files, skipped) = build_review_files(root, scope)?;

    let mut findings = Vec::new();

    // Declarative path: run the review pack's cached AST queries over each
    // parsed file, then apply the OVERLAP filter (debug-leftover /
    // todo-introduced are line-level rules) on each hit's 1-based start line.
    for file in &files {
        for rule in &pack.rules {
            if !rule.languages.contains(&file.lang) {
                continue;
            }
            let Some(query) = pack.query_cache.get(file.lang, &rule.id) else {
                continue;
            };
            for node in crate::audit::run_ast_matcher(
                query,
                file.tree.root_node(),
                file.source.as_bytes(),
            ) {
                let line = u32::try_from(node.start_position().row)
                    .unwrap_or(u32::MAX)
                    .saturating_add(1);
                if is_introduced_line(line, &file.added_ranges) {
                    findings.push(review_ast_hit_to_finding(rule, node, &file.rel));
                }
            }
        }
    }

    // Programmatic path: the four cross-file / fingerprint / re-parse
    // detectors. Stubbed in 06-02 (return no findings) so the dispatch graph
    // is live; 06-03/06-04 fill their own submodule bodies without touching
    // this file.
    findings.append(&mut fingerprint::detect(&files));
    findings.append(&mut deadcode::detect(&files));
    findings.append(&mut commented_code::detect(&files));
    findings.append(&mut orphan::detect(root, &files));

    findings.retain(|f| f.severity >= opts.severity_min);
    Ok((findings, skipped))
}

/// Build the parse-once [`ReviewFile`] set for `scope`. Unreadable / oversized
/// / unparseable files are collected as [`ScanError`] skips rather than
/// aborting the whole review (a hostile or half-broken repo must never panic
/// review — CLAUDE.md rule 1). A grammar mismatch (a genuine getdev bug) is
/// fatal.
fn build_review_files(
    root: &Path,
    scope: &ReviewScope,
) -> Result<(Vec<ReviewFile>, Vec<ScanError>), ReviewError> {
    let mut files = Vec::new();
    let mut skipped = Vec::new();

    match scope {
        ReviewScope::Diff(changed) => {
            for cf in changed {
                // A deleted file has no content to review.
                if cf.status == ReviewChangeStatus::Deleted {
                    continue;
                }
                // Defensive: never resolve a `..`-escaping diff path outside
                // the project root (threat T-06 tampering / path traversal).
                if Path::new(&cf.path)
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    continue;
                }
                let path = root.join(&cf.path);
                let Some(lang) = Lang::from_path(&path) else {
                    continue;
                };
                let is_new_file = cf.status == ReviewChangeStatus::Added;
                push_review_file(
                    &path,
                    cf.path.clone(),
                    lang,
                    cf.added_ranges.clone(),
                    is_new_file,
                    &mut files,
                    &mut skipped,
                )?;
            }
        }
        ReviewScope::All => {
            for entry in project_walker(root).build().flatten() {
                if !entry.file_type().is_some_and(|t| t.is_file()) {
                    continue;
                }
                let path = entry.path();
                let Some(lang) = Lang::from_path(path) else {
                    continue;
                };
                let rel = relative_display(path, root);
                // Whole-file synthesized added range: every line is
                // "introduced" (Pattern 3). The source read below is reused,
                // so we compute the range after the read to avoid reading
                // twice — see `push_review_file`.
                push_review_file(
                    path,
                    rel,
                    lang,
                    Vec::new(), // sentinel: All synthesizes the range post-read
                    true,
                    &mut files,
                    &mut skipped,
                )?;
            }
        }
    }

    // For `All`, every file's `added_ranges` was left empty as a sentinel;
    // fill each with its own whole-file `[1, line_count]` range now that the
    // source has been read once.
    if matches!(scope, ReviewScope::All) {
        for file in &mut files {
            let line_count = file.source.lines().count().max(1);
            file.added_ranges = vec![(1, u32::try_from(line_count).unwrap_or(u32::MAX))];
        }
    }

    Ok((files, skipped))
}

/// Read + parse one candidate file ONCE and push a [`ReviewFile`], or record
/// a per-file skip. Grammar mismatches propagate as fatal (a getdev bug);
/// read/size/parse trouble is a collected skip.
#[allow(clippy::too_many_arguments)]
fn push_review_file(
    path: &Path,
    rel: String,
    lang: Lang,
    added_ranges: Vec<(u32, u32)>,
    is_new_file: bool,
    files: &mut Vec<ReviewFile>,
    skipped: &mut Vec<ScanError>,
) -> Result<(), ReviewError> {
    let source = match read_source_capped(path) {
        Ok(source) => source,
        Err(err) => {
            skipped.push(err);
            return Ok(());
        }
    };
    let mut parser = Parser::new();
    // A grammar/version mismatch is a getdev bug — fail loudly (fatal),
    // exactly as `audit`/`scan` do.
    parser.set_language(&lang.language()).map_err(ScanError::from)?;
    let Some(tree) = parser.parse(&source, None) else {
        skipped.push(ScanError::Parse {
            path: path.to_path_buf(),
        });
        return Ok(());
    };
    files.push(ReviewFile {
        rel,
        lang,
        source,
        tree,
        added_ranges,
        is_new_file,
    });
    Ok(())
}

/// CONTAINMENT policy (06-RESEARCH.md Pattern 2): the whole `node_span`
/// (1-based inclusive `(start_line, end_line)`) must lie entirely inside a
/// single added range. For declaration-level rules — flagging a whole
/// function only when the WHOLE declaration is introduced, never because one
/// unrelated line inside a 20-year-old function was touched. Consumed by the
/// programmatic detectors in 06-03/06-04.
#[allow(dead_code)]
pub(crate) fn is_introduced_declaration(node_span: (u32, u32), added: &[(u32, u32)]) -> bool {
    added
        .iter()
        .any(|&(a, b)| a <= node_span.0 && node_span.1 <= b)
}

/// OVERLAP policy (06-RESEARCH.md Pattern 2): a single 1-based `line` need
/// only intersect an added range. For line-level rules (`debug-leftover`,
/// `todo-introduced`, `commented-code-block`) whose finding unit IS the line
/// — which is either wholly new or not a candidate at all.
pub(crate) fn is_introduced_line(line: u32, added: &[(u32, u32)]) -> bool {
    added.iter().any(|&(a, b)| a <= line && line <= b)
}

/// Mirror of `audit::ast_hit_to_finding` but with `command: "review"`.
/// Heuristic rules (confidence below `high`) surface their reasoning in
/// `detail` from the rule's own `description` (FP policy, docs/SPEC-RULES.md)
/// — never a hardcoded per-rule string.
fn review_ast_hit_to_finding(rule: &rules::Rule, node: Node<'_>, file: &str) -> Finding {
    let pos = node.start_position();
    let end_pos = node.end_position();
    let detail = (rule.confidence != Confidence::High).then(|| rule.description.clone());
    Finding {
        id: rule.id.clone(),
        command: "review".to_owned(),
        severity: rule.severity,
        confidence: rule.confidence,
        file: file.to_owned(),
        line: Some(u32::try_from(pos.row).unwrap_or(u32::MAX).saturating_add(1)),
        column: Some(
            u32::try_from(pos.column)
                .unwrap_or(u32::MAX)
                .saturating_add(1),
        ),
        end_line: Some(
            u32::try_from(end_pos.row)
                .unwrap_or(u32::MAX)
                .saturating_add(1),
        ),
        message: rule.message.clone(),
        detail,
        suggestion: None,
        remediation: Some(rule.remediation.clone()),
        fixable: false,
        refs: rule.refs.clone(),
        fingerprint: None,
    }
}

#[cfg(test)]
mod tests {
    //! Pure-function tests only (the added-range policy helpers). The
    //! filesystem-driven spine tests that exercise `run` end-to-end live in
    //! `tests/review_spine.rs` — deliberately kept OUT of this source file so
    //! this module stays free of any file-write token (the phase's "review
    //! never mutates" grep gate over `crates/getdev-core/src/review/`).

    use super::*;

    #[test]
    fn containment_requires_whole_span_inside_a_single_range() {
        let added = [(10, 20)];
        assert!(is_introduced_declaration((12, 18), &added));
        assert!(is_introduced_declaration((10, 20), &added));
        // one edge outside the range
        assert!(!is_introduced_declaration((9, 18), &added));
        assert!(!is_introduced_declaration((12, 21), &added));
        // spanning two ranges (an unchanged middle) legitimately fails
        assert!(!is_introduced_declaration((10, 30), &[(10, 15), (25, 30)]));
    }

    #[test]
    fn overlap_only_needs_the_line_inside_a_range() {
        let added = [(10, 20), (30, 30)];
        assert!(is_introduced_line(10, &added));
        assert!(is_introduced_line(15, &added));
        assert!(is_introduced_line(30, &added));
        assert!(!is_introduced_line(9, &added));
        assert!(!is_introduced_line(21, &added));
    }
}
