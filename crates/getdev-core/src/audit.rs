//! `core::audit` — the read-only analyzer that runs a compiled
//! [`crate::rules::RulePack`] over a project's files into `Vec<Finding>`.
//! Mirrors `real.rs`'s shape: network-free, no `println!`, pure data-in/
//! data-out. **Imports NO `getdev_registry` type and NO network code**
//! (REQ-privacy); never mutates (REQ-safe-by-default; no `core::mutate`
//! involvement).
//!
//! Structured file-outer/rule-inner (04-RESEARCH.md Pitfall 7): every file
//! is parsed at most ONCE per invocation, and every applicable rule's
//! matcher runs against that single parsed tree — never once per rule.

use std::path::Path;

use getdev_grammars::tree_sitter::{Node, QueryCursor};
use globset::{Glob, GlobSet, GlobSetBuilder};
use streaming_iterator::StreamingIterator;

use crate::findings::{Confidence, Finding, Severity};
use crate::frameworks::DetectedFrameworks;
use crate::rules::{CompiledTextMatcher, Matcher, Rule, RulePack};
use crate::scan::{
    read_source_capped, Lang, ScanContext, ScanError, ScannedFile, StringAssignment,
};
use crate::secrets::{PatternError, SecretMatch, SecretPatterns};

/// Everything that filters findings after they're produced.
/// `--ignore`/`--rules` are wired at the CLI tier (docs/PLAN.md §2.3); this
/// engine only knows the severity floor.
#[derive(Debug, Clone, Copy)]
pub struct AuditOptions {
    pub severity_min: Severity,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            severity_min: Severity::Info,
        }
    }
}

/// Fatal engine-level failures only — a broken embedded query/grammar
/// mismatch, or the embedded secret pattern pack failing to compile. A
/// per-file read/parse/size problem is never fatal (collected in the
/// second return value of [`run`] instead), mirroring `scan::scan_path`.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error(transparent)]
    Scan(#[from] ScanError),
    #[error(transparent)]
    Secrets(#[from] PatternError),
}

/// Run every rule in `pack` over the shared parse-once [`ScanContext`] `ctx`,
/// gated by `frameworks` (project-level `frameworks:` selector) and each
/// rule's `languages`/`path_glob` selectors, producing schema-conformant
/// [`Finding`]s. Findings below `opts.severity_min` are dropped before
/// returning.
///
/// Parse-once (CLAUDE.md rule 5): audit does NO walk and NO parse of its own —
/// it iterates `ctx.files` (already walked + parsed ONCE by
/// [`ScanContext::build`]) for the AST/secret/text matchers over source files,
/// and `ctx.other_files` for the text-regex matcher kind over non-source files
/// (Firebase `.rules`/`.rules.json`), reading only the few that a `file_glob`
/// selects. The oversized/unreadable SOURCE files the shared scan pass already
/// skipped live in `ctx.skipped`; the second return value here carries only the
/// non-source read failures audit itself incurs.
///
/// # Errors
/// Returns [`AuditError`] only for fatal engine conditions (a grammar/query
/// mismatch, or the embedded secret pattern pack failing to parse) — never
/// for a single unreadable/oversized project file, which is collected in
/// the second return value (or `ctx.skipped`) instead.
pub fn run(
    ctx: &ScanContext,
    pack: &RulePack,
    frameworks: &DetectedFrameworks,
    opts: &AuditOptions,
) -> Result<(Vec<Finding>, Vec<ScanError>), AuditError> {
    let path_globs = compile_path_globs(pack);
    let text_rules = compile_text_matchers(pack);
    let secret_patterns = SecretPatterns::embedded()?;
    let lang_ctx = LangFileContext {
        pack,
        path_globs: &path_globs,
        frameworks,
        secret_patterns: &secret_patterns,
    };

    let mut findings = Vec::new();
    let mut skipped = Vec::new();

    // Source files: walked + parsed exactly once by `ScanContext`. Run the
    // text-regex matchers over the cached source, then the AST/secret matchers
    // over the cached tree — no re-read, no re-parse.
    for file in &ctx.files {
        let rel = file.rel.to_string_lossy();
        // IN-02: glob text-regex `file_glob` against the SAME project-relative
        // base the AST `path_glob` gate uses, never the absolute path.
        let rel_path = file.rel.as_path();
        run_text_matchers(
            &text_rules,
            &path_globs,
            frameworks,
            rel_path,
            &rel,
            file.source.as_bytes(),
            &mut findings,
        );

        match process_lang_file(file, &rel, &lang_ctx) {
            Ok(mut hits) => findings.append(&mut hits),
            Err(err @ (ScanError::Grammar(_) | ScanError::Query(_))) => {
                return Err(err.into());
            }
            Err(err) => skipped.push(err),
        }
    }

    // Non-source files: the text-regex matcher kind only (Firebase
    // `.rules`/`.rules.json` — no tree-sitter grammar). Enumerated from the
    // SAME single walk via `ctx.other_files`; a file no `file_glob` selects is
    // never read (F7-adjacent: don't pay a read cost for files no rule cares
    // about).
    for other in &ctx.other_files {
        let rel = other.rel.to_string_lossy();
        let rel_path = other.rel.as_path();
        let has_candidate = text_rules
            .iter()
            .any(|tr| tr.matcher.glob_matches(rel_path));
        if !has_candidate {
            continue;
        }
        let source = match read_source_capped(&other.abs) {
            Ok(source) => source,
            Err(err) => {
                skipped.push(err);
                continue;
            }
        };
        run_text_matchers(
            &text_rules,
            &path_globs,
            frameworks,
            rel_path,
            &rel,
            source.as_bytes(),
            &mut findings,
        );
    }

    findings.retain(|f| f.severity >= opts.severity_min);
    Ok((findings, skipped))
}

/// Run every `{file_glob, text_pattern}` matcher whose glob selects `rel_path`
/// against `bytes`, honoring the rule's `frameworks:` and `path_glob:` gates —
/// shared verbatim between the source-file and non-source-file passes so the
/// text-regex behavior can never drift between them.
fn run_text_matchers(
    text_rules: &[TextRule<'_>],
    path_globs: &[Option<GlobSet>],
    frameworks: &DetectedFrameworks,
    rel_path: &Path,
    rel: &str,
    bytes: &[u8],
    findings: &mut Vec<Finding>,
) {
    for tr in text_rules {
        if !tr.matcher.glob_matches(rel_path) {
            continue;
        }
        if !framework_gate(tr.rule, frameworks) {
            continue;
        }
        if !path_glob_gate(path_globs[tr.rule_index].as_ref(), rel) {
            continue;
        }
        if tr.matcher.is_match(rel_path, bytes) {
            findings.push(text_hit_to_finding(tr.rule, rel));
        }
    }
}

/// Everything [`process_lang_file`] needs beyond the current file itself —
/// bundled to keep the function's argument count clippy-clean, not for any
/// deeper reason.
struct LangFileContext<'a> {
    pack: &'a RulePack,
    path_globs: &'a [Option<GlobSet>],
    frameworks: &'a DetectedFrameworks,
    secret_patterns: &'a SecretPatterns,
}

/// One file's worth of AST/secret matching over an ALREADY-parsed
/// [`ScannedFile`] (Pitfall 7 / CLAUDE.md rule 5 — the file was parsed once by
/// [`ScanContext::build`], never re-parsed here): runs every applicable rule's
/// AST or secret matcher against that single cached tree.
fn process_lang_file(
    file: &ScannedFile,
    rel: &str,
    ctx: &LangFileContext<'_>,
) -> Result<Vec<Finding>, ScanError> {
    let lang = file.lang;
    let root_node = file.tree.root_node();
    let bytes = file.source.as_bytes();

    let mut findings = Vec::new();

    for (idx, rule) in ctx.pack.rules.iter().enumerate() {
        if !rule_applies_to_file(
            rule,
            ctx.path_globs[idx].as_ref(),
            lang,
            ctx.frameworks,
            rel,
        ) {
            continue;
        }
        // AST: all same-language AST matchers of this rule were merged into
        // ONE cached query at load time (see `rules::compile_rule`), so run
        // it exactly ONCE per (lang, rule) here. Iterating per matcher entry
        // would re-run the same cached query and duplicate every finding.
        let has_ast_for_lang = rule
            .matchers
            .iter()
            .any(|m| matches!(m, Matcher::Ast { language, .. } if *language == lang));
        if has_ast_for_lang {
            if let Some(query) = ctx.pack.query_cache.get(lang, &rule.id) {
                for node in run_ast_matcher(query, root_node, bytes) {
                    findings.push(ast_hit_to_finding(rule, node, bytes, rel));
                }
            }
        }

        // Secret: classify the file's string assignments once if this rule
        // declares a secret matcher.
        if rule.matchers.iter().any(|m| matches!(m, Matcher::Secret)) {
            let assignments = crate::scan::string_assignments_from_tree(
                &file.tree,
                &file.source,
                lang,
                &file.abs,
            )?;
            for assignment in &assignments {
                if let Some(secret) = ctx
                    .secret_patterns
                    .classify(&assignment.value, &assignment.name)
                {
                    // PREC-04/D-09: suppress the generic entropy fallback in
                    // test/scaffolding files (credential-shaped fixture strings)
                    // — a provider-format match (`pattern_id != "entropy"`) is
                    // NEVER skipped, so a planted key in a test file still fires.
                    if secret.pattern_id == "entropy" && crate::secrets::is_test_fixture_path(rel) {
                        continue;
                    }
                    findings.push(secret_hit_to_finding(rule, assignment, &secret, rel));
                }
            }
        }
    }

    Ok(findings)
}

/// Every match already satisfied every `#eq?`/`#match?`/`#any-of?`
/// predicate in the query text before being yielded here — the vendored
/// tree-sitter Rust binding evaluates these automatically inside
/// `QueryMatches::advance()` (04-RESEARCH.md Pattern 1, VERIFIED against
/// the vendored binding source). No manual predicate re-checking needed.
/// The anchor capture is `@finding` if the query names one, else the
/// match's first capture.
///
/// `pub(crate)` so `core::review`'s declarative path reuses this exact
/// matcher-execution loop unchanged (06-02) — review only differs by adding
/// an added-line-range post-filter over the returned nodes.
pub(crate) fn run_ast_matcher<'tree>(
    query: &getdev_grammars::tree_sitter::Query,
    root: Node<'tree>,
    source: &[u8],
) -> Vec<Node<'tree>> {
    let capture_names = query.capture_names();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(query, root, source);
    let mut hits = Vec::new();
    while let Some(m) = matches.next() {
        let anchor = m
            .captures
            .iter()
            .find(|c| capture_names[c.index as usize] == "finding")
            .or_else(|| m.captures.first());
        if let Some(capture) = anchor {
            hits.push(capture.node);
        }
    }
    hits
}

/// One rule's `{file_glob, text_pattern}` matcher, pre-compiled once per
/// [`run`] invocation (not persisted on [`RulePack`] — 04-01-SUMMARY.md
/// decision — and never recompiled per file).
struct TextRule<'a> {
    rule_index: usize,
    rule: &'a Rule,
    matcher: CompiledTextMatcher,
}

fn compile_text_matchers(pack: &RulePack) -> Vec<TextRule<'_>> {
    let mut out = Vec::new();
    for (rule_index, rule) in pack.rules.iter().enumerate() {
        for matcher in &rule.matchers {
            if let Matcher::TextRegex {
                file_glob,
                text_pattern,
            } = matcher
            {
                if let Ok(compiled) =
                    CompiledTextMatcher::compile(&rule.id, "audit::run", file_glob, text_pattern)
                {
                    out.push(TextRule {
                        rule_index,
                        rule,
                        matcher: compiled,
                    });
                }
            }
        }
    }
    out
}

/// Every rule's optional `path_glob:` selector, compiled once per [`run`]
/// invocation and indexed positionally by `pack.rules`. `None` for a rule
/// with no `path_glob` (unrestricted).
fn compile_path_globs(pack: &RulePack) -> Vec<Option<GlobSet>> {
    pack.rules
        .iter()
        .map(|rule| {
            if rule.path_glob.is_empty() {
                return None;
            }
            let mut builder = GlobSetBuilder::new();
            for pattern in &rule.path_glob {
                if let Ok(glob) = Glob::new(pattern) {
                    builder.add(glob);
                }
            }
            builder.build().ok()
        })
        .collect()
}

/// Project-level gate (04-RESEARCH.md Pattern 5 / Pitfall 3): a rule with a
/// non-empty `frameworks:` list only activates when at least one listed
/// framework is present in `frameworks` — never a hardcoded per-framework
/// branch here.
fn framework_gate(rule: &Rule, frameworks: &DetectedFrameworks) -> bool {
    rule.frameworks.is_empty() || rule.frameworks.iter().any(|f| frameworks.contains(*f))
}

fn path_glob_gate(glob: Option<&GlobSet>, rel: &str) -> bool {
    glob.is_none_or(|g| g.is_match(rel))
}

/// The declarative selection gate every AST/secret-matcher rule must pass
/// for `lang`-typed file `rel` before any of its matchers even run:
/// `lang` must be in the rule's declared `languages`, its `frameworks:`
/// gate (if any) must be satisfied, and its `path_glob:` gate (if any) must
/// match. Text-regex matchers bypass the `languages` check entirely (they
/// have no grammar and are gated purely by their own per-matcher
/// `file_glob`, checked separately) — 04-RESEARCH.md Pattern 4/Pitfall 7.
fn rule_applies_to_file(
    rule: &Rule,
    rule_glob: Option<&GlobSet>,
    lang: Lang,
    frameworks: &DetectedFrameworks,
    rel: &str,
) -> bool {
    rule.languages.contains(&lang)
        && framework_gate(rule, frameworks)
        && path_glob_gate(rule_glob, rel)
}

/// Heuristic rules (any rule whose declared `confidence` is below `high`)
/// must surface their reasoning in the finding's `detail` field (FP policy,
/// docs/SPEC-RULES.md) — sourced from the rule's own `description`, never a
/// per-rule hardcoded string.
fn is_heuristic(rule: &Rule) -> bool {
    rule.confidence != Confidence::High
}

fn heuristic_detail(rule: &Rule) -> Option<String> {
    is_heuristic(rule).then(|| rule.description.clone())
}

fn ast_hit_to_finding(rule: &Rule, node: Node<'_>, source: &[u8], file: &str) -> Finding {
    let pos = node.start_position();
    let end_pos = node.end_position();
    Finding {
        id: rule.id.clone(),
        command: "audit".to_owned(),
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
        detail: heuristic_detail(rule),
        suggestion: None,
        remediation: Some(rule.remediation.clone()),
        fixable: false,
        refs: rule.refs.clone(),
        // D-01/D-11 (Shape 1, real node): anchor on the matched node's kind +
        // its source text, captured inside the parse-once pass (no re-parse —
        // CLAUDE.md rule 5). `.unwrap_or_default()` keeps clippy clean and, for
        // the impossible non-UTF-8 span, degrades to the empty seed.
        seed: crate::fingerprint::FingerprintSeed {
            node_kind: node.kind(),
            matched_text: node.utf8_text(source).unwrap_or_default().to_owned(),
        },
        fingerprint: None,
    }
}

/// Text-regex matches are whole-file (no tree-sitter node to anchor a
/// line/column on) — `line`/`column`/`end_line` stay `None`.
fn text_hit_to_finding(rule: &Rule, file: &str) -> Finding {
    Finding {
        id: rule.id.clone(),
        command: "audit".to_owned(),
        severity: rule.severity,
        confidence: rule.confidence,
        file: file.to_owned(),
        line: None,
        column: None,
        end_line: None,
        message: rule.message.clone(),
        detail: heuristic_detail(rule),
        suggestion: None,
        remediation: Some(rule.remediation.clone()),
        fixable: false,
        refs: rule.refs.clone(),
        // D-02 (Shape 3, no node/span): whole-file text-regex hits have no
        // anchor node, so the rule message is the stable fallback seed. The
        // batch pass normalizes matched_text centrally.
        seed: crate::fingerprint::FingerprintSeed {
            node_kind: "message_fallback",
            matched_text: rule.message.clone(),
        },
        fingerprint: None,
    }
}

/// Pitfall 6: routes exclusively through `secrets::classify`'s already-
/// masked [`SecretMatch::masked`] — never slices/re-derives a preview of
/// the raw value inline here.
fn secret_hit_to_finding(
    rule: &Rule,
    assignment: &StringAssignment,
    secret: &SecretMatch,
    file: &str,
) -> Finding {
    let provider = if secret.provider == "generic" {
        "high-entropy".to_owned()
    } else {
        secret.provider.clone()
    };
    Finding {
        id: rule.id.clone(),
        command: "audit".to_owned(),
        severity: rule.severity,
        confidence: rule.confidence,
        file: file.to_owned(),
        line: Some(assignment.line),
        column: Some(assignment.column),
        end_line: Some(assignment.line),
        message: format!(
            "{provider} secret assigned to '{}' ({})",
            assignment.name, secret.masked
        ),
        detail: Some(format!("matched pattern '{}'", secret.pattern_id)),
        suggestion: None,
        remediation: Some(rule.remediation.clone()),
        fixable: false,
        refs: rule.refs.clone(),
        // D-05: the raw secret value is the identity seed — two distinct
        // secrets on one line differentiate intrinsically. It is hashed only;
        // `FingerprintSeed`'s redacting `Debug` + `#[serde(skip)]` keep it off
        // every wire/renderer (Invariant 2). This is the tracer's ONE real seed.
        seed: crate::fingerprint::FingerprintSeed {
            node_kind: "secret_literal",
            matched_text: assignment.value.clone(),
        },
        fingerprint: None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::rules::{self, QueryCache};
    use std::path::PathBuf;

    /// Test-local shim: build a one-shot parse-once [`ScanContext`] for `root`
    /// and drive the real `super::run` over it — exactly how the CLI (and, in
    /// 07-04, `check`) invoke audit post-07-02. Shadows the glob-imported
    /// `super::run` so every fixture assertion below stays byte-identical while
    /// the analyzer's public entry now takes `&ScanContext` instead of `&Path`.
    fn run(
        root: &Path,
        pack: &RulePack,
        frameworks: &DetectedFrameworks,
        opts: &AuditOptions,
    ) -> Result<(Vec<Finding>, Vec<ScanError>), AuditError> {
        let ctx = crate::scan::ScanContext::build(root).unwrap();
        super::run(&ctx, pack, frameworks, opts)
    }

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-audit-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Build a `RulePack` from a directory of rule YAML files, exactly like
    /// `getdev-cli`'s `--rules` flag would — `load_user_pack` gives us
    /// typed `Rule`s, and we independently compile their AST queries into a
    /// fresh `QueryCache` (mirrors what `load_embedded`/`merge` do
    /// internally) so tests never need the embedded pack to contain
    /// anything.
    fn build_pack(rules_dir: &Path) -> RulePack {
        let (rules, errors) = rules::load_user_pack(rules_dir);
        assert!(errors.is_empty(), "rule load errors: {errors:?}");
        let mut query_cache = QueryCache::new();
        // Compile via the real `compile_rule` (not a per-matcher loop) so
        // tests exercise the same same-language-matcher merge that
        // production `load_embedded`/`merge` use.
        for rule in &rules {
            rules::compile_rule(&mut query_cache, rule, "test").unwrap();
        }
        RulePack { rules, query_cache }
    }

    const AST_RULE_YAML: &str = r#"
id: audit/test-dangerous-call
severity: high
confidence: high
languages: [javascript]
description: test rule — dangerous call detected
message: "dangerous call detected"
remediation: remove it
refs: []
matchers:
  - language: javascript
    query: |
      (call_expression
        function: (identifier) @fn (#eq? @fn "dangerousCall")) @finding
fixtures:
  positive: [a.js, b.js, c.js]
  negative: [d.js, e.js, f.js]
"#;

    #[test]
    fn ast_rule_fires_on_positive_and_not_on_negative() {
        let rules_dir = tempdir("ast-rules");
        std::fs::write(rules_dir.join("rule.yaml"), AST_RULE_YAML).unwrap();
        let pack = build_pack(&rules_dir);

        let project = tempdir("ast-project");
        std::fs::write(project.join("positive.js"), "dangerousCall();\n").unwrap();
        std::fs::write(project.join("negative.js"), "safeCall();\n").unwrap();

        let (findings, skipped) = run(
            &project,
            &pack,
            &DetectedFrameworks::default(),
            &AuditOptions::default(),
        )
        .unwrap();
        assert!(skipped.is_empty());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "audit/test-dangerous-call");
        assert_eq!(findings[0].file, "positive.js");
        assert_eq!(findings[0].line, Some(1));
        assert_eq!(findings[0].column, Some(1));
    }

    const TWO_MATCHER_RULE_YAML: &str = r#"
id: audit/test-two-matchers
severity: high
confidence: high
languages: [javascript]
description: test rule — two same-language AST matchers
message: "two-matcher finding"
remediation: remove it
refs: []
matchers:
  - language: javascript
    query: |
      (call_expression
        function: (identifier) @fn (#eq? @fn "alpha")) @finding
  - language: javascript
    query: |
      (call_expression
        function: (identifier) @fn (#eq? @fn "beta")) @finding
fixtures:
  positive: [a.js, b.js, c.js]
  negative: [d.js, e.js, f.js]
"#;

    /// Regression: a rule with several same-language AST matchers must
    /// (a) fire ALL its patterns — not silently drop every matcher after
    /// the first (the `QueryCache` is keyed by `(Lang, rule_id)`), and
    /// (b) report each real hit exactly ONCE — not once per matcher entry.
    /// Pre-fix `both.js` produced two findings both on line 1 (the first
    /// matcher run twice, the second dropped); post-fix it produces one hit
    /// on line 1 (`alpha`) and one on line 2 (`beta`).
    #[test]
    fn same_language_matchers_all_fire_without_duplication() {
        let rules_dir = tempdir("two-matcher-rules");
        std::fs::write(rules_dir.join("rule.yaml"), TWO_MATCHER_RULE_YAML).unwrap();
        let pack = build_pack(&rules_dir);

        // File exercising BOTH patterns: exactly two findings, on lines 1 & 2.
        let project = tempdir("two-matcher-both");
        std::fs::write(project.join("both.js"), "alpha();\nbeta();\n").unwrap();
        let (findings, skipped) = run(
            &project,
            &pack,
            &DetectedFrameworks::default(),
            &AuditOptions::default(),
        )
        .unwrap();
        assert!(skipped.is_empty());
        assert_eq!(
            findings.len(),
            2,
            "both patterns fire once each: {findings:?}"
        );
        let mut lines: Vec<u32> = findings.iter().filter_map(|f| f.line).collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![1, 2], "one hit per pattern, no duplicates");

        // File exercising ONE pattern: exactly one finding (not two).
        let project_one = tempdir("two-matcher-one");
        std::fs::write(project_one.join("one.js"), "alpha();\n").unwrap();
        let (findings_one, _skipped) = run(
            &project_one,
            &pack,
            &DetectedFrameworks::default(),
            &AuditOptions::default(),
        )
        .unwrap();
        assert_eq!(
            findings_one.len(),
            1,
            "single hit must not be duplicated per matcher entry: {findings_one:?}"
        );
    }

    const OVERRIDE_EMBEDDED_YAML: &str = r#"
id: audit/test-override
severity: high
confidence: high
languages: [javascript]
description: embedded rule — matches alpha()
message: "embedded finding"
remediation: remove it
refs: []
matchers:
  - language: javascript
    query: |
      (call_expression
        function: (identifier) @fn (#eq? @fn "alpha")) @finding
fixtures:
  positive: [a.js, b.js, c.js]
  negative: [d.js, e.js, f.js]
"#;

    const OVERRIDE_USER_YAML: &str = r#"
id: audit/test-override
severity: high
confidence: high
languages: [javascript]
description: user override — matches beta() instead
message: "user override finding"
remediation: remove it
refs: []
matchers:
  - language: javascript
    query: |
      (call_expression
        function: (identifier) @fn (#eq? @fn "beta")) @finding
fixtures:
  positive: [a.js, b.js, c.js]
  negative: [d.js, e.js, f.js]
"#;

    /// BL-01 regression: a `--rules` user rule that overrides an embedded
    /// rule of the same id replaces its AST query ENTIRELY. Pre-fix, the
    /// `(lang, id)`-keyed cache's already-present fast-path kept the embedded
    /// query, so the override was silently ineffective (the embedded pattern
    /// ran under the user's metadata). Post-fix: `merge` evicts the embedded
    /// query first, so the override's query is what runs.
    #[test]
    fn user_pack_override_replaces_embedded_query() {
        let embedded_dir = tempdir("override-embedded");
        std::fs::write(embedded_dir.join("rule.yaml"), OVERRIDE_EMBEDDED_YAML).unwrap();
        let embedded = build_pack(&embedded_dir);

        let user_dir = tempdir("override-user");
        std::fs::write(user_dir.join("rule.yaml"), OVERRIDE_USER_YAML).unwrap();
        let (user_rules, errs) = rules::load_user_pack(&user_dir);
        assert!(errs.is_empty(), "user pack load errors: {errs:?}");

        let (merged, warnings) = rules::merge(embedded, user_rules);
        assert_eq!(warnings.len(), 1, "override should warn once: {warnings:?}");

        // The override matches beta(), not alpha().
        let proj_beta = tempdir("override-beta");
        std::fs::write(proj_beta.join("f.js"), "beta();\n").unwrap();
        let (hits_beta, _) = run(
            &proj_beta,
            &merged,
            &DetectedFrameworks::default(),
            &AuditOptions::default(),
        )
        .unwrap();
        assert_eq!(
            hits_beta.len(),
            1,
            "override query must fire on beta(): {hits_beta:?}"
        );
        assert_eq!(hits_beta[0].message, "user override finding");

        // The embedded pattern (alpha) must no longer fire — it was replaced.
        let proj_alpha = tempdir("override-alpha");
        std::fs::write(proj_alpha.join("f.js"), "alpha();\n").unwrap();
        let (hits_alpha, _) = run(
            &proj_alpha,
            &merged,
            &DetectedFrameworks::default(),
            &AuditOptions::default(),
        )
        .unwrap();
        assert!(
            hits_alpha.is_empty(),
            "embedded query must be evicted by the override: {hits_alpha:?}"
        );
    }

    const FRAMEWORK_SCOPED_RULE_YAML: &str = r#"
id: audit/test-framework-scoped
severity: high
confidence: high
languages: [javascript]
frameworks: [express]
description: test rule — express-scoped
message: "express-scoped finding"
remediation: remove it
refs: []
matchers:
  - language: javascript
    query: |
      (call_expression
        function: (identifier) @fn (#eq? @fn "dangerousCall")) @finding
fixtures:
  positive: [a.js, b.js, c.js]
  negative: [d.js, e.js, f.js]
"#;

    /// SC2/Pitfall 3: a `frameworks: [express]` rule must NOT fire when
    /// `DetectedFrameworks::default()` (all false) is passed, even though
    /// the syntax matches.
    #[test]
    fn framework_scoped_rule_suppressed_when_framework_absent() {
        let rules_dir = tempdir("framework-rules");
        std::fs::write(rules_dir.join("rule.yaml"), FRAMEWORK_SCOPED_RULE_YAML).unwrap();
        let pack = build_pack(&rules_dir);

        let project = tempdir("framework-project");
        std::fs::write(project.join("hit.js"), "dangerousCall();\n").unwrap();

        let (findings, _skipped) = run(
            &project,
            &pack,
            &DetectedFrameworks::default(),
            &AuditOptions::default(),
        )
        .unwrap();
        assert!(findings.is_empty());

        let frameworks = DetectedFrameworks {
            express: true,
            ..DetectedFrameworks::default()
        };
        let (findings, _skipped) =
            run(&project, &pack, &frameworks, &AuditOptions::default()).unwrap();
        assert_eq!(findings.len(), 1);
    }

    const PATH_GLOB_RULE_YAML: &str = r#"
id: audit/test-path-scoped
severity: high
confidence: high
languages: [javascript]
path_glob: ["only/**"]
description: test rule — path-scoped
message: "path-scoped finding"
remediation: remove it
refs: []
matchers:
  - language: javascript
    query: |
      (call_expression
        function: (identifier) @fn (#eq? @fn "dangerousCall")) @finding
fixtures:
  positive: [a.js, b.js, c.js]
  negative: [d.js, e.js, f.js]
"#;

    #[test]
    fn path_glob_rule_fires_only_in_the_globbed_path() {
        let rules_dir = tempdir("path-glob-rules");
        std::fs::write(rules_dir.join("rule.yaml"), PATH_GLOB_RULE_YAML).unwrap();
        let pack = build_pack(&rules_dir);

        let project = tempdir("path-glob-project");
        std::fs::create_dir_all(project.join("only")).unwrap();
        std::fs::create_dir_all(project.join("elsewhere")).unwrap();
        std::fs::write(project.join("only/hit.js"), "dangerousCall();\n").unwrap();
        std::fs::write(project.join("elsewhere/hit.js"), "dangerousCall();\n").unwrap();

        let (findings, _skipped) = run(
            &project,
            &pack,
            &DetectedFrameworks::default(),
            &AuditOptions::default(),
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "only/hit.js");
    }

    const SECRET_RULE_YAML: &str = r#"
id: audit/hardcoded-secret
severity: critical
confidence: high
languages: [javascript, python]
description: test rule — hardcoded secret
message: "hardcoded secret detected"
remediation: move to an environment variable
refs: []
matchers:
  - secret: true
fixtures:
  positive: [a.js, b.js, c.js]
  negative: [d.js, e.js, f.js]
"#;

    #[test]
    fn secret_matcher_rule_emits_masked_finding_never_the_raw_value() {
        let rules_dir = tempdir("secret-rules");
        std::fs::write(rules_dir.join("rule.yaml"), SECRET_RULE_YAML).unwrap();
        let pack = build_pack(&rules_dir);

        let project = tempdir("secret-project");
        std::fs::write(
            project.join("config.js"),
            "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
        )
        .unwrap();

        let (findings, skipped) = run(
            &project,
            &pack,
            &DetectedFrameworks::default(),
            &AuditOptions::default(),
        )
        .unwrap();
        assert!(skipped.is_empty());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "audit/hardcoded-secret");

        let json = serde_json::to_string(&findings).unwrap();
        assert!(!json.contains("FAKEFAKEFAKE1234"));
        assert!(json.contains("sk_live_…1234"));
    }

    /// PREC-04/D-09: an entropy-fallback secret in a `*.test.*` file is
    /// suppressed, but a provider-format key in that same test file still fires
    /// (the gate is on the entropy fallback only — recall preserved), and an
    /// entropy secret in a non-test file is unaffected.
    #[test]
    fn entropy_fallback_is_suppressed_in_test_files_but_provider_keys_still_fire() {
        let rules_dir = tempdir("secret-testpath-rules");
        std::fs::write(rules_dir.join("rule.yaml"), SECRET_RULE_YAML).unwrap();
        let pack = build_pack(&rules_dir);

        let project = tempdir("secret-testpath-project");
        // an entropy-fallback secret (mixed-case+digit random body) in a test
        // file — must be suppressed.
        std::fs::write(
            project.join("thing.test.js"),
            "const apiToken = \"9fQ4cA2e78bZ1dY6fX3aP5cV0e9K\";\n",
        )
        .unwrap();
        // a provider-format key in a test file — must STILL fire.
        std::fs::write(
            project.join("keys.spec.js"),
            "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
        )
        .unwrap();
        // an entropy-fallback secret in a NON-test file — unaffected.
        std::fs::write(
            project.join("config.js"),
            "const apiToken = \"7hK2mN9pQ4rS6tV8wX1yZ3bC5dE0fG\";\n",
        )
        .unwrap();

        let (findings, _skipped) = run(
            &project,
            &pack,
            &DetectedFrameworks::default(),
            &AuditOptions::default(),
        )
        .unwrap();

        let files: std::collections::HashSet<&str> =
            findings.iter().map(|f| f.file.as_str()).collect();
        assert!(
            !files.contains("thing.test.js"),
            "entropy fallback in a .test.js file must be suppressed, got: {findings:?}"
        );
        assert!(
            files.contains("keys.spec.js"),
            "a provider-format key in a .spec.js file must still fire, got: {findings:?}"
        );
        assert!(
            files.contains("config.js"),
            "an entropy secret in a non-test file must be unaffected, got: {findings:?}"
        );
    }

    const TEXT_REGEX_RELATIVE_GLOB_YAML: &str = r#"
id: audit/test-text-relative-glob
severity: high
confidence: high
languages: [javascript]
description: test rule — root-relative file_glob text matcher
message: "relative-glob text hit"
remediation: fix it
refs: []
matchers:
  - file_glob: "config/*.rules"
    text_pattern: "allow all"
fixtures:
  positive: [a.rules, b.rules, c.rules]
  negative: [d.rules, e.rules, f.rules]
"#;

    /// IN-02: a text-regex `file_glob` written root-relative (no `**/`
    /// prefix) must match against the project-relative path, exactly like the
    /// AST `path_glob` gate. Pre-fix the matcher globbed the ABSOLUTE path, so
    /// `config/*.rules` never matched and the rule was silently dead.
    #[test]
    fn text_matcher_globs_against_relative_path() {
        let rules_dir = tempdir("text-rel-rules");
        std::fs::write(rules_dir.join("rule.yaml"), TEXT_REGEX_RELATIVE_GLOB_YAML).unwrap();
        let pack = build_pack(&rules_dir);

        let project = tempdir("text-rel-project");
        std::fs::create_dir_all(project.join("config")).unwrap();
        std::fs::write(project.join("config/firestore.rules"), "allow all\n").unwrap();
        // Same content, outside config/ — the relative glob must NOT match it.
        std::fs::write(project.join("elsewhere.rules"), "allow all\n").unwrap();

        let (findings, skipped) = run(
            &project,
            &pack,
            &DetectedFrameworks::default(),
            &AuditOptions::default(),
        )
        .unwrap();
        assert!(skipped.is_empty());
        assert_eq!(
            findings.len(),
            1,
            "relative file_glob must fire: {findings:?}"
        );
        assert_eq!(findings[0].file, "config/firestore.rules");
    }

    #[test]
    fn findings_below_severity_floor_are_dropped() {
        let rules_dir = tempdir("severity-rules");
        std::fs::write(rules_dir.join("rule.yaml"), AST_RULE_YAML).unwrap();
        let pack = build_pack(&rules_dir);

        let project = tempdir("severity-project");
        std::fs::write(project.join("hit.js"), "dangerousCall();\n").unwrap();

        let opts = AuditOptions {
            severity_min: Severity::Critical,
        };
        let (findings, _skipped) =
            run(&project, &pack, &DetectedFrameworks::default(), &opts).unwrap();
        assert!(findings.is_empty(), "high < critical floor must be dropped");
    }
}
