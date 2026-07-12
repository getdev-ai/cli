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

use getdev_grammars::tree_sitter::{Node, Parser, QueryCursor};
use globset::{Glob, GlobSet, GlobSetBuilder};
use streaming_iterator::StreamingIterator;

use crate::deps::relative_display;
use crate::findings::{Confidence, Finding, Severity};
use crate::frameworks::DetectedFrameworks;
use crate::rules::{CompiledTextMatcher, Matcher, Rule, RulePack};
use crate::scan::{project_walker, read_source_capped, Lang, ScanError, StringAssignment};
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

/// Run every rule in `pack` over every file under `root`, gated by
/// `frameworks` (project-level `frameworks:` selector) and each rule's
/// `languages`/`path_glob` selectors, producing schema-conformant
/// [`Finding`]s. Findings below `opts.severity_min` are dropped before
/// returning.
///
/// # Errors
/// Returns [`AuditError`] only for fatal engine conditions (a grammar/query
/// mismatch, or the embedded secret pattern pack failing to parse) — never
/// for a single unreadable/oversized project file, which is collected in
/// the second return value instead.
pub fn run(
    root: &Path,
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

    for entry in project_walker(root).build().flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        let rel = relative_display(path, root);
        let lang = Lang::from_path(path);

        let candidate_text: Vec<&TextRule<'_>> = text_rules
            .iter()
            .filter(|tr| tr.matcher.glob_matches(path))
            .collect();

        // Nothing in the pack could possibly apply to this file — skip it
        // without even reading it (F7-adjacent: don't pay a read cost for
        // files no rule cares about).
        if lang.is_none() && candidate_text.is_empty() {
            continue;
        }

        let source = match read_source_capped(path) {
            Ok(source) => source,
            Err(err) => {
                skipped.push(err);
                continue;
            }
        };
        let bytes = source.as_bytes();

        for tr in &candidate_text {
            if !framework_gate(tr.rule, frameworks) {
                continue;
            }
            if !path_glob_gate(path_globs[tr.rule_index].as_ref(), &rel) {
                continue;
            }
            if tr.matcher.is_match(path, bytes) {
                findings.push(text_hit_to_finding(tr.rule, &rel));
            }
        }

        if let Some(lang) = lang {
            match process_lang_file(path, &rel, lang, &source, &lang_ctx) {
                Ok(mut hits) => findings.append(&mut hits),
                Err(err @ (ScanError::Grammar(_) | ScanError::Query(_))) => {
                    return Err(err.into());
                }
                Err(err) => skipped.push(err),
            }
        }
    }

    findings.retain(|f| f.severity >= opts.severity_min);
    Ok((findings, skipped))
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

/// One file's worth of AST/secret matching — parses `source` exactly ONCE
/// (Pitfall 7) and runs every applicable rule's AST or secret matcher
/// against that single tree.
fn process_lang_file(
    path: &Path,
    rel: &str,
    lang: Lang,
    source: &str,
    ctx: &LangFileContext<'_>,
) -> Result<Vec<Finding>, ScanError> {
    let language = lang.language();
    let mut parser = Parser::new();
    parser.set_language(&language)?;
    let tree = parser.parse(source, None).ok_or_else(|| ScanError::Parse {
        path: path.to_path_buf(),
    })?;
    let root_node = tree.root_node();
    let bytes = source.as_bytes();

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
                    findings.push(ast_hit_to_finding(rule, node, rel));
                }
            }
        }

        // Secret: classify the file's string assignments once if this rule
        // declares a secret matcher.
        if rule.matchers.iter().any(|m| matches!(m, Matcher::Secret)) {
            let assignments = crate::scan::string_assignments_from_tree(&tree, source, lang, path)?;
            for assignment in &assignments {
                if let Some(secret) = ctx
                    .secret_patterns
                    .classify(&assignment.value, &assignment.name)
                {
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
fn run_ast_matcher<'tree>(
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

fn ast_hit_to_finding(rule: &Rule, node: Node<'_>, file: &str) -> Finding {
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
        fingerprint: None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::rules::{self, QueryCache};
    use std::path::PathBuf;

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
