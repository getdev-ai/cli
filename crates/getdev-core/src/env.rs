//! `getdev env` — extract hardcoded secrets to `.env`.
//!
//! Pipeline (docs/PLAN.md §2.3): **detect → plan → apply**. This module
//! implements detect + plan; apply (`--write`) goes through `core::mutate`
//! (P1 slice 2). Default is always dry-run.
//!
//! Raw secret values stay inside [`PlanEntry::value`] (crate-private, never
//! serialized); everything user-visible carries only masked previews.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::findings::{Finding, Severity};
use crate::mutate::{self, MutateError, PlannedWrite};
use crate::scan::{self, Lang, ScanContext, ScanError, StringAssignment};
use crate::secrets::{PatternError, SecretMatch, SecretPatterns};

#[derive(Debug, thiserror::Error)]
pub enum EnvError {
    #[error(transparent)]
    Patterns(#[from] PatternError),
    #[error(transparent)]
    Scan(#[from] ScanError),
    #[error(transparent)]
    Mutate(#[from] MutateError),
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} changed since the plan was computed — re-run getdev env")]
    Stale { path: PathBuf },
}

#[derive(Debug, Clone)]
pub struct EnvOptions {
    /// target env file name, default ".env"
    pub env_file: String,
    /// also extract http(s) URLs + connection strings assigned to identifiers
    /// (`--include-urls`). Default `false` — when unset, detection is
    /// byte-identical to secret-only behaviour. The CLI flag / `[env]
    /// include_urls` config that flips this is wired in 08-05; this crate only
    /// owns the detection it gates.
    pub include_urls: bool,
}

impl Default for EnvOptions {
    fn default() -> Self {
        Self {
            env_file: ".env".to_owned(),
            include_urls: false,
        }
    }
}

/// One planned extraction: a detected secret plus the env var it becomes.
///
/// `Debug` is hand-rolled (C6/03-REVIEW.md) rather than derived: the derive
/// would print `value` (the raw secret) verbatim, and nothing today stops a
/// future `dbg!(entry)` or `format!("{entry:?}")` from leaking it. Every
/// other field is unchanged from the derived output.
pub struct PlanEntry {
    pub var_name: String,
    /// project-relative path, forward slashes
    pub file: String,
    pub lang: Lang,
    pub line: u32,
    pub column: u32,
    pub identifier: String,
    pub secret: SecretMatch,
    /// byte span of the literal (incl. quotes) for the rewrite step
    pub value_span: (usize, usize),
    /// the raw secret — crate-private; only apply may read it
    pub(crate) value: String,
}

impl std::fmt::Debug for PlanEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlanEntry")
            .field("var_name", &self.var_name)
            .field("file", &self.file)
            .field("lang", &self.lang)
            .field("line", &self.line)
            .field("column", &self.column)
            .field("identifier", &self.identifier)
            .field("secret", &self.secret)
            .field("value_span", &self.value_span)
            .field("value", &"«redacted»")
            .finish()
    }
}

#[derive(Debug)]
pub struct EnvPlan {
    pub entries: Vec<PlanEntry>,
    /// files skipped as unreadable (reported, never fatal)
    pub skipped: Vec<ScanError>,
    /// whether the target env file already exists at the scan root
    pub env_file_exists: bool,
}

/// Detect hardcoded secrets under `root` and plan their extraction. Walks +
/// parses the project itself (the standalone `getdev env` entry). `check`
/// (07-04) instead reuses its shared parse-once context via
/// [`plan_from_context`] so there is no second walk.
pub fn plan(root: &Path, options: &EnvOptions) -> Result<EnvPlan, EnvError> {
    let (assignments, skipped) = scan::collect_string_assignments(root)?;
    plan_from_assignments(root, options, assignments, skipped)
}

/// [`plan`] over a caller-provided parse-once [`ScanContext`] — the DETECT-mode
/// entry `check` (07-04) uses so secret detection reuses check's single shared
/// scan instead of walking + parsing the project a second time (CLAUDE.md
/// rule 5 / Phase 7 Success Criterion 1). The string assignments come from the
/// context's cached trees ([`scan::string_assignments_from_context`]); the
/// oversized/unreadable SOURCE skips live in [`ScanContext::skipped`], surfaced
/// by the context's owner, so the returned plan's `skipped` is empty (no
/// double-count — the same ownership split 07-02/07-03 established).
pub fn plan_from_context(ctx: &ScanContext, options: &EnvOptions) -> Result<EnvPlan, EnvError> {
    let assignments = scan::string_assignments_from_context(ctx);
    plan_from_assignments(&ctx.root, options, assignments, Vec::new())
}

/// Shared body of [`plan`]/[`plan_from_context`]: classify already-collected
/// string assignments into extraction entries. Factored out so the walking and
/// shared-context callers produce byte-identical plans from the same
/// classification/dedupe/order logic (one code path, never two).
fn plan_from_assignments(
    root: &Path,
    options: &EnvOptions,
    mut assignments: Vec<StringAssignment>,
    skipped: Vec<ScanError>,
) -> Result<EnvPlan, EnvError> {
    let patterns = SecretPatterns::embedded()?;

    // WR-03/02-env-REVIEW.md: `dedupe_name` assigns the `_2` suffix in the
    // order it visits assignments, so which of two same-named secrets gets
    // `API_KEY` vs `API_KEY_2` — a name→value binding written to `.env` —
    // must not depend on filesystem walk order (`collect_string_assignments`
    // yields `ignore::WalkBuilder` traversal order, which is OS/FS-dependent).
    // Impose a stable total order (path, then byte offset within the file)
    // before the dedupe loop so the same input always produces the same
    // bindings — the non-negotiable deterministic-core guarantee (CLAUDE.md).
    assignments.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.value_span.0.cmp(&b.value_span.0))
    });

    let env_path = root.join(&options.env_file);
    let mut taken = existing_env_keys(&env_path);
    let env_file_exists = env_path.exists();

    let mut entries = Vec::new();
    for assignment in assignments {
        // Secret patterns first (unchanged). When `--include-urls` is on and a
        // value is NOT already a secret, additionally test it against the
        // deterministic URL / connection-string classifier — folded into the
        // same loop, gated so default behaviour is byte-identical.
        let secret = match patterns.classify(&assignment.value, &assignment.name) {
            Some(secret) => secret,
            None if options.include_urls => match crate::secrets::classify_url(&assignment.value) {
                Some(url_match) => url_match,
                None => continue,
            },
            None => continue,
        };
        let base_name = if secret.env_key.is_empty() {
            identifier_to_env_key(&assignment.name)
        } else {
            secret.env_key.clone()
        };
        let var_name = dedupe_name(&base_name, &mut taken);
        entries.push(PlanEntry {
            var_name,
            file: relative_display(&assignment.path, root),
            lang: assignment.lang,
            line: assignment.line,
            column: assignment.column,
            identifier: assignment.name,
            secret,
            value_span: assignment.value_span,
            value: assignment.value,
        });
    }

    // stable order: worst severity first, then file/line — matches renderers
    entries.sort_by(|a, b| {
        b.secret
            .severity
            .cmp(&a.secret.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    Ok(EnvPlan {
        entries,
        skipped,
        env_file_exists,
    })
}

/// Render the plan as findings (docs/SPEC-FINDINGS.md). The findings list IS
/// the dry-run output contract for `getdev env`.
pub fn findings(plan: &EnvPlan, options: &EnvOptions) -> Vec<Finding> {
    plan.entries
        .iter()
        .map(|entry| {
            let provider = if entry.secret.provider == "generic" {
                "high-entropy".to_owned()
            } else {
                entry.secret.provider.clone()
            };
            Finding {
                id: "env/hardcoded-secret".to_owned(),
                command: "env".to_owned(),
                severity: entry.secret.severity,
                confidence: entry.secret.confidence,
                file: entry.file.clone(),
                line: Some(entry.line),
                column: Some(entry.column),
                end_line: Some(entry.line),
                message: format!(
                    "{provider} secret assigned to '{}' ({})",
                    entry.identifier, entry.secret.masked
                ),
                detail: Some(format!(
                    "matched pattern '{}'; planned extraction: {} in {}",
                    entry.secret.pattern_id, entry.var_name, options.env_file
                )),
                suggestion: Some(format!(
                    "extract to {} in {}",
                    entry.var_name, options.env_file
                )),
                remediation: Some("run: getdev env --write".to_owned()),
                fixable: true,
                refs: vec!["https://getdev.ai/rules/env/hardcoded-secret".to_owned()],
                fingerprint: None,
            }
        })
        .collect()
}

/// STRIPE_SECRET_KEY-style name from an identifier: camelCase / kebab-case /
/// snake_case → SCREAMING_SNAKE.
pub fn identifier_to_env_key(identifier: &str) -> String {
    let mut out = String::with_capacity(identifier.len() + 4);
    let mut prev_lower = false;
    for c in identifier.chars() {
        if c == '-' || c == '_' || c == ' ' {
            if !out.ends_with('_') {
                out.push('_');
            }
            prev_lower = false;
        } else if c.is_ascii_uppercase() && prev_lower {
            out.push('_');
            out.push(c);
            prev_lower = false;
        } else {
            out.push(c.to_ascii_uppercase());
            prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        }
    }
    let out = out.trim_matches('_').to_owned();
    if out.is_empty() {
        return "SECRET".to_owned();
    }
    // WR-01/02-env-REVIEW.md: a leading digit (e.g. from the string-keyed
    // object shape `{"2fa_token": …}`) would produce `process.env.2FA_TOKEN`
    // — a JS syntax error whose reparse-verify failure aborts the ENTIRE
    // `--write`, stranding every other valid extraction — and a non-POSIX
    // shell name that can't be `export`ed. Both a JS identifier and a POSIX
    // env name may begin with `_` but never a digit, so prefix one: sanitize
    // the entry rather than let it block the whole plan.
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{out}")
    } else {
        out
    }
}

fn dedupe_name(base: &str, taken: &mut HashSet<String>) -> String {
    if taken.insert(base.to_owned()) {
        return base.to_owned();
    }
    // IN-01/02-env-REVIEW.md: bound the counter and never panic. The old
    // `for n in 2..` used an inferred `i32` that would itself panic on
    // overflow before the trailing `unreachable!` was reached — a latent
    // panic path in library code, forbidden by CLAUDE.md hard rule 1.
    // Exhaustion needs ~4 billion same-named secrets (practically
    // impossible); on that theoretical ceiling, fall back to the base name
    // (a duplicate .env key is harmless — last-wins — and far better than a
    // crash across the crate boundary).
    for n in 2u32..=u32::MAX {
        let candidate = format!("{base}_{n}");
        if taken.insert(candidate.clone()) {
            return candidate;
        }
    }
    base.to_owned()
}

fn existing_env_keys(env_path: &Path) -> HashSet<String> {
    let Ok(content) = std::fs::read_to_string(env_path) else {
        return HashSet::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return None;
            }
            line.split_once('=').map(|(key, _)| key.trim().to_owned())
        })
        .collect()
}

fn relative_display(path: &Path, root: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.to_string_lossy().replace('\\', "/")
}

/// Highest severity in the plan, if any — used for `--fail-on`.
pub fn max_severity(plan: &EnvPlan) -> Option<Severity> {
    plan.entries.iter().map(|e| e.secret.severity).max()
}

/// What `apply` did, for the command's summary output.
#[derive(Debug)]
pub struct AppliedSummary {
    pub vars_written: Vec<String>,
    /// C9/03-REVIEW.md: planned var names that were NOT appended to the env
    /// file because a same-named key already existed there at apply time
    /// (the `.env` may have changed since `plan()` ran — edited externally,
    /// or a second `getdev env --write` raced this one). Source files were
    /// still rewritten to reference these var names; only the duplicate
    /// `.env` line was skipped.
    pub vars_skipped_stale: Vec<String>,
    pub files_rewritten: Vec<String>,
    pub env_file_created: bool,
    pub example_file: String,
    pub gitignore_patched: bool,
}

/// Apply the plan (`--write`): rewrite each literal to the stack's idiomatic
/// env accessor, write `.env` (values) and `.env.example` (keys only), and
/// ensure the env file is gitignored. All disk changes go through
/// [`crate::mutate`] — verified in memory first, atomic, rolled back on
/// mid-plan failure. NOTE: raw secret values are written to exactly one
/// place: the env file.
pub fn apply(
    root: &Path,
    plan: &EnvPlan,
    options: &EnvOptions,
    hook: Option<&dyn crate::mutate::PreMutateHook>,
) -> Result<AppliedSummary, EnvError> {
    let mut writes: Vec<PlannedWrite> = Vec::new();

    // group rewrites per file, replacing spans back-to-front
    let mut by_file: Vec<(&str, Vec<&PlanEntry>)> = Vec::new();
    for entry in &plan.entries {
        match by_file.iter_mut().find(|(file, _)| *file == entry.file) {
            Some((_, group)) => group.push(entry),
            None => by_file.push((entry.file.as_str(), vec![entry])),
        }
    }

    let mut files_rewritten = Vec::new();
    for (file, mut group) in by_file {
        let path = root.join(file);
        let original = std::fs::read_to_string(&path).map_err(|source| EnvError::Read {
            path: path.clone(),
            source,
        })?;
        group.sort_by_key(|e| std::cmp::Reverse(e.value_span.0));

        let lang = group[0].lang;
        let mut content = original.clone();
        for entry in &group {
            let (start, end) = entry.value_span;
            // the span must still hold the exact literal we planned against
            let current = content.get(start..end);
            if current.is_none_or(|lit| !lit.contains(entry.value.as_str())) {
                return Err(EnvError::Stale { path });
            }
            content.replace_range(start..end, &accessor(lang, &entry.var_name));
        }
        if lang == Lang::Python {
            content = ensure_os_import(&content);
        }

        files_rewritten.push(file.to_owned());
        writes.push(PlannedWrite::RewriteSource {
            path,
            lang,
            original,
            new_content: content,
        });
    }

    // .env — append values, never rewrite existing lines. `env_original` is
    // re-read from disk right here, at apply time — not whatever `.env`
    // looked like when `plan()` computed dedupe suffixes. C9/03-REVIEW.md:
    // if a planned key has since appeared in the file (edited externally
    // between plan and apply, or a second `getdev env --write` raced this
    // one), appending it again would duplicate the key — dotenv parsers
    // silently last-wins-shadow duplicate keys, hiding whichever line came
    // first. Skip those instead of duplicating, and report the skip.
    let env_path = root.join(&options.env_file);
    let env_original = read_optional(&env_path);
    let existing_env_keys = keys_of(env_original.as_deref().unwrap_or(""));
    let mut env_content = env_original.clone().unwrap_or_default();
    ensure_trailing_newline(&mut env_content);
    let mut vars_written = Vec::new();
    let mut vars_skipped_stale = Vec::new();
    let mut new_lines = String::new();
    // IN-04/02-env-REVIEW.md: `entry.value` is the VERBATIM inner text of the
    // source literal — `scan::strip_string_delimiters` removes the quotes but
    // does NOT decode escapes (`\n`, `\x41`, `\uXXXX`). This is intentional
    // and load-bearing: the staleness guard above (`content.get(span)` must
    // still `.contains(entry.value)`) compares against the on-disk source
    // bytes, so the value must stay in source form. The trade-off is that a
    // secret literal containing backslash escapes is emitted to `.env` in its
    // escaped source form, which can differ from the program's runtime value.
    // Impact is negligible in practice — provider keys and high-entropy
    // fallbacks are escape-free — and decoding correctly is language-specific
    // (JS vs Python escape grammars) and belongs in the scan/parse layer, not
    // here. Documented as a known limitation rather than half-decoded.
    for entry in &plan.entries {
        if existing_env_keys.contains(&entry.var_name) {
            vars_skipped_stale.push(entry.var_name.clone());
            continue;
        }
        new_lines.push_str(&format!(
            "{}={}\n",
            entry.var_name,
            dotenv_quote(&entry.value)
        ));
        vars_written.push(entry.var_name.clone());
    }
    if !new_lines.is_empty() {
        env_content.push_str("# added by getdev env\n");
        env_content.push_str(&new_lines);
    }
    writes.push(PlannedWrite::WriteFile {
        path: env_path,
        original: env_original.clone(),
        new_content: env_content,
    });

    // .env.example — keys only, never values
    let example_file = format!("{}.example", options.env_file);
    let example_path = root.join(&example_file);
    let example_original = read_optional(&example_path);
    let mut example_content = example_original.clone().unwrap_or_default();
    ensure_trailing_newline(&mut example_content);
    let existing_example_keys = keys_of(example_original.as_deref().unwrap_or(""));
    for entry in &plan.entries {
        if !existing_example_keys.contains(&entry.var_name) {
            example_content.push_str(&format!("{}=\n", entry.var_name));
        }
    }
    writes.push(PlannedWrite::WriteFile {
        path: example_path,
        original: example_original,
        new_content: example_content,
    });

    // .gitignore — ensure the env file can't be committed going forward
    let gitignore_path = root.join(".gitignore");
    let gitignore_original = read_optional(&gitignore_path);
    let gitignore_patched = !gitignore_covers(
        gitignore_original.as_deref().unwrap_or(""),
        &options.env_file,
    );
    if gitignore_patched {
        let mut gitignore_content = gitignore_original.clone().unwrap_or_default();
        ensure_trailing_newline(&mut gitignore_content);
        gitignore_content.push_str(&options.env_file);
        gitignore_content.push('\n');
        writes.push(PlannedWrite::WriteFile {
            path: gitignore_path,
            original: gitignore_original,
            new_content: gitignore_content,
        });
    }

    mutate::apply(writes, hook)?;

    Ok(AppliedSummary {
        vars_written,
        vars_skipped_stale,
        files_rewritten,
        env_file_created: env_original.is_none(),
        example_file,
        gitignore_patched,
    })
}

/// The idiomatic env accessor for each stack.
fn accessor(lang: Lang, var_name: &str) -> String {
    match lang {
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => format!("process.env.{var_name}"),
        Lang::Python => format!("os.environ[\"{var_name}\"]"),
    }
}

/// Insert `import os` if the module doesn't import it, after any shebang,
/// leading comments, module docstring, and `from __future__ import …`
/// statements (inserting before the docstring would demote it to a plain
/// expression; inserting before a `__future__` import is a SyntaxError —
/// CPython requires those to be the first statement(s) in the module,
/// C1/03-REVIEW.md).
fn ensure_os_import(content: &str) -> String {
    let has_os_import = content.lines().any(|line| {
        let line = line.trim_start();
        // Only forms that actually bind the name `os` satisfy the
        // requirement. `import os.path` still binds `os` (and the submodule),
        // so it counts. `from os import getenv` / `from os.path import join`
        // bind `getenv`/`join` — NOT `os` — so they must NOT count
        // (CR-01/02-env-REVIEW.md): treating them as satisfied suppressed the
        // `import os` injection, leaving the injected `os.environ[...]`
        // referencing an unbound name → `NameError` at runtime, while
        // reparse-verify (syntax-only) still passed.
        line == "import os"
            || line.starts_with("import os ")
            || line.starts_with("import os,")
            || line.starts_with("import os.")
    });
    if has_os_import {
        return content.to_owned();
    }

    let mut insert_at = 0;
    let mut in_docstring: Option<&str> = None;
    for line in content.split_inclusive('\n') {
        let trimmed = line.trim();
        if let Some(delim) = in_docstring {
            insert_at += line.len();
            if trimmed.ends_with(delim) {
                in_docstring = None;
            }
            continue;
        }
        let is_prefix = trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with("#!")
            || trimmed.starts_with("# -*-");
        if is_prefix {
            insert_at += line.len();
            continue;
        }
        if let Some(delim) = ["\"\"\"", "'''"].iter().find(|d| trimmed.starts_with(**d)) {
            insert_at += line.len();
            // single-line docstring closes on the same line
            if trimmed.len() < delim.len() * 2 || !trimmed.ends_with(*delim) {
                in_docstring = Some(delim);
            }
            continue;
        }
        if trimmed.starts_with("from __future__ import") {
            insert_at += line.len();
            continue;
        }
        break;
    }

    let mut out = String::with_capacity(content.len() + 12);
    out.push_str(&content[..insert_at]);
    out.push_str("import os\n");
    out.push_str(&content[insert_at..]);
    out
}

/// dotenv-format value: quote when the value contains characters that would
/// change meaning unquoted.
///
/// WR-02/02-env-REVIEW.md: a newline is whitespace, so it triggers quoting —
/// but writing the raw newline splits `KEY=` across physical lines, and
/// dotenv parsers that don't support multi-line double-quoted values mis-read
/// the key and every line after it. Highest-severity secret shapes (PEM
/// private keys — the `private-key-block` pattern — and JS/Python
/// triple-quoted literals) carry real newlines, so escape `\n`/`\r` inside
/// the quoted branch (dotenv decodes `\n`/`\r` back inside double quotes),
/// keeping the value on one logical line. `\\` is escaped first so the
/// backslashes we introduce for `\n`/`\r` are not doubled.
fn dotenv_quote(value: &str) -> String {
    if value.contains(|c: char| c.is_whitespace() || c == '#' || c == '"' || c == '\'') {
        format!(
            "\"{}\"",
            value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\r', "\\r")
                .replace('\n', "\\n")
        )
    } else {
        value.to_owned()
    }
}

fn read_optional(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn ensure_trailing_newline(content: &mut String) {
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
}

fn keys_of(env_content: &str) -> HashSet<String> {
    env_content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return None;
            }
            line.split_once('=').map(|(k, _)| k.trim().to_owned())
        })
        .collect()
}

fn gitignore_covers(gitignore: &str, env_file: &str) -> bool {
    gitignore.lines().any(|line| {
        let line = line.trim();
        line == env_file || line == format!("/{env_file}") || line == ".env*" || line == ".env.*"
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn identifier_naming() {
        assert_eq!(identifier_to_env_key("stripeKey"), "STRIPE_KEY");
        assert_eq!(identifier_to_env_key("apiToken2"), "API_TOKEN2");
        assert_eq!(identifier_to_env_key("db-password"), "DB_PASSWORD");
        assert_eq!(identifier_to_env_key("AWS_SECRET"), "AWS_SECRET");
        assert_eq!(identifier_to_env_key("_"), "SECRET");
    }

    /// WR-01 regression: a name starting with a digit must be sanitized to a
    /// valid JS identifier / POSIX env name (leading `_`), not left as
    /// `2FA_TOKEN` which would compile to `process.env.2FA_TOKEN`.
    #[test]
    fn identifier_naming_prefixes_leading_digit() {
        assert_eq!(identifier_to_env_key("2fa_token"), "_2FA_TOKEN");
        assert_eq!(identifier_to_env_key("3d-secret"), "_3D_SECRET");
        // a digit that only appears mid-name is fine, unchanged
        assert_eq!(identifier_to_env_key("oauth2Token"), "OAUTH2_TOKEN");
    }

    /// WR-01 end-to-end: a secret whose object key starts with a digit must
    /// NOT abort the whole `--write`. Both it and a normal secret in the same
    /// file get extracted, and the rewritten source parses cleanly (apply's
    /// reparse-verify would reject `process.env.2FA_TOKEN`).
    #[test]
    fn apply_sanitizes_leading_digit_name_without_aborting_plan() {
        let dir = std::env::temp_dir().join(format!(
            "getdev-env-wr01-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // digit-leading object key (entropy secret) + a normal provider key
        std::fs::write(
            dir.join("cfg.js"),
            "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n\
             const cfg = { \"2fa_token\": \"9fQ4cA2e78bZ1dY6fX3aP5cV0e9K\" };\n",
        )
        .unwrap();

        let plan = plan(&dir, &EnvOptions::default()).unwrap();
        // both secrets planned — neither dropped
        assert_eq!(plan.entries.len(), 2, "both secrets must be planned");
        let names: Vec<&str> = plan.entries.iter().map(|e| e.var_name.as_str()).collect();
        assert!(
            names.contains(&"_2FA_TOKEN"),
            "leading digit sanitized: {names:?}"
        );
        assert!(names.contains(&"STRIPE_SECRET_KEY"), "{names:?}");

        // apply must succeed — mutate's reparse-verify rejects invalid JS, so
        // Ok here proves `process.env._2FA_TOKEN` is syntactically valid.
        apply(&dir, &plan, &EnvOptions::default(), None).unwrap();

        let rewritten = std::fs::read_to_string(dir.join("cfg.js")).unwrap();
        assert!(rewritten.contains("process.env._2FA_TOKEN"), "{rewritten}");
        assert!(
            rewritten.contains("process.env.STRIPE_SECRET_KEY"),
            "{rewritten}"
        );

        let env_file = std::fs::read_to_string(dir.join(".env")).unwrap();
        assert!(env_file.contains("_2FA_TOKEN="), "{env_file}");
        assert!(env_file.contains("STRIPE_SECRET_KEY="), "{env_file}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dedupe_appends_counter() {
        let mut taken = HashSet::from(["STRIPE_SECRET_KEY".to_owned()]);
        assert_eq!(
            dedupe_name("STRIPE_SECRET_KEY", &mut taken),
            "STRIPE_SECRET_KEY_2"
        );
        assert_eq!(
            dedupe_name("STRIPE_SECRET_KEY", &mut taken),
            "STRIPE_SECRET_KEY_3"
        );
        assert_eq!(dedupe_name("OTHER", &mut taken), "OTHER");
    }

    /// IN-01 regression: the suffix loop must keep producing unique names via
    /// the counter path without panicking, even after many collisions (the
    /// old `for n in 2..` inferred an `i32` that would panic on overflow).
    #[test]
    fn dedupe_never_panics_over_many_collisions() {
        let mut taken = HashSet::new();
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let name = dedupe_name("KEY", &mut taken);
            assert!(seen.insert(name), "each dedupe result must be unique");
        }
        // base name first, then KEY_2..KEY_1000 — all distinct, no panic
        assert!(seen.contains("KEY"));
        assert!(seen.contains("KEY_1000"));
    }

    /// C1 regression: `import os` must land AFTER any `from __future__
    /// import …` line(s) — CPython requires future-imports to be the first
    /// statement(s) in the module, so inserting `import os` before them
    /// raises `SyntaxError: from __future__ imports must occur at the
    /// beginning of the file`.
    #[test]
    fn ensure_os_import_lands_after_future_imports() {
        let content = "from __future__ import annotations\n\nvalue = 1\n";
        let out = ensure_os_import(content);

        let future_pos = out.find("from __future__ import annotations").unwrap();
        let os_pos = out.find("import os").unwrap();
        assert!(
            os_pos > future_pos,
            "import os must be inserted after the __future__ import, got:\n{out}"
        );

        // must also parse cleanly as Python
        let mut parser = getdev_grammars::tree_sitter::Parser::new();
        parser.set_language(&Lang::Python.language()).unwrap();
        let tree = parser.parse(&out, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "rewritten module must parse cleanly:\n{out}"
        );
    }

    /// Multiple future-import lines (a real-world shape) all get skipped.
    #[test]
    fn ensure_os_import_skips_multiple_future_imports() {
        let content = "\"\"\"Module docstring.\"\"\"\nfrom __future__ import annotations\nfrom __future__ import division\n\nvalue = 1\n";
        let out = ensure_os_import(content);
        let last_future = out.rfind("from __future__ import division").unwrap();
        let os_pos = out.find("import os").unwrap();
        assert!(os_pos > last_future);

        let mut parser = getdev_grammars::tree_sitter::Parser::new();
        parser.set_language(&Lang::Python.language()).unwrap();
        let tree = parser.parse(&out, None).unwrap();
        assert!(!tree.root_node().has_error());
    }

    fn parses_clean(src: &str) -> bool {
        let mut parser = getdev_grammars::tree_sitter::Parser::new();
        parser.set_language(&Lang::Python.language()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        !tree.root_node().has_error()
    }

    /// CR-01 regression: `from os import getenv` binds `getenv`, NOT `os`, so
    /// it must NOT satisfy the `import os` requirement. Without the injected
    /// `import os`, the rewritten `os.environ["…"]` raises `NameError: name
    /// 'os' is not defined` at runtime — a silently-broken module that
    /// reparse-verify (syntax-only) never catches.
    #[test]
    fn ensure_os_import_injects_when_only_from_os_import_present() {
        let content = "from os import getenv\n\nvalue = 1\n";
        let out = ensure_os_import(content);
        assert!(
            out.lines().any(|l| l.trim() == "import os"),
            "import os must be injected even though `from os import …` is present, got:\n{out}"
        );
        assert!(
            parses_clean(&out),
            "rewritten module must parse cleanly:\n{out}"
        );
    }

    /// `from os.path import join` likewise binds `join`, not `os`.
    #[test]
    fn ensure_os_import_injects_when_only_from_os_path_import_present() {
        let content = "from os.path import join\n\nvalue = 1\n";
        let out = ensure_os_import(content);
        assert!(
            out.lines().any(|l| l.trim() == "import os"),
            "import os must be injected for `from os.path import …`, got:\n{out}"
        );
        assert!(
            parses_clean(&out),
            "rewritten module must parse cleanly:\n{out}"
        );
    }

    /// End-to-end through `apply`: a Python module that only does
    /// `from os import getenv` and hardcodes a secret must, after --write,
    /// gain a real `import os` and reference it via `os.environ[...]` —
    /// binding `os` so the module still runs.
    #[test]
    fn apply_injects_import_os_for_from_os_import_module() {
        let dir = std::env::temp_dir().join(format!(
            "getdev-env-cr01-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config.py"),
            "from os import getenv\n\naws_key = \"AKIAFAKEFAKEFAKEFAKE\"\n",
        )
        .unwrap();

        let plan = plan(&dir, &EnvOptions::default()).unwrap();
        apply(&dir, &plan, &EnvOptions::default(), None).unwrap();

        let rewritten = std::fs::read_to_string(dir.join("config.py")).unwrap();
        assert!(
            rewritten.lines().any(|l| l.trim() == "import os"),
            "apply must inject `import os`, got:\n{rewritten}"
        );
        assert!(
            rewritten.contains("os.environ[\"AWS_ACCESS_KEY_ID\"]"),
            "apply must rewrite the literal to os.environ[...], got:\n{rewritten}"
        );
        // the `from os import getenv` must survive; `os` must now be bound
        assert!(rewritten.contains("from os import getenv"));
        assert!(
            parses_clean(&rewritten),
            "rewritten module must parse cleanly:\n{rewritten}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A genuine `import os` must NOT be duplicated.
    #[test]
    fn ensure_os_import_not_duplicated_when_os_truly_bound() {
        let content = "import os\n\nvalue = 1\n";
        let out = ensure_os_import(content);
        assert_eq!(
            out.matches("import os").count(),
            1,
            "must not duplicate import os:\n{out}"
        );
    }

    /// `import os.path` binds `os` too — still counts, no second import.
    #[test]
    fn ensure_os_import_respects_import_os_submodule() {
        let content = "import os.path\n\nvalue = 1\n";
        let out = ensure_os_import(content);
        assert_eq!(
            out, content,
            "import os.path already binds os; nothing to inject"
        );
    }

    /// C6 regression: `{:?}` on a `PlanEntry` must never print the raw
    /// secret value, even though the field carries it internally.
    #[test]
    fn plan_entry_debug_redacts_value() {
        let entry = PlanEntry {
            var_name: "STRIPE_SECRET_KEY".to_owned(),
            file: "pay.js".to_owned(),
            lang: Lang::JavaScript,
            line: 1,
            column: 1,
            identifier: "stripeKey".to_owned(),
            secret: crate::secrets::SecretPatterns::embedded()
                .unwrap()
                .classify("sk_live_FAKEFAKEFAKE1234", "stripeKey")
                .unwrap(),
            value_span: (0, 10),
            value: "sk_live_FAKEFAKEFAKE1234".to_owned(),
        };
        let debug_output = format!("{entry:?}");
        assert!(!debug_output.contains("sk_live_FAKEFAKEFAKE1234"));
        assert!(debug_output.contains("«redacted»"));
    }

    /// WR-03 regression: when two files assign the same base var name, which
    /// gets `API_KEY` vs `API_KEY_2` (a name→value binding written to disk)
    /// must be deterministic — pinned to path order, not filesystem walk
    /// order. The alphabetically-first path always wins the un-suffixed name.
    #[test]
    fn dedupe_suffix_binding_is_deterministic_across_files() {
        let dir = std::env::temp_dir().join(format!(
            "getdev-env-wr03-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // same base name (`apiKey` → API_KEY) in two files, distinct values
        std::fs::write(
            dir.join("a.js"),
            "const apiKey = \"9fQ4cA2e78bZ1dY6fX3aP5cV0e9K\";\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("b.js"),
            "const apiKey = \"7kP2mN8qR4tW6vX1yZ3bC5dF9gH0\";\n",
        )
        .unwrap();

        // repeat: the binding must be identical every run
        for _ in 0..5 {
            let plan = plan(&dir, &EnvOptions::default()).unwrap();
            let name_for = |file: &str| -> String {
                plan.entries
                    .iter()
                    .find(|e| e.file == file)
                    .map(|e| e.var_name.clone())
                    .unwrap_or_default()
            };
            assert_eq!(name_for("a.js"), "API_KEY", "first path wins the base name");
            assert_eq!(name_for("b.js"), "API_KEY_2", "later path gets the suffix");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// WR-02 regression: a multi-line value (PEM key / triple-quoted literal)
    /// must be written as a single logical `.env` entry — quoted with `\n`
    /// escaped — not split across physical lines.
    #[test]
    fn dotenv_quote_escapes_newlines_into_one_line() {
        let pem = "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----";
        let quoted = dotenv_quote(pem);
        assert!(
            !quoted.contains('\n'),
            "quoted value must not contain a raw newline: {quoted:?}"
        );
        assert!(
            quoted.starts_with('"') && quoted.ends_with('"'),
            "{quoted:?}"
        );
        assert_eq!(
            quoted,
            "\"-----BEGIN KEY-----\\nabc\\ndef\\n-----END KEY-----\""
        );
        // a whole `KEY=value\n` line stays a single physical line
        let line = format!("K={quoted}\n");
        assert_eq!(line.matches('\n').count(), 1, "one trailing newline only");
        // carriage returns are escaped too
        assert!(!dotenv_quote("a\r\nb").contains('\r'));
    }

    /// IN-04 characterization: `entry.value` is the verbatim source literal
    /// (escapes NOT decoded), by design — the staleness guard compares against
    /// on-disk source bytes. A secret whose literal contains a `\n` escape is
    /// therefore emitted to `.env` in its escaped source form, and apply still
    /// succeeds (no spurious Stale error). This pins the documented behavior;
    /// decoding escapes would be a language-specific scan-layer change.
    #[test]
    fn env_value_is_written_verbatim_escapes_not_decoded() {
        let dir = std::env::temp_dir().join(format!(
            "getdev-env-in04-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // the JS source literal contains a two-char `\n` escape (backslash + n),
        // NOT an actual newline; the value is high-entropy + secret-ish name.
        std::fs::write(
            dir.join("cfg.js"),
            "const apiToken = \"9fQ4cA2e78bZ1\\ndY6fX3aP5cV0e9K\";\n",
        )
        .unwrap();

        let plan = plan(&dir, &EnvOptions::default()).unwrap();
        assert_eq!(
            plan.entries.len(),
            1,
            "value with a \\n escape still classifies"
        );
        // apply must not raise Stale — the verbatim value matches source bytes
        apply(&dir, &plan, &EnvOptions::default(), None).unwrap();

        let env_file = std::fs::read_to_string(dir.join(".env")).unwrap();
        // written in escaped source form (literal backslash-n), NOT a newline
        assert!(
            env_file.contains("9fQ4cA2e78bZ1\\ndY6fX3aP5cV0e9K"),
            "value emitted verbatim (escapes not decoded), got:\n{env_file}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The gate defaults off: `EnvOptions::default()` never enables URL
    /// detection, so today's secret-only behaviour is preserved untouched.
    #[test]
    fn include_urls_defaults_off() {
        assert!(!EnvOptions::default().include_urls);
    }

    /// Regression: with `include_urls=false`, a file that contains BOTH a real
    /// secret and a URL/DSN plans EXACTLY the secret — byte-identical to
    /// today. The URL is invisible unless the gate is on.
    #[test]
    fn include_urls_off_is_byte_identical_to_secret_only() {
        let dir = fresh_dir("gate-off");
        std::fs::write(
            dir.join("cfg.js"),
            "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n\
             const dbUrl = \"postgres://u:p@host:5432/db\";\n\
             const apiBase = \"https://api.example.com/v1\";\n",
        )
        .unwrap();

        let plan = plan(&dir, &EnvOptions::default()).unwrap();
        assert_eq!(
            plan.entries.len(),
            1,
            "only the secret is planned when the gate is off"
        );
        assert_eq!(plan.entries[0].var_name, "STRIPE_SECRET_KEY");
        assert_eq!(plan.entries[0].secret.provider, "stripe");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With the gate ON: the credentialed DSN and the plain URL are planned
    /// alongside the secret, and the DSN's finding masks the credential — the
    /// raw password never reaches the output (T-08-04).
    #[test]
    fn include_urls_on_plans_urls_and_masks_credentials() {
        let dir = fresh_dir("gate-on");
        std::fs::write(
            dir.join("cfg.js"),
            "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n\
             const dbUrl = \"postgres://admin:s3cr3tP@db.internal:5432/app\";\n\
             const apiBase = \"https://api.example.com/v1\";\n",
        )
        .unwrap();

        let opts = EnvOptions {
            include_urls: true,
            ..Default::default()
        };
        let plan = plan(&dir, &opts).unwrap();
        let names: Vec<&str> = plan.entries.iter().map(|e| e.var_name.as_str()).collect();
        assert_eq!(plan.entries.len(), 3, "secret + DSN + URL: {names:?}");
        assert!(names.contains(&"STRIPE_SECRET_KEY"), "{names:?}");
        assert!(names.contains(&"DB_URL"), "{names:?}");
        assert!(names.contains(&"API_BASE"), "{names:?}");

        // credential never leaks into any finding field
        let findings = findings(&plan, &opts);
        let json = serde_json::to_string(&findings).unwrap();
        assert!(
            !json.contains("s3cr3tP"),
            "raw DSN credential leaked into findings: {json}"
        );
        assert!(
            json.contains("postgres://admin:…@db.internal:5432/app"),
            "masked DSN preview missing: {json}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn fresh_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-env-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn plan_end_to_end_on_temp_project() {
        let dir = std::env::temp_dir().join(format!("getdev-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("pay.js"),
            "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
        )
        .unwrap();
        std::fs::write(dir.join("aws.py"), "aws_key = \"AKIAFAKEFAKEFAKEFAKE\"\n").unwrap();
        // existing .env forces a collision suffix
        std::fs::write(dir.join(".env"), "STRIPE_SECRET_KEY=already-there\n").unwrap();

        let plan = plan(&dir, &EnvOptions::default()).unwrap();
        assert_eq!(plan.entries.len(), 2);
        assert!(plan.env_file_exists);
        let names: Vec<&str> = plan.entries.iter().map(|e| e.var_name.as_str()).collect();
        assert!(names.contains(&"STRIPE_SECRET_KEY_2"));
        assert!(names.contains(&"AWS_ACCESS_KEY_ID"));

        let findings = findings(&plan, &EnvOptions::default());
        let json = serde_json::to_string(&findings).unwrap();
        assert!(
            !json.contains("FAKEFAKEFAKE"),
            "raw secret leaked into findings"
        );
        assert!(json.contains("sk_live_…1234"));
    }
}
