//! `getdev env` — extract hardcoded secrets to `.env`.
//!
//! Pipeline (docs/PLAN.md §2.3): **detect → plan → apply**. This module
//! implements detect + plan; apply (`--write`) goes through `core::mutate`
//! (P1 slice 2). Default is always dry-run.
//!
//! Raw secret values stay inside [`PlanEntry::value`] (crate-private, never
//! serialized); everything user-visible carries only masked previews.

use std::collections::HashSet;
use std::path::Path;

use crate::findings::{Finding, Severity};
use crate::scan::{self, ScanError};
use crate::secrets::{PatternError, SecretMatch, SecretPatterns};

#[derive(Debug, thiserror::Error)]
pub enum EnvError {
    #[error(transparent)]
    Patterns(#[from] PatternError),
    #[error(transparent)]
    Scan(#[from] ScanError),
}

#[derive(Debug, Clone)]
pub struct EnvOptions {
    /// target env file name, default ".env"
    pub env_file: String,
}

impl Default for EnvOptions {
    fn default() -> Self {
        Self {
            env_file: ".env".to_owned(),
        }
    }
}

/// One planned extraction: a detected secret plus the env var it becomes.
#[derive(Debug)]
pub struct PlanEntry {
    pub var_name: String,
    /// project-relative path, forward slashes
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub identifier: String,
    pub secret: SecretMatch,
    /// byte span of the literal (incl. quotes) for the rewrite step
    pub value_span: (usize, usize),
    /// the raw secret — crate-private; only `mutate`/apply may read it
    /// (unused until the --write slice lands)
    #[allow(dead_code)]
    pub(crate) value: String,
}

#[derive(Debug)]
pub struct EnvPlan {
    pub entries: Vec<PlanEntry>,
    /// files skipped as unreadable (reported, never fatal)
    pub skipped: Vec<ScanError>,
    /// whether the target env file already exists at the scan root
    pub env_file_exists: bool,
}

/// Detect hardcoded secrets under `root` and plan their extraction.
pub fn plan(root: &Path, options: &EnvOptions) -> Result<EnvPlan, EnvError> {
    let patterns = SecretPatterns::embedded()?;
    let (assignments, skipped) = scan::collect_string_assignments(root)?;

    let env_path = root.join(&options.env_file);
    let mut taken = existing_env_keys(&env_path);
    let env_file_exists = env_path.exists();

    let mut entries = Vec::new();
    for assignment in assignments {
        let Some(secret) = patterns.classify(&assignment.value, &assignment.name) else {
            continue;
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
        "SECRET".to_owned()
    } else {
        out
    }
}

fn dedupe_name(base: &str, taken: &mut HashSet<String>) -> String {
    if taken.insert(base.to_owned()) {
        return base.to_owned();
    }
    for n in 2.. {
        let candidate = format!("{base}_{n}");
        if taken.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("dedupe counter exhausted")
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
