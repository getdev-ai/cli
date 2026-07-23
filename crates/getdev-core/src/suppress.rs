//! `[ignore]` and `[[suppress]]` findings filtering (B2 audit fix: these
//! config sections were parsed by `config.rs` and validated at load time,
//! but nothing ever read them — a project could pin `ignore.rules =
//! ["audit/debug-mode-enabled"]` and every run would still report it.
//!
//! Applied by `env`/`real` (the CLI command layer) on the finalized findings
//! list, before `FindingsReport::new` — every renderer downstream (terminal,
//! `--json`) only ever sees the filtered set. `check -v` (a later phase)
//! is expected to reuse the same [`filter_findings`] so suppressions are
//! surfaced consistently, per docs/SPEC-CONFIG.md's "Suppressions are
//! surfaced in `check -v` so they don't rot silently."

use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::findings::Finding;

/// Why a finding was removed from the reported set.
#[derive(Debug, Clone)]
pub enum SuppressionReason {
    /// `finding.id` is listed in `[ignore] rules`.
    IgnoredRule,
    /// `finding.file` starts with one of `[ignore] paths`.
    IgnoredPath(String),
    /// `[[suppress]]` matched by fingerprint; carries the mandatory `reason`.
    Suppressed(String),
}

impl SuppressionReason {
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::IgnoredRule => "ignored (rule listed in [ignore] rules)".to_owned(),
            Self::IgnoredPath(prefix) => {
                format!("ignored (path under [ignore] paths prefix '{prefix}')")
            }
            Self::Suppressed(reason) => format!("suppressed: {reason}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SuppressedFinding {
    pub finding: Finding,
    pub reason: SuppressionReason,
}

#[derive(Debug, Default)]
pub struct FilterOutcome {
    pub kept: Vec<Finding>,
    pub suppressed: Vec<SuppressedFinding>,
}

/// Stable identity hash for a finding: `sha256:` + hex digest of
/// `(rule id, file, line)` — the "(rule, file, normalized context)" formula
/// docs/SPEC-FINDINGS.md documents for the (currently unpopulated on the
/// wire) `Finding.fingerprint` field. Computed here independently of that
/// field so `[[suppress]]` works today without changing the `--json`
/// envelope shape (which stays exactly as documented until the wider
/// baseline feature, v0.2, populates `fingerprint` on every finding).
#[must_use]
pub fn fingerprint(finding: &Finding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding.id.as_bytes());
    hasher.update(b"\0");
    hasher.update(finding.file.as_bytes());
    hasher.update(b"\0");
    if let Some(line) = finding.line {
        hasher.update(line.to_string().as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// Filter `findings` per `cfg.ignore` and `cfg.suppressions`. Order of
/// precedence for *why* a dropped finding was dropped: ignored-by-rule,
/// then ignored-by-path, then suppressed-by-fingerprint — the first that
/// matches wins (a finding is only ever reported once as suppressed).
#[must_use]
pub fn filter_findings(findings: Vec<Finding>, cfg: &Config) -> FilterOutcome {
    let mut outcome = FilterOutcome::default();
    for finding in findings {
        if cfg.ignore.rules.iter().any(|rule| rule == &finding.id) {
            outcome.suppressed.push(SuppressedFinding {
                finding,
                reason: SuppressionReason::IgnoredRule,
            });
            continue;
        }
        if let Some(prefix) = cfg
            .ignore
            .paths
            .iter()
            .find(|prefix| finding.file.starts_with(prefix.as_str()))
        {
            outcome.suppressed.push(SuppressedFinding {
                finding,
                reason: SuppressionReason::IgnoredPath(prefix.clone()),
            });
            continue;
        }
        let fp = fingerprint(&finding);
        if let Some(suppression) = cfg.suppressions.iter().find(|s| s.fingerprint == fp) {
            outcome.suppressed.push(SuppressedFinding {
                finding,
                reason: SuppressionReason::Suppressed(suppression.reason.clone()),
            });
            continue;
        }
        outcome.kept.push(finding);
    }
    outcome
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::findings::{Confidence, Severity};

    fn finding(id: &str, file: &str, line: Option<u32>) -> Finding {
        Finding {
            id: id.to_owned(),
            command: "real".to_owned(),
            severity: Severity::High,
            confidence: Confidence::High,
            file: file.to_owned(),
            line,
            column: None,
            end_line: None,
            message: "test finding".to_owned(),
            detail: None,
            suggestion: None,
            remediation: None,
            fixable: false,
            refs: vec![],
            seed: crate::fingerprint::FingerprintSeed::default(),
            fingerprint: None,
        }
    }

    #[test]
    fn ignored_rule_is_dropped_with_a_reason() {
        let mut cfg = Config::default();
        cfg.ignore.rules = vec!["real/phantom-import".to_owned()];
        let outcome = filter_findings(
            vec![finding("real/phantom-import", "src/app.js", Some(3))],
            &cfg,
        );
        assert!(outcome.kept.is_empty());
        assert_eq!(outcome.suppressed.len(), 1);
        assert!(matches!(
            outcome.suppressed[0].reason,
            SuppressionReason::IgnoredRule
        ));
    }

    #[test]
    fn ignored_path_prefix_is_dropped() {
        let mut cfg = Config::default();
        cfg.ignore.paths = vec!["vendor/".to_owned()];
        let outcome = filter_findings(
            vec![
                finding("real/phantom-import", "vendor/lib/x.js", Some(1)),
                finding("real/phantom-import", "src/app.js", Some(1)),
            ],
            &cfg,
        );
        assert_eq!(outcome.kept.len(), 1);
        assert_eq!(outcome.kept[0].file, "src/app.js");
        assert_eq!(outcome.suppressed.len(), 1);
    }

    #[test]
    fn suppression_matches_by_fingerprint_and_carries_the_reason() {
        let f = finding("audit/hardcoded-secret", "src/config.js", Some(9));
        let fp = fingerprint(&f);
        let cfg = Config {
            suppressions: vec![crate::config::Suppression {
                fingerprint: fp,
                reason: "test fixture key, not a real secret".to_owned(),
            }],
            ..Config::default()
        };
        let outcome = filter_findings(vec![f], &cfg);
        assert!(outcome.kept.is_empty());
        assert_eq!(outcome.suppressed.len(), 1);
        match &outcome.suppressed[0].reason {
            SuppressionReason::Suppressed(reason) => {
                assert_eq!(reason, "test fixture key, not a real secret");
            }
            other => panic!("expected Suppressed, got {other:?}"),
        }
    }

    #[test]
    fn fingerprint_changes_with_line_but_not_with_message() {
        let a = finding("real/phantom-import", "src/app.js", Some(3));
        let mut b = finding("real/phantom-import", "src/app.js", Some(3));
        b.message = "a completely different message".to_owned();
        assert_eq!(fingerprint(&a), fingerprint(&b));

        let c = finding("real/phantom-import", "src/app.js", Some(4));
        assert_ne!(fingerprint(&a), fingerprint(&c));
    }

    #[test]
    fn unmatched_findings_pass_through_unchanged() {
        let cfg = Config::default();
        let outcome = filter_findings(
            vec![finding("real/phantom-import", "src/app.js", Some(3))],
            &cfg,
        );
        assert_eq!(outcome.kept.len(), 1);
        assert!(outcome.suppressed.is_empty());
    }
}
