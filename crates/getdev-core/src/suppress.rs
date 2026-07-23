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
        // D-12: match on the STORED `finding.fingerprint` (the canonical
        // `gdv1:` identity written by `fingerprint::assign_fingerprints`) —
        // never recompute an ad-hoc `(rule,file,line)` hash here. A finding
        // with no fingerprint (unreachable once the batch pass has run before
        // every command's `filter_findings`) simply never matches a
        // `[[suppress]]` entry.
        if let Some(suppression) = finding
            .fingerprint
            .as_deref()
            .and_then(|fp| cfg.suppressions.iter().find(|s| s.fingerprint == fp))
        {
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
        // D-12: the finding must carry its canonical `gdv1:` fingerprint first
        // (the batch pass is the sole writer), and the `[[suppress]]` entry
        // must pin that same stored value — `filter_findings` reads the field,
        // it no longer recomputes an ad-hoc hash.
        let mut f = finding("audit/hardcoded-secret", "src/config.js", Some(9));
        crate::fingerprint::assign_fingerprints(std::slice::from_mut(&mut f));
        let fp = f.fingerprint.clone().unwrap();
        assert!(fp.starts_with("gdv1:"), "stored fingerprint must be gdv1:");
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

    /// D-12/D-13 inversion of the old `fingerprint_changes_with_line_but_not_with_message`:
    /// that test encoded BOTH wrong behaviors of the deleted ad-hoc formula
    /// (identity keyed on the raw line, blind to matched content). The `gdv1:`
    /// identity flips both polarities — a line shift leaves the fingerprint
    /// byte-identical, and a change in matched content produces a different one.
    #[test]
    fn fingerprint_stable_across_line_shift_and_changes_with_content() {
        // Give the findings a real content seed so the batch pass has something
        // to hash beyond the default empty seed.
        let seed = |text: &str| crate::fingerprint::FingerprintSeed {
            node_kind: "string",
            matched_text: text.to_owned(),
        };
        let fp_of = |mut f: Finding| {
            crate::fingerprint::assign_fingerprints(std::slice::from_mut(&mut f));
            f.fingerprint.clone().unwrap()
        };

        // Same rule/file/content, different line → byte-identical identity.
        let mut a = finding("real/phantom-import", "src/app.js", Some(3));
        a.seed = seed("not-a-real-logger-xyz");
        let mut b = finding("real/phantom-import", "src/app.js", Some(103));
        b.seed = seed("not-a-real-logger-xyz");
        assert_eq!(
            fp_of(a.clone()),
            fp_of(b),
            "a line shift must not change the fingerprint"
        );

        // Same rule/file/line, different matched content → different identity.
        let mut c = finding("real/phantom-import", "src/app.js", Some(3));
        c.seed = seed("some-other-import-name");
        assert_ne!(
            fp_of(a),
            fp_of(c),
            "a change in matched content must change the fingerprint"
        );
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
