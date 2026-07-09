//! Renderers. Every renderer consumes the same [`FindingsReport`]; analyzers
//! never print — all user-facing output flows through this module.

use std::fmt::Write as _;

use owo_colors::OwoColorize;

use crate::findings::{Confidence, Finding, FindingsReport, Severity};

/// Whether terminal output should use ANSI colors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    On,
    Off,
}

impl ColorMode {
    /// Resolve from the environment: `--no-color` flag wins, then the
    /// `NO_COLOR` convention (any non-empty value), then whether stdout is
    /// a terminal (the caller passes that — core does not probe the tty).
    pub fn resolve(no_color_flag: bool, stdout_is_tty: bool) -> Self {
        let no_color_env = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        if no_color_flag || no_color_env || !stdout_is_tty {
            Self::Off
        } else {
            Self::On
        }
    }
}

/// The `--json` output: the serialized [`FindingsReport`], pretty-printed,
/// trailing newline. Schema: docs/SPEC-FINDINGS.md.
pub fn render_json(report: &FindingsReport) -> Result<String, serde_json::Error> {
    let mut out = serde_json::to_string_pretty(report)?;
    out.push('\n');
    Ok(out)
}

/// Human terminal output: findings grouped by severity (worst first), each
/// with location, message, and the most actionable next step.
pub fn render_terminal(report: &FindingsReport, color: ColorMode) -> String {
    let mut out = String::new();

    if report.findings.is_empty() {
        let _ = writeln!(out, "no findings — clean");
        return out;
    }

    for severity in Severity::ALL_DESC {
        let group: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect();
        if group.is_empty() {
            continue;
        }
        for finding in group {
            render_finding(&mut out, finding, color);
        }
    }

    let s = &report.summary;
    let _ = writeln!(
        out,
        "{} finding(s): {} critical · {} high · {} medium · {} low · {} info ({} fixable)",
        s.total(),
        s.critical,
        s.high,
        s.medium,
        s.low,
        s.info,
        s.fixable
    );
    out
}

fn render_finding(out: &mut String, finding: &Finding, color: ColorMode) {
    let location = match finding.line {
        Some(line) => format!("{}:{line}", finding.file),
        None => finding.file.clone(),
    };

    let label = severity_label(finding.severity, color);
    let _ = writeln!(out, "{label:<10} {:<28} {location}", finding.id);

    let mut message = finding.message.clone();
    if finding.confidence < Confidence::High {
        let _ = write!(message, " (confidence: {})", finding.confidence);
    }
    let _ = writeln!(out, "  {message}");

    if let Some(suggestion) = &finding.suggestion {
        let _ = writeln!(out, "  → {suggestion}");
    } else if let Some(remediation) = &finding.remediation {
        let _ = writeln!(out, "  → {remediation}");
    }
}

fn severity_label(severity: Severity, color: ColorMode) -> String {
    let text = severity.as_str().to_uppercase();
    if color == ColorMode::Off {
        return text;
    }
    match severity {
        Severity::Critical => text.red().bold().to_string(),
        Severity::High => text.red().to_string(),
        Severity::Medium => text.yellow().to_string(),
        Severity::Low => text.cyan().to_string(),
        Severity::Info => text.dimmed().to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::findings::{ProjectInfo, Summary};

    fn report(findings: Vec<Finding>) -> FindingsReport {
        FindingsReport::new(
            "0.1.0-dev",
            ProjectInfo {
                path: ".".into(),
                stack: vec!["node".into()],
            },
            findings,
        )
    }

    fn finding(severity: Severity, confidence: Confidence) -> Finding {
        Finding {
            id: "real/nonexistent-package".into(),
            command: "real".into(),
            severity,
            confidence,
            file: "requirements.txt".into(),
            line: Some(4),
            column: None,
            end_line: None,
            message: "Package 'requests-auth-helper' does not exist on PyPI".into(),
            detail: None,
            suggestion: Some("did you mean 'requests-oauthlib'?".into()),
            remediation: None,
            fixable: false,
            refs: vec![],
            fingerprint: None,
        }
    }

    #[test]
    fn json_matches_schema_shape() {
        let rendered =
            render_json(&report(vec![finding(Severity::Critical, Confidence::High)])).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["schema_version"], "1");
        assert_eq!(value["findings"][0]["id"], "real/nonexistent-package");
        assert!(rendered.ends_with('\n'));
    }

    #[test]
    fn terminal_groups_worst_first_and_shows_location() {
        let out = render_terminal(
            &report(vec![
                finding(Severity::Low, Confidence::High),
                finding(Severity::Critical, Confidence::High),
            ]),
            ColorMode::Off,
        );
        let critical_pos = out.find("CRITICAL").unwrap();
        let low_pos = out.find("LOW").unwrap();
        assert!(critical_pos < low_pos);
        assert!(out.contains("requirements.txt:4"));
        assert!(out.contains("→ did you mean 'requests-oauthlib'?"));
        assert!(out.contains("2 finding(s)"));
        // no ANSI escapes when color is off
        assert!(!out.contains('\u{1b}'));
    }

    #[test]
    fn low_confidence_is_visually_distinguished() {
        let out = render_terminal(
            &report(vec![finding(Severity::High, Confidence::Low)]),
            ColorMode::Off,
        );
        assert!(out.contains("(confidence: low)"));
    }

    #[test]
    fn clean_report_says_clean() {
        let out = render_terminal(&report(vec![]), ColorMode::Off);
        assert!(out.contains("no findings"));
        let empty = Summary::default();
        assert_eq!(empty.total(), 0);
    }
}
