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

    // `severity_label` returns the label already padded to the column width
    // (and colorized after padding) — do NOT re-apply a `:<10` here: under
    // color the string carries ANSI escape bytes, and format-spec padding
    // counts those bytes, so the columns would drift by the escape length
    // (IN-03).
    let label = severity_label(finding.severity, color);
    let _ = writeln!(out, "{label} {:<28} {location}", finding.id);

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

/// Column width the severity label is padded to. Must fit the widest label
/// (`CRITICAL`, 8) plus breathing room.
const SEVERITY_LABEL_WIDTH: usize = 10;

fn severity_label(severity: Severity, color: ColorMode) -> String {
    // IN-03: pad the PLAIN text to the column width FIRST, then colorize the
    // padded string. Colorizing first (and padding the result) would make the
    // caller's width spec count the ANSI escape bytes and misalign every
    // colored row. With this order the visible width is always
    // `SEVERITY_LABEL_WIDTH` whether color is on or off.
    let text = format!(
        "{:<width$}",
        severity.as_str().to_uppercase(),
        width = SEVERITY_LABEL_WIDTH
    );
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

    /// Strip ANSI SGR escape sequences (`ESC [ ... m`) so a colored line can
    /// be measured by its VISIBLE width.
    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                // consume up to and including the terminating 'm'
                for e in chars.by_ref() {
                    if e == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// IN-03 regression: under color the severity label carries ANSI escape
    /// bytes, but its VISIBLE width must stay fixed so the `id`/location
    /// columns line up. Render two findings whose labels differ in length
    /// (`CRITICAL` vs `LOW`) with color ON, strip the escapes, and assert the
    /// id column starts at the same visible offset on both rows.
    #[test]
    fn colored_labels_keep_columns_aligned() {
        let out = render_terminal(
            &report(vec![
                finding(Severity::Critical, Confidence::High),
                finding(Severity::Low, Confidence::High),
            ]),
            ColorMode::On,
        );
        // color must actually have been applied
        assert!(
            out.contains('\u{1b}'),
            "expected ANSI escapes with color on"
        );

        let id_col = |needle: &str| -> usize {
            let line = out
                .lines()
                .map(strip_ansi)
                .find(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("no {needle} row in:\n{out}"));
            line.find("real/nonexistent-package")
                .unwrap_or_else(|| panic!("id must be present on the row: {line}"))
        };
        assert_eq!(
            id_col("CRITICAL"),
            id_col("LOW"),
            "the id column must start at the same visible offset regardless of label length"
        );
        // and the visible offset is exactly the padded label width + 1 space
        assert_eq!(id_col("CRITICAL"), SEVERITY_LABEL_WIDTH + 1);
    }

    #[test]
    fn clean_report_says_clean() {
        let out = render_terminal(&report(vec![]), ColorMode::Off);
        assert!(out.contains("no findings"));
        let empty = Summary::default();
        assert_eq!(empty.total(), 0);
    }
}
