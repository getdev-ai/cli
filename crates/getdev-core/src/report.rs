//! Renderers. Every renderer consumes the same [`FindingsReport`]; analyzers
//! never print — all user-facing output flows through this module.

use std::fmt::Write as _;

use owo_colors::OwoColorize;

use crate::findings::{Confidence, Finding, FindingsReport, Severity, Summary};

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

/// The per-severity Ship Score deduction weights, worst-first — the SINGLE
/// versioned source of the scoring table (docs/SPEC-COMMANDS.md `check`:
/// "weights live in one versioned source file and are printed with `-v`").
/// Each value is [`Severity::ship_score_weight`], so the formula is never
/// duplicated: [`ship_score`] applies it and [`render_ship_score_weights`]
/// prints it. `Info` is intentionally excluded (weight 0 — info never dents
/// the score).
pub const SHIP_SCORE_WEIGHTS: [(Severity, i32); 4] = [
    (Severity::Critical, Severity::Critical.ship_score_weight()),
    (Severity::High, Severity::High.ship_score_weight()),
    (Severity::Medium, Severity::Medium.ship_score_weight()),
    (Severity::Low, Severity::Low.ship_score_weight()),
];

/// Compute the Ship Score (docs/SPEC-COMMANDS.md `check`): start at 100 and
/// subtract each finding's [`Severity::ship_score_weight`], floored at 0. The
/// per-severity weights are the single versioned source
/// ([`SHIP_SCORE_WEIGHTS`]); this is the ONLY place the formula is evaluated.
/// `check` is the only command that ever sets `FindingsReport.score`.
pub fn ship_score(summary: &Summary) -> u8 {
    let deduction = summary.critical as i32 * Severity::Critical.ship_score_weight()
        + summary.high as i32 * Severity::High.ship_score_weight()
        + summary.medium as i32 * Severity::Medium.ship_score_weight()
        + summary.low as i32 * Severity::Low.ship_score_weight();
    (100 - deduction).clamp(0, 100) as u8
}

/// Render the versioned Ship Score weight table for `check -v`, so the CLI
/// never inlines the weights (they stay single-sourced in `getdev-core`).
pub fn render_ship_score_weights() -> String {
    let mut out = String::new();
    let _ = writeln!(out, "ship score weights (start 100, floor 0):");
    for (severity, weight) in SHIP_SCORE_WEIGHTS {
        let _ = writeln!(out, "  {:<8} -{weight}", severity.as_str());
    }
    out
}

/// Human terminal output: findings grouped by severity (worst first), each
/// with location, message, and the most actionable next step.
pub fn render_terminal(report: &FindingsReport, color: ColorMode) -> String {
    let mut out = String::new();

    // `check` is the only command that sets `score` (docs/SPEC-COMMANDS.md):
    // when present, lead with the normative Ship Score banner instead of the
    // trailing summary line. Every other command leaves `score = None` and the
    // renderer behaves exactly as before.
    if let Some(score) = report.score {
        render_score_banner(&mut out, &report.summary, score);
    }

    if report.findings.is_empty() {
        // The banner already conveys a clean run (Ship Score 100/100 · all
        // zeros) for `check`; only the non-check path prints the plain line.
        if report.score.is_none() {
            let _ = writeln!(out, "no findings — clean");
        }
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

    if report.score.is_some() {
        render_top_three(&mut out, &report.findings);
        let fixable = report.summary.fixable;
        if fixable > 0 {
            let _ = writeln!(
                out,
                "{fixable} finding(s) fixable — run: getdev env --write"
            );
        }
    } else {
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
    }
    out
}

/// Visible inner width of the Ship Score banner box (columns between the
/// vertical borders). Sized to fit the normative golden-block content line
/// `  N critical · N high · N medium · N low` with breathing room.
const BANNER_INNER_WIDTH: usize = 46;

/// The normative Ship Score banner (docs/SPEC-COMMANDS.md `check` golden
/// block): a box-drawn header carrying the `NN/100` score and the
/// `N critical · N high · N medium · N low` tally. Deterministic string
/// output — no color-dependent content (the box is identical whether ANSI is
/// on or off).
fn render_score_banner(out: &mut String, summary: &Summary, score: u8) {
    let title = "─ getdev check ";
    let title_cols = title.chars().count();
    let fill = BANNER_INNER_WIDTH.saturating_sub(title_cols);
    let _ = writeln!(out, "┌{title}{}┐", "─".repeat(fill));
    let score_line = format!("  Ship Score: {score}/100");
    let _ = writeln!(out, "│{score_line:<BANNER_INNER_WIDTH$}│");
    let counts = format!(
        "  {} critical · {} high · {} medium · {} low",
        summary.critical, summary.high, summary.medium, summary.low
    );
    let _ = writeln!(out, "│{counts:<BANNER_INNER_WIDTH$}│");
    let _ = writeln!(out, "└{}┘", "─".repeat(BANNER_INNER_WIDTH));
}

/// The getdev wordmark (figlet "slant"), shown once by `getdev init` as a
/// first-run welcome. A plain raw literal — the `render_welcome_banner` caller
/// decides whether it is colorized. Kept ASCII-only so it renders identically
/// in any terminal encoding.
const WELCOME_WORDMARK: &str = r"               __      __
   ____ ____  / /_____/ /__ _   __
  / __ `/ _ \/ __/ __  / _ \ | / /
 / /_/ /  __/ /_/ /_/ /  __/ |/ /
 \__, /\___/\__/\__,_/\___/|___/
/____/";

/// The one-time first-run welcome banner for `getdev init`: the slant wordmark
/// plus a two-line tagline that only restates the product promise (NO
/// call-to-action — CLAUDE.md standing rules; no telemetry/CTA/account-gating).
/// `color` gates ANSI only: `Off` returns the exact same shape as plain UTF-8,
/// so `--no-color`/`NO_COLOR`/a piped stdout yield a clean monochrome banner.
/// The caller decides *whether* to show it (init suppresses under `--quiet` and
/// `--json`); this decides only *how* it looks. `version` is the CLI's
/// `CARGO_PKG_VERSION`, threaded in because `getdev-core` has no version of its
/// own to print.
pub fn render_welcome_banner(version: &str, color: ColorMode) -> String {
    let promise = "  verify · secure · ship AI-generated code";
    let footer = format!("  v{version} · local-first · nothing leaves your machine");
    let mut out = String::new();
    match color {
        ColorMode::On => {
            let _ = writeln!(out, "{}", WELCOME_WORDMARK.cyan().bold());
            let _ = writeln!(out, "{}", promise.dimmed());
            let _ = writeln!(out, "{}", footer.dimmed());
        }
        ColorMode::Off => {
            let _ = writeln!(out, "{WELCOME_WORDMARK}");
            let _ = writeln!(out, "{promise}");
            let _ = writeln!(out, "{footer}");
        }
    }
    out
}

/// "top 3 things to fix first" (docs/SPEC-COMMANDS.md `check`): the three
/// highest-severity findings. `findings` is already sorted worst-first by
/// [`FindingsReport::new`], so the slice head IS that ordering — deterministic
/// with no re-sort.
fn render_top_three(out: &mut String, findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    let _ = writeln!(out, "\ntop 3 things to fix first:");
    for (n, finding) in findings.iter().take(3).enumerate() {
        let location = match finding.line {
            Some(line) => format!("{}:{line}", finding.file),
            None => finding.file.clone(),
        };
        let _ = writeln!(
            out,
            "  {}. {} {location} — {}",
            n + 1,
            finding.id,
            finding.message
        );
    }
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

    fn summary(critical: usize, high: usize, medium: usize, low: usize) -> Summary {
        Summary {
            critical,
            high,
            medium,
            low,
            info: 0,
            fixable: 0,
        }
    }

    /// The Ship Score formula is the single normative source
    /// (docs/SPEC-COMMANDS.md `check`: critical −25, high −10, medium −4,
    /// low −1; floor 0). Assert it exactly against several tallies, including
    /// the SPEC golden block's own tally.
    #[test]
    fn ship_score_applies_the_versioned_formula() {
        // clean project → perfect score
        assert_eq!(ship_score(&summary(0, 0, 0, 0)), 100);
        // one of each weighted severity: 100 − (25+10+4+1) = 60
        assert_eq!(ship_score(&summary(1, 1, 1, 1)), 60);
        // mid-range: 100 − (25+2·10+3·1) = 100 − 48 = 52
        assert_eq!(ship_score(&summary(1, 2, 0, 3)), 52);
        // the SPEC golden block's tally (2 critical · 3 high · 5 medium ·
        // 4 low): deduction = 50+30+20+4 = 104, floored to 0. (The SPEC's
        // banner illustration prints "43/100" for these counts, which is
        // arithmetically inconsistent with the same SPEC's stated weights;
        // the formula — the normative rule per docs/SPEC-FINDINGS.md
        // invariant 5 — governs, and it floors here.)
        assert_eq!(ship_score(&summary(2, 3, 5, 4)), 0);
        // info never dents the score
        let mut only_info = summary(0, 0, 0, 0);
        only_info.info = 9;
        assert_eq!(ship_score(&only_info), 100);
    }

    /// The weight table is single-sourced: each entry equals the corresponding
    /// `Severity::ship_score_weight`, and `-v` prints them.
    #[test]
    fn ship_score_weights_are_single_sourced_and_printable() {
        assert_eq!(
            SHIP_SCORE_WEIGHTS,
            [
                (Severity::Critical, 25),
                (Severity::High, 10),
                (Severity::Medium, 4),
                (Severity::Low, 1),
            ]
        );
        for (severity, weight) in SHIP_SCORE_WEIGHTS {
            assert_eq!(severity.ship_score_weight(), weight);
        }
        let printed = render_ship_score_weights();
        assert!(printed.contains("critical -25"));
        assert!(printed.contains("low      -1"));
    }

    /// When a score is present (`check`), the terminal renderer leads with the
    /// normative box-drawn banner and closes with "top 3 things to fix first"
    /// plus the fixable hint — none of which appear for the plain (score-less)
    /// path.
    #[test]
    fn score_present_renders_ship_banner_and_top_three() {
        let mut rep = report(vec![
            finding(Severity::Critical, Confidence::High),
            finding(Severity::Low, Confidence::High),
        ]);
        rep.score = Some(ship_score(&rep.summary));
        let out = render_terminal(&rep, ColorMode::Off);
        assert!(out.contains("┌─ getdev check "));
        assert!(out.contains("Ship Score: "));
        assert!(out.contains("1 critical · 0 high · 0 medium · 1 low"));
        assert!(out.contains("top 3 things to fix first:"));
        // the box borders are balanced
        assert!(out.contains('└') && out.contains('┐'));
        // and the plain summary line is NOT emitted in score mode
        assert!(!out.contains("finding(s): 1 critical"));
    }

    /// A clean `check` run still shows the banner (100/100) rather than the
    /// bare "no findings" line.
    #[test]
    fn score_present_clean_shows_full_banner() {
        let mut rep = report(vec![]);
        rep.score = Some(ship_score(&rep.summary));
        let out = render_terminal(&rep, ColorMode::Off);
        assert!(out.contains("Ship Score: 100/100"));
        assert!(out.contains("0 critical · 0 high · 0 medium · 0 low"));
        assert!(!out.contains("no findings"));
    }

    /// The first-run welcome banner: plain mode carries the wordmark, the
    /// product-promise tagline, and the version, with zero ANSI bytes; colored
    /// mode wraps the same content in escape sequences. Neither mode emits a
    /// call-to-action (CLAUDE.md standing rules).
    #[test]
    fn welcome_banner_plain_is_ansi_free_colored_is_not() {
        let plain = render_welcome_banner("0.1.0", ColorMode::Off);
        assert!(plain.contains("verify · secure · ship AI-generated code"));
        assert!(plain.contains("v0.1.0 · local-first · nothing leaves your machine"));
        // slant wordmark signature fragment
        assert!(plain.contains("____"));
        // plain mode is escape-free (safe to pipe)
        assert!(!plain.contains('\u{1b}'));
        // no CTA creeps in
        let lower = plain.to_lowercase();
        assert!(!lower.contains("star") && !lower.contains("sign up") && !lower.contains("http"));

        let colored = render_welcome_banner("0.1.0", ColorMode::On);
        assert!(colored.contains('\u{1b}'));
        assert!(colored.contains("nothing leaves your machine"));
    }
}
