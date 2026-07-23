//! Renderers. Every renderer consumes the same [`FindingsReport`]; analyzers
//! never print — all user-facing output flows through this module.

use std::collections::BTreeMap;
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

/// The resolved stdout render format for a findings command (docs/SPEC-FINDINGS.md
/// §Renderers, D-04/D-10). `Human`/`Json` are the two existing renderers
/// ([`render_terminal`]/[`render_json`]); `Agent` is the token-lean LLM format
/// ([`render_agent`]). Hosted in `core` so the CLI's clap `ValueEnum` maps onto
/// exactly these three render targets with no bool×enum truth-table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// The default terminal render — grouped, colored, human reading aid.
    #[default]
    Human,
    /// The serialized findings envelope (`--json`, alias `--format=json`).
    Json,
    /// The deterministic, ANSI-free, LLM-shaped report (`--format=agent`).
    Agent,
}

/// The single-sourced exit-gate verdict (D-02/D-03): the OR-to-fail /
/// AND-to-pass composition of the `--fail-on` severity gate and the
/// `--min-score` Ship-Score gate. Produced by [`evaluate_gate`] and consumed by
/// BOTH the CLI exit code (plan 12-03) and [`render_agent`]'s `GATE:` line, so
/// the printed verdict and the process exit code can never disagree. Carries
/// enough detail (`failed_severity`/`failed_score` + the thresholds + the score)
/// to render the `GATE:` reason fragments without a second computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateOutcome {
    /// The overall verdict: `failed_severity || failed_score` (OR-to-fail).
    pub failed: bool,
    /// The `--fail-on` threshold evaluated (`None` ⇒ no severity gate).
    pub fail_on: Option<Severity>,
    /// The `--min-score` floor evaluated (`None` ⇒ no score gate).
    pub min_score: Option<u8>,
    /// The Ship Score the gate compared against (`report.score`) — `None` on
    /// every non-`check` command, which makes `--min-score` inert (D-01).
    pub score: Option<u8>,
    /// True iff findings ≥ `fail_on` (the severity gate tripped).
    pub failed_severity: bool,
    /// True iff `score < min_score` (the score gate tripped; inert when
    /// `report.score` is `None`).
    pub failed_score: bool,
}

/// Evaluate the exit gate (D-02/D-03): the sole implementation of the
/// `--fail-on` + `--min-score` verdict. `failed_severity` mirrors the inline
/// `fail_on.is_some_and(|t| summary.at_or_above(t) > 0)` every command tail used
/// before; `failed_score` is `score < min_score` and is inert when the report
/// carries no score (`check` is the only command that sets one — D-01). The two
/// compose OR-to-fail: `failed` is true iff EITHER trips, so `exit 0` requires
/// both to pass. Infallible — no `unwrap`/`expect`, no panic.
pub fn evaluate_gate(
    report: &FindingsReport,
    fail_on: Option<Severity>,
    min_score: Option<u8>,
) -> GateOutcome {
    let failed_severity = fail_on.is_some_and(|t| report.summary.at_or_above(t) > 0);
    let failed_score = match (min_score, report.score) {
        (Some(min), Some(score)) => score < min,
        _ => false,
    };
    GateOutcome {
        failed: failed_severity || failed_score,
        fail_on,
        min_score,
        score: report.score,
        failed_severity,
        failed_score,
    }
}

/// Upper bound on the synthesized `NEXT ACTIONS` checklist ([`render_agent`],
/// D-07): the deduped remediation list is capped so the section stays
/// token-lean; a trailing `… (M more)` line signals truncation. Single named
/// source — never a scattered magic literal (CLAUDE.md rule 7 spirit).
pub const NEXT_ACTIONS_CAP: usize = 10;

/// The `agent` renderer (`--format=agent`, docs/SPEC-FINDINGS.md §Renderers,
/// D-05..D-09): a deterministic, plain-text, ANSI-free, token-lean report —
/// `--json` minus the JSON tax, plus a synthesized next-actions checklist. Four
/// labeled sections:
///
/// ```text
/// GATE: <pass|fail>[ · score NN/100 < min NN][ · <sev>+ findings ≥ <fail-on>]
/// SUMMARY: <N> findings · <C> critical · … · <K> fixable[ · score NN/100]
/// FINDINGS:
/// <sev> <id> <file>:<line>:<col> — <message> [fixable] <gdv1:…>
/// NEXT ACTIONS:
/// - <deduped remediation>
/// ```
///
/// The `GATE:` line is rendered from the SAME [`GateOutcome`] the CLI exit code
/// reads (D-03), so the printed verdict and the exit code can never disagree.
/// Secret masking is structural (Invariant 2, D-08): like every renderer it
/// consumes only the already-masked `Finding` fields (`message`, `id`, `file`,
/// position) and the one-way `gdv1:` digest — it NEVER touches `finding.seed`
/// (`#[serde(skip)]`, redacting `Debug`), which for `env` findings is the raw
/// secret. No color, ever (an agent reads bytes, not a TTY): the output contains
/// no `\u{1b}`. Deterministic: a pure function of the already-totally-ordered
/// `report.findings`.
pub fn render_agent(report: &FindingsReport, gate: &GateOutcome) -> String {
    let mut out = String::new();

    // GATE: — from the single-sourced `evaluate_gate` (D-03). Each reason
    // fragment appears only when its gate actually tripped, and reads as the
    // failing comparison (`score NN < min NN`, `sev+ ≥ fail-on`).
    let verdict = if gate.failed { "fail" } else { "pass" };
    let _ = write!(out, "GATE: {verdict}");
    if gate.failed_score {
        if let (Some(score), Some(min)) = (gate.score, gate.min_score) {
            let _ = write!(out, " · score {score}/100 < min {min}");
        }
    }
    if gate.failed_severity {
        if let Some(fail_on) = gate.fail_on {
            let sev = fail_on.as_str();
            let _ = write!(out, " · {sev}+ findings ≥ {sev}");
        }
    }
    out.push('\n');

    // SUMMARY: — the severity tally; the `· score NN/100` fragment only when
    // `report.score` is `Some` (i.e. `check` set it), mirroring the envelope's
    // omit-not-null score.
    let s = &report.summary;
    let _ = write!(
        out,
        "SUMMARY: {} findings · {} critical · {} high · {} medium · {} low · {} info · {} fixable",
        s.total(),
        s.critical,
        s.high,
        s.medium,
        s.low,
        s.info,
        s.fixable
    );
    if let Some(score) = report.score {
        let _ = write!(out, " · score {score}/100");
    }
    out.push('\n');

    // No summary-by-default collapse for the agent format (D-05): it always
    // carries the full machine list. When empty, FINDINGS/NEXT-ACTIONS collapse
    // to one clean line under the header.
    if report.findings.is_empty() {
        let _ = writeln!(out, "no findings — clean");
        return out;
    }

    // FINDINGS: one dense, flat, worst-first line per finding — a greppable,
    // total-ordered list (no per-file grouping; that is a human reading aid).
    let _ = writeln!(out, "FINDINGS:");
    for finding in &report.findings {
        // Position degrades exactly like the human renderer, but carries the
        // file so each line is self-contained: `file:line:col` / `file:line` /
        // `file`.
        let position = match (finding.line, finding.column) {
            (Some(line), Some(column)) => format!("{}:{line}:{column}", finding.file),
            (Some(line), None) => format!("{}:{line}", finding.file),
            _ => finding.file.clone(),
        };
        // Confidence < high is appended to the message exactly as the human
        // renderer does (SPEC-FINDINGS: renderers must distinguish confidence).
        let mut message = finding.message.clone();
        if finding.confidence < Confidence::High {
            let _ = write!(message, " (confidence: {})", finding.confidence);
        }
        let fixable = if finding.fixable { " [fixable]" } else { "" };
        // The `gdv1:` token is embedded verbatim (D-06) so an agent can diff
        // runs / cross-reference a baseline without a second `--json` call. The
        // batch fingerprint pass populates it before any render; the fallback is
        // a defensive placeholder that never carries secret material.
        let fingerprint = finding.fingerprint.as_deref().unwrap_or("gdv1:?");
        let _ = writeln!(
            out,
            "{} {} {position} — {message}{fixable} {fingerprint}",
            finding.severity.as_str(),
            finding.id
        );
    }

    // NEXT ACTIONS: the deduped set of `suggestion.or(remediation)` (the same
    // precedence `render_finding`/`render_top_three` use), keyed by the action
    // string. `report.findings` is already totally ordered worst-first, so
    // first-appearance IS worst-severity-first — a plain insertion-order dedupe
    // yields the deterministic (severity desc, first-index) ordering D-07 asks
    // for. Capped at `NEXT_ACTIONS_CAP` with a `… (M more)` line when truncated.
    let _ = writeln!(out, "NEXT ACTIONS:");
    let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
    let mut actions: Vec<&str> = Vec::new();
    for finding in &report.findings {
        if let Some(action) = finding
            .suggestion
            .as_deref()
            .or(finding.remediation.as_deref())
        {
            if seen.insert(action, ()).is_none() {
                actions.push(action);
            }
        }
    }
    for action in actions.iter().take(NEXT_ACTIONS_CAP) {
        let _ = writeln!(out, "- {action}");
    }
    if actions.len() > NEXT_ACTIONS_CAP {
        let _ = writeln!(out, "… ({} more)", actions.len() - NEXT_ACTIONS_CAP);
    }

    out
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

/// Human terminal output: findings grouped by FILE (worst file first, per-file
/// severity tally in the header), each row as position · severity · message ·
/// rule-id with the most actionable next step on a `→` continuation line.
pub fn render_terminal(report: &FindingsReport, color: ColorMode, verbose: bool) -> String {
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

    // Summary-by-default (B-06, docs/SPEC-COMMANDS.md): a report longer than the
    // threshold would flood the terminal, so the DEFAULT human render collapses
    // to the summary (banner / tally) + the top-3 worst findings + one reminder
    // line — the full per-file list is shown only for short reports or with
    // `-v`. Deterministic (a count, not a tty probe): identical piped or
    // interactive, so CI logs / grep / corpus snapshots are unaffected. Machine
    // paths (`--json`, `-o`) never reach here and always carry the full report.
    if !verbose && report.findings.len() > SUMMARY_ONLY_THRESHOLD {
        // The worst 3, for every command (not just `check`) — the banner above
        // already covers the score path; render the tally for the rest.
        render_top_three(&mut out, &report.findings);
        if report.score.is_none() {
            render_summary_tally(&mut out, &report.summary);
        }
        let _ = writeln!(
            out,
            "\n{} findings — showing the top 3. Full list: re-run with -v · full report: -o report.json or --json",
            report.findings.len()
        );
        if report.score.is_some() {
            let fixable = report.summary.fixable;
            if fixable > 0 {
                let _ = writeln!(
                    out,
                    "{fixable} finding(s) fixable — run: getdev env --write"
                );
            }
        }
        return out;
    }

    // Findings are globally sorted worst-first (severity → file → line, …) by
    // [`FindingsReport::new`]; group them by FILE for reading. A file's first
    // appearance in that order fixes the group order — worst file first, path
    // as the tiebreak — and each group inherits severity-then-line order.
    // Deterministic: pure re-arrangement of an already-deterministic order.
    let mut file_order: Vec<&str> = Vec::new();
    let mut groups: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for finding in &report.findings {
        if !groups.contains_key(finding.file.as_str()) {
            file_order.push(finding.file.as_str());
        }
        groups
            .entry(finding.file.as_str())
            .or_default()
            .push(finding);
    }
    for (i, file) in file_order.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let group = &groups[file];
        render_file_header(&mut out, file, group, color);
        for finding in group {
            render_finding(&mut out, finding, color);
        }
    }

    // A very long terminal report is better read from a file — point at `-o`
    // once the list stops being scannable (threshold, not truncation: CI logs
    // and grep keep the complete output either way).
    if report.findings.len() > SUMMARY_ONLY_THRESHOLD {
        let _ = writeln!(
            out,
            "\ntip: {} findings — write the full JSON report to a file with: -o report.json",
            report.findings.len()
        );
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
        render_summary_tally(&mut out, &report.summary);
    }
    out
}

/// Findings count past which the human terminal render collapses to
/// summary-by-default (B-06): banner/tally + top-3 + a reminder line, with the
/// full per-file list shown only for short reports or under `-v`. The same
/// threshold gates the non-collapsed `-o` tip. Single source — no duplicate
/// magic number.
pub const SUMMARY_ONLY_THRESHOLD: usize = 25;

/// The one-line severity tally (`N finding(s): … (K fixable)`) that closes a
/// score-less report and stands in for the banner in a collapsed non-`check`
/// render — single-sourced so the two callers never drift.
fn render_summary_tally(out: &mut String, s: &Summary) {
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

/// Short terminal companion for `-o/--output` runs: the score banner and
/// top-3 when present (`check`), the one-line tally always — the full
/// findings list lives in the report file, so the terminal stays scannable.
pub fn render_terminal_short(report: &FindingsReport) -> String {
    let mut out = String::new();
    if let Some(score) = report.score {
        render_score_banner(&mut out, &report.summary, score);
        render_top_three(&mut out, &report.findings);
    }
    render_summary_tally(&mut out, &report.summary);
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
    // Plain facts, not a call-to-action (CLAUDE.md standing rules): where the
    // source lives, where the docs live, and the license — the three things a
    // first-run user reasonably wants at hand.
    let links = "  getdev.ai · github.com/getdev-ai/cli · Apache-2.0";
    let mut out = String::new();
    match color {
        ColorMode::On => {
            let _ = writeln!(out, "{}", WELCOME_WORDMARK.cyan().bold());
            let _ = writeln!(out, "{}", promise.dimmed());
            let _ = writeln!(out, "{}", footer.dimmed());
            let _ = writeln!(out, "{}", links.dimmed());
        }
        ColorMode::Off => {
            let _ = writeln!(out, "{WELCOME_WORDMARK}");
            let _ = writeln!(out, "{promise}");
            let _ = writeln!(out, "{footer}");
            let _ = writeln!(out, "{links}");
        }
    }
    out
}

/// The one-line first-run clarity hint `getdev check` prints when the project
/// has no `.getdev.toml` (docs/SPEC-COMMANDS.md `check`): a dim reminder that
/// config is optional and where to customize it. Human-render only — the caller
/// (`check`) suppresses it under `--json`/`--quiet`/a non-tty stdout/CI; this
/// decides only how the dim line looks. It carries a trailing newline so it
/// slots directly under the score banner. NO call-to-action beyond naming the
/// command (CLAUDE.md standing rules).
pub fn render_no_config_hint(color: ColorMode) -> String {
    let hint = "using built-in defaults · run `getdev init` to customize";
    match color {
        ColorMode::On => format!("{}\n", hint.dimmed()),
        ColorMode::Off => format!("{hint}\n"),
    }
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

/// `{path} — {n} finding(s) · {severity tallies}` group header. The path is
/// the anchor a reader scans for, so it carries the emphasis; the tally is
/// context and stays dim.
fn render_file_header(out: &mut String, file: &str, group: &[&Finding], color: ColorMode) {
    let mut counts: BTreeMap<Severity, usize> = BTreeMap::new();
    for finding in group {
        *counts.entry(finding.severity).or_default() += 1;
    }
    let tally = Severity::ALL_DESC
        .iter()
        .filter_map(|sev| {
            counts
                .get(sev)
                .map(|n| format!("{n} {}", sev.as_str().to_lowercase()))
        })
        .collect::<Vec<_>>()
        .join(" · ");
    let plural = if group.len() == 1 {
        "finding"
    } else {
        "findings"
    };
    let meta = format!("— {} {plural} · {tally}", group.len());
    match color {
        ColorMode::On => {
            let _ = writeln!(out, "{} {}", file.bold(), meta.dimmed());
        }
        ColorMode::Off => {
            let _ = writeln!(out, "{file} {meta}");
        }
    }
}

/// One finding row plus its remediation continuation line:
///
/// ```text
///   12:3  ✖ critical  stripe secret assigned to 'stripeKey' (sk_live_…9f2a)  env/hardcoded-secret
///         → extract to STRIPE_SECRET_KEY in .env
/// ```
///
/// Position (`line:column`, right-aligned) leads so rows in one file scan
/// like a compiler's output; the rule id trails dimmed — present for grep
/// and `[ignore] rules`, out of the reading line.
fn render_finding(out: &mut String, finding: &Finding, color: ColorMode) {
    let position = match (finding.line, finding.column) {
        (Some(line), Some(column)) => format!("{line}:{column}"),
        (Some(line), None) => line.to_string(),
        _ => "—".to_owned(),
    };
    let mut message = finding.message.clone();
    if finding.confidence < Confidence::High {
        let _ = write!(message, " (confidence: {})", finding.confidence);
    }

    // IN-03: pad plain text FIRST, colorize the padded string after — ANSI
    // escape bytes inside a format-spec width would drift every colored row.
    let position_padded = format!("{position:>POSITION_WIDTH$}");
    let severity_padded = format!(
        "{} {:<SEVERITY_WIDTH$}",
        severity_glyph(finding.severity),
        finding.severity.as_str().to_lowercase()
    );
    match color {
        ColorMode::On => {
            let _ = writeln!(
                out,
                "  {} {} {}  {}",
                position_padded.dimmed(),
                colorize_severity(&severity_padded, finding.severity),
                message,
                finding.id.dimmed()
            );
        }
        ColorMode::Off => {
            let _ = writeln!(
                out,
                "  {position_padded} {severity_padded} {message}  {}",
                finding.id
            );
        }
    }

    let fix = finding.suggestion.as_ref().or(finding.remediation.as_ref());
    if let Some(fix) = fix {
        let arrow = format!("  {:>POSITION_WIDTH$} → {fix}", "");
        match color {
            ColorMode::On => {
                let _ = writeln!(out, "{}", arrow.dimmed());
            }
            ColorMode::Off => {
                let _ = writeln!(out, "{arrow}");
            }
        }
    }
}

/// Right-aligned width of the `line:column` position column — fits
/// `9999:999` without wobble on realistic files.
const POSITION_WIDTH: usize = 8;
/// Width the lowercase severity word is padded to (`critical`, 8).
const SEVERITY_WIDTH: usize = 8;

/// One glyph per severity — content, not decoration: identical with color
/// on or off, so a piped/`NO_COLOR` run keeps the same visual hierarchy.
fn severity_glyph(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "✖",
        Severity::High => "▲",
        Severity::Medium => "●",
        Severity::Low => "○",
        Severity::Info => "·",
    }
}

fn colorize_severity(text: &str, severity: Severity) -> String {
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
            seed: crate::fingerprint::FingerprintSeed::default(),
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
            false,
        );
        let critical_pos = out.find("✖ critical").unwrap();
        let low_pos = out.find("○ low").unwrap();
        assert!(critical_pos < low_pos);
        // one file group header carrying the per-file tally...
        assert!(out.contains("requirements.txt — 2 findings · 1 critical · 1 low"));
        // ...and the line number in the position column of each row
        assert!(out.contains("       4 "));
        assert!(out.contains("→ did you mean 'requests-oauthlib'?"));
        // the rule id trails the row for grep/[ignore] use
        assert!(out.contains("real/nonexistent-package"));
        assert!(out.contains("2 finding(s)"));
        // no ANSI escapes when color is off
        assert!(!out.contains('\u{1b}'));
    }

    #[test]
    fn low_confidence_is_visually_distinguished() {
        let out = render_terminal(
            &report(vec![finding(Severity::High, Confidence::Low)]),
            ColorMode::Off,
            false,
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

    /// IN-03 regression: under color the severity chip carries ANSI escape
    /// bytes, but its VISIBLE width must stay fixed so the message column
    /// lines up. Render two findings whose severity words differ in length
    /// (`critical` vs `low`) with color ON, strip the escapes, and assert the
    /// message starts at the same visible offset on both rows.
    #[test]
    fn colored_labels_keep_columns_aligned() {
        let out = render_terminal(
            &report(vec![
                finding(Severity::Critical, Confidence::High),
                finding(Severity::Low, Confidence::High),
            ]),
            ColorMode::On,
            false,
        );
        // color must actually have been applied
        assert!(
            out.contains('\u{1b}'),
            "expected ANSI escapes with color on"
        );

        let message_col = |needle: &str| -> usize {
            let line = out
                .lines()
                .map(strip_ansi)
                .find(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("no {needle} row in:\n{out}"));
            line.find("Package 'requests-auth-helper'")
                .unwrap_or_else(|| panic!("message must be present on the row: {line}"))
        };
        assert_eq!(
            message_col("✖ critical"),
            message_col("○ low"),
            "the message column must start at the same visible offset regardless of severity word length"
        );
        // and the offset is exactly: 2 indent + position column + 1 space +
        // glyph (1 char = 3 UTF-8 bytes; `find` returns BYTE offsets) +
        // 1 space + padded severity word + 1 space
        assert_eq!(
            message_col("✖ critical"),
            2 + POSITION_WIDTH + 1 + (3 + 1) + SEVERITY_WIDTH + 1
        );
    }

    #[test]
    fn clean_report_says_clean() {
        let out = render_terminal(&report(vec![]), ColorMode::Off, false);
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
        let out = render_terminal(&rep, ColorMode::Off, false);
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
        let out = render_terminal(&rep, ColorMode::Off, false);
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

    /// The check no-config hint names the exact next step (`getdev init`) with no
    /// call-to-action beyond that; plain mode is ANSI-free (safe to pipe), colored
    /// mode wraps the same content in escapes. Both end with a single newline so
    /// the line slots under the score banner.
    #[test]
    fn no_config_hint_names_init_and_is_ansi_free_when_plain() {
        let plain = render_no_config_hint(ColorMode::Off);
        assert_eq!(
            plain,
            "using built-in defaults · run `getdev init` to customize\n"
        );
        assert!(!plain.contains('\u{1b}'), "plain mode must be escape-free");

        let colored = render_no_config_hint(ColorMode::On);
        assert!(colored.contains('\u{1b}'), "colored mode wraps ANSI");
        assert!(colored.contains("run `getdev init` to customize"));
    }

    /// A report whose length exceeds [`SUMMARY_ONLY_THRESHOLD`], for the
    /// summary-by-default (B-06) tests. All findings share the same file, so the
    /// per-file group header only appears in the FULL render — a clean signal
    /// that the collapsed render omitted the per-file list.
    fn long_report() -> FindingsReport {
        let findings = (0..SUMMARY_ONLY_THRESHOLD + 5)
            .map(|_| finding(Severity::Medium, Confidence::High))
            .collect::<Vec<_>>();
        report(findings)
    }

    /// Collapsed (B-06): a report longer than the threshold with `verbose=false`
    /// renders the top-3 + the reminder line + the tally, and NONE of the
    /// beyond-top per-file rows (no group header, no glyph rows, no `-o` tip).
    #[test]
    fn long_report_collapses_to_summary_by_default() {
        let rep = long_report();
        let total = rep.findings.len();
        let out = render_terminal(&rep, ColorMode::Off, false);
        // top-3 + reminder + tally are present
        assert!(out.contains("top 3 things to fix first:"));
        assert!(out.contains(&format!(
            "{total} findings — showing the top 3. Full list: re-run with -v · full report: -o report.json or --json"
        )));
        assert!(out.contains(&format!("{total} finding(s):")));
        // the full per-file list is NOT rendered: no group header, no severity
        // glyph rows, no `-o` tip (the reminder line supersedes it)
        assert!(!out.contains("requirements.txt —"));
        assert!(!out.contains("● medium"));
        assert!(!out.contains("write the full JSON report"));
    }

    /// Verbose (B-06): the SAME long report with `verbose=true` renders the full
    /// per-file list (group header + every row) and NO collapse reminder.
    #[test]
    fn long_report_verbose_renders_full_list() {
        let rep = long_report();
        let out = render_terminal(&rep, ColorMode::Off, true);
        // full list: the per-file group header and the glyph rows are present
        assert!(out.contains("requirements.txt —"));
        assert!(out.contains("● medium"));
        // no collapse — the reminder line is absent
        assert!(!out.contains("showing the top 3"));
        // the >threshold `-o` tip still trails the full verbose render
        assert!(out.contains("write the full JSON report"));
    }

    /// Short (B-06): a report UNDER the threshold with `verbose=false` renders
    /// the full per-file list unchanged — no collapse, no reminder line. This is
    /// what keeps golden examples and the corpus snapshot (< threshold) stable.
    #[test]
    fn short_report_renders_full_list_without_collapse() {
        let rep = report(vec![
            finding(Severity::Critical, Confidence::High),
            finding(Severity::Low, Confidence::High),
        ]);
        let out = render_terminal(&rep, ColorMode::Off, false);
        assert!(out.contains("requirements.txt —"));
        assert!(out.contains("✖ critical"));
        assert!(!out.contains("showing the top 3"));
    }

    // ---- LOOP-01: evaluate_gate — the single-sourced OR-to-fail exit gate ----

    /// `--fail-on` alone: findings ≥ threshold ⇒ fail; below ⇒ pass. The verdict
    /// is byte-for-byte the inline `fail_on.is_some_and(...)` every command tail
    /// used before this helper existed.
    #[test]
    fn gate_fail_on_only_matches_inline_logic() {
        let rep = report(vec![finding(Severity::High, Confidence::High)]);
        // at-or-above the threshold trips it
        let hit = evaluate_gate(&rep, Some(Severity::High), None);
        assert!(hit.failed && hit.failed_severity && !hit.failed_score);
        // below the threshold does not
        assert!(!evaluate_gate(&rep, Some(Severity::Critical), None).failed);
        // and it equals the pre-refactor inline expression exactly
        let inline = Some(Severity::High).is_some_and(|t| rep.summary.at_or_above(t) > 0);
        assert_eq!(
            evaluate_gate(&rep, Some(Severity::High), None).failed,
            inline
        );
    }

    /// `--min-score` alone: `score < min` ⇒ fail; `score ≥ min` ⇒ pass; a
    /// score-less report (every non-`check` command) with a min set ⇒ inert.
    #[test]
    fn gate_min_score_only() {
        let mut rep = report(vec![finding(Severity::Low, Confidence::High)]);
        rep.score = Some(60);
        assert!(evaluate_gate(&rep, None, Some(80)).failed, "60 < 80 fails");
        assert!(
            !evaluate_gate(&rep, None, Some(60)).failed,
            "60 ≥ 60 passes"
        );
        assert!(!evaluate_gate(&rep, None, Some(0)).failed, "60 ≥ 0 passes");
        // score None ⇒ min-score inert (D-01: only `check` scores).
        let noscore = report(vec![finding(Severity::Low, Confidence::High)]);
        let out = evaluate_gate(&noscore, None, Some(100));
        assert!(
            !out.failed && !out.failed_score,
            "no score ⇒ min-score inert"
        );
    }

    /// Both gates compose OR-to-fail / AND-to-pass: fail if EITHER trips, pass
    /// only when both pass; neither given ⇒ pass.
    #[test]
    fn gate_both_or_to_fail() {
        let mut rep = report(vec![finding(Severity::High, Confidence::High)]);
        rep.score = Some(50);
        // severity trips, score passes
        assert!(evaluate_gate(&rep, Some(Severity::High), Some(0)).failed);
        // score trips, severity passes
        assert!(evaluate_gate(&rep, Some(Severity::Critical), Some(80)).failed);
        // both pass ⇒ pass
        assert!(!evaluate_gate(&rep, Some(Severity::Critical), Some(50)).failed);
        // neither given ⇒ pass
        assert!(!evaluate_gate(&rep, None, None).failed);
    }

    /// When it fails, the outcome carries enough to render the `GATE:` reasons:
    /// which gate(s) tripped plus the thresholds and the compared score.
    #[test]
    fn gate_reasons_carried_for_rendering() {
        let mut rep = report(vec![finding(Severity::High, Confidence::High)]);
        rep.score = Some(40);
        let out = evaluate_gate(&rep, Some(Severity::High), Some(80));
        assert!(out.failed && out.failed_severity && out.failed_score);
        assert_eq!(out.fail_on, Some(Severity::High));
        assert_eq!(out.min_score, Some(80));
        assert_eq!(out.score, Some(40));
    }

    // ---- LOOP-02: render_agent — the deterministic, secret-safe agent format --

    /// Populate `gdv1:` fingerprints the way the CLI does before any render, so
    /// the agent lines carry real tokens.
    fn fingerprinted(findings: Vec<Finding>) -> FindingsReport {
        let mut rep = report(findings);
        crate::fingerprint::assign_fingerprints(&mut rep.findings);
        rep
    }

    /// The agent shape carries all four labeled sections and is ANSI-free.
    #[test]
    fn agent_shape_has_all_sections_and_no_ansi() {
        let rep = fingerprinted(vec![finding(Severity::Critical, Confidence::High)]);
        let gate = evaluate_gate(&rep, None, None);
        let out = render_agent(&rep, &gate);
        assert!(out.starts_with("GATE: pass\n"));
        assert!(out.contains("\nSUMMARY: 1 findings · 1 critical · "));
        assert!(out.contains("\nFINDINGS:\n"));
        assert!(out.contains("\nNEXT ACTIONS:\n"));
        assert!(!out.contains('\u{1b}'), "agent output must be ANSI-free");
    }

    /// A clean report collapses FINDINGS/NEXT-ACTIONS to one line under the
    /// header (still prints GATE + SUMMARY).
    #[test]
    fn agent_clean_report_collapses_to_clean_line() {
        let rep = report(vec![]);
        let gate = evaluate_gate(&rep, None, None);
        let out = render_agent(&rep, &gate);
        assert!(out.starts_with("GATE: pass\n"));
        assert!(out.contains("SUMMARY: 0 findings · "));
        assert!(out.contains("no findings — clean"));
        assert!(!out.contains("FINDINGS:"));
        assert!(!out.contains("NEXT ACTIONS:"));
    }

    /// One dense finding line: `sev id file:line[:col] — message [fixable] gdv1:`
    /// with low-confidence annotated and the fingerprint verbatim.
    #[test]
    fn agent_finding_line_carries_position_message_and_fingerprint() {
        let rep = fingerprinted(vec![finding(Severity::High, Confidence::Low)]);
        let gate = evaluate_gate(&rep, None, None);
        let out = render_agent(&rep, &gate);
        // severity word · id · file:line (column None ⇒ file:line) · message
        assert!(out.contains("high real/nonexistent-package requirements.txt:4 — Package"));
        assert!(out.contains("(confidence: low)"));
        let fp = rep.findings[0].fingerprint.clone().unwrap();
        assert!(out.contains(&fp) && fp.starts_with("gdv1:"));
        // not fixable ⇒ no [fixable] marker
        assert!(!out.contains("[fixable]"));
    }

    /// `[fixable]` appears only for fixable findings; the remediation feeds the
    /// NEXT ACTIONS list when there is no suggestion.
    #[test]
    fn agent_marks_fixable_and_lists_remediation() {
        let mut f = finding(Severity::Medium, Confidence::High);
        f.fixable = true;
        f.suggestion = None;
        f.remediation = Some("run: getdev env --write".into());
        let rep = fingerprinted(vec![f]);
        let gate = evaluate_gate(&rep, None, None);
        let out = render_agent(&rep, &gate);
        assert!(out.contains(" [fixable] gdv1:"));
        assert!(out.contains("- run: getdev env --write"));
    }

    /// NEXT ACTIONS dedupes an identical suggestion to one line and orders
    /// worst-severity-first (the critical carrier precedes the high's action).
    #[test]
    fn agent_next_actions_dedupe_and_worst_first() {
        let mut a = finding(Severity::Low, Confidence::High);
        a.suggestion = Some("shared action".into());
        let mut b = finding(Severity::Critical, Confidence::High);
        b.suggestion = Some("shared action".into());
        let mut c = finding(Severity::High, Confidence::High);
        c.suggestion = Some("unique action".into());
        let rep = fingerprinted(vec![a, b, c]);
        let gate = evaluate_gate(&rep, None, None);
        let out = render_agent(&rep, &gate);
        assert_eq!(out.matches("- shared action").count(), 1, "deduped to one");
        let shared = out.find("- shared action").unwrap();
        let unique = out.find("- unique action").unwrap();
        assert!(
            shared < unique,
            "worst-severity carrier's action comes first"
        );
    }

    /// NEXT ACTIONS caps at `NEXT_ACTIONS_CAP` with a trailing `… (M more)` line.
    #[test]
    fn agent_next_actions_caps_with_more_line() {
        let findings = (0..NEXT_ACTIONS_CAP + 3)
            .map(|i| {
                let mut f = finding(Severity::Medium, Confidence::High);
                f.suggestion = Some(format!("action {i:02}"));
                f
            })
            .collect::<Vec<_>>();
        let rep = fingerprinted(findings);
        let gate = evaluate_gate(&rep, None, None);
        let out = render_agent(&rep, &gate);
        let action_lines = out.lines().filter(|l| l.starts_with("- action ")).count();
        assert_eq!(action_lines, NEXT_ACTIONS_CAP);
        assert!(out.contains("… (3 more)"));
    }

    /// D-08 (Invariant 2 on the new surface): two findings whose seeds are
    /// distinct raw secrets — the agent output contains NEITHER raw secret while
    /// carrying BOTH distinct `gdv1:` fingerprints.
    #[test]
    fn agent_never_leaks_a_secret_but_carries_fingerprints() {
        // Build the raw secrets from pieces so this test source is not itself the
        // leak the assertion checks for.
        let secret_a = format!("sk_live_{}{}", "AAAA", "SECRETBODYONE1234");
        let secret_b = format!("sk_live_{}{}", "BBBB", "SECRETBODYTWO5678");
        let mut fa = finding(Severity::Critical, Confidence::High);
        fa.id = "env/hardcoded-secret".into();
        fa.file = "src/config.ts".into();
        fa.line = Some(5);
        fa.column = Some(10);
        fa.message = "stripe secret assigned to 'A' (sk_live_…1234)".into();
        fa.suggestion = None;
        fa.remediation = Some("extract to .env".into());
        fa.seed = crate::fingerprint::FingerprintSeed {
            node_kind: "secret_literal",
            matched_text: secret_a.clone(),
        };
        let mut fb = fa.clone();
        fb.column = Some(40);
        fb.message = "stripe secret assigned to 'B' (sk_live_…5678)".into();
        fb.seed = crate::fingerprint::FingerprintSeed {
            node_kind: "secret_literal",
            matched_text: secret_b.clone(),
        };
        let rep = fingerprinted(vec![fa, fb]);
        let fp_a = rep.findings[0].fingerprint.clone().unwrap();
        let fp_b = rep.findings[1].fingerprint.clone().unwrap();
        assert_ne!(fp_a, fp_b, "distinct secrets ⇒ distinct fingerprints");
        let gate = evaluate_gate(&rep, None, None);
        let out = render_agent(&rep, &gate);
        assert!(!out.contains(&secret_a), "raw secret A leaked");
        assert!(!out.contains(&secret_b), "raw secret B leaked");
        assert!(!out.contains("SECRETBODYONE"), "secret A body leaked");
        assert!(!out.contains("SECRETBODYTWO"), "secret B body leaked");
        assert!(out.contains(&fp_a), "fingerprint A must be present");
        assert!(out.contains(&fp_b), "fingerprint B must be present");
    }

    /// D-09: the agent render is strictly smaller than the JSON render for a
    /// representative multi-finding report — a real byte measurement.
    #[test]
    fn agent_is_smaller_than_json() {
        let findings = (0..8)
            .map(|i| {
                let sev = if i % 2 == 0 {
                    Severity::High
                } else {
                    Severity::Medium
                };
                let mut f = finding(sev, Confidence::High);
                f.file = format!("src/file{i}.ts");
                f.remediation = Some(format!("fix issue {i}"));
                f
            })
            .collect::<Vec<_>>();
        let rep = fingerprinted(findings);
        let gate = evaluate_gate(&rep, None, None);
        let agent = render_agent(&rep, &gate);
        let json = render_json(&rep).unwrap();
        assert!(
            agent.len() < json.len(),
            "agent {} bytes must be < json {} bytes",
            agent.len(),
            json.len()
        );
    }

    /// The GATE line renders the tripped-gate reason fragments (D-05), and the
    /// SUMMARY carries the score fragment when `check` set a score.
    #[test]
    fn agent_gate_line_shows_tripped_reasons() {
        let mut rep = fingerprinted(vec![finding(Severity::High, Confidence::High)]);
        rep.score = Some(40);
        let gate = evaluate_gate(&rep, Some(Severity::High), Some(80));
        let out = render_agent(&rep, &gate);
        let first = out.lines().next().unwrap();
        assert!(first.starts_with("GATE: fail"));
        assert!(first.contains("score 40/100 < min 80"));
        assert!(first.contains("high+ findings ≥ high"));
        assert!(
            out.contains("· score 40/100\n"),
            "SUMMARY carries the score"
        );
    }

    /// Deterministic: two renders of the same report are byte-identical.
    #[test]
    fn agent_output_is_deterministic() {
        let rep = fingerprinted(vec![
            finding(Severity::Critical, Confidence::High),
            finding(Severity::Low, Confidence::High),
        ]);
        let gate = evaluate_gate(&rep, None, None);
        assert_eq!(render_agent(&rep, &gate), render_agent(&rep, &gate));
    }
}
