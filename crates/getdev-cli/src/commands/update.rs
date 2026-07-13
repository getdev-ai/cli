//! `getdev update` — the thin CLI boundary over the 08-04 self-update engine.
//!
//! This module owns only presentation + the `anyhow` boundary: it calls
//! [`crate::update::run`] (the verified, atomic, offline-respecting engine) and
//! renders its [`UpdateOutcome`] as a concise human line (default) or a small
//! JSON object (`--json`). The engine's typed [`crate::update::UpdateError`] is
//! surfaced through `?` into an `anyhow::Error` here (exit 2 via `main`), so no
//! `unwrap`/`expect` and no engine-internal error type leaks past the CLI.
//!
//! Contractual scope (docs/SPEC-COMMANDS.md `getdev update`, CLAUDE.md rule 6):
//! GLOBAL FLAGS ONLY. Channel / pin / downgrade are `[update]` config (08-04),
//! never per-command flags; `--offline` makes the whole thing an explicit
//! no-op skip.

use std::io::IsTerminal;

use owo_colors::OwoColorize;

use getdev_core::config::UpdateConfig;
use getdev_core::report::ColorMode;

use crate::update::{self, UpdateOutcome};

/// Global-derived inputs only (no per-command flags) plus the resolved
/// `[update]` config that the engine reads for channel/pin/downgrade.
pub struct UpdateArgs {
    /// Resolved `--offline` / `GETDEV_OFFLINE` — the engine short-circuits to
    /// an explicit `Skipped` no-op before any network client is built.
    pub offline: bool,
    /// Machine-readable outcome object (global `--json`).
    pub json: bool,
    /// Suppress the secondary hint line (global `--quiet`). The outcome line
    /// itself is the command's primary result, so it prints regardless.
    pub quiet: bool,
    /// Global `--no-color` (also honors `NO_COLOR`) — decolorizes the outcome
    /// marker.
    pub no_color: bool,
    /// Resolved `[update]` config (channel / pin / allow_downgrade).
    pub cfg: UpdateConfig,
}

pub fn run(args: &UpdateArgs) -> anyhow::Result<u8> {
    // The typed engine error becomes an `anyhow::Error` here (exit 2 via
    // `main`'s mapping) — the single CLI boundary the plan prescribes.
    let outcome = update::run(args.offline, &args.cfg)?;

    if args.json {
        println!("{}", render_json(&outcome)?);
        // Every non-error outcome (Skipped / UpToDate / Updated) is a success.
        return Ok(0);
    }

    let color = ColorMode::resolve(args.no_color, std::io::stdout().is_terminal());
    println!("{}", human_line(&outcome, color));
    // The follow-up hint (e.g. "restart to pick up the new binary") is chatter,
    // suppressed under `--quiet`; the outcome line above always prints.
    if !args.quiet {
        if let Some(hint) = hint_line(&outcome) {
            println!("{hint}");
        }
    }

    Ok(0)
}

/// One concise, user-reportable line per outcome. `Skipped` names `offline`
/// explicitly (Pitfall 4: an offline no-op is never a stale "up to date"). The
/// leading marker is colorized unless `--no-color`/`NO_COLOR`.
fn human_line(outcome: &UpdateOutcome, color: ColorMode) -> String {
    match outcome {
        UpdateOutcome::Skipped => format!(
            "{} — offline (no network touched, nothing changed)",
            marker("skipped", color, Tone::Dim)
        ),
        UpdateOutcome::UpToDate { version } => {
            format!(
                "{} (getdev {version})",
                marker("up to date", color, Tone::Ok)
            )
        }
        UpdateOutcome::Updated { from, to } => {
            format!(
                "{} getdev {from} -> {to}",
                marker("updated", color, Tone::Ok)
            )
        }
    }
}

/// An optional secondary line, suppressed under `--quiet`. Only a completed
/// swap warrants one (the running process still executes the OLD binary until
/// it is restarted).
fn hint_line(outcome: &UpdateOutcome) -> Option<String> {
    match outcome {
        UpdateOutcome::Updated { to, .. } => Some(format!("restart getdev to run {to}")),
        UpdateOutcome::Skipped | UpdateOutcome::UpToDate { .. } => None,
    }
}

/// The color intent of the marker word.
enum Tone {
    /// A positive terminal state (up to date / updated).
    Ok,
    /// A neutral no-op (skipped).
    Dim,
}

/// Colorize the leading marker word per [`ColorMode`], mirroring `doctor`'s
/// owo-colors-to-`String` pattern (so the returned line is a plain `String`
/// regardless of color).
fn marker(text: &str, color: ColorMode, tone: Tone) -> String {
    match (color, tone) {
        (ColorMode::Off, _) => text.to_owned(),
        (ColorMode::On, Tone::Ok) => text.green().to_string(),
        (ColorMode::On, Tone::Dim) => text.dimmed().to_string(),
    }
}

/// A small, stable `--json` object mirroring the human outcome. Not the
/// findings schema (this command reports an action, not findings), so it stays
/// a minimal `{ "outcome": ... }` document.
fn render_json(outcome: &UpdateOutcome) -> anyhow::Result<String> {
    let value = match outcome {
        UpdateOutcome::Skipped => serde_json::json!({
            "outcome": "skipped",
            "reason": "offline",
        }),
        UpdateOutcome::UpToDate { version } => serde_json::json!({
            "outcome": "up_to_date",
            "version": version,
        }),
        UpdateOutcome::Updated { from, to } => serde_json::json!({
            "outcome": "updated",
            "from": from,
            "to": to,
        }),
    };
    Ok(serde_json::to_string_pretty(&value)?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn skipped_human_line_names_offline() {
        let line = human_line(&UpdateOutcome::Skipped, ColorMode::Off);
        assert!(line.contains("offline"), "got: {line}");
        assert!(line.contains("skipped"), "got: {line}");
    }

    #[test]
    fn up_to_date_line_carries_the_version() {
        let line = human_line(
            &UpdateOutcome::UpToDate {
                version: "0.1.0".to_owned(),
            },
            ColorMode::Off,
        );
        assert!(line.contains("0.1.0"), "got: {line}");
    }

    #[test]
    fn updated_line_shows_the_transition() {
        let line = human_line(
            &UpdateOutcome::Updated {
                from: "0.1.0".to_owned(),
                to: "0.1.2".to_owned(),
            },
            ColorMode::Off,
        );
        assert!(line.contains("0.1.0"), "got: {line}");
        assert!(line.contains("0.1.2"), "got: {line}");
    }

    #[test]
    fn only_a_completed_update_emits_a_restart_hint() {
        assert!(hint_line(&UpdateOutcome::Skipped).is_none());
        assert!(hint_line(&UpdateOutcome::UpToDate {
            version: "0.1.0".to_owned()
        })
        .is_none());
        let hint = hint_line(&UpdateOutcome::Updated {
            from: "0.1.0".to_owned(),
            to: "0.1.2".to_owned(),
        })
        .unwrap();
        assert!(hint.contains("0.1.2"), "got: {hint}");
    }

    #[test]
    fn json_skipped_is_a_minimal_offline_object() {
        let json = render_json(&UpdateOutcome::Skipped).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["outcome"], "skipped");
        assert_eq!(value["reason"], "offline");
    }

    #[test]
    fn json_updated_carries_from_and_to() {
        let json = render_json(&UpdateOutcome::Updated {
            from: "0.1.0".to_owned(),
            to: "0.1.2".to_owned(),
        })
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["outcome"], "updated");
        assert_eq!(value["from"], "0.1.0");
        assert_eq!(value["to"], "0.1.2");
    }
}
