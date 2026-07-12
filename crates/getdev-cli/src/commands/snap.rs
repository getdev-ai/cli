//! `getdev snap` — the user-facing surface over `getdev-gitx`'s snapshot
//! plumbing. This layer NEVER prints from the library: `getdev-gitx` returns
//! data (`SnapOutcome`/`SnapMeta`/`DiffSummary`/`PruneOutcome`), and this
//! command renders it as a bespoke table + `--json` document, mirroring the
//! `doctor.rs` non-Finding precedent (snapshots are not findings, so they never
//! flow through the `FindingsReport` renderers).
//!
//! Scope is exactly the SPEC-COMMANDS contract — `snap [-m] | list | diff <id>
//! | prune` — with no flags or subcommands beyond it (CLAUDE.md hard rule 6).
//! Ids are typed `u32` by clap, which structurally rejects non-integer/negative
//! input as a clean parse error and forbids relative addressing (D-03, V5).

use std::io::IsTerminal;
use std::path::PathBuf;

use owo_colors::OwoColorize;
use serde::Serialize;

use getdev_core::report::ColorMode;
use getdev_gitx::snap::{self, Namespace};

/// The `snap` subcommand, mirrored from the clap enum in `main.rs` so this
/// module stays clap-free (the same shape the rest of `commands/` follows —
/// each command owns a plain args struct, not a clap type).
pub enum SnapAction {
    /// `snap list`
    List,
    /// `snap diff <id>`
    Diff { id: u32 },
    /// `snap prune`
    Prune,
}

pub struct SnapArgs {
    pub path: PathBuf,
    /// Machine-readable output (global flag) — a bespoke JSON document, NOT a
    /// `FindingsReport` (doctor precedent).
    pub json: bool,
    /// Disable ANSI colors on the table header (global flag).
    pub no_color: bool,
    /// Suppress incidental chatter (global flag).
    pub quiet: bool,
    /// Retention budget for create/prune (`[snap] keep`, default 20).
    pub keep: u32,
    /// `-m/--message` label for a `snap` create.
    pub message: Option<String>,
    /// `None` = create; otherwise the requested sub-action.
    pub action: Option<SnapAction>,
}

pub fn run(args: &SnapArgs) -> anyhow::Result<u8> {
    match &args.action {
        None => create(args),
        Some(SnapAction::List) => list(args),
        Some(SnapAction::Diff { id }) => diff(args, *id),
        Some(SnapAction::Prune) => prune(args),
    }
}

/// `#[derive(Serialize)]` JSON shape for a `snap` create (doctor precedent —
/// small and stable).
#[derive(Serialize)]
struct SnapCreated {
    id: u32,
    created: bool,
    skipped_noop: bool,
}

fn create(args: &SnapArgs) -> anyhow::Result<u8> {
    let message = args.message.as_deref().unwrap_or("snapshot");
    // `dedupe = false`: an explicit manual `snap` always records a checkpoint
    // even if the tree is unchanged is NOT wanted — but `snapshot` only skips
    // when `dedupe` is set, so a manual snap of an unchanged tree still creates
    // a ref. We pass `false` per the plan (auto-snaps are the deduped ones).
    let outcome = snap::snapshot(&args.path, Namespace::Snaps, message, false, args.keep)?;
    if args.json {
        let out = SnapCreated {
            id: outcome.id,
            created: !outcome.skipped_noop,
            skipped_noop: outcome.skipped_noop,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else if outcome.skipped_noop {
        println!("working tree unchanged — no new snapshot");
    } else {
        println!("snap {} created", outcome.id);
    }
    Ok(0)
}

/// One `snap list` row as it renders in `--json` (id, age in seconds, message,
/// files changed). The friendly `Nm`/`Nh`/`Nd` age string is a terminal-only
/// concern; JSON keeps the raw seconds so consumers can format their own.
#[derive(Serialize)]
struct SnapRow<'a> {
    id: u32,
    age_secs: u64,
    message: &'a str,
    files_changed: usize,
}

fn list(args: &SnapArgs) -> anyhow::Result<u8> {
    let rows = snap::list(&args.path)?;
    if args.json {
        let json: Vec<SnapRow> = rows
            .iter()
            .map(|r| SnapRow {
                id: r.id,
                age_secs: r.age_secs,
                message: &r.message,
                files_changed: r.files_changed,
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(0);
    }

    if rows.is_empty() {
        if !args.quiet {
            println!("no snapshots yet — run `getdev snap` to create one");
        }
        return Ok(0);
    }

    let color = ColorMode::resolve(args.no_color, std::io::stdout().is_terminal());
    let header = format!("  {:<5} {:<7} {:<6} {}", "id", "age", "files", "message");
    match color {
        ColorMode::On => println!("{}", header.dimmed()),
        ColorMode::Off => println!("{header}"),
    }
    for row in &rows {
        println!(
            "  {:<5} {:<7} {:<6} {}",
            row.id,
            friendly_age(row.age_secs),
            row.files_changed,
            row.message
        );
    }
    Ok(0)
}

/// `#[derive(Serialize)]` JSON shape for `snap diff <id>` — a count summary
/// only (v0.1 emits no per-file patches, and never file content: T-05-20).
#[derive(Serialize)]
struct DiffJson {
    id: u32,
    added: usize,
    deleted: usize,
    modified: usize,
}

fn diff(args: &SnapArgs, id: u32) -> anyhow::Result<u8> {
    let summary = snap::diff(&args.path, id)?;
    if args.json {
        let out = DiffJson {
            id,
            added: summary.added,
            deleted: summary.deleted,
            modified: summary.modified,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!(
            "{} added · {} deleted · {} modified since snapshot {id}",
            summary.added, summary.deleted, summary.modified
        );
    }
    Ok(0)
}

/// `#[derive(Serialize)]` JSON shape for `snap prune`.
#[derive(Serialize)]
struct PruneJson {
    pruned: usize,
    kept: usize,
}

fn prune(args: &SnapArgs) -> anyhow::Result<u8> {
    let outcome = snap::prune(&args.path, Namespace::Snaps, args.keep)?;
    if args.json {
        let out = PruneJson {
            pruned: outcome.deleted_ids.len(),
            kept: outcome.kept,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!(
            "pruned {} snapshot(s), {} kept",
            outcome.deleted_ids.len(),
            outcome.kept
        );
    }
    Ok(0)
}

/// Render a committer-age in seconds as a compact `Ns`/`Nm`/`Nh`/`Nd` string —
/// the one time-derived human field `list` exposes (DEC-01: ids/messages stay
/// deterministic; only this display column reads the wall clock).
fn friendly_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}
