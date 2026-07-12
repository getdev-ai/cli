//! `getdev back` — the reversible restore surface over `getdev-gitx`.
//!
//! `back` is designed to be ALWAYS reversible (D-04): before it restores
//! anything it records a pre-restore auto-snap under `refs/getdev/auto/<N>` and
//! then prints an undo pointer that names that EXPLICIT id — never a bare
//! `back`, because bare `back` targets the latest MANUAL snapshot (D-02), not
//! the auto-snap just taken (05-RESEARCH § Open Question 1).
//!
//! Bare `back` restores the most recent manual snapshot (`latest_manual`); a
//! `back <id>` restores that specific id. In an interactive, non-`--quiet` TTY
//! `back` prints a one-line change summary and asks a single `y/N`; when
//! non-interactive or under `--quiet` it proceeds without prompting so it stays
//! deterministic and scriptable in CI/pipes (D-04, T-05-19). Ids are typed
//! `u32` by clap, so a bad id is a clean parse error, never a panic (V5).

use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use owo_colors::OwoColorize;
use serde::Serialize;

use getdev_core::report::ColorMode;
use getdev_gitx::snap::{self, Namespace};

pub struct BackArgs {
    pub path: PathBuf,
    /// Machine-readable output (global flag) — a bespoke JSON document.
    pub json: bool,
    /// Disable ANSI colors on the undo pointer (global flag).
    pub no_color: bool,
    /// Suppress the interactive prompt and proceed deterministically (global
    /// flag) — the non-interactive escape hatch for CI/pipes (D-04).
    pub quiet: bool,
    /// Retention budget for the pre-restore auto-snap (`[snap] keep`).
    pub keep: u32,
    /// `None` = latest manual snapshot (D-02); otherwise the specific id.
    pub id: Option<u32>,
}

/// `#[derive(Serialize)]` JSON shape for a restore — the restore counts plus
/// the target and the explicit undo-pointer id.
#[derive(Serialize)]
struct BackResult {
    target: u32,
    restored: usize,
    removed: usize,
    readded: usize,
    undo_id: u32,
}

pub fn run(args: &BackArgs) -> anyhow::Result<u8> {
    // 1. Resolve the target: an explicit id, or the latest manual snapshot for
    //    a bare `back` (D-02). No manual snapshot yet is a clean error.
    let target = match args.id {
        Some(n) => n,
        None => snap::latest_manual(&args.path)?
            .ok_or_else(|| anyhow::anyhow!("no snapshots yet — run `getdev snap` first"))?,
    };

    // 2. Compute the change summary WITHOUT mutating. This also resolves the
    //    target, so a bad id surfaces here as a clean `no snapshot with id <n>`
    //    error before anything is touched (T-05-10).
    let summary = snap::diff(&args.path, target)?;

    // 3. Prompt gate (D-04): only in an interactive, non-`--quiet` TTY (stdin
    //    AND stdout). Otherwise auto-proceed so pipes/CI never hang (T-05-19).
    let interactive =
        !args.quiet && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    if interactive {
        // Restore effect, framed for the user: modified-since paths are
        // overwritten (restored), created-since paths are removed, removed-since
        // paths are re-added.
        println!(
            "{} restored · {} removed · {} re-added",
            summary.modified, summary.added, summary.deleted
        );
        print!("restore snapshot {target}? [y/N] ");
        std::io::stdout().flush().ok();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("back cancelled");
            return Ok(0);
        }
    }

    // 4. Pre-restore auto-snap FIRST — the always-reversible guarantee (D-04).
    //    `dedupe = true` so an unchanged tree does not churn the auto namespace
    //    (D-07); its id is the undo pointer (D-08 message).
    let undo = snap::snapshot(
        &args.path,
        Namespace::Auto,
        "auto: pre-restore",
        true,
        args.keep,
    )?;

    // 5. Restore the working tree to the target snapshot.
    let done = snap::restore(&args.path, target)?;

    // 6. Always print the undo pointer, naming the EXPLICIT pre-restore id
    //    (Open Q1: not a bare `back`, which would target the latest manual snap
    //    per D-02, not this auto-snap).
    if args.json {
        let out = BackResult {
            target,
            restored: done.restored,
            removed: done.removed,
            readded: done.readded,
            undo_id: undo.id,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        // The undo pointer names the EXPLICIT pre-restore id; emphasize the
        // exact command to run so it is unmissable in a terminal.
        let color = ColorMode::resolve(args.no_color, std::io::stdout().is_terminal());
        let undo_cmd = format!("getdev back {}", undo.id);
        let undo_cmd = match color {
            ColorMode::On => undo_cmd.bold().to_string(),
            ColorMode::Off => undo_cmd,
        };
        println!("restored snapshot {target} — run `{undo_cmd}` to undo");
    }
    Ok(0)
}

