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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn unique_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-back-cli-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn git_init(dir: &std::path::Path) {
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["init", "--quiet"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "git init failed for {}", dir.display());
    }

    /// Count live `refs/getdev/auto/` refs — the pre-mutation / pre-restore
    /// safety net. `snap list` is manual-namespace-only, so we shell directly.
    fn count_auto_refs(dir: &std::path::Path) -> usize {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["for-each-ref", "--format=%(refname)", "refs/getdev/auto/"])
            .output()
            .unwrap();
        assert!(out.status.success(), "for-each-ref failed");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count()
    }

    /// Whether the user's real `HEAD` resolves to a commit — false on a fresh
    /// `git init` (unborn HEAD). getdev must never create a user commit, so this
    /// stays false throughout.
    fn head_resolves(dir: &std::path::Path) -> bool {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["rev-parse", "--verify", "--quiet", "HEAD"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Count of the user's real branches (`refs/heads/`) — getdev never touches
    /// these, so it stays 0 throughout.
    fn branch_count(dir: &std::path::Path) -> usize {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["for-each-ref", "--format=%(refname)", "refs/heads/"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count()
    }

    /// The phase exit-gate at the CLI level: `snap` → `env --write` (which,
    /// via 05-05, records a pre-mutation auto-snap) → `back` restores the
    /// working tree byte-for-byte, takes its own pre-restore auto-snap, and
    /// never touches the user's branches/HEAD. Hermetic; no network.
    #[test]
    fn snap_env_write_back_round_trips_tree() {
        let dir = unique_dir("roundtrip");
        git_init(&dir);

        let one_path = dir.join("one.js");
        let two_path = dir.join("two.js");
        std::fs::write(&one_path, "const a = \"sk_live_AAAAAAAAAAAAAAAA01\";\n").unwrap();
        std::fs::write(&two_path, "const b = \"sk_live_BBBBBBBBBBBBBBBB02\";\n").unwrap();
        let one_orig = std::fs::read(&one_path).unwrap();
        let two_orig = std::fs::read(&two_path).unwrap();

        // The user's real git state starts pristine (unborn HEAD, no branches).
        assert!(!head_resolves(&dir), "fresh repo has an unborn HEAD");
        assert_eq!(branch_count(&dir), 0, "no user branches before");

        let cfg = getdev_core::config::Config::default();

        // snap #1 — a manual checkpoint of the raw (pre-`env`) tree.
        crate::commands::snap::run(&crate::commands::snap::SnapArgs {
            path: dir.clone(),
            json: false,
            no_color: true,
            quiet: true,
            keep: cfg.snap.keep,
            message: Some("before env".to_owned()),
            action: None,
        })
        .unwrap();

        // env --write: mutates both source files AND records a pre-mutation
        // auto-snap (05-05).
        crate::commands::env::run(&crate::commands::env::EnvArgs {
            output: None,
            path: dir.clone(),
            json: false,
            no_color: true,
            fail_on: None,
            env_file: ".env".to_owned(),
            include_urls: false,
            write: true,
            cfg: cfg.clone(),
            quiet: true,
            verbose: 0,
        })
        .unwrap();

        let one_after_env = std::fs::read_to_string(&one_path).unwrap();
        assert!(
            one_after_env.contains("process.env"),
            "env --write should rewrite the source, got:\n{one_after_env}"
        );
        assert_eq!(
            count_auto_refs(&dir),
            1,
            "env --write records exactly one pre-mutation auto-snap"
        );

        // back to snap #1 — non-interactive (`quiet: true`) so it auto-proceeds.
        run(&BackArgs {
            path: dir.clone(),
            json: false,
            no_color: true,
            quiet: true,
            keep: cfg.snap.keep,
            id: Some(1),
        })
        .unwrap();

        // Round-trip: both sources are byte-for-byte their pre-`env` content.
        assert_eq!(
            std::fs::read(&one_path).unwrap(),
            one_orig,
            "one.js must be restored byte-for-byte"
        );
        assert_eq!(
            std::fs::read(&two_path).unwrap(),
            two_orig,
            "two.js must be restored byte-for-byte"
        );
        // Exact-not-additive (D-05): `.gitignore`, created by `env --write`
        // (not present in snapshot #1) and itself not ignored, is removed on
        // restore. The `.env` file is deliberately left untouched — `env
        // --write` patched `.gitignore` to ignore it, so it left the snapshotted
        // scope and restore never classifies a gitignored path for removal
        // (T-05-09).
        assert!(
            !dir.join(".gitignore").exists(),
            "restore removes non-ignored files created since the snapshot"
        );
        // A pre-restore auto-snap ref was created (env's #1 + back's pre-restore).
        assert_eq!(
            count_auto_refs(&dir),
            2,
            "back must take its own pre-restore auto-snap before restoring"
        );

        // The user's real branches/HEAD are untouched throughout.
        assert!(!head_resolves(&dir), "getdev never creates a user commit");
        assert_eq!(branch_count(&dir), 0, "getdev never creates a user branch");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
