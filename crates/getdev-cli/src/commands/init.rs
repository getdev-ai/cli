//! `getdev init` — non-interactive first-run setup (**zero prompts, ever**).
//! Mirrors `commands::env`/`commands::ship`'s `plan → mutate::apply(writes,
//! hook) → report` shape: it builds a batch of [`PlannedWrite::WriteFile`]s and
//! hands them to the ONE audited [`getdev_core::mutate::apply`] path (atomic
//! write → rollback), with the multi-file [`AutoSnapHook`] firing before any
//! mutation.
//!
//! Plain `getdev init` writes `.getdev.toml` (detected stack + defaults, only if
//! absent) and prints a one-line hint naming the optional extras. `getdev init
//! --all` (with `--yes` as a back-compat alias) ALSO installs, deterministically
//! and with no prompts (docs/SPEC-COMMANDS.md `getdev init`):
//!   1. a `.git/hooks/pre-commit` hook (`getdev check --quiet --fail-on
//!      critical`),
//!   2. an agent-context managed block in any PRESENT
//!      `CLAUDE.md`/`AGENTS.md`/`.cursorrules` (never creates one),
//!   3. a `.git/hooks/post-checkout` auto-snap hook (`getdev snap`).
//!
//! **Why no prompts (B-07):** a prompt after `getdev init` breaks CI/pipes and
//! determinism, and a blocking `read_line` renders as a blind cursor with no
//! exit in embedded/agent terminals — the exact field failure this command was
//! rewritten to remove. The welcome banner also moved OUT of `init`: it is now a
//! one-time first-run greeting shown by `main` on the first getdev invocation of
//! any command (a best-effort cache-dir marker), not by `init`.
//!
//! **Never-clobber (contract):** init only CREATES new files or UPSERTS a
//! marker-delimited managed block. A pre-existing `.getdev.toml` or hook is
//! skipped with a message — another tool's setup is never overwritten. The
//! managed-block upsert is idempotent: re-running init leaves user content
//! outside the markers byte-identical.
//!
//! **Executable bit:** `mutate`'s `atomic_write` hardens every new file to
//! `0600` (IN-07, deliberately kept for secret writes). A non-executable git
//! hook is silently never run, so a CLI-tier `set_permissions(0o700)` follow-up
//! corrects the two hook files after they are written. This is NOT a content
//! write and does not weaken `mutate`'s default.
//!
//! **Network:** none. **Mutates:** yes — only via `core::mutate`.

use std::path::{Path, PathBuf};

use getdev_core::config::Config;
use getdev_core::deps;
use getdev_core::mutate::{self, PlannedWrite};
use getdev_core::scan::ScanContext;
use getdev_core::ship::{self, ShipStack};

/// The marker pair that delimits the getdev-managed region inside an
/// agent-context file. Everything OUTSIDE the pair is user content and is never
/// touched; the region between (inclusive) is replaced idempotently on re-run.
const MARKER_START: &str = "<!-- getdev:managed:start -->";
const MARKER_END: &str = "<!-- getdev:managed:end -->";

/// The agent-context files init will upsert a managed block into — but ONLY if
/// they already exist (init appends to present agent files, never creates one).
const AGENT_FILES: [&str; 3] = ["CLAUDE.md", "AGENTS.md", ".cursorrules"];

pub struct InitArgs {
    pub path: PathBuf,
    /// Install the optional extras too (pre-commit hook, agent-context managed
    /// block, auto-snap post-checkout hook) in addition to writing
    /// `.getdev.toml`. Off by default: plain `init` writes only the config and
    /// prints a hint. No prompting either way — `init` is fully non-interactive
    /// (docs/SPEC-COMMANDS.md `getdev init`; B-07). Clap exposes `--yes` as a
    /// back-compat alias for this flag.
    pub all: bool,
    /// Resolved config — supplies the `[snap]` knobs backing the auto-snap hook
    /// that fires before a multi-file mutation.
    pub cfg: Config,
    /// Suppress the per-step status chatter and the extras hint (global flag).
    pub quiet: bool,
    /// Machine-readable mode: `init` has no JSON payload of its own — this only
    /// suppresses the summary/hint chatter so a scripted `getdev init --json`
    /// stays quiet (global flag).
    pub json: bool,
}

pub fn run(args: &InitArgs) -> anyhow::Result<u8> {
    // Parse-once stack detection, reusing ship::detect_stack over a shared
    // ScanContext-fed dependency graph (07-05) — no forked detector.
    let ctx = ScanContext::build(&args.path)?;
    let (graph, _skipped) = deps::build_graph_with_context(&ctx, &args.path)?;
    let stack = ship::detect_stack(&graph, &args.path);

    let mut writes: Vec<PlannedWrite> = Vec::new();
    // Hook paths whose executable bit must be corrected AFTER mutate::apply
    // (mutate writes new files 0600; a non-executable hook git never runs).
    let mut hooks_to_chmod: Vec<PathBuf> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // --- 1. .getdev.toml (unconditional, but never clobber an existing one) ---
    let config_path = args.path.join(".getdev.toml");
    if config_path.exists() {
        notes.push(".getdev.toml already exists — leaving it untouched".to_owned());
    } else {
        writes.push(PlannedWrite::WriteFile {
            path: config_path,
            original: None,
            new_content: render_getdev_toml(stack),
        });
        notes.push(format!(
            ".getdev.toml — written (detected stack: {})",
            stack.as_str()
        ));
    }

    // Git hooks require a repository. Without a `.git` dir there is nowhere to
    // install them, so skip both hook offers with a clear message rather than
    // writing a hook git would never see.
    let git_dir = args.path.join(".git");
    let is_git_repo = git_dir.is_dir();

    // --- 2. pre-commit hook (--all only) -------------------------------------
    if is_git_repo {
        if args.all {
            let hook_path = git_dir.join("hooks").join("pre-commit");
            if hook_path.exists() {
                notes
                    .push(".git/hooks/pre-commit already exists — leaving it untouched".to_owned());
            } else {
                writes.push(PlannedWrite::WriteFile {
                    path: hook_path.clone(),
                    original: None,
                    new_content: PRE_COMMIT_HOOK.to_owned(),
                });
                hooks_to_chmod.push(hook_path);
                notes.push(".git/hooks/pre-commit — written (getdev check)".to_owned());
            }
        }
    } else {
        notes.push("not a git repository — skipping git hook setup".to_owned());
    }

    // --- 3. agent-context managed block (--all only) -------------------------
    if args.all {
        for name in AGENT_FILES {
            let agent_path = args.path.join(name);
            // Only append to an agent file that already exists — init never
            // creates a CLAUDE.md/AGENTS.md/.cursorrules of its own.
            let existing = match std::fs::read_to_string(&agent_path) {
                Ok(text) => text,
                Err(_) => continue,
            };
            match upsert_managed_block(&existing, AGENT_BLOCK_BODY) {
                // Idempotent: the block is already current — no rewrite queued.
                ManagedBlockOutcome::Unchanged => {
                    notes.push(format!("{name} — managed block already up to date"));
                }
                ManagedBlockOutcome::Updated(updated) => {
                    notes.push(format!("{name} — managed block upserted"));
                    writes.push(PlannedWrite::WriteFile {
                        path: agent_path,
                        original: Some(existing),
                        new_content: updated,
                    });
                }
                // Malformed markers: leave the file untouched and tell the
                // user, rather than risk clobbering content across the
                // ambiguous region (WR-03).
                ManagedBlockOutcome::Anomaly(reason) => {
                    notes.push(format!(
                        "{name} — left untouched: {reason}; resolve the getdev:managed markers by hand"
                    ));
                }
            }
        }
    }

    // --- 4. auto-snap post-checkout hook (--all only) ------------------------
    if is_git_repo && args.all {
        let hook_path = git_dir.join("hooks").join("post-checkout");
        if hook_path.exists() {
            notes.push(".git/hooks/post-checkout already exists — leaving it untouched".to_owned());
        } else {
            writes.push(PlannedWrite::WriteFile {
                path: hook_path.clone(),
                original: None,
                new_content: POST_CHECKOUT_HOOK.to_owned(),
            });
            hooks_to_chmod.push(hook_path);
            notes.push(".git/hooks/post-checkout — written (getdev snap)".to_owned());
        }
    }

    // --- apply through the ONE audited mutate path ---------------------------
    // A multi-file plan (writes.len() > 1) fires the AutoSnapHook before any I/O
    // — the same safety net env/ship rely on. Gate it on the config toggle, and
    // build it into a `let` so it outlives the `apply` call.
    let hook = if args.cfg.snap.auto_snap_before_fix {
        Some(AutoSnapHook {
            root: &args.path,
            keep: args.cfg.snap.keep,
        })
    } else {
        None
    };
    if !writes.is_empty() {
        mutate::apply(
            writes,
            hook.as_ref()
                .map(|h| h as &dyn getdev_core::mutate::PreMutateHook),
        )?;
    }

    // CLI-tier executable-bit fix-up: correct mutate's hardened 0600 to 0700 for
    // the hook files (a non-executable hook git silently never runs). This is
    // set_permissions, not a content write — mutate's default stays intact.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for hook_path in &hooks_to_chmod {
            std::fs::set_permissions(hook_path, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    // Summary + (plain `init` only) the one-line extras hint. Non-interactive:
    // there is never a prompt here — the hint just names what `--all` would add
    // and how to install it (docs/SPEC-COMMANDS.md `getdev init`).
    if !args.quiet && !args.json {
        for note in &notes {
            println!("{note}");
        }
        if !args.all {
            println!();
            println!(
                "optional: pre-commit hook · agent-context block · auto-snap hook — run `getdev init --all` to install"
            );
        }
        println!();
        println!("getdev is set up — run `getdev check` to see your Ship Score");
    }

    Ok(0)
}

/// The result of an [`upsert_managed_block`] transform.
enum ManagedBlockOutcome {
    /// The managed block is already byte-identical — nothing to write.
    Unchanged,
    /// New file content to write (a clean in-place replace, or a first append
    /// under existing user content).
    Updated(String),
    /// The file's markers are malformed — the payload is the human-facing
    /// reason. The file is left UNTOUCHED so init can never clobber user
    /// content across ambiguous markers (WR-03).
    Anomaly(&'static str),
}

/// Idempotent marker-delimited upsert (pure string transform, no I/O).
///
/// Safe cases only:
/// - **no markers** → append a fresh block under the existing content;
/// - **exactly one well-ordered `START…END` pair** → replace that region
///   (inclusive) in place, preserving everything outside byte-for-byte.
///
/// Anything else — a reversed pair (`END` before `START`), an orphaned single
/// marker, or duplicated markers — is an [`ManagedBlockOutcome::Anomaly`]: the
/// file is left untouched and the caller warns. Blindly splicing on the first
/// `find` of each marker (the pre-WR-03 behavior) could delete every byte
/// between an unrelated stray marker and the real one, or corrupt a reversed
/// pair; and blindly appending would grow a fresh block on every re-run once a
/// duplicate exists (non-idempotent). Refusing to touch a malformed file is the
/// only choice that is both non-destructive and idempotent.
fn upsert_managed_block(existing: &str, body: &str) -> ManagedBlockOutcome {
    let block = format!("{MARKER_START}\n{body}\n{MARKER_END}");
    let starts = existing.matches(MARKER_START).count();
    let ends = existing.matches(MARKER_END).count();

    match (starts, ends) {
        // First run: no managed block yet — append cleanly under user content.
        (0, 0) => {
            let mut out = existing.to_owned();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&block);
            out.push('\n');
            ManagedBlockOutcome::Updated(out)
        }
        // Exactly one of each — the only shape we replace in place, and only
        // when START precedes END (a well-ordered, non-overlapping pair).
        (1, 1) => {
            let (Some(start), Some(end_at)) =
                (existing.find(MARKER_START), existing.find(MARKER_END))
            else {
                return ManagedBlockOutcome::Anomaly("getdev managed markers are malformed");
            };
            if start >= end_at {
                return ManagedBlockOutcome::Anomaly("getdev end marker precedes its start marker");
            }
            let end = end_at + MARKER_END.len();
            let mut out = String::with_capacity(existing.len() + block.len());
            out.push_str(&existing[..start]);
            out.push_str(&block);
            out.push_str(&existing[end..]);
            if out == existing {
                ManagedBlockOutcome::Unchanged
            } else {
                ManagedBlockOutcome::Updated(out)
            }
        }
        // Duplicated or orphaned markers — refuse to guess which span is ours.
        _ => ManagedBlockOutcome::Anomaly("duplicated or orphaned getdev managed markers"),
    }
}

/// Map the detected [`ShipStack`] onto the `[project] stack` config value,
/// which is the coarse `"auto" | "node" | "python"` axis (docs/SPEC-CONFIG.md),
/// not the finer ship preset.
fn project_stack(stack: ShipStack) -> &'static str {
    match stack {
        ShipStack::NodeNextjs | ShipStack::Node => "node",
        ShipStack::Fastapi | ShipStack::Flask | ShipStack::Django => "python",
        ShipStack::Unknown => "auto",
    }
}

/// The `.getdev.toml` body: the detected `[project] stack` plus the documented
/// defaults (docs/SPEC-CONFIG.md full v0.1 surface). Every key here is a real,
/// `deny_unknown_fields`-valid config key, so the written file round-trips
/// cleanly through `Config::parse`.
fn render_getdev_toml(stack: ShipStack) -> String {
    format!(
        "# .getdev.toml — getdev project configuration\n\
         # generated by `getdev init`; see https://getdev.ai\n\
         # detected stack: {detected}\n\
         \n\
         [project]\n\
         stack = \"{project}\"\n\
         \n\
         [check]\n\
         fail_on = \"high\"\n\
         \n\
         [real]\n\
         offline = false\n\
         check_apis = true\n\
         typosquat_sensitivity = \"normal\"\n\
         \n\
         [audit]\n\
         severity_min = \"low\"\n\
         \n\
         [review]\n\
         against = \"HEAD\"\n\
         \n\
         [env]\n\
         env_file = \".env\"\n\
         \n\
         [snap]\n\
         keep = 20\n\
         auto_snap_before_fix = true\n\
         \n\
         [ship]\n\
         target = \"auto\"\n\
         run_build = false\n",
        detected = stack.as_str(),
        project = project_stack(stack),
    )
}

/// The pre-commit hook body — a POSIX shell script running the fast critical
/// gate. Written non-executable by mutate (0600); the CLI-tier chmod above
/// corrects it to 0700.
const PRE_COMMIT_HOOK: &str = "#!/bin/sh\n\
     # managed by `getdev init` — block a commit on any critical finding\n\
     getdev check --quiet --fail-on critical\n";

/// The post-checkout auto-snap hook body — records a getdev snapshot on every
/// checkout so the user always has an undo point (07-RESEARCH A3: a literal
/// hook, not prose).
const POST_CHECKOUT_HOOK: &str = "#!/bin/sh\n\
     # managed by `getdev init` — snapshot the working tree on checkout\n\
     getdev snap\n";

/// The agent-context guidance placed between the managed-block markers, so a
/// coding agent reading CLAUDE.md/AGENTS.md/.cursorrules learns the getdev
/// workflow (docs/SPEC-COMMANDS.md step 3).
const AGENT_BLOCK_BODY: &str = "## getdev\n\
     \n\
     This project uses getdev to verify AI-generated code. Before large\n\
     changes run `getdev snap` (a reversible checkpoint); after changes run\n\
     `getdev check` and address findings. Use `getdev env --write` to move\n\
     hardcoded secrets into `.env`. All getdev commands run locally — nothing\n\
     leaves your machine.";

/// The concrete `PreMutateHook` backing `core::mutate`'s auto-snap seam with a
/// real `getdev-gitx` snapshot — identical to `commands::env`/`commands::ship`,
/// only the message differs. Before a multi-file `init` mutates anything it
/// records a deduped safety snapshot under `refs/getdev/auto/<N>`; any
/// `GitxError` aborts the plan closed (a security tool must not write multiple
/// files with no undo path).
struct AutoSnapHook<'a> {
    root: &'a Path,
    keep: u32,
}

impl getdev_core::mutate::PreMutateHook for AutoSnapHook<'_> {
    fn before_multi_file_write(&self, _paths: &[&Path]) -> Result<(), String> {
        getdev_gitx::snap::snapshot(
            self.root,
            getdev_gitx::snap::Namespace::Auto,
            "auto: before init",
            true,
            self.keep,
        )
        .map(|_outcome| ())
        .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{upsert_managed_block, ManagedBlockOutcome, MARKER_END, MARKER_START};

    fn updated(existing: &str) -> String {
        match upsert_managed_block(existing, "BODY") {
            ManagedBlockOutcome::Updated(out) => out,
            other => panic!("expected Updated, got {}", label(&other)),
        }
    }

    fn label(o: &ManagedBlockOutcome) -> &'static str {
        match o {
            ManagedBlockOutcome::Unchanged => "Unchanged",
            ManagedBlockOutcome::Updated(_) => "Updated",
            ManagedBlockOutcome::Anomaly(_) => "Anomaly",
        }
    }

    #[test]
    fn appends_a_fresh_block_when_no_markers_present() {
        let out = updated("# Notes\n\nkeep me\n");
        assert_eq!(out.matches(MARKER_START).count(), 1);
        assert_eq!(out.matches(MARKER_END).count(), 1);
        assert!(out.starts_with("# Notes\n\nkeep me\n"));
        assert!(out.contains("\nBODY\n"));
    }

    #[test]
    fn appending_into_empty_content_needs_no_leading_blank_line() {
        let out = updated("");
        assert!(out.starts_with(MARKER_START), "no leading blank: {out:?}");
    }

    #[test]
    fn replaces_a_well_ordered_pair_in_place_and_preserves_surrounding_bytes() {
        let existing = format!("above\n{MARKER_START}\nOLD\n{MARKER_END}\nbelow\n");
        let out = updated(&existing);
        assert_eq!(
            out,
            format!("above\n{MARKER_START}\nBODY\n{MARKER_END}\nbelow\n")
        );
    }

    #[test]
    fn re_running_on_a_current_block_is_unchanged() {
        let existing = format!("x\n{MARKER_START}\nBODY\n{MARKER_END}\ny\n");
        assert!(matches!(
            upsert_managed_block(&existing, "BODY"),
            ManagedBlockOutcome::Unchanged
        ));
    }

    #[test]
    fn reversed_markers_are_an_anomaly_and_never_splice() {
        // END before START — the pre-WR-03 guard could splice these and corrupt
        // the file; now it is refused untouched.
        let existing = format!("a\n{MARKER_END}\nuser stuff\n{MARKER_START}\nb\n");
        assert!(matches!(
            upsert_managed_block(&existing, "BODY"),
            ManagedBlockOutcome::Anomaly(_)
        ));
    }

    #[test]
    fn a_stray_extra_start_marker_never_deletes_user_content() {
        // A stray START in prose ABOVE the real block: first-find splicing would
        // have deleted everything between the stray marker and the real END.
        let existing = format!(
            "intro mentioning {MARKER_START} in prose\n\nreal block:\n{MARKER_START}\nOLD\n{MARKER_END}\ntail\n"
        );
        assert!(matches!(
            upsert_managed_block(&existing, "BODY"),
            ManagedBlockOutcome::Anomaly(_)
        ));
    }

    #[test]
    fn an_orphaned_single_marker_is_an_anomaly() {
        let existing = format!("only an opening marker\n{MARKER_START}\ntrailing\n");
        assert!(matches!(
            upsert_managed_block(&existing, "BODY"),
            ManagedBlockOutcome::Anomaly(_)
        ));
    }
}
