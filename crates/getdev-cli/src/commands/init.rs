//! `getdev init` — interactive first-run setup. Mirrors `commands::env`/
//! `commands::ship`'s `plan → mutate::apply(writes, hook) → report` shape: it
//! builds a batch of [`PlannedWrite::WriteFile`]s and hands them to the ONE
//! audited [`getdev_core::mutate::apply`] path (atomic write → rollback), with
//! the multi-file [`AutoSnapHook`] firing before any mutation.
//!
//! It does four things (docs/SPEC-COMMANDS.md `getdev init`):
//!   1. writes `.getdev.toml` (detected stack + defaults),
//!   2. offers a `.git/hooks/pre-commit` hook (`getdev check --quiet --fail-on
//!      critical`),
//!   3. offers an agent-context managed block in any present
//!      `CLAUDE.md`/`AGENTS.md`/`.cursorrules`,
//!   4. offers a `.git/hooks/post-checkout` auto-snap hook (`getdev snap`).
//!
//! **Never-clobber (contract):** init only CREATES new files or UPSERTS a
//! marker-delimited managed block. A pre-existing `.getdev.toml` or hook is
//! skipped with a message — another tool's setup is never overwritten. The
//! managed-block upsert is idempotent: re-running init leaves user content
//! outside the markers byte-identical.
//!
//! **`--yes`** bypasses every `dialoguer` prompt with documented defaults
//! (yes to each offer) — CI/non-interactive safe.
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
    /// Bypass every interactive prompt, taking the documented default (yes) for
    /// each offer — non-interactive/CI-safe (docs/SPEC-COMMANDS.md).
    pub yes: bool,
    /// Resolved config — supplies the `[snap]` knobs backing the auto-snap hook
    /// that fires before a multi-file mutation.
    pub cfg: Config,
    /// Suppress the per-step status chatter AND the welcome banner (global flag).
    pub quiet: bool,
    /// Disable ANSI colors in the welcome banner (global flag; `NO_COLOR` and a
    /// non-tty stdout are honored too, via `ColorMode::resolve`).
    pub no_color: bool,
    /// Machine-readable mode: suppress the decorative welcome banner entirely
    /// (global flag). `init` has no JSON payload of its own — this only gates
    /// the banner so a scripted `getdev init --json` stays free of art.
    pub json: bool,
}

pub fn run(args: &InitArgs) -> anyhow::Result<u8> {
    // First-run welcome (decorative only): shown once at the very top of
    // `getdev init`, before the interactive offers. Suppressed under `--quiet`
    // and `--json`; rendered plain (no ANSI) under `--no-color`/`NO_COLOR`/a
    // non-tty stdout. It carries NO call-to-action — the tagline restates the
    // product promise only (CLAUDE.md standing rules: no telemetry/CTA).
    if !args.quiet && !args.json {
        use std::io::IsTerminal as _;
        let color =
            getdev_core::report::ColorMode::resolve(args.no_color, std::io::stdout().is_terminal());
        print!(
            "{}",
            getdev_core::report::render_welcome_banner(env!("CARGO_PKG_VERSION"), color)
        );
        println!();
    }

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

    // --- 2. pre-commit hook (offered) ----------------------------------------
    if is_git_repo {
        if offer("install a pre-commit hook (getdev check)?", args.yes)? {
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

    // --- 3. agent-context managed block (offered) ----------------------------
    if offer("add a getdev managed block to agent files?", args.yes)? {
        for name in AGENT_FILES {
            let agent_path = args.path.join(name);
            // Only append to an agent file that already exists — init never
            // creates a CLAUDE.md/AGENTS.md/.cursorrules of its own.
            let existing = match std::fs::read_to_string(&agent_path) {
                Ok(text) => text,
                Err(_) => continue,
            };
            let updated = upsert_managed_block(&existing, AGENT_BLOCK_BODY);
            // Idempotent: if the block is already current, don't queue a
            // no-op rewrite of identical bytes.
            if updated == existing {
                notes.push(format!("{name} — managed block already up to date"));
                continue;
            }
            notes.push(format!("{name} — managed block upserted"));
            writes.push(PlannedWrite::WriteFile {
                path: agent_path,
                original: Some(existing),
                new_content: updated,
            });
        }
    }

    // --- 4. auto-snap post-checkout hook (offered) ---------------------------
    if is_git_repo && offer("install an auto-snap post-checkout hook?", args.yes)? {
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

    if !args.quiet {
        for note in &notes {
            println!("{note}");
        }
        println!();
        println!("getdev is set up — run `getdev check` to see your Ship Score");
    }

    Ok(0)
}

/// Offer a yes/no step: `--yes` takes the documented default (yes) and bypasses
/// the prompt entirely (CI-safe); otherwise ask a plain line-based `[Y/n]`
/// question on stdout. Deliberately NOT a raw-mode prompt library: raw mode
/// hides the cursor, swallows unechoed keystrokes, and renders to stderr —
/// when any of that misfires the user sees a blank line that eats typing and
/// concludes the program hung (observed in the field on v0.1.2, which used
/// `dialoguer`). A flushed stdout prompt + `read_line` echoes what the user
/// types, accepts Enter for the default, and behaves identically in every
/// terminal. Non-TTY stdin/stdout without `--yes` skips the offer (answer
/// no) instead of blocking on input that can never arrive; EOF (ctrl-d)
/// likewise answers no.
fn offer(prompt: &str, yes: bool) -> anyhow::Result<bool> {
    use std::io::{IsTerminal as _, Write as _};
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        println!("{prompt} — skipped (non-interactive; pass --yes to accept offers)");
        return Ok(false);
    }
    let mut stdout = std::io::stdout();
    write!(stdout, "{prompt} [Y/n]: ")?;
    stdout.flush()?;
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line)? == 0 {
        println!();
        return Ok(false);
    }
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "" | "y" | "yes"
    ))
}

/// Idempotent marker-delimited upsert (pure string transform, no I/O): replace
/// the region between [`MARKER_START`]/[`MARKER_END`] (inclusive) if both are
/// present, else append a fresh block. Everything outside the markers is user
/// content and is preserved byte-for-byte — so running init twice neither
/// duplicates the block nor alters the surrounding file.
fn upsert_managed_block(existing: &str, body: &str) -> String {
    let block = format!("{MARKER_START}\n{body}\n{MARKER_END}");
    if let (Some(start), Some(end_at)) = (existing.find(MARKER_START), existing.find(MARKER_END)) {
        let end = end_at + MARKER_END.len();
        if end >= start {
            let mut out = String::with_capacity(existing.len() + block.len());
            out.push_str(&existing[..start]);
            out.push_str(&block);
            out.push_str(&existing[end..]);
            return out;
        }
    }
    // No markers yet — append the block after the existing content, separated by
    // a blank line so it reads cleanly under whatever the user already wrote.
    let mut out = existing.to_owned();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&block);
    out.push('\n');
    out
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
