#![forbid(unsafe_code)]

mod commands;
mod progress;
mod update;

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use getdev_core::config::{self, Config};
use getdev_core::findings::Severity;

#[derive(Parser)]
#[command(
    name = "getdev",
    version,
    about = "verify, secure, and ship AI-generated code",
    long_about = "getdev — verify, secure, and ship AI-generated code.\n\
                  One binary, runs locally, nothing leaves your machine."
)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,
    #[command(subcommand)]
    command: Command,
}

/// True global flags (docs/PLAN.md §2.2): accepted after any subcommand
/// thanks to clap's `global = true`, resolved once in `main` and threaded
/// explicitly to each command — no hidden global state, consistent with
/// `scan.rs`'s parse-once design. B4 audit fix: `--json`/`--no-color`/
/// `--path`/`--fail-on` moved here from being per-command duplicates on
/// `env`/`real` only — every command now genuinely shares one flag surface.
#[derive(Args, Debug, Clone)]
struct GlobalArgs {
    /// Machine-readable output (findings schema, docs/SPEC-FINDINGS.md)
    #[arg(long, global = true)]
    json: bool,
    /// Write the full JSON report to FILE (findings commands: check/real/
    /// audit/review/env/ship); the terminal keeps a short summary. With
    /// --json, only the file path is printed
    #[arg(long, short = 'o', global = true, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Suppress banner/progress; findings only
    #[arg(long, short = 'q', global = true, conflicts_with = "verbose")]
    quiet: bool,
    /// Debug-level detail (repeatable: -vv)
    #[arg(
        long,
        short = 'v',
        global = true,
        action = clap::ArgAction::Count,
        conflicts_with = "quiet"
    )]
    verbose: u8,
    /// Disable ANSI colors (NO_COLOR is also honored)
    #[arg(long, global = true)]
    no_color: bool,
    /// Alternate config file (default: ./.getdev.toml)
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Run against a directory other than CWD
    #[arg(long, global = true, default_value = ".", value_name = "DIR")]
    path: PathBuf,
    /// Exit code 1 if any finding is at or above this severity
    /// (critical|high|medium|low)
    #[arg(long, global = true, value_name = "SEVERITY", value_parser = parse_fail_on)]
    fail_on: Option<Severity>,
    /// Apply auto-fixes where the command supports them
    #[arg(long, global = true)]
    fix: bool,
    /// Never hit the network; use cache only
    #[arg(long, global = true)]
    offline: bool,
}

impl Default for GlobalArgs {
    fn default() -> Self {
        Self {
            json: false,
            output: None,
            quiet: false,
            verbose: 0,
            no_color: false,
            config: None,
            path: PathBuf::from("."),
            fail_on: None,
            fix: false,
            offline: false,
        }
    }
}

/// `--fail-on` accepts `critical|high|medium|low` only — `info` is rejected
/// at parse time (docs/PLAN.md §2.2; info-level findings never fail a run).
fn parse_fail_on(raw: &str) -> Result<Severity, String> {
    if raw == "info" {
        return Err(
            "info is not a valid --fail-on threshold (must be critical|high|medium|low — \
             info-level findings never fail a run per docs/PLAN.md §2.2)"
                .to_owned(),
        );
    }
    raw.parse::<Severity>()
}

/// `audit --severity <min>` accepts the full `critical|high|medium|low|info`
/// range (unlike `--fail-on`) — it's a display/reporting floor, not an
/// exit-code threshold.
fn parse_severity(raw: &str) -> Result<Severity, String> {
    raw.parse::<Severity>()
}

#[derive(Subcommand)]
enum Command {
    /// Umbrella scan: real + audit + env(detect) + review --all over one shared
    /// parse pass, with a Ship Score banner. `check --json --fail-on high` is
    /// the canonical CI line. Global flags only (docs/SPEC-COMMANDS.md `check`).
    Check,
    /// Extract hardcoded secrets to .env (dry-run by default)
    Env {
        /// Target env file (default: `[env] env_file` in config, else ".env")
        #[arg(long, value_name = "PATH")]
        env_file: Option<String>,
        /// Apply the plan: write the env files and rewrite references
        #[arg(long)]
        write: bool,
        /// Also extract http(s) URLs and connection strings (DSNs) assigned to
        /// identifiers, not just secret-pattern matches (docs/SPEC-COMMANDS.md
        /// `env`). ORs with `[env] include_urls` config.
        #[arg(long)]
        include_urls: bool,
    },
    /// Verify packages / APIs / model strings actually exist
    Real {
        /// Only run the dependency/package existence checks
        #[arg(long, conflicts_with_all = ["apis_only", "models_only"])]
        deps_only: bool,
        /// Only run the API-surface checks
        #[arg(long, conflicts_with_all = ["deps_only", "models_only"])]
        apis_only: bool,
        /// Only run the LLM model-string check
        #[arg(long, conflicts_with_all = ["deps_only", "apis_only"])]
        models_only: bool,
    },
    /// Security scan tuned to AI-generated failure patterns (offline,
    /// non-mutating; docs/SPEC-COMMANDS.md `getdev audit`)
    Audit {
        /// Drop findings below this severity (critical|high|medium|low|info;
        /// default: `[audit] severity_min` in config, else low)
        #[arg(long, value_name = "SEVERITY", value_parser = parse_severity)]
        severity: Option<Severity>,
        /// Suppress findings from this rule id (repeatable)
        #[arg(long, value_name = "RULE_ID")]
        ignore: Vec<String>,
        /// Merge a directory of user-authored rule YAML into the embedded
        /// pack (declarative-only — never executable)
        #[arg(long, value_name = "DIR")]
        rules: Option<PathBuf>,
    },
    /// Analyze a diff for agent-session artifacts (working tree vs `HEAD` by
    /// default; offline, non-mutating). Rule prefix `review/`. Diff extraction
    /// via getdev-gitx (docs/SPEC-COMMANDS.md `getdev review`).
    Review {
        /// Compare the working tree against `<ref>` (e.g. `main`, `HEAD~3`)
        /// instead of `HEAD`
        #[arg(long, value_name = "REF", conflicts_with_all = ["staged", "all"])]
        against: Option<String>,
        /// Review only the staged changes (index vs `HEAD`)
        #[arg(long, conflicts_with_all = ["against", "all"])]
        staged: bool,
        /// Review the whole tree, not just the diff (no git required)
        #[arg(long, conflicts_with_all = ["against", "staged"])]
        all: bool,
    },
    /// Prepare & validate for deploy: detect the stack, run the three `ship/*`
    /// validators, and print a per-target checklist. `--write` generates a
    /// multi-stage Dockerfile + .dockerignore + SHIP.md via `core::mutate`;
    /// `--run-build` is the ONLY opt-in that executes project code (off by
    /// default). No flags beyond these + globals (docs/SPEC-COMMANDS.md `ship`).
    Ship {
        /// Generate Dockerfile + .dockerignore + SHIP.md (via core::mutate)
        #[arg(long)]
        write: bool,
        /// Deployment target for the checklist (default: `[ship] target`, else
        /// auto-detected/docker)
        #[arg(long, value_enum, value_name = "TARGET")]
        target: Option<ShipTarget>,
        /// Run the project's build — the ONLY command that executes project
        /// code, off by default (getdev never runs your code without this)
        #[arg(long)]
        run_build: bool,
    },
    /// Working-tree checkpoints under `refs/getdev/` (git-hidden; never touches
    /// user branches/index/stash). `snap [-m <msg>] | list | diff <id> | prune`
    Snap {
        /// Label for the snapshot
        #[arg(short = 'm', long, value_name = "MSG")]
        message: Option<String>,
        #[command(subcommand)]
        action: Option<SnapAction>,
    },
    /// Restore the latest manual snapshot (or a specific `<id>`) — always
    /// reversible (takes a pre-restore auto-snap first)
    Back {
        /// Snapshot id to restore (default: the most recent manual snapshot)
        id: Option<u32>,
    },
    /// Non-interactive first-run setup (zero prompts): write `.getdev.toml`
    /// (detected stack + defaults, only if absent) and print a hint listing the
    /// optional extras. `--all` ALSO installs a pre-commit hook, an
    /// agent-context managed block (into an existing agent file only), and an
    /// auto-snap post-checkout hook — deterministically, never clobbering
    /// pre-existing content (docs/SPEC-COMMANDS.md `init`; B-07).
    Init {
        /// Also install the optional extras (pre-commit hook, agent-context
        /// block, auto-snap hook). `--yes` is a back-compat alias
        #[arg(long, alias = "yes")]
        all: bool,
    },
    /// Self-diagnostics: toolchain, git availability, grammar integrity
    Doctor,
    /// Self-update the binary from GitHub Releases: verify the release's
    /// SHA-256 checksum + keyed-cosign signature, then atomically replace the
    /// running binary (mutates the binary only, never project files). Channel /
    /// pin / downgrade are `[update]` config — NO per-command flags, global
    /// flags only (docs/SPEC-COMMANDS.md `update`, CLAUDE.md rule 6).
    /// `--offline` makes it an explicit no-op.
    Update,
}

/// The `getdev ship --target` values (docs/SPEC-COMMANDS.md `ship`). A thin
/// clap `ValueEnum` at the CLI boundary that maps onto
/// [`getdev_core::ship::ShipTarget`] — `core::ship` owns the canonical enum;
/// this only exists so clap can parse/validate the flag and render `--help`.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum ShipTarget {
    Vercel,
    Railway,
    Fly,
    Docker,
    Vps,
}

impl From<ShipTarget> for getdev_core::ship::ShipTarget {
    fn from(target: ShipTarget) -> Self {
        match target {
            ShipTarget::Vercel => Self::Vercel,
            ShipTarget::Railway => Self::Railway,
            ShipTarget::Fly => Self::Fly,
            ShipTarget::Docker => Self::Docker,
            ShipTarget::Vps => Self::Vps,
        }
    }
}

/// The `getdev snap` sub-actions. Ids are typed `u32` so clap rejects
/// non-integer/negative input as a clean parse error and relative addressing is
/// structurally impossible (D-03, V5) — no custom parser, no extra flags
/// (CLAUDE.md hard rule 6).
#[derive(Subcommand)]
enum SnapAction {
    /// List manual snapshots (id, age, message, files changed). Auto-snaps
    /// (the pre-fix/pre-restore safety net) are not listed — they are what
    /// `getdev back` restores from.
    List,
    /// Summarize the changes since snapshot `<id>`
    Diff {
        /// Snapshot id
        id: u32,
    },
    /// Enforce retention (keep the newest `[snap] keep`, delete the rest)
    Prune,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => std::process::ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            // exit-code contract (docs/PLAN.md §2.2):
            // 1 findings ≥ --fail-on · 2 execution error · 3 config error
            if err
                .downcast_ref::<getdev_core::config::ConfigError>()
                .is_some()
            {
                std::process::ExitCode::from(3)
            } else {
                std::process::ExitCode::from(2)
            }
        }
    }
}

/// Resolves config precedence once (flags > project > global > defaults)
/// and threads the result explicitly to every command — see `GlobalArgs`'s
/// doc-comment for why this stays explicit rather than becoming hidden
/// global state.
fn run(cli: Cli) -> anyhow::Result<u8> {
    // One-time first-run welcome (best-effort): the decorative banner shows once,
    // on the first getdev invocation of ANY command, then never again. It NEVER
    // fails or delays a command — see `maybe_first_run_welcome`. Runs before the
    // doctor early-return so it covers every command uniformly.
    maybe_first_run_welcome(cli.global.quiet, cli.global.json, cli.global.no_color);

    // B3: doctor must survive a malformed config — it exists specifically to
    // diagnose things like a broken `.getdev.toml`, so a `ConfigError` here
    // must never kill the process before doctor's own checks even run.
    // Every other command keeps the hard exit-3 via `Config::resolve`'s `?`
    // below (docs/PLAN.md §2.2 exit-code contract); doctor resolves config
    // leniently (falls back to defaults) and separately reports the same
    // parse failure as a failed row via its own `Config::load` check.
    if matches!(cli.command, Command::Doctor) {
        // IN-02: honor the global `--path` like every other command — doctor
        // validates the config at the target directory, not an unconditional
        // CWD. `--path` defaults to "." so unqualified `getdev doctor` is
        // unchanged.
        let cfg =
            Config::resolve(cli.global.config.as_deref(), &cli.global.path).unwrap_or_default();
        let offline = config::offline_resolved(cli.global.offline, &cfg);
        return commands::doctor::run(&commands::doctor::DoctorArgs {
            path: cli.global.path.clone(),
            offline,
            fix: cli.global.fix,
            json: cli.global.json,
            quiet: cli.global.quiet,
            no_color: cli.global.no_color,
        });
    }

    let cfg = Config::resolve(cli.global.config.as_deref(), &cli.global.path)?;
    let offline = config::offline_resolved(cli.global.offline, &cfg);
    let quiet = cli.global.quiet;
    let verbose = cli.global.verbose;
    let json = cli.global.json;
    let output = cli.global.output.clone();
    let no_color = cli.global.no_color;
    let fail_on = cli.global.fail_on;
    let path = cli.global.path.clone();

    match cli.command {
        // The umbrella command: real + audit + env(detect) + review --all over
        // ONE shared ScanContext, a single-sourced Ship Score, and the standard
        // `--fail-on` exit contract (docs/SPEC-COMMANDS.md `check`). Global
        // flags only — no command-specific flags (CLAUDE.md rule 6). `--fix`
        // maps to `env --write` via the existing global path, not this default
        // aggregation run.
        Command::Check => commands::check::run(&commands::check::CheckArgs {
            path,
            json,
            output: output.clone(),
            no_color,
            fail_on,
            offline,
            cfg: cfg.clone(),
            quiet,
            verbose,
        }),
        // B5: global `--fix` behaves exactly like `--write` on `env` — its
        // findings are all `fixable: true`, and docs/SPEC-COMMANDS.md's
        // "--fix on check maps to this" implies the same for the bare
        // command. Previously `--fix` silently did nothing here.
        Command::Env {
            env_file,
            write,
            include_urls,
        } => {
            // B2(a): `[env] env_file` feeds EnvOptions when `--env-file`
            // wasn't explicitly passed — the flag stays `Option<String>`
            // (no `default_value`) specifically so "unset" is distinguishable
            // from "user passed .env", which a `value_source` lookup would
            // otherwise be needed for.
            let env_file = env_file.unwrap_or_else(|| cfg.env.env_file.clone());
            // The `--include-urls` flag ORs with `[env] include_urls` config —
            // either turns on 08-02's URL/DSN detection (mirroring the env_file
            // flag-over-config precedence above). 08-02 shipped the detection
            // engine, so the old "documented-but-unimplemented" warning is gone.
            let include_urls = include_urls || cfg.env.include_urls;
            commands::env::run(&commands::env::EnvArgs {
                path,
                json,
                output: output.clone(),
                no_color,
                fail_on,
                env_file,
                include_urls,
                write: write || cli.global.fix,
                cfg: cfg.clone(),
                quiet,
                verbose,
            })
        }
        Command::Real {
            deps_only,
            apis_only,
            models_only,
        } => commands::real::run(&commands::real::RealArgs {
            path,
            json,
            output: output.clone(),
            no_color,
            fail_on,
            offline,
            deps_only,
            apis_only,
            models_only,
            check_apis: cfg.real.check_apis,
            typosquat_sensitivity: cfg.real.typosquat_sensitivity.clone(),
            cfg: cfg.clone(),
            quiet,
            verbose,
        }),
        Command::Audit {
            severity,
            ignore,
            rules,
        } => {
            let severity_min = severity.unwrap_or(cfg.audit.severity_min);
            commands::audit::run(&commands::audit::AuditArgs {
                path,
                json,
                output: output.clone(),
                no_color,
                fail_on,
                severity_min,
                ignore,
                rules_dir: rules,
                cfg: cfg.clone(),
                quiet,
                verbose,
            })
        }
        Command::Review {
            against,
            staged,
            all,
        } => {
            // The CLI is the sole boundary that maps `getdev_gitx::diff` types
            // onto `core::review`'s own input types — `core::review` may not
            // depend on `getdev-gitx` (ARCHITECTURE.md; 06-02-SUMMARY). `--all`
            // bypasses git entirely (the walker synthesizes whole-file ranges).
            let scope = if all {
                getdev_core::review::ReviewScope::All
            } else {
                let diff_scope = if staged {
                    getdev_gitx::diff::DiffScope::Staged
                } else if let Some(reference) = against {
                    // Open Q1 LOCKED: working tree vs the given ref.
                    getdev_gitx::diff::DiffScope::Against(reference)
                } else if cfg.review.against != "HEAD" {
                    // `[review] against` supplies the comparison ref when
                    // `--against` is absent; the default ("HEAD") is the common
                    // working-tree-vs-HEAD case below.
                    getdev_gitx::diff::DiffScope::Against(cfg.review.against.clone())
                } else {
                    getdev_gitx::diff::DiffScope::WorkingTreeVsHead
                };
                // A `GitxError` (git absent/too old) surfaces as an anyhow error
                // → exit 2 via `main`'s mapping. A non-repo yields zero changed
                // files (never an error), so `getdev review` on a folder with no
                // git prints a clean report and exits 0.
                let changed = getdev_gitx::diff::changed_files(&path, &diff_scope)?;
                let mapped = changed.into_iter().map(map_changed_file).collect();
                getdev_core::review::ReviewScope::Diff(mapped)
            };
            commands::review::run(&commands::review::ReviewArgs {
                path,
                json,
                output: output.clone(),
                no_color,
                fail_on,
                // Review has no `--severity` flag/config — report every
                // `review/*` finding; suppression is config + `--fail-on` only.
                severity_min: Severity::Info,
                scope,
                cfg: cfg.clone(),
                quiet,
                verbose,
            })
        }
        Command::Ship {
            write,
            target,
            run_build,
        } => commands::ship::run(&commands::ship::ShipArgs {
            path,
            // Safe-by-default: ship generates files ONLY on the explicit
            // `--write` (unlike `env`, the global `--fix` never triggers a
            // deploy-scaffold mutation — critical constraint).
            write,
            target: target.map(Into::into),
            run_build,
            json,
            output: output.clone(),
            no_color,
            fail_on,
            cfg: cfg.clone(),
            quiet,
            verbose,
        }),
        Command::Snap { message, action } => {
            // Map the clap sub-action onto the command layer's clap-free mirror
            // so `commands/snap.rs` stays a plain args struct like every other
            // command (doctor precedent).
            let action = action.map(|a| match a {
                SnapAction::List => commands::snap::SnapAction::List,
                SnapAction::Diff { id } => commands::snap::SnapAction::Diff { id },
                SnapAction::Prune => commands::snap::SnapAction::Prune,
            });
            commands::snap::run(&commands::snap::SnapArgs {
                path,
                json,
                no_color,
                quiet,
                keep: cfg.snap.keep,
                message,
                action,
            })
        }
        Command::Back { id } => commands::back::run(&commands::back::BackArgs {
            path,
            json,
            no_color,
            quiet,
            keep: cfg.snap.keep,
            id,
        }),
        Command::Init { all } => commands::init::run(&commands::init::InitArgs {
            path,
            all,
            cfg: cfg.clone(),
            quiet,
            json,
        }),
        Command::Doctor => {
            // Doctor is dispatched above (before config resolution) and
            // returns, so this arm is unreachable today. It stays a
            // non-panicking `bail!` rather than `unreachable!` so a future
            // reorder of the two dispatch sites degrades to a clean CLI error
            // (exit 2), never a panic across the crate boundary (CLAUDE.md
            // rule 1). IN-01.
            anyhow::bail!("internal: doctor should have been dispatched before config resolution")
        }
        // Self-update: global flags only. Offline is already resolved above
        // (same path as doctor/real); `[update]` config carries channel/pin/
        // downgrade so the command surface stays flag-free (CLAUDE.md rule 6).
        Command::Update => commands::update::run(&commands::update::UpdateArgs {
            offline,
            json,
            quiet,
            no_color,
            cfg: cfg.update.clone(),
        }),
    }
}

/// Best-effort one-time first-run welcome. Prints the decorative welcome banner
/// EXACTLY once — guarded by a `.welcomed` marker in getdev's cache dir (the
/// same dir the registry cache uses, `GETDEV_CACHE_DIR`-overridable for tests) —
/// and only when stdout is a TTY and output is not suppressed (`--quiet`/
/// `--json`), honoring `--no-color`/`NO_COLOR` via `ColorMode::resolve`.
///
/// **Never fails or delays a command (B-07 spirit):** every filesystem step is
/// wrapped so an unreadable/unwritable cache dir simply means the banner may
/// show again later — it can never surface an error or block a command. If the
/// marker cannot be written, the banner has still been shown; the only cost is a
/// possible repeat on the next run.
fn maybe_first_run_welcome(quiet: bool, json: bool, no_color: bool) {
    use std::io::IsTerminal as _;
    // Decorative-only: nothing to show under --quiet/--json or when piped.
    if quiet || json || !std::io::stdout().is_terminal() {
        return;
    }
    let cache_dir = getdev_registry::cache::cache_dir();
    // Already welcomed — a best-effort existence check; a read error (treated as
    // "absent") at worst re-shows the banner, never breaks the command.
    if already_welcomed(&cache_dir) {
        return;
    }
    let color = getdev_core::report::ColorMode::resolve(no_color, true);
    print!(
        "{}",
        getdev_core::report::render_welcome_banner(env!("CARGO_PKG_VERSION"), color)
    );
    println!();
    record_welcomed(&cache_dir);
}

/// The first-run marker path inside getdev's cache dir. A sibling of the
/// registry cache DB, so the two share one best-effort, `GETDEV_CACHE_DIR`-
/// overridable location.
fn welcome_marker(cache_dir: &std::path::Path) -> PathBuf {
    cache_dir.join(".welcomed")
}

/// Whether the one-time welcome has already been shown. Best-effort: any IO
/// error is treated as "not yet welcomed" (at worst the banner shows again).
fn already_welcomed(cache_dir: &std::path::Path) -> bool {
    welcome_marker(cache_dir).exists()
}

/// Record that the welcome was shown so it never shows again. Best-effort —
/// every IO error (dir create + touch) is swallowed; a failure is invisible to
/// the user by design and never delays or fails a command (B-07 spirit).
fn record_welcomed(cache_dir: &std::path::Path) {
    let _ = std::fs::create_dir_all(cache_dir);
    let _ = std::fs::write(welcome_marker(cache_dir), b"");
}

/// Map a `getdev-gitx` changed file onto `core::review`'s own input type. This
/// is the single boundary where the two mirror-image structs meet: `core::review`
/// deliberately does NOT depend on `getdev-gitx` (ARCHITECTURE.md fixes the
/// crate-dependency direction), so the CLI — which depends on both — performs
/// the translation (06-02-SUMMARY key decision).
fn map_changed_file(
    file: getdev_gitx::diff::ChangedFile,
) -> getdev_core::review::ReviewChangedFile {
    use getdev_core::review::{ReviewChangeStatus, ReviewChangedFile};
    use getdev_gitx::diff::ChangeStatus;

    let status = match file.status {
        ChangeStatus::Added => ReviewChangeStatus::Added,
        ChangeStatus::Modified => ReviewChangeStatus::Modified,
        ChangeStatus::Deleted => ReviewChangeStatus::Deleted,
    };
    ReviewChangedFile {
        path: file.path,
        status,
        added_ranges: file.added_ranges,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::{already_welcomed, record_welcomed, welcome_marker};

    fn scratch_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-cli-welcome-ut-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// The one-time welcome is driven entirely by the cache-dir marker: absent
    /// on a fresh cache (so the banner would show once), present after the first
    /// run (so it never shows again), and idempotent on re-record. An explicit
    /// scratch dir stands in for a temp `GETDEV_CACHE_DIR` — the same override
    /// the real `cache_dir()` reads — with no unsafe process-env mutation.
    #[test]
    fn welcome_marker_gates_the_banner_to_a_single_showing() {
        let dir = scratch_dir("once");

        // Fresh cache: nothing written yet → not welcomed (banner would show).
        assert!(
            !already_welcomed(&dir),
            "a fresh cache dir must report not-yet-welcomed"
        );

        // First showing records the marker; now the banner is suppressed forever.
        record_welcomed(&dir);
        assert!(
            already_welcomed(&dir),
            "after recording, the marker must exist so the banner never shows again"
        );
        assert!(
            welcome_marker(&dir).is_file(),
            "the marker is a real file inside the cache dir"
        );

        // Idempotent: re-recording keeps it welcomed, never errors.
        record_welcomed(&dir);
        assert!(already_welcomed(&dir), "re-record stays welcomed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `record_welcomed` is best-effort and must never panic even when the cache
    /// dir cannot be created (here a path whose parent is a regular file) — a
    /// marker failure can never delay or fail a command (B-07 spirit).
    #[test]
    fn record_welcomed_swallows_io_errors() {
        let base = scratch_dir("io-swallow");
        std::fs::create_dir_all(&base).unwrap();
        // A file where a directory is expected: create_dir_all under it fails.
        let file_as_parent = base.join("not-a-dir");
        std::fs::write(&file_as_parent, b"x").unwrap();
        let unwritable = file_as_parent.join("cache");

        // Must not panic; and with no marker written, it stays not-welcomed.
        record_welcomed(&unwritable);
        assert!(
            !already_welcomed(&unwritable),
            "a failed marker write leaves the state not-welcomed (banner may retry), never errors"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
