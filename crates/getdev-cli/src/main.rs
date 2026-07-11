#![forbid(unsafe_code)]

mod commands;
mod update;

use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};

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

#[derive(Subcommand)]
enum Command {
    /// Extract hardcoded secrets to .env (dry-run by default)
    Env {
        /// Target env file
        #[arg(long, default_value = ".env", value_name = "PATH")]
        env_file: String,
        /// Apply the plan: write the env files and rewrite references
        #[arg(long)]
        write: bool,
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
    /// Self-diagnostics: toolchain, git availability, grammar integrity
    Doctor,
    /// P0 de-risking spike: walk + parse + query a directory (dev-only)
    #[command(hide = true)]
    Spike {
        /// Directory to scan
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
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
    // B3: doctor must survive a malformed config — it exists specifically to
    // diagnose things like a broken `.getdev.toml`, so a `ConfigError` here
    // must never kill the process before doctor's own checks even run.
    // Every other command keeps the hard exit-3 via `Config::resolve`'s `?`
    // below (docs/PLAN.md §2.2 exit-code contract); doctor resolves config
    // leniently (falls back to defaults) and separately reports the same
    // parse failure as a failed row via its own `Config::load` check.
    if matches!(cli.command, Command::Doctor) {
        let cfg = Config::resolve(cli.global.config.as_deref(), Path::new(".")).unwrap_or_default();
        let offline = config::offline_resolved(cli.global.offline, &cfg);
        return commands::doctor::run(&commands::doctor::DoctorArgs {
            offline,
            fix: cli.global.fix,
            json: cli.global.json,
            quiet: cli.global.quiet,
            no_color: cli.global.no_color,
        })
        .map(|()| 0);
    }

    let cfg = Config::resolve(cli.global.config.as_deref(), &cli.global.path)?;
    let offline = config::offline_resolved(cli.global.offline, &cfg);
    let quiet = cli.global.quiet;
    let verbose = cli.global.verbose;
    let json = cli.global.json;
    let no_color = cli.global.no_color;
    let fail_on = cli.global.fail_on;
    let path = cli.global.path.clone();

    match cli.command {
        Command::Env { env_file, write } => commands::env::run(&commands::env::EnvArgs {
            path,
            json,
            no_color,
            fail_on,
            env_file,
            write,
            quiet,
            verbose,
        }),
        Command::Real {
            deps_only,
            apis_only,
            models_only,
        } => commands::real::run(&commands::real::RealArgs {
            path,
            json,
            no_color,
            fail_on,
            offline,
            deps_only,
            apis_only,
            models_only,
            quiet,
            verbose,
        }),
        Command::Doctor => {
            unreachable!("Command::Doctor is handled before config resolution above")
        }
        Command::Spike { dir } => commands::spike::run(&dir).map(|()| 0),
    }
}
