#![forbid(unsafe_code)]

mod commands;
mod update;

use clap::{Args, Parser, Subcommand};
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
/// `scan.rs`'s parse-once design.
#[derive(Args, Debug, Clone, Default)]
struct GlobalArgs {
    /// Suppress banner/progress; findings only
    #[arg(long, short = 'q', global = true)]
    quiet: bool,
    /// Debug-level detail (repeatable: -vv)
    #[arg(long, short = 'v', global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Alternate config file (default: ./.getdev.toml)
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Never hit the network; use cache only
    #[arg(long, global = true)]
    offline: bool,
    /// Apply auto-fixes where the command supports them
    #[arg(long, global = true)]
    fix: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Extract hardcoded secrets to .env (dry-run by default)
    Env {
        /// Directory to scan
        #[arg(long, default_value = ".")]
        path: PathBuf,
        /// Machine-readable output (findings schema)
        #[arg(long)]
        json: bool,
        /// Disable ANSI colors (NO_COLOR is also honored)
        #[arg(long)]
        no_color: bool,
        /// Exit 1 if any finding is at or above this severity
        #[arg(long, value_name = "SEVERITY")]
        fail_on: Option<Severity>,
        /// Target env file
        #[arg(long, default_value = ".env", value_name = "PATH")]
        env_file: String,
        /// Apply the plan: write the env files and rewrite references
        #[arg(long)]
        write: bool,
    },
    /// Verify packages / APIs / model strings actually exist
    Real {
        /// Directory to scan
        #[arg(long, default_value = ".")]
        path: PathBuf,
        /// Machine-readable output (findings schema)
        #[arg(long)]
        json: bool,
        /// Disable ANSI colors (NO_COLOR is also honored)
        #[arg(long)]
        no_color: bool,
        /// Exit 1 if any finding is at or above this severity
        #[arg(long, value_name = "SEVERITY")]
        fail_on: Option<Severity>,
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
        path: PathBuf,
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
    let path = command_path(&cli.command);
    let cfg = Config::resolve(cli.global.config.as_deref(), &path)?;
    let offline = config::offline_resolved(cli.global.offline, &cfg);
    let quiet = cli.global.quiet;
    let verbose = cli.global.verbose;

    match cli.command {
        Command::Env {
            path,
            json,
            no_color,
            fail_on,
            env_file,
            write,
        } => commands::env::run(&commands::env::EnvArgs {
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
            path,
            json,
            no_color,
            fail_on,
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
        Command::Doctor => commands::doctor::run(offline, cli.global.fix).map(|()| 0),
        Command::Spike { path } => commands::spike::run(&path).map(|()| 0),
    }
}

/// The directory config resolution and (where applicable) the command
/// itself operate against. `doctor` is self-diagnostic and has no `--path`
/// of its own (docs/PLAN.md §2.3 doesn't list one) — it resolves config
/// against `.`, matching its pre-existing behavior.
fn command_path(command: &Command) -> PathBuf {
    match command {
        Command::Env { path, .. } | Command::Real { path, .. } | Command::Spike { path } => {
            path.clone()
        }
        Command::Doctor => PathBuf::from("."),
    }
}
