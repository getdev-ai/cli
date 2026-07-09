#![forbid(unsafe_code)]

mod commands;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    #[command(subcommand)]
    command: Command,
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
    let result = match cli.command {
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
        }),
        Command::Doctor => commands::doctor::run().map(|()| 0),
        Command::Spike { path } => commands::spike::run(&path).map(|()| 0),
    };
    match result {
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
