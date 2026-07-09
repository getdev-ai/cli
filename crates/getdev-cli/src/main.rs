#![forbid(unsafe_code)]

mod commands;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
        Command::Doctor => commands::doctor::run(),
        Command::Spike { path } => commands::spike::run(&path),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
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
