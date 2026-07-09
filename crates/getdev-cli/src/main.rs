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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Doctor => commands::doctor::run(),
        Command::Spike { path } => commands::spike::run(&path),
    }
}
