use std::io::IsTerminal;
use std::path::Path;

use getdev_core::env::{self, EnvOptions};
use getdev_core::findings::{FindingsReport, ProjectInfo, Severity};
use getdev_core::report::{self, ColorMode};

pub struct EnvArgs {
    pub path: std::path::PathBuf,
    pub json: bool,
    pub no_color: bool,
    pub fail_on: Option<Severity>,
    pub env_file: String,
}

pub fn run(args: &EnvArgs) -> anyhow::Result<u8> {
    let options = EnvOptions {
        env_file: args.env_file.clone(),
    };
    let plan = env::plan(&args.path, &options)?;
    let findings = env::findings(&plan, &options);
    let report = FindingsReport::new(
        env!("CARGO_PKG_VERSION"),
        ProjectInfo {
            path: display_path(&args.path),
            stack: Vec::new(),
        },
        findings,
    );

    if args.json {
        print!("{}", report::render_json(&report)?);
    } else {
        let color = ColorMode::resolve(args.no_color, std::io::stdout().is_terminal());
        print!("{}", report::render_terminal(&report, color));
        if !plan.entries.is_empty() {
            println!();
            println!(
                "dry run — nothing written. {} secret(s) would move to {} (getdev env --write)",
                plan.entries.len(),
                options.env_file
            );
        }
        if !plan.skipped.is_empty() {
            println!(
                "{} unreadable file(s) skipped (-v for details)",
                plan.skipped.len()
            );
        }
    }

    let failed = args
        .fail_on
        .is_some_and(|threshold| report.summary.at_or_above(threshold) > 0);
    Ok(u8::from(failed))
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
