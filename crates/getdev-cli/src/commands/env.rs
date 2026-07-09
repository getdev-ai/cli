use std::io::IsTerminal;
use std::path::Path;

use getdev_core::env::{self, EnvOptions};
use getdev_core::findings::{Confidence, Finding, FindingsReport, ProjectInfo, Severity};
use getdev_core::report::{self, ColorMode};

pub struct EnvArgs {
    pub path: std::path::PathBuf,
    pub json: bool,
    pub no_color: bool,
    pub fail_on: Option<Severity>,
    pub env_file: String,
    pub write: bool,
}

pub fn run(args: &EnvArgs) -> anyhow::Result<u8> {
    let options = EnvOptions {
        env_file: args.env_file.clone(),
    };
    let plan = env::plan(&args.path, &options)?;
    let mut findings = env::findings(&plan, &options);

    // the env file being in git history is its own critical finding —
    // getdev never rewrites history automatically (rotation guidance instead)
    let env_committed = getdev_gitx::is_tracked(&args.path, &options.env_file);
    if env_committed {
        findings.push(env_file_committed_finding(&options.env_file));
    }

    let applied = if args.write && !plan.entries.is_empty() {
        Some(env::apply(&args.path, &plan, &options)?)
    } else {
        None
    };

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
        match &applied {
            Some(summary) => {
                println!();
                println!(
                    "applied: {} var(s) → {} ({}), {} file(s) rewritten{}",
                    summary.vars_written.len(),
                    options.env_file,
                    if summary.env_file_created {
                        "created"
                    } else {
                        "appended"
                    },
                    summary.files_rewritten.len(),
                    if summary.gitignore_patched {
                        ", .gitignore patched"
                    } else {
                        ""
                    }
                );
                println!(
                    "keys documented in {} — commit that file, never {}",
                    summary.example_file, options.env_file
                );
            }
            None if !plan.entries.is_empty() => {
                println!();
                println!(
                    "dry run — nothing written. {} secret(s) would move to {} (getdev env --write)",
                    plan.entries.len(),
                    options.env_file
                );
            }
            None => {}
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

fn env_file_committed_finding(env_file: &str) -> Finding {
    Finding {
        id: "env/env-file-committed".to_owned(),
        command: "env".to_owned(),
        severity: Severity::Critical,
        confidence: Confidence::High,
        file: env_file.to_owned(),
        line: None,
        column: None,
        end_line: None,
        message: format!("{env_file} is committed to git — its secrets are in history"),
        detail: Some(
            "values in git history stay exposed even after the file is removed; \
             getdev never rewrites history automatically"
                .to_owned(),
        ),
        suggestion: Some("rotate every credential in this file, then remove it from git".to_owned()),
        remediation: Some(format!(
            "git rm --cached {env_file} && commit; rotate all keys; consider git-filter-repo for history"
        )),
        fixable: false,
        refs: vec!["https://getdev.ai/rules/env/env-file-committed".to_owned()],
        fingerprint: None,
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
