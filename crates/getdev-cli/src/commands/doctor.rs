use std::path::Path;
use std::process::Command;

use getdev_core::config::Config;
use getdev_grammars::tree_sitter::Parser;

use crate::update::{self, ReleaseCheck};

pub fn run(offline: bool) -> anyhow::Result<()> {
    let mut failures = 0;

    println!("getdev {}", env!("CARGO_PKG_VERSION"));
    println!();

    // config validity (.getdev.toml in CWD; missing file is fine)
    match Config::load(Path::new(".")) {
        Ok(_) => report(true, "config (.getdev.toml valid or absent)"),
        Err(err) => {
            failures += 1;
            report(false, &format!("config: {err}"));
        }
    }

    // git availability (required for snap/back/review)
    match Command::new("git").arg("--version").output() {
        Ok(out) if out.status.success() => {
            let version = String::from_utf8_lossy(&out.stdout);
            report(true, version.trim());
        }
        _ => {
            failures += 1;
            report(
                false,
                "git not found on PATH — snap/back/review require it (https://git-scm.com/downloads)",
            );
        }
    }

    // grammar integrity: every embedded grammar must load and parse a snippet
    let grammars = [
        ("javascript", getdev_grammars::javascript(), "const x = 1;"),
        (
            "typescript",
            getdev_grammars::typescript(),
            "const x: number = 1;",
        ),
        ("tsx", getdev_grammars::tsx(), "const x = <a>{1}</a>;"),
        ("python", getdev_grammars::python(), "x = 1\n"),
    ];
    for (name, language, snippet) in grammars {
        let mut parser = Parser::new();
        let healthy = parser.set_language(&language).is_ok()
            && parser
                .parse(snippet, None)
                .is_some_and(|t| !t.root_node().has_error());
        if healthy {
            report(true, &format!("grammar {name}"));
        } else {
            failures += 1;
            report(false, &format!("grammar {name} failed to load/parse"));
        }
    }

    // version vs latest: skipped under --offline; a repo with no releases
    // yet (pre-launch) is expected state, not a failure; an unreachable
    // GitHub is a soft note, never a hard fail (03-RESEARCH.md "Environment
    // Availability").
    match update::latest_release_version(offline) {
        ReleaseCheck::Skipped => report(true, "version check skipped (--offline)"),
        ReleaseCheck::UpToDate => report(
            true,
            &format!("version {} (up to date)", env!("CARGO_PKG_VERSION")),
        ),
        ReleaseCheck::Outdated { latest } => report(
            true,
            &format!(
                "version {} (latest: {latest} — see https://github.com/getdev-ai/cli/releases)",
                env!("CARGO_PKG_VERSION")
            ),
        ),
        ReleaseCheck::NoReleasesYet => {
            report(true, "version check: no releases published yet");
        }
        ReleaseCheck::Unreachable => {
            report(true, "version check: github releases unreachable (skipped)");
        }
    }

    println!();
    if failures == 0 {
        println!("all checks passed");
        Ok(())
    } else {
        anyhow::bail!("{failures} check(s) failed");
    }
}

fn report(ok: bool, message: &str) {
    let mark = if ok { "ok  " } else { "FAIL" };
    println!("  [{mark}] {message}");
}
