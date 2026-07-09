use std::process::Command;

use getdev_grammars::tree_sitter::Parser;

pub fn run() -> anyhow::Result<()> {
    let mut failures = 0;

    println!("getdev {}", env!("CARGO_PKG_VERSION"));
    println!();

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
