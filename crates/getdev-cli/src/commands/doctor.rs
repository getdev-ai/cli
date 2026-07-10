use std::path::Path;
use std::process::Command;

use getdev_core::config::Config;
use getdev_grammars::tree_sitter::Parser;
use getdev_registry::{cache, Cache, Ecosystem, Existence, RegistryClient};

use crate::update::{self, ReleaseCheck};

/// A name that will never collide with a real cached package — used only to
/// exercise a trivial read against the cache without mutating it (the
/// "PRAGMA integrity_check / a trivial read" doctor is contractually meant
/// to do, docs/PLAN.md §2.3).
const CACHE_HEALTH_PROBE_NAME: &str = "__getdev_doctor_health_probe__";

pub fn run(offline: bool, fix: bool) -> anyhow::Result<()> {
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

    // cache size & integrity, with a cache-only --fix (T-3-12: --fix must
    // never touch anything but the corrupt cache files under cache_dir()).
    let cache_dir = cache::cache_dir();
    match cache_health(&cache_dir) {
        CacheHealth::Absent => {
            report(true, "cache: not yet created (first run will create it)");
        }
        CacheHealth::Healthy { size_bytes } => {
            report(
                true,
                &format!(
                    "cache ({}) healthy, {}",
                    cache_dir.display(),
                    human_size(size_bytes)
                ),
            );
        }
        CacheHealth::Corrupt { reason } => {
            if fix {
                match std::fs::remove_dir_all(&cache_dir) {
                    Ok(()) => report(
                        true,
                        &format!("cache: corrupt cache cleared (--fix): {reason}"),
                    ),
                    Err(err) => {
                        failures += 1;
                        report(
                            false,
                            &format!(
                                "cache: --fix failed to clear {}: {err}",
                                cache_dir.display()
                            ),
                        );
                    }
                }
            } else {
                failures += 1;
                report(
                    false,
                    &format!("cache: {reason} (run `getdev doctor --fix` to clear it)"),
                );
            }
        }
    }

    // registry reachability: unless offline, a probe of npm + PyPI for a
    // known-good package via getdev-registry (the only crate allowed
    // network access). Inconclusive/unreachable is a soft note, never a
    // hard fail — the registries themselves being briefly unreachable is
    // not a getdev problem.
    if offline {
        report(true, "registry reachability skipped (--offline)");
    } else {
        report(true, &registry_reachability_message());
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

enum CacheHealth {
    /// The cache directory doesn't exist yet — nothing to check, not a
    /// failure (it will be created on first `getdev real` run).
    Absent,
    Healthy {
        size_bytes: u64,
    },
    Corrupt {
        reason: String,
    },
}

fn cache_health(dir: &Path) -> CacheHealth {
    if !dir.exists() {
        return CacheHealth::Absent;
    }
    match Cache::open_at(dir) {
        Err(err) => CacheHealth::Corrupt {
            reason: format!("failed to open: {err}"),
        },
        Ok(opened) => match opened.get_existence(Ecosystem::Npm, CACHE_HEALTH_PROBE_NAME) {
            Err(err) => CacheHealth::Corrupt {
                reason: format!("integrity check failed: {err}"),
            },
            Ok(_) => CacheHealth::Healthy {
                size_bytes: dir_size_bytes(dir),
            },
        },
    }
}

/// Flat, non-recursive sum — the registry cache directory holds at most a
/// handful of SQLite files (`cache.sqlite3`, `-wal`, `-shm`), never
/// subdirectories.
fn dir_size_bytes(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.metadata().ok())
        .filter(std::fs::Metadata::is_file)
        .map(|meta| meta.len())
        .sum()
}

fn human_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn registry_reachability_message() -> String {
    let Ok(client) = RegistryClient::new(false) else {
        return "registry reachability: could not build http client (inconclusive)".to_owned();
    };
    let npm = client.existence(Ecosystem::Npm, "left-pad");
    let pypi = client.existence(Ecosystem::Pypi, "requests");
    match (npm, pypi) {
        (Ok(Existence::Found), Ok(Existence::Found)) => "registry reachable (npm, pypi)".to_owned(),
        _ => "registry reachability: inconclusive (npm/pypi unreachable or slow)".to_owned(),
    }
}
