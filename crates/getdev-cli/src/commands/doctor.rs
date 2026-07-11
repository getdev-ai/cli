use std::io::IsTerminal;
use std::path::Path;
use std::process::Command;

use owo_colors::OwoColorize;
use serde::Serialize;

use getdev_core::config::Config;
use getdev_core::report::ColorMode;
use getdev_grammars::tree_sitter::Parser;
use getdev_registry::{cache, Cache, Ecosystem, Existence, RegistryClient};

use crate::update::{self, ReleaseCheck};

/// A name that will never collide with a real cached package — used only to
/// exercise a trivial read against the cache without mutating it (the
/// "PRAGMA integrity_check / a trivial read" doctor is contractually meant
/// to do, docs/PLAN.md §2.3).
const CACHE_HEALTH_PROBE_NAME: &str = "__getdev_doctor_health_probe__";

/// Schema version of the `--json` doctor report — versioned independently
/// of `getdev-core`'s findings schema (doctor is a pass/fail table, not a
/// findings report).
const DOCTOR_SCHEMA_VERSION: &str = "1";

pub struct DoctorArgs {
    pub offline: bool,
    pub fix: bool,
    /// B4: machine-readable pass/fail table (global flag, docs/PLAN.md §2.2).
    pub json: bool,
    /// B4: suppress the banner (global flag).
    pub quiet: bool,
    /// B4: disable ANSI colors on the ok/FAIL markers (global flag).
    pub no_color: bool,
}

/// One row of the check table. This is the stable `--json` shape: `name` +
/// `ok`, nothing else — kept intentionally small so it stays stable as more
/// checks are added over time.
#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    ok: bool,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    schema_version: &'static str,
    tool_version: &'static str,
    checks: Vec<DoctorCheck>,
    ok: bool,
}

pub fn run(args: &DoctorArgs) -> anyhow::Result<u8> {
    let mut checks: Vec<DoctorCheck> = Vec::new();

    // config validity (.getdev.toml in CWD; missing file is fine). B3: a
    // malformed config must never kill doctor before it can diagnose
    // anything — doctor resolves config leniently here (a ConfigError
    // becomes a failed row, not a process exit) while every other command
    // keeps the hard exit-3 in main.rs.
    match Config::load(Path::new(".")) {
        Ok(_) => checks.push(row(true, "config (.getdev.toml valid or absent)")),
        Err(err) => checks.push(row(false, &format!("config: {err}"))),
    }

    // git availability (required for snap/back/review)
    match Command::new("git").arg("--version").output() {
        Ok(out) if out.status.success() => {
            let version = String::from_utf8_lossy(&out.stdout);
            checks.push(row(true, version.trim()));
        }
        _ => checks.push(row(
            false,
            "git not found on PATH — snap/back/review require it (https://git-scm.com/downloads)",
        )),
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
            checks.push(row(true, &format!("grammar {name}")));
        } else {
            checks.push(row(false, &format!("grammar {name} failed to load/parse")));
        }
    }

    // version vs latest: skipped under --offline; a repo with no releases
    // yet (pre-launch) is expected state, not a failure; an unreachable
    // GitHub is a soft note, never a hard fail (03-RESEARCH.md "Environment
    // Availability").
    match update::latest_release_version(args.offline) {
        ReleaseCheck::Skipped => checks.push(row(true, "version check skipped (--offline)")),
        ReleaseCheck::UpToDate => checks.push(row(
            true,
            &format!("version {} (up to date)", env!("CARGO_PKG_VERSION")),
        )),
        ReleaseCheck::Outdated { latest } => checks.push(row(
            true,
            &format!(
                "version {} (latest: {latest} — see {})",
                env!("CARGO_PKG_VERSION"),
                update::releases_page_url()
            ),
        )),
        ReleaseCheck::NoReleasesYet => {
            checks.push(row(true, "version check: no releases published yet"));
        }
        ReleaseCheck::Unreachable => {
            checks.push(row(
                true,
                "version check: github releases unreachable (skipped)",
            ));
        }
    }

    // cache size & integrity, with a cache-only --fix (T-3-12: --fix must
    // never touch anything but the corrupt cache files under cache_dir()).
    let cache_dir = cache::cache_dir();
    match cache_health(&cache_dir) {
        CacheHealth::Absent => {
            checks.push(row(
                true,
                "cache: not yet created (first run will create it)",
            ));
        }
        CacheHealth::Healthy { size_bytes } => {
            checks.push(row(
                true,
                &format!(
                    "cache ({}) healthy, {}",
                    cache_dir.display(),
                    human_size(size_bytes)
                ),
            ));
        }
        CacheHealth::Corrupt { reason } => {
            if args.fix {
                // F3(b): --fix must only ever delete a directory that
                // actually looks like a getdev registry cache — refuse
                // (rather than silently wiping it) if `GETDEV_CACHE_DIR`
                // was misconfigured to point somewhere else entirely.
                if looks_like_getdev_cache(&cache_dir) {
                    match std::fs::remove_dir_all(&cache_dir) {
                        Ok(()) => checks.push(row(
                            true,
                            &format!("cache: corrupt cache cleared (--fix): {reason}"),
                        )),
                        Err(err) => checks.push(row(
                            false,
                            &format!(
                                "cache: --fix failed to clear {}: {err}",
                                cache_dir.display()
                            ),
                        )),
                    }
                } else {
                    checks.push(row(
                        false,
                        &format!(
                            "cache: refusing to --fix — {} does not look like a getdev cache \
                             directory (unexpected contents); check GETDEV_CACHE_DIR",
                            cache_dir.display()
                        ),
                    ));
                }
            } else {
                checks.push(row(
                    false,
                    &format!("cache: {reason} (run `getdev doctor --fix` to clear it)"),
                ));
            }
        }
    }

    // registry reachability: unless offline, a probe of npm + PyPI for a
    // known-good package via getdev-registry (the only crate allowed
    // network access). Inconclusive/unreachable is a soft note, never a
    // hard fail — the registries themselves being briefly unreachable is
    // not a getdev problem.
    if args.offline {
        checks.push(row(true, "registry reachability skipped (--offline)"));
    } else {
        checks.push(row(true, &registry_reachability_message()));
    }

    let failures = checks.iter().filter(|c| !c.ok).count();

    if args.json {
        let report = DoctorReport {
            schema_version: DOCTOR_SCHEMA_VERSION,
            tool_version: env!("CARGO_PKG_VERSION"),
            ok: failures == 0,
            checks,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        if !args.quiet {
            println!("getdev {}", env!("CARGO_PKG_VERSION"));
            println!();
        }
        let color = ColorMode::resolve(args.no_color, std::io::stdout().is_terminal());
        for check in &checks {
            print_row(check, color);
        }
        println!();
        if failures == 0 {
            println!("all checks passed");
        }
    }

    // F3(c): a health-check failure (corrupt cache, missing git, a bad
    // grammar, ...) means the environment is unhealthy — exit 1, distinct
    // from a genuine execution error (exit 2), which is reserved for
    // doctor itself failing to run (e.g. the `?` above on JSON
    // serialization). Every check above already recovered from its own
    // failure into a failed row rather than propagating an `Err`, so this
    // function only ever returns `Err` for a real execution fault.
    Ok(u8::from(failures > 0))
}

fn row(ok: bool, message: &str) -> DoctorCheck {
    DoctorCheck {
        name: message.to_owned(),
        ok,
    }
}

fn print_row(check: &DoctorCheck, color: ColorMode) {
    let mark = if check.ok { "ok  " } else { "FAIL" };
    let mark = match (check.ok, color) {
        (_, ColorMode::Off) => mark.to_owned(),
        (true, ColorMode::On) => mark.green().to_string(),
        (false, ColorMode::On) => mark.red().bold().to_string(),
    };
    println!("  [{mark}] {}", check.name);
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

/// The set of file names a genuine getdev registry cache directory may
/// contain (mirrors `getdev_registry::cache`'s `cache.sqlite3` plus
/// SQLite's own WAL/journal side-files).
const KNOWN_CACHE_ENTRIES: &[&str] = &[
    "cache.sqlite3",
    "cache.sqlite3-wal",
    "cache.sqlite3-shm",
    "cache.sqlite3-journal",
];

/// F3(b): sanity-checks that `dir` actually looks like a getdev registry
/// cache before `--fix` is allowed to `remove_dir_all` it — a misconfigured
/// `GETDEV_CACHE_DIR` pointing at an unrelated directory (a user's home
/// directory, a project directory, ...) must never be silently wiped just
/// because it happens to contain SOME failure `Cache::open_at` reads as
/// corrupt. Refuses (returns `false`) on any entry that isn't one of
/// [`KNOWN_CACHE_ENTRIES`], and requires at least the primary DB file to be
/// present at all.
fn looks_like_getdev_cache(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut saw_db_file = false;
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return false; // non-UTF8 entry name — surprising, refuse
        };
        if !KNOWN_CACHE_ENTRIES.contains(&name.as_str()) {
            return false;
        }
        if name == "cache.sqlite3" {
            saw_db_file = true;
        }
    }
    saw_db_file
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
