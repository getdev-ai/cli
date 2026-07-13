//! network_egress.rs — source-level proof of getdev's network boundary
//! (SC4, DEC-05, docs/ARCHITECTURE.md "Network boundary rule").
//!
//! This is the "narrative proof" half of the two-layer privacy guardrail
//! locked in D-02. Its companion is `deny.toml`, which works at the
//! dependency-graph level (a new async runtime / second HTTP client / LLM SDK
//! entering the tree fails `cargo deny check bans`). This test works at the
//! *source-symbol* level: it proves that the network code getdev actually
//! contains is confined to the two sanctioned locations and dials only the
//! three sanctioned destinations. Neither layer alone is complete — a
//! dependency can be present but never called (caught only by the symbol
//! scan), and a symbol can be reached transitively without appearing in our
//! source (caught only by the dep-graph scan) — so both run in CI (08-06).
//!
//! Two mechanically-different assertions, matching the boundary rule exactly:
//!
//!   1. NETWORK SYMBOLS (`reqwest::`, `std::net::`, `TcpStream`, …) may appear
//!      ONLY under `crates/getdev-registry/src/**` (npm/PyPI clients) and
//!      `crates/getdev-cli/src/update/**` (GitHub Releases self-update). A
//!      network symbol anywhere else — `getdev-core`, `getdev-gitx`,
//!      `getdev-grammars`, or the rest of `getdev-cli` — is a FAILURE.
//!
//!   2. NETWORK HOSTS: every `http(s)://` host literal *inside those two
//!      locations* must be one of the exhaustively-allowed destinations
//!      (npm registry, PyPI, GitHub Releases). Any other host is a FAILURE.
//!
//! The host scan is deliberately scoped to the two network locations rather
//! than the whole tree: elsewhere, `https://…` literals are finding `refs`
//! (`getdev.ai/rules/…`), doc links (`git-scm.com`), generated Dockerfile
//! `HEALTHCHECK` templates (`localhost`), and detection *fixtures*
//! (`api.example.com`, `sentry.io`) — none of which getdev ever dials. A host
//! literal is inert without a network symbol to dial it, and assertion (1)
//! already confines every network symbol; scoping the host scan keeps the
//! proof honest instead of drowning it in false positives on documentation.
//!
//! This test lives in `tests/` (not `src/`), and the scan walks only
//! `crates/*/src/**`, so it never scans — and never self-trips on — its own
//! source, which necessarily contains every forbidden token as a pattern.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

/// Network-capable source symbols. Path-qualified (`reqwest::`, `std::net::`)
/// or unmistakable std socket type names, so ordinary prose/identifiers never
/// match. This is the concrete surface the boundary rule governs; the
/// dependency-graph layer (`deny.toml`) covers alternative clients that would
/// arrive as new crates rather than as these symbols.
const NETWORK_SYMBOLS: &[&str] = &[
    "reqwest::",
    "std::net::",
    "TcpStream",
    "TcpListener",
    "UdpSocket",
];

/// The exhaustive host allowlist (DEC-05): npm registry (+ its download-count
/// API), PyPI (+ its file host), and GitHub (self-update: releases API and the
/// human releases page). Nothing else may be dialed.
const ALLOWED_HOSTS: &[&str] = &[
    "registry.npmjs.org",
    "api.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "api.github.com",
    "github.com",
];

/// Source subtrees permitted to contain network symbols, expressed as path
/// suffixes joined with the platform separator so the check is OS-agnostic.
/// These are the ONLY two network-owning locations in the workspace.
fn allowed_network_locations() -> [PathBuf; 2] {
    [
        ["crates", "getdev-registry", "src"].iter().collect(),
        ["crates", "getdev-cli", "src", "update"].iter().collect(),
    ]
}

/// Workspace root = two levels up from this crate's manifest dir
/// (`<root>/crates/getdev-cli`).
fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .expect("crates/getdev-cli is nested two levels below the workspace root")
        .to_path_buf()
}

/// Collect every `crates/*/src/**/*.rs` file under the workspace root.
fn workspace_source_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates_dir = root.join("crates");
    let entries = match fs::read_dir(&crates_dir) {
        Ok(entries) => entries,
        Err(_) => return out,
    };
    for crate_entry in entries.flatten() {
        let src = crate_entry.path().join("src");
        if src.is_dir() {
            collect_rs_files(&src, &mut out);
        }
    }
    out.sort();
    out
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// True iff `path` lives under one of the two sanctioned network locations.
fn is_allowed_network_location(path: &Path, root: &Path) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    allowed_network_locations()
        .iter()
        .any(|loc| rel.starts_with(loc))
}

/// Extract the host of every `http://`/`https://` literal in `contents`.
/// A host runs up to the first `/`, `"`, `'`, `` ` ``, whitespace, `)`, `\`,
/// `:` (port), or `@` (userinfo) — enough to pull the authority out of a Rust
/// string literal or doc comment.
fn extract_hosts(contents: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for scheme in ["https://", "http://"] {
        let mut rest = contents;
        while let Some(idx) = rest.find(scheme) {
            let after = &rest[idx + scheme.len()..];
            let end = after
                .find(|c: char| {
                    c == '/'
                        || c == '"'
                        || c == '\''
                        || c == '`'
                        || c == ')'
                        || c == '\\'
                        || c == ':'
                        || c == '@'
                        || c.is_whitespace()
                })
                .unwrap_or(after.len());
            let host = &after[..end];
            if !host.is_empty() {
                hosts.push(host.to_string());
            }
            rest = &after[end..];
        }
    }
    hosts
}

/// ASSERTION 1 — no network symbol appears outside the two sanctioned
/// network-owning locations.
#[test]
fn network_symbols_are_confined_to_registry_and_update() {
    let root = workspace_root();
    let mut violations: Vec<String> = Vec::new();

    for file in workspace_source_files(&root) {
        if is_allowed_network_location(&file, &root) {
            continue;
        }
        let contents = match fs::read_to_string(&file) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let rel = file.strip_prefix(&root).unwrap_or(&file).display();
        for symbol in NETWORK_SYMBOLS {
            if contents.contains(symbol) {
                violations.push(format!(
                    "  {rel}: contains network symbol `{symbol}` outside the \
                     permitted network locations (getdev-registry / \
                     getdev-cli::update) — DEC-05 network boundary violated"
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "network-capable symbols found outside getdev-registry / \
         getdev-cli::update (see docs/ARCHITECTURE.md network boundary rule):\n{}",
        violations.join("\n")
    );
}

/// ASSERTION 2 — every host literal inside the two network locations is on the
/// exhaustive DEC-05 allowlist.
#[test]
fn network_hosts_are_only_npm_pypi_github() {
    let root = workspace_root();
    let mut violations: Vec<String> = Vec::new();

    for file in workspace_source_files(&root) {
        if !is_allowed_network_location(&file, &root) {
            continue;
        }
        let contents = match fs::read_to_string(&file) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let rel = file.strip_prefix(&root).unwrap_or(&file).display();
        for host in extract_hosts(&contents) {
            if !ALLOWED_HOSTS.contains(&host.as_str()) {
                violations.push(format!(
                    "  {rel}: references host `{host}`, not on the DEC-05 \
                     allowlist (npm registry / PyPI / GitHub Releases)"
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "network host literal outside the exhaustive DEC-05 allowlist:\n{}\n\
         allowed: {ALLOWED_HOSTS:?}",
        violations.join("\n")
    );
}

/// Guard-rail on the guard-rail: the scan must actually see the source tree
/// and the two known network locations, otherwise a silently-empty walk would
/// make both assertions vacuously pass (e.g. after a directory rename).
#[test]
fn scan_actually_covers_the_workspace() {
    let root = workspace_root();
    let files = workspace_source_files(&root);
    assert!(
        files.len() > 20,
        "expected the workspace source walk to find many .rs files, got {} — \
         the scan is not seeing crates/*/src and would vacuously pass",
        files.len()
    );

    // Both network locations must exist and contain at least one scanned file,
    // proving the allowlist paths still match the real layout.
    for loc in allowed_network_locations() {
        let hits = files
            .iter()
            .filter(|f| f.strip_prefix(&root).unwrap_or(f).starts_with(&loc))
            .count();
        assert!(
            hits > 0,
            "sanctioned network location `{}` matched no source files — the \
             path allowlist has drifted from the real crate layout",
            loc.display()
        );
    }

    // And each network location must genuinely contain a network symbol —
    // otherwise assertion (1)'s "confined here" claim is untested.
    let root_ref = &root;
    let network_symbol_present = |loc: &Path| -> bool {
        files
            .iter()
            .filter(|f| f.strip_prefix(root_ref).unwrap_or(f).starts_with(loc))
            .any(|f| {
                fs::read_to_string(f)
                    .map(|c| NETWORK_SYMBOLS.iter().any(|s| c.contains(s)))
                    .unwrap_or(false)
            })
    };
    for loc in allowed_network_locations() {
        assert!(
            network_symbol_present(&loc),
            "sanctioned network location `{}` contains no network symbol — the \
             confinement assertion would be vacuous",
            loc.display()
        );
    }
}
