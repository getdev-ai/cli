//! The precision oracle (PREC-01) — the recorded v0.2 exit gate that turns
//! "raise real-world precision from <1% to >90%" into a CI contract.
//!
//! For every synthetic app under `testdata/corpus/precision/`, this runs
//! `getdev check --offline --json` (hermetic: `GETDEV_OFFLINE=1` + a throwaway
//! `GETDEV_CACHE_DIR` seeded from the app's `getdev-cache-seed.json`, no
//! network), partitions each **warning+** finding into TRUE (its `(id, file)`
//! is in that app's `getdev-precision.json`) vs FALSE (not catalogued), and
//! computes per-rule + overall **actionable precision = true ÷ (true + false)**.
//! It records the per-rule table (recorded, not eyeballed) and asserts overall
//! **≥ 0.90**.
//!
//! This is a NEW file, never an edit of `corpus.rs` — avoiding a cross-phase
//! conflict with the Phase 12/16 CLI-test work — and it duplicates a small
//! hermetic-seed helper rather than sharing one. It composes with, never
//! replaces, `corpus.rs::seeded_recall_is_100_percent` (the unchanged recall
//! floor).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use getdev_registry::{Cache, Ecosystem, Existence};
use serde::Deserialize;
use serde_json::Value;

fn precision_corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/precision")
}

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-precision-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

#[derive(Debug, Deserialize)]
struct CacheSeed {
    #[serde(default)]
    npm: BTreeMap<String, bool>,
    #[serde(default)]
    pypi: BTreeMap<String, bool>,
}

/// The per-app catalog of findings getdev is EXPECTED to legitimately produce.
#[derive(Debug, Deserialize)]
struct PrecisionCatalog {
    #[serde(default, rename = "true")]
    true_findings: Vec<CatalogEntry>,
}

#[derive(Debug, Deserialize, Clone)]
struct CatalogEntry {
    id: String,
    file: String,
}

fn list_app_dirs() -> Vec<PathBuf> {
    let root = precision_corpus_root();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap_or_else(|err| panic!("read {}: {err}", root.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn app_label(app_dir: &Path) -> String {
    app_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_owned()
}

fn load_catalog(app_dir: &Path) -> Vec<CatalogEntry> {
    let path = app_dir.join("getdev-precision.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let catalog: PrecisionCatalog =
        serde_json::from_str(&text).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()));
    catalog.true_findings
}

/// Seed a throwaway cache from the app's `getdev-cache-seed.json`, run
/// `getdev check --offline --json --path <app>` hermetically, and parse the
/// report. Never mutates the app dir — only the temp cache is written, and it
/// is removed before returning.
fn run_check(app_dir: &Path, label: &str) -> Value {
    let cache_dir = tmp_dir(label);

    let seed_path = app_dir.join("getdev-cache-seed.json");
    if seed_path.is_file() {
        let text = std::fs::read_to_string(&seed_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", seed_path.display()));
        let seed: CacheSeed = serde_json::from_str(&text)
            .unwrap_or_else(|err| panic!("parse {}: {err}", seed_path.display()));
        let cache = Cache::open_at(&cache_dir).expect("open temp cache");
        for (name, exists) in &seed.npm {
            let existence = if *exists {
                Existence::Found
            } else {
                Existence::Missing
            };
            cache
                .put_existence(Ecosystem::Npm, name, existence)
                .expect("seed npm existence row");
        }
        for (name, exists) in &seed.pypi {
            let existence = if *exists {
                Existence::Found
            } else {
                Existence::Missing
            };
            cache
                .put_existence(Ecosystem::Pypi, name, existence)
                .expect("seed pypi existence row");
        }
    }

    let assert = getdev()
        .env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", &cache_dir)
        // hermetic git: never read the developer's real git config, and never
        // let review reach for a real repo baseline.
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .arg("check")
        .arg("--offline")
        .arg("--json")
        .arg("--path")
        .arg(app_dir)
        .timeout(Duration::from_secs(60))
        .assert();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let code = output.status.code();
    assert_eq!(
        code,
        Some(0),
        "getdev check crashed or exited non-zero for {label} — exit={code:?} \
         stdout={stdout} stderr={stderr}",
    );
    let report: Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("stdout was not valid JSON ({err}) for {label}: stdout={stdout} stderr={stderr}")
    });
    let _ = std::fs::remove_dir_all(&cache_dir);
    report
}

/// A finding counts toward the actionable-precision measurement only at
/// warning+ severity — mirrors `corpus.rs::is_warning_plus`. An info-severity
/// finding is a verification note ("could not verify N usages"), never a claim
/// something is wrong, so it never counts for or against precision.
fn is_warning_plus(finding: &Value) -> bool {
    finding["severity"].as_str() != Some("info")
}

fn warning_plus_findings(report: &Value) -> Vec<(String, String)> {
    report["findings"]
        .as_array()
        .expect("findings is an array")
        .iter()
        .filter(|f| is_warning_plus(f))
        .map(|f| {
            (
                f["id"].as_str().unwrap_or("?").to_owned(),
                f["file"].as_str().unwrap_or("?").to_owned(),
            )
        })
        .collect()
}

/// PREC-01 (D-12): per-rule + overall actionable precision ≥ 0.90, recorded.
#[test]
fn precision_is_at_least_90_percent() {
    let apps = list_app_dirs();
    assert!(
        apps.len() >= 6,
        "expected >= 6 precision apps, found {}",
        apps.len()
    );

    // per-rule accumulation across every app.
    let mut per_rule_true: BTreeMap<String, usize> = BTreeMap::new();
    let mut per_rule_false: BTreeMap<String, usize> = BTreeMap::new();
    let mut false_details: Vec<String> = Vec::new();
    let mut overall_true = 0usize;
    let mut overall_false = 0usize;

    for app_dir in &apps {
        let label = app_label(app_dir);
        let catalog: BTreeSet<(String, String)> = load_catalog(app_dir)
            .into_iter()
            .map(|e| (e.id, e.file))
            .collect();
        let report = run_check(app_dir, &label);
        for (id, file) in warning_plus_findings(&report) {
            let is_true = catalog.contains(&(id.clone(), file.clone()));
            if is_true {
                *per_rule_true.entry(id).or_insert(0) += 1;
                overall_true += 1;
            } else {
                *per_rule_false.entry(id.clone()).or_insert(0) += 1;
                overall_false += 1;
                false_details.push(format!("{label}: FALSE {id} @ {file}"));
            }
        }
    }

    // Record the per-rule table (the "recorded, not eyeballed" requirement) —
    // emitted to stdout so a CI log with --nocapture preserves the figure.
    let mut rules: BTreeSet<String> = BTreeSet::new();
    rules.extend(per_rule_true.keys().cloned());
    rules.extend(per_rule_false.keys().cloned());
    println!("\n=== precision oracle — per-rule actionable precision ===");
    for rule in &rules {
        let t = per_rule_true.get(rule).copied().unwrap_or(0);
        let f = per_rule_false.get(rule).copied().unwrap_or(0);
        let total = t + f;
        let p = if total == 0 {
            1.0
        } else {
            t as f64 / total as f64
        };
        println!(
            "  {rule}: {t} true / {f} false = {:.1}% precision",
            p * 100.0
        );
    }
    let overall_total = overall_true + overall_false;
    let overall = if overall_total == 0 {
        1.0
    } else {
        overall_true as f64 / overall_total as f64
    };
    println!(
        "  OVERALL: {overall_true} true / {overall_false} false = {:.1}% precision (n={overall_total})",
        overall * 100.0
    );
    println!("=========================================================\n");

    assert!(
        overall >= 0.90,
        "actionable precision {:.1}% < 90% floor (PREC-01) — offending false findings:\n{}",
        overall * 100.0,
        false_details.join("\n")
    );
}

/// PREC-01 (D-13) recall anchor: every planted TRUE `(id, file)` in the
/// catalogs is actually produced — recall cannot silently collapse to trivially
/// satisfy precision. The phase-level recall floor stays
/// `corpus.rs::seeded_recall_is_100_percent` (unchanged, must stay green).
#[test]
fn recall_anchor_findings_are_present() {
    let apps = list_app_dirs();
    let mut anchors_checked = 0usize;
    let mut misses = Vec::new();

    for app_dir in &apps {
        let label = app_label(app_dir);
        let catalog = load_catalog(app_dir);
        if catalog.is_empty() {
            continue;
        }
        let report = run_check(app_dir, &label);
        let produced: BTreeSet<(String, String)> =
            warning_plus_findings(&report).into_iter().collect();
        for entry in &catalog {
            anchors_checked += 1;
            if !produced.contains(&(entry.id.clone(), entry.file.clone())) {
                misses.push(format!(
                    "{label}: missing planted true {} @ {}",
                    entry.id, entry.file
                ));
            }
        }
    }

    assert!(
        anchors_checked >= 3,
        "expected >= 3 planted recall anchors across the corpus, found {anchors_checked}"
    );
    assert!(
        misses.is_empty(),
        "recall anchors not produced (recall cannot collapse to satisfy precision):\n{}",
        misses.join("\n")
    );
}

/// Provider-key prefixes whose presence in the corpus marks a value as
/// secret-SHAPED. A real leaked secret carries no synthetic marker; the one
/// planted recall anchor uses an obviously-synthetic body (`FAKE`), so it is
/// allowed. Any provider-shaped value WITHOUT a synthetic marker fails.
const PROVIDER_PREFIXES: &[&str] = &[
    "sk_live_",
    "rk_live_",
    "sk-ant-",
    "ghp_",
    "gho_",
    "github_pat_",
    "AKIA",
    "ASIA",
    "AIza",
    "xoxb-",
    "xoxp-",
    "SG.",
    "glpat-",
];
const SYNTHETIC_MARKERS: &[&str] = &[
    "FAKE",
    "EXAMPLE",
    "PLACEHOLDER",
    "DUMMY",
    "XXXX",
    "REDACTED",
    "NOTREAL",
    "SAMPLE",
];

/// PREC-01 (D-14): the corpus is provably secret-free at rest — no file
/// contains a real-secret-shaped value (a provider prefix followed by a body
/// with no synthetic marker). Proves the corpus never carries a real leaked
/// credential while still permitting the synthetic `FAKE`-bodied recall anchor.
#[test]
fn precision_corpus_is_secret_free() {
    let root = precision_corpus_root();
    let mut offenders = Vec::new();
    walk_files(&root, &mut |path, contents| {
        for prefix in PROVIDER_PREFIXES {
            let mut search_from = 0;
            while let Some(rel) = contents[search_from..].find(prefix) {
                let start = search_from + rel;
                // capture the token: the prefix plus the following key-body chars.
                let body: String = contents[start..]
                    .chars()
                    .take_while(|c| {
                        c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.'
                    })
                    .collect();
                let upper = body.to_uppercase();
                let is_synthetic = SYNTHETIC_MARKERS.iter().any(|m| upper.contains(m));
                // require enough body to be a plausible key, not a bare prefix
                // appearing in prose/config (e.g. "AKIA" alone).
                if body.len() >= prefix.len() + 6 && !is_synthetic {
                    offenders.push(format!(
                        "{}: provider-shaped value '{}' has no synthetic marker",
                        path.display(),
                        body
                    ));
                }
                search_from = start + prefix.len();
            }
        }
    });

    assert!(
        offenders.is_empty(),
        "the precision corpus must be secret-free (synthetic values only) — offenders:\n{}",
        offenders.join("\n")
    );
}

/// Recursively read every UTF-8 file under `root`, invoking `visit(path,
/// contents)`. Binary/unreadable files are skipped.
fn walk_files(root: &Path, visit: &mut impl FnMut(&Path, &str)) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_files(&path, visit);
        } else if let Ok(contents) = std::fs::read_to_string(&path) {
            visit(&path, &contents);
        }
    }
}
