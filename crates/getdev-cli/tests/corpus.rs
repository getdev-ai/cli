//! Hermetic corpus integration tests — the P2 exit gate (docs/PLAN.md §9.1/
//! §9.3, docs/TESTING.md "Corpus integration"/"The corpus"): 100% seeded
//! fake-defect recall and < 5% sentinel false-positive rate, fully offline +
//! seeded cache. Reuses the `GETDEV_OFFLINE`/`GETDEV_CACHE_DIR` seeding
//! pattern from `real_cli.rs` (03-05) — every invocation sets
//! `GETDEV_OFFLINE=1` and points `GETDEV_CACHE_DIR` at a throwaway temp
//! directory seeded from the app's `getdev-cache-seed.json` — zero live
//! network calls anywhere (docs/TESTING.md "no network in CI").
//!
//! This harness only reads `testdata/corpus/**` and writes to temp cache/app
//! directories under `std::env::temp_dir()` — it never mutates a corpus
//! fixture.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use getdev_registry::{Cache, Ecosystem, Existence};
use serde::Deserialize;
use serde_json::Value;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus")
}

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-corpus-{label}-{}-{}",
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

#[derive(Debug, Deserialize)]
struct ExpectedCatalog {
    seeded: Vec<ExpectedFinding>,
}

#[derive(Debug, Deserialize)]
struct ExpectedFinding {
    id: String,
    file: String,
    /// Human-readable metadata only — matching is by `id` + `file`, per
    /// the plan's own recall criterion ("same id + file").
    #[serde(default)]
    #[allow(dead_code)]
    package: Option<String>,
}

/// Load `app_dir`'s `getdev-cache-seed.json` (if present) into a fresh temp
/// `Cache`, then run `getdev real --offline --json --path <app_dir>`
/// hermetically and parse the resulting `FindingsReport` JSON. Never writes
/// into `app_dir` itself — only the temp cache dir is mutated, and it is
/// removed again before returning.
fn run_real(app_dir: &Path, label: &str) -> Value {
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
        .arg("real")
        .arg("--offline")
        .arg("--json")
        .arg("--path")
        .arg(app_dir)
        .timeout(Duration::from_secs(30))
        .assert();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!(
            "stdout was not valid JSON ({err}) for {}: stdout={stdout} stderr={}",
            app_dir.display(),
            String::from_utf8_lossy(&output.stderr)
        )
    });

    let _ = std::fs::remove_dir_all(&cache_dir);
    report
}

/// Every `real/*` finding in a parsed report.
fn real_findings(report: &Value) -> Vec<&Value> {
    report["findings"]
        .as_array()
        .expect("findings is an array")
        .iter()
        .filter(|f| f["id"].as_str().is_some_and(|id| id.starts_with("real/")))
        .collect()
}

fn list_app_dirs(dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn seeded_apps() -> Vec<PathBuf> {
    list_app_dirs(&corpus_root().join("seeded"))
}

fn sentinel_apps() -> Vec<PathBuf> {
    list_app_dirs(&corpus_root().join("sentinels"))
}

fn app_label(app_dir: &Path) -> String {
    app_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_owned()
}

/// The P2 exit gate (docs/PLAN.md §9.3): 100% of every seeded app's
/// catalogued fake-package/API/model-string defects must be caught —
/// recall is measured against each app's `getdev-expected.json`, matching
/// on rule `id` + `file` (a seeded defect's exact line can shift as the
/// corpus evolves; id + file is the stable, documented recall criterion).
#[test]
fn seeded_recall_is_100_percent() {
    let apps = seeded_apps();
    assert!(
        apps.len() >= 10,
        "expected >= 10 seeded apps, found {}",
        apps.len()
    );

    let mut misses = Vec::new();
    for app_dir in &apps {
        let label = app_label(app_dir);
        let expected_path = app_dir.join("getdev-expected.json");
        let expected: ExpectedCatalog = serde_json::from_str(
            &std::fs::read_to_string(&expected_path)
                .unwrap_or_else(|err| panic!("read {}: {err}", expected_path.display())),
        )
        .unwrap_or_else(|err| panic!("parse {}: {err}", expected_path.display()));
        assert!(
            !expected.seeded.is_empty(),
            "{label}: getdev-expected.json has no seeded entries"
        );

        let report = run_real(app_dir, &label);
        let findings = real_findings(&report);

        for exp in &expected.seeded {
            let found = findings.iter().any(|f| {
                f["id"].as_str() == Some(exp.id.as_str())
                    && f["file"].as_str() == Some(exp.file.as_str())
            });
            if !found {
                misses.push(format!("{label}: missing {} @ {}", exp.id, exp.file));
            }
        }
    }

    assert!(
        misses.is_empty(),
        "seeded recall is not 100% (the P2 exit criterion) -- missed findings:\n{}",
        misses.join("\n")
    );
}

/// The false-positive budget (docs/PLAN.md §9.2): the aggregate `real/*`
/// finding rate across all sentinel snapshots, measured per scanned source
/// file (JS/TS/TSX/Python, excluding vendored `node_modules`/
/// `site-packages` surface stubs — the same units `deps`/`apisurface`
/// actually scan), must stay under 5%.
#[test]
fn sentinels_stay_quiet() {
    let apps = sentinel_apps();
    assert!(
        apps.len() >= 10,
        "expected >= 10 sentinel snapshots, found {}",
        apps.len()
    );

    let mut total_findings = 0usize;
    let mut total_files = 0usize;
    let mut offenders = Vec::new();

    for app_dir in &apps {
        let label = app_label(app_dir);
        let report = run_real(app_dir, &label);
        let findings = real_findings(&report);
        total_findings += findings.len();
        total_files += count_source_files(app_dir);
        for f in &findings {
            offenders.push(format!(
                "{label}: {} [{}] {}:{} :: {}",
                f["id"].as_str().unwrap_or("?"),
                f["confidence"].as_str().unwrap_or("?"),
                f["file"].as_str().unwrap_or("?"),
                f["line"]
                    .as_u64()
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                f["message"].as_str().unwrap_or("?"),
            ));
        }
    }

    let fp_rate = total_findings as f64 / total_files.max(1) as f64;
    assert!(
        fp_rate < 0.05,
        "sentinel false-positive rate {:.1}% ({total_findings}/{total_files} scanned files) \
         exceeds the 5% budget (docs/PLAN.md §9.2):\n{}",
        fp_rate * 100.0,
        offenders.join("\n")
    );
}

/// Every source file (JS/TS/TSX/Python) under `app_dir`, excluding vendored
/// `node_modules`/`site-packages` surface stubs.
fn count_source_files(app_dir: &Path) -> usize {
    fn walk(dir: &Path, count: &mut usize) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if matches!(
                    path.file_name().and_then(|n| n.to_str()),
                    Some("node_modules" | "site-packages")
                ) {
                    continue;
                }
                walk(&path, count);
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if matches!(
                    ext,
                    "js" | "jsx" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "tsx" | "py"
                ) {
                    *count += 1;
                }
            }
        }
    }
    let mut count = 0;
    walk(app_dir, &mut count);
    count
}

/// Hermeticity proof (T-3-07, REQ-privacy): the whole corpus run makes zero
/// live network calls. A package with **no** cache-seed row at all must
/// resolve `Inconclusive` under `--offline` — never a fabricated
/// `real/nonexistent-package` finding from an unconfirmed lookup.
#[test]
fn corpus_run_is_hermetic() {
    let app_dir = tmp_dir("hermetic-app");
    std::fs::write(
        app_dir.join("requirements.txt"),
        "some-uncached-package-xyz==1.0.0\n",
    )
    .expect("write requirements.txt");

    let cache_dir = tmp_dir("hermetic-cache");
    // Deliberately no cache seed at all for "some-uncached-package-xyz".
    let assert = getdev()
        .env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .arg("real")
        .arg("--offline")
        .arg("--json")
        .arg("--path")
        .arg(&app_dir)
        .timeout(Duration::from_secs(10))
        .assert();

    let output = assert.get_output();
    let code = output.status.code().unwrap_or(-1);
    assert!(
        (0..=3).contains(&code),
        "exit code {code} outside the docs/PLAN.md §2.2 contract"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout was not valid JSON ({err}): {stdout}"));
    let findings = real_findings(&report);
    assert!(
        findings
            .iter()
            .all(|f| f["id"].as_str() != Some("real/nonexistent-package")),
        "an uncached package under --offline must never fabricate real/nonexistent-package \
         (never Missing from an unconfirmed lookup), got: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&app_dir);
    let _ = std::fs::remove_dir_all(&cache_dir);
}

/// Canonical golden-file snapshot for one representative seeded app —
/// regression coverage on the report shape (docs/TESTING.md "insta").
/// Non-deterministic fields (timestamp, tool version, absolute path) are
/// redacted before snapshotting.
#[test]
fn express_hello_report_shape_matches_snapshot() {
    let app_dir = corpus_root().join("seeded").join("express-hello");
    let mut report = run_real(&app_dir, "snapshot-express-hello");
    report["generated_at"] = Value::String("<redacted>".to_owned());
    report["tool_version"] = Value::String("<redacted>".to_owned());
    report["project"]["path"] = Value::String("<redacted>".to_owned());
    insta::assert_json_snapshot!(report);
}
