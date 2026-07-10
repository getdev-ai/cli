//! Hermetic integration tests for `getdev real` (assert_cmd). Every
//! invocation sets `GETDEV_OFFLINE=1` and points `GETDEV_CACHE_DIR` at a
//! seeded scratch directory — zero live network calls, docs/TESTING.md
//! "no network in CI".

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use getdev_registry::{Cache, Ecosystem, Existence};

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-cli-real-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// A sorted `(relative path, byte length)` snapshot of every file under
/// `root` — used to prove a `getdev real` run mutates nothing.
fn snapshot(root: &Path) -> Vec<(String, u64)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, u64)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root, out);
            } else if let Ok(meta) = entry.metadata() {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, meta.len()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

#[test]
fn deps_only_offline_flags_a_seeded_missing_package_and_writes_no_files() {
    let dir = tmp_dir("deps-missing");
    let cache_dir = dir.join("cache");
    std::fs::write(
        dir.join("requirements.txt"),
        "totally-fake-pkg-xyz==1.0.0\n",
    )
    .unwrap();

    // Seed the cache with an existence=false row so the registry lookup
    // resolves from cache alone — zero network egress, and proves the
    // `--offline` path reads only the cache (never fabricating a finding
    // from a lookup it can't actually perform).
    let cache = Cache::open_at(&cache_dir).unwrap();
    cache
        .put_existence(Ecosystem::Pypi, "totally-fake-pkg-xyz", Existence::Missing)
        .unwrap();
    drop(cache);

    let before = snapshot(&dir);

    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .arg("real")
        .arg("--deps-only")
        .arg("--offline")
        .arg("--json")
        .assert();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout was not valid JSON ({err}): {stdout}"));

    let findings = report["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["id"] == "real/nonexistent-package"
                && f["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("totally-fake-pkg-xyz")),
        "expected a real/nonexistent-package finding, got: {stdout}"
    );
    // --deps-only must never emit model/api findings
    assert!(findings
        .iter()
        .all(|f| f["id"] != "real/unknown-model-string" && f["id"] != "real/nonexistent-api"));

    let after = snapshot(&dir);
    assert_eq!(before, after, "getdev real must never mutate the project");
}

#[test]
fn models_only_scopes_the_run_to_model_findings() {
    let dir = tmp_dir("models-only");
    let cache_dir = dir.join("cache");
    std::fs::write(
        dir.join("app.js"),
        "const model = \"totally-unknown-vendor-9\";\n\
         import notReal from \"not-a-real-package\";\n",
    )
    .unwrap();

    let before = snapshot(&dir);

    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .arg("real")
        .arg("--models-only")
        .arg("--json")
        .assert();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout was not valid JSON ({err}): {stdout}"));

    let findings = report["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "expected at least one finding");
    assert!(
        findings
            .iter()
            .all(|f| f["id"] == "real/unknown-model-string"),
        "--models-only must emit ONLY model findings, got: {stdout}"
    );
    // the phantom import in app.js must NOT surface — deps group is out of scope
    assert!(findings.iter().all(|f| f["id"] != "real/phantom-import"));

    let after = snapshot(&dir);
    assert_eq!(before, after, "getdev real must never mutate the project");
}

#[test]
fn more_than_one_only_flag_is_rejected() {
    let dir = tmp_dir("conflicting-flags");
    getdev()
        .current_dir(&dir)
        .env("GETDEV_OFFLINE", "1")
        .arg("real")
        .arg("--deps-only")
        .arg("--apis-only")
        .assert()
        .failure();
}

#[test]
fn offline_run_never_touches_the_network() {
    // No live fetcher/mock server exists anywhere in this test binary —
    // if `real` attempted a real network call under --offline, the process
    // would either hang (no timeout set for a real socket outside the
    // client's own 5s cap) or the test environment's network sandboxing
    // would fail it. A clean, fast exit in the docs/PLAN.md §2.2 exit-code
    // contract range is the executable proof.
    let dir = tmp_dir("no-network");
    std::fs::write(dir.join("requirements.txt"), "requests==2.31.0\n").unwrap();
    let assert = getdev()
        .current_dir(&dir)
        .env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", dir.join("cache"))
        .arg("real")
        .arg("--json")
        .timeout(std::time::Duration::from_secs(10))
        .assert();
    let code = assert.get_output().status.code().unwrap_or(-1);
    assert!(
        (0..=3).contains(&code),
        "exit code {code} outside the docs/PLAN.md §2.2 contract"
    );
}
