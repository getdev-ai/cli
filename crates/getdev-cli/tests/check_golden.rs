//! Golden snapshot for the normative `getdev check` Ship Score banner
//! (docs/SPEC-COMMANDS.md `check`). Runs `check` deterministically offline over
//! a fixed small temp project and pins the box-drawn `Ship Score: NN/100`
//! header + the `N critical · N high · N medium · N low` line + findings grouped
//! by severity + the "top 3 things to fix first" section. Hermetic:
//! `GETDEV_OFFLINE=1` + a seeded `GETDEV_CACHE_DIR`, so there is zero network
//! egress and the terminal output carries no volatile fields (no timestamp, no
//! absolute path).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use assert_cmd::Command;
use getdev_registry::{Cache, Ecosystem, Existence};

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-cli-check-golden-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// The normative banner shape over a fixed project spanning three analyzer
/// families: `real/nonexistent-package` (seeded Missing), a hardcoded secret
/// (`audit/` + `env/`), and a `review/` debug leftover. The accepted snapshot
/// under `tests/snapshots/` IS the golden banner (`cargo insta review`).
#[test]
fn check_banner_matches_golden() {
    let dir = tmp_dir("banner");
    let cache_dir = dir.join("cache");

    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","dependencies":{"requests-auth-helper":"^1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("payments.js"),
        "const stripeKey = \"sk_live_ABCDEFGHIJKLMNOP01\";\n\
         console.log(\"debug\", stripeKey);\n",
    )
    .unwrap();

    let cache = Cache::open_at(&cache_dir).unwrap();
    cache
        .put_existence(Ecosystem::Npm, "requests-auth-helper", Existence::Missing)
        .unwrap();
    drop(cache);

    let output = getdev()
        .env("GETDEV_OFFLINE", "1")
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .arg("check")
        .arg("--offline")
        .arg("--no-color")
        .arg("--path")
        .arg(&dir)
        .assert()
        .get_output()
        .clone();

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    insta::assert_snapshot!("check_banner", stdout);

    let _ = std::fs::remove_dir_all(&dir);
}
