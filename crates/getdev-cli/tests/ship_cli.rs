//! Hermetic integration tests for `getdev ship` (assert_cmd). These prove the
//! user-visible contract of 07-06 against inline temp projects — NO docker
//! required (the real `docker build` exit gate is 07-07):
//!
//! * `--write` generates a multi-stage Dockerfile (+ HEALTHCHECK), a
//!   `.dockerignore`, and `SHIP.md` — every file via `core::mutate` — and is
//!   idempotent (authoritative regeneration).
//! * the Django preset never bakes `collectstatic` into the build (Pitfall 2).
//! * `--target` selects the per-target `SHIP.md` checklist; the default is
//!   docker.
//! * getdev NEVER executes project code without `--run-build` (REQ-privacy) —
//!   proven with a build-step sentinel that must stay absent.
//! * the default run mutates nothing (safe-by-default).
//! * the three `ship/*` validators surface in `--json`.
//! * a static gate: no bare filesystem write in the production ship sources.
//!
//! Every project is controlled by the test itself and lives under a fresh temp
//! dir. Auto-snap is disabled via an inline `.getdev.toml` for the pure
//! content tests (so they need no git); one dedicated test git-inits and
//! asserts the multi-file auto-snap fires (REQ-cmd-ship SC4).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-cli-ship-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Drop a `.getdev.toml` that turns the multi-file auto-snap OFF, so a
/// `--write` run needs no git repo — it still exercises the real
/// `mutate::apply` path (hook `None`, per the `writes.len() > 1` gate).
fn disable_auto_snap(dir: &Path) {
    std::fs::write(
        dir.join(".getdev.toml"),
        "[snap]\nauto_snap_before_fix = false\n",
    )
    .unwrap();
}

fn write(dir: &Path, rel: &str, contents: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

/// A minimal Next.js project: `next` declared + an API route (the
/// `frameworks::detect` `nextjs_api` signal `detect_stack` keys off).
fn seed_nextjs_project(dir: &Path) {
    write(dir, "package.json", r#"{"dependencies":{"next":"14.0.0"}}"#);
    write(
        dir,
        "pages/api/hello.ts",
        "export default function handler() {}\n",
    );
}

/// A minimal Django project — `django` in `requirements.txt` is the one
/// membership check `detect_stack` adds on top of `frameworks::detect`.
fn seed_django_project(dir: &Path) {
    write(dir, "requirements.txt", "django>=5.0\ngunicorn\n");
    write(dir, "manage.py", "def main():\n    pass\n");
}

/// Test 1: `getdev ship --write` on a Next.js project generates a multi-stage
/// Dockerfile (>=2 `FROM`, a `HEALTHCHECK`), a `.dockerignore` (`.env`,
/// `node_modules`), and `SHIP.md` — and re-running is idempotent (RESEARCH
/// Open Q3: `--write` is authoritative regeneration, never an error).
#[test]
fn write_generates_dockerfile_and_dockerignore() {
    let dir = tmp_dir("write");
    seed_nextjs_project(&dir);
    disable_auto_snap(&dir);

    getdev()
        .args(["ship", "--write", "--no-color", "--path"])
        .arg(&dir)
        .assert()
        .success();

    let dockerfile = std::fs::read_to_string(dir.join("Dockerfile")).unwrap();
    assert!(
        dockerfile.matches("FROM ").count() >= 2,
        "Dockerfile must be multi-stage, got:\n{dockerfile}"
    );
    assert!(
        dockerfile.contains("HEALTHCHECK"),
        "Dockerfile must carry a HEALTHCHECK, got:\n{dockerfile}"
    );

    let dockerignore = std::fs::read_to_string(dir.join(".dockerignore")).unwrap();
    assert!(
        dockerignore.contains(".env"),
        ".dockerignore must exclude .env, got:\n{dockerignore}"
    );
    assert!(
        dockerignore.contains("node_modules"),
        ".dockerignore must exclude node_modules, got:\n{dockerignore}"
    );

    assert!(dir.join("SHIP.md").is_file(), "SHIP.md must be generated");

    // Idempotent regeneration: a second --write succeeds and leaves the same
    // authoritative content (no accumulation, no error).
    getdev()
        .args(["ship", "--write", "--no-color", "--path"])
        .arg(&dir)
        .assert()
        .success();
    let dockerfile2 = std::fs::read_to_string(dir.join("Dockerfile")).unwrap();
    assert_eq!(
        dockerfile, dockerfile2,
        "re-running --write must regenerate identical content"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test 2: the Django Dockerfile never runs `collectstatic` at build time —
/// a working `docker build` must not depend on the user's runtime settings
/// (07-RESEARCH Pitfall 2). The deferred step lives in SHIP.md instead.
#[test]
fn django_dockerfile_has_no_collectstatic() {
    let dir = tmp_dir("django");
    seed_django_project(&dir);
    disable_auto_snap(&dir);

    getdev()
        .args(["ship", "--write", "--no-color", "--path"])
        .arg(&dir)
        .assert()
        .success();

    let dockerfile = std::fs::read_to_string(dir.join("Dockerfile")).unwrap();
    assert!(
        dockerfile.matches("FROM ").count() >= 2 && dockerfile.contains("HEALTHCHECK"),
        "Django Dockerfile must be multi-stage with a HEALTHCHECK, got:\n{dockerfile}"
    );
    assert!(
        !dockerfile.to_lowercase().contains("collectstatic"),
        "Django Dockerfile must NOT run collectstatic at build time, got:\n{dockerfile}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test 3: `--target` selects the per-target `SHIP.md` checklist; the default
/// (no `--target`) is docker. vercel vs vps produce materially different
/// checklists.
#[test]
fn per_target_checklist() {
    let read_ship_md = |target: Option<&str>| -> String {
        let dir = tmp_dir(&format!("target-{}", target.unwrap_or("default")));
        seed_nextjs_project(&dir);
        disable_auto_snap(&dir);
        let mut cmd = getdev();
        cmd.args(["ship", "--write", "--no-color"]);
        if let Some(t) = target {
            cmd.args(["--target", t]);
        }
        cmd.arg("--path").arg(&dir).assert().success();
        let md = std::fs::read_to_string(dir.join("SHIP.md")).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        md
    };

    let vercel = read_ship_md(Some("vercel"));
    let vps = read_ship_md(Some("vps"));
    let default = read_ship_md(None);

    assert!(
        vercel.to_lowercase().contains("vercel"),
        "--target vercel checklist must mention vercel, got:\n{vercel}"
    );
    assert!(
        vps.to_lowercase().contains("vps") || vps.to_lowercase().contains("reverse proxy"),
        "--target vps checklist must be VPS-specific, got:\n{vps}"
    );
    assert_ne!(
        vercel, vps,
        "different --target values must produce different SHIP.md checklists"
    );
    assert!(
        default.to_lowercase().contains("docker"),
        "the default target must be docker, got:\n{default}"
    );
}

/// Test 4 (REQ-privacy, T-07-15): getdev NEVER executes project code without
/// `--run-build`. The project's build step would create a sentinel file; we
/// confirm it is ABSENT after a plain `getdev ship` AND after `getdev ship
/// --write` — no subprocess is ever spawned by default.
#[test]
fn no_build_without_flag() {
    let dir = tmp_dir("no-build");
    // A build script that, IF run, would drop an observable sentinel.
    write(
        &dir,
        "package.json",
        r#"{"scripts":{"build":"node -e \"require('fs').writeFileSync('BUILD_SENTINEL','x')\""}}"#,
    );
    write(&dir, "server.js", "app.listen(3000);\n");
    disable_auto_snap(&dir);

    let sentinel = dir.join("BUILD_SENTINEL");

    // default run: no build, no mutation, no sentinel.
    getdev()
        .args(["ship", "--no-color", "--path"])
        .arg(&dir)
        .assert()
        .success();
    assert!(
        !sentinel.exists(),
        "getdev ship (default) must not execute the project build"
    );

    // --write generates files but STILL never runs the build.
    getdev()
        .args(["ship", "--write", "--no-color", "--path"])
        .arg(&dir)
        .assert()
        .success();
    assert!(
        !sentinel.exists(),
        "getdev ship --write must not execute the project build either"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test 5: the default run (no `--write`) is non-mutating — no Dockerfile,
/// `.dockerignore`, or `SHIP.md` is created (safe-by-default).
#[test]
fn default_run_does_not_mutate() {
    let dir = tmp_dir("no-mutate");
    seed_nextjs_project(&dir);

    getdev()
        .args(["ship", "--no-color", "--path"])
        .arg(&dir)
        .assert()
        .success();

    assert!(
        !dir.join("Dockerfile").exists(),
        "no Dockerfile without --write"
    );
    assert!(
        !dir.join(".dockerignore").exists(),
        "no .dockerignore without --write"
    );
    assert!(!dir.join("SHIP.md").exists(), "no SHIP.md without --write");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test 6: the three `ship/*` validators surface in `--json`. A referenced-
/// but-undeclared env var fires `ship/missing-env-declaration`; a numeric
/// `listen(3000)` fires `ship/hardcoded-port`.
#[test]
fn validation_findings_reported() {
    let dir = tmp_dir("validate");
    write(
        &dir,
        "server.js",
        "const t = process.env.API_TOKEN;\napp.listen(3000);\n",
    );

    let assert = getdev()
        .args(["ship", "--json", "--no-color", "--path"])
        .arg(&dir)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout was not valid JSON ({err}): {stdout}"));
    let ids: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["id"].as_str())
        .collect();

    assert!(
        ids.contains(&"ship/missing-env-declaration"),
        "expected ship/missing-env-declaration, got: {ids:?}"
    );
    assert!(
        ids.contains(&"ship/hardcoded-port"),
        "expected ship/hardcoded-port, got: {ids:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// D-14 #5 wire population: EVERY finding in `ship --json` carries a populated
/// `gdv1:` fingerprint. `ship` runs `assign_fingerprints` before
/// `filter_findings` (11-05); this per-command guard proves the standalone
/// `ship` validator path stays fingerprinted (RESEARCH Pitfall 1). Mirrors
/// `audit_cli.rs`'s tracer proof.
#[test]
fn ship_json_populates_gdv1_fingerprint_on_every_finding() {
    let dir = tmp_dir("gdv1-wire");
    // A referenced-but-undeclared env var + a hardcoded port seed two ship/*
    // validator findings so the "every finding" quantifier is non-vacuous.
    write(
        &dir,
        "server.js",
        "const t = process.env.API_TOKEN;\napp.listen(3000);\n",
    );

    let assert = getdev()
        .args(["ship", "--json", "--no-color", "--path"])
        .arg(&dir)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout was not valid JSON ({err}): {stdout}"));
    let findings = report["findings"].as_array().unwrap();
    assert!(
        !findings.is_empty(),
        "expected at least one ship finding to assert on, got: {stdout}"
    );
    assert!(
        findings.iter().all(|f| f["fingerprint"]
            .as_str()
            .is_some_and(|fp| fp.starts_with("gdv1:"))),
        "every ship --json finding must carry a gdv1: fingerprint, got: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test 7 (REQ-cmd-ship SC4): a multi-file `ship --write` records exactly one
/// `refs/getdev/auto/` snapshot BEFORE mutating — the multi-file auto-snap
/// firing through the same `core::mutate` gate `env --write` uses.
#[test]
fn write_auto_snaps_before_generation() {
    let dir = tmp_dir("autosnap");
    seed_nextjs_project(&dir);
    git_init(&dir);

    assert_eq!(count_auto_refs(&dir), 0, "no auto ref before the run");
    getdev()
        .args(["ship", "--write", "--no-color", "--path"])
        .arg(&dir)
        .assert()
        .success();

    assert_eq!(
        count_auto_refs(&dir),
        1,
        "a multi-file ship --write must record exactly one auto-snap before mutating"
    );
    // and the generation still happened
    assert!(dir.join("Dockerfile").is_file());
    assert!(dir.join("SHIP.md").is_file());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test 8 (T-07-16 static gate): the PRODUCTION ship sources never bypass
/// `core::mutate` with a bare filesystem write. `commands/ship.rs` contains no
/// `fs::write` at all; any `fs::write` in `core/ship.rs` lives only inside its
/// `#[cfg(test)]` module (test-fixture setup, not the mutation path).
#[test]
fn ship_sources_have_no_bare_filesystem_write() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));

    let cli_ship = std::fs::read_to_string(manifest.join("src/commands/ship.rs")).unwrap();
    assert!(
        !cli_ship.contains("fs::write"),
        "commands/ship.rs must route every write through core::mutate — found a bare fs::write"
    );

    let core_ship = std::fs::read_to_string(manifest.join("../getdev-core/src/ship.rs")).unwrap();
    let test_module = core_ship
        .find("#[cfg(test)]")
        .expect("core/ship.rs has a #[cfg(test)] module");
    let production = &core_ship[..test_module];
    assert!(
        !production.contains("fs::write"),
        "core/ship.rs production code must not perform a bare filesystem write"
    );
}

// --- git helpers (mirror env.rs's auto-snap test harness) -------------------

fn git_init(dir: &Path) {
    let ok = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["init", "--quiet"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "git init failed for {}", dir.display());
}

fn count_auto_refs(dir: &Path) -> usize {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["for-each-ref", "--format=%(refname)", "refs/getdev/auto/"])
        .output()
        .unwrap();
    assert!(out.status.success(), "for-each-ref failed");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count()
}
