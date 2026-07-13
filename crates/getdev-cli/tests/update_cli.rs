//! Hermetic integration coverage for the `getdev update` self-update engine
//! (SC1 / REQ-cmd-update). NEVER touches the network: every invocation forces
//! offline mode and points `GETDEV_CACHE_DIR` at a scratch dir (docs/CI.md
//! "no network in CI").
//!
//! ## Where each guarantee is proven
//!
//! `getdev-cli` is a **bin-only** crate (no `lib.rs`), so an integration test
//! can only drive the *binary* black-box via `assert_cmd` — it cannot call
//! `update::run()` or the pure gate functions directly. And the `getdev
//! update` subcommand itself is wired in 08-05 (which owns `main.rs`), not
//! here — this plan (08-04) exposes `update::run()` and the engine internals.
//!
//! The engine's four failure-abort proofs are therefore **unit tests** that
//! call the real production functions with seeded, in-memory bytes (fully
//! hermetic, no lib seam or live GitHub roundtrip needed):
//!
//! | Behavior                     | Proof (unit test)                                              |
//! |------------------------------|---------------------------------------------------------------|
//! | offline no-op                | `update::tests::run_offline_is_a_skip_no_op`                  |
//! | checksum mismatch → no swap  | `update::tests::checksum_mismatch_aborts_before_swap`        |
//! | signature mismatch → no swap | `update::tests::signature_mismatch_aborts_before_swap`       |
//! | downgrade refused            | `update::tests::downgrade_refused_before_any_gate_or_swap`   |
//! | both gates pass → swap runs  | `update::tests::both_gates_pass_then_and_only_then_apply_runs` |
//!
//! What an integration test *can* drive today is the offline no-op contract at
//! the process boundary: `update::run` and the version probe share ONE offline
//! guard (`ReleaseCheck::Skipped` semantics — research Pitfall 4: offline must
//! be an explicit skip, never a stale "up to date"). That guard is observable
//! through `getdev doctor`'s version row. The full end-to-end live upgrade is
//! 08-08's manual 3-OS smoke (it needs an actually-published prior release).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use assert_cmd::Command;

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn scratch_cache(label: &str) -> PathBuf {
    std::env::temp_dir()
        .join(format!(
            "getdev-cli-update-it-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
        .join("cache")
}

/// The `GETDEV_OFFLINE` env var must short-circuit the self-update version
/// probe to an explicit skip BEFORE any network client is built — the same
/// guard `update::run` runs first (Pitfall 4). Observable through doctor's
/// version row, driven here entirely by the env var (no `--offline` flag).
#[test]
fn offline_env_var_short_circuits_the_update_probe_with_an_explicit_skip() {
    let assert = getdev()
        .env("GETDEV_CACHE_DIR", scratch_cache("env"))
        .env("GETDEV_OFFLINE", "1")
        .arg("doctor")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        stdout.contains("version check skipped (--offline)"),
        "GETDEV_OFFLINE must make the update version probe an explicit skip, got:\n{stdout}"
    );
}

/// The `--offline` flag path of the SAME shared guard: offline is a first-class
/// no-op across BOTH the update version probe and registry reachability —
/// never a silent stale result. This is the process-level expression of the
/// engine's offline contract (`update::run(true, ..) == Ok(Skipped)`, proven
/// as a unit test).
#[test]
fn offline_flag_makes_the_whole_update_path_a_clean_no_op() {
    let assert = getdev()
        .env("GETDEV_CACHE_DIR", scratch_cache("flag"))
        .arg("doctor")
        .arg("--offline")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        stdout.contains("version check skipped (--offline)"),
        "the update version probe must be an explicit offline skip, got:\n{stdout}"
    );
    assert!(
        stdout.contains("registry reachability skipped (--offline)"),
        "offline must be a total no-op (no network at all), got:\n{stdout}"
    );
}
