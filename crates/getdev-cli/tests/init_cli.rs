//! Hermetic integration tests for `getdev init` (assert_cmd). `init` is fully
//! NON-INTERACTIVE (B-07) — there is never a prompt — so these drive it against
//! inline temp git repos with no stdin choreography:
//!
//! * plain `getdev init` writes ONLY `.getdev.toml`, prints the one-line extras
//!   hint, and installs NO hooks / NO managed block (config is optional).
//! * `getdev init --all` (and its `--yes` back-compat alias) ALSO writes a
//!   `.git/hooks/pre-commit` (running `getdev check --quiet --fail-on
//!   critical`), a `.git/hooks/post-checkout`, and upserts the agent-context
//!   block into a pre-existing `CLAUDE.md` — every file via `core::mutate`.
//! * both hook files are EXECUTABLE after write (Unix mode bits) — proving the
//!   CLI-tier chmod corrects `mutate`'s hardened 0600 default (a content-only
//!   check would pass while the hook silently never fires).
//! * the agent-context managed block is an idempotent marker-delimited upsert:
//!   running init twice neither duplicates the block nor alters user content
//!   outside the markers.
//! * a pre-existing `.getdev.toml` / pre-commit hook is NEVER clobbered
//!   (creates-new-files / appends-managed-blocks-only contract).
//! * with no agent file present, `--all` creates no managed block (append-only).
//! * regression (B-07): `getdev init` with empty/piped stdin never blocks and
//!   exits 0 — the blind-cursor hang is structurally impossible now.
//! * a static gate: no bare filesystem write in `commands/init.rs`.
//!
//! Every repo is controlled by the test and lives under a fresh temp dir; the
//! auto-snap fires through `getdev-gitx`, which blanks global/system git config
//! and sets its own committer identity, so these need no ambient git setup.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

const MARKER_START: &str = "<!-- getdev:managed:start -->";
const MARKER_END: &str = "<!-- getdev:managed:end -->";

fn getdev() -> Command {
    Command::cargo_bin("getdev").expect("the getdev binary should build for tests")
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-cli-init-it-{label}-{}-{}",
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

/// `git init` a hermetic repo so `.git/hooks/` exists for the hook writes and
/// the multi-file auto-snap has a repo to write `refs/getdev/auto/` into.
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

/// Run `getdev init <flag> --no-color` over `dir` (a hermetic cache dir keeps
/// the first-run welcome marker out of the developer's real `~/.getdev`).
fn run_init(dir: &Path, flag: &[&str]) {
    let cache_dir = dir.join(".cache-init-it");
    let mut cmd = getdev();
    cmd.env("GETDEV_CACHE_DIR", &cache_dir).arg("init");
    for f in flag {
        cmd.arg(f);
    }
    cmd.args(["--no-color", "--path"])
        .arg(dir)
        .assert()
        .success();
}

/// Install-everything path used by most tests — `--all` (and, where noted, its
/// `--yes` alias) installs the config + both hooks + the managed block.
fn run_init_all(dir: &Path) {
    run_init(dir, &["--all"]);
}

/// Test 1: `getdev init --all` writes `.getdev.toml`, `.git/hooks/pre-commit`,
/// and `.git/hooks/post-checkout`; the pre-commit body runs the critical gate.
#[test]
fn all_writes_config_and_hooks() {
    let dir = tmp_dir("writes");
    git_init(&dir);

    run_init_all(&dir);

    assert!(
        dir.join(".getdev.toml").is_file(),
        ".getdev.toml must be written"
    );
    let pre_commit = dir.join(".git").join("hooks").join("pre-commit");
    let post_checkout = dir.join(".git").join("hooks").join("post-checkout");
    assert!(pre_commit.is_file(), "pre-commit hook must be written");
    assert!(
        post_checkout.is_file(),
        "post-checkout hook must be written"
    );

    let body = std::fs::read_to_string(&pre_commit).unwrap();
    assert!(
        body.contains("getdev check --quiet --fail-on critical"),
        "pre-commit hook must run the critical gate, got:\n{body}"
    );

    // the .getdev.toml is real, parseable config (round-trips through the loader)
    let toml = std::fs::read_to_string(dir.join(".getdev.toml")).unwrap();
    assert!(
        toml.contains("[project]") && toml.contains("stack ="),
        "generated .getdev.toml must carry the detected [project] stack, got:\n{toml}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test 2 (T-07-24, Unix-only): both hook files are EXECUTABLE after write —
/// the CLI-tier chmod corrects mutate's 0600 default. A non-executable git hook
/// is silently never run, so a content-only assertion would pass while the hook
/// does nothing in real usage.
#[cfg(unix)]
#[test]
fn hook_is_executable() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tmp_dir("exec");
    git_init(&dir);
    run_init_all(&dir);

    for hook in ["pre-commit", "post-checkout"] {
        let path = dir.join(".git").join("hooks").join(hook);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert!(
            mode & 0o111 != 0,
            "{hook} must be executable after write, mode was {mode:o}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test 3 (T-07-22): the agent-context managed block is an idempotent
/// marker-delimited upsert. Seed a CLAUDE.md with user content, run init twice:
/// exactly one block, markers present, and the user content outside the markers
/// is byte-identical to the original.
#[test]
fn managed_block_is_idempotent() {
    let dir = tmp_dir("idempotent");
    git_init(&dir);
    let original = "# My Project\n\nImportant user notes — do not lose me.\n";
    std::fs::write(dir.join("CLAUDE.md"), original).unwrap();

    run_init_all(&dir);
    let after_first = std::fs::read_to_string(dir.join("CLAUDE.md")).unwrap();

    run_init_all(&dir);
    let after_second = std::fs::read_to_string(dir.join("CLAUDE.md")).unwrap();

    // idempotent: the file is byte-identical across the two runs
    assert_eq!(
        after_first, after_second,
        "a second init must not change CLAUDE.md"
    );

    // exactly one managed block, both markers present
    assert_eq!(
        after_second.matches(MARKER_START).count(),
        1,
        "exactly one managed block, got:\n{after_second}"
    );
    assert!(
        after_second.contains(MARKER_END),
        "closing marker must be present, got:\n{after_second}"
    );

    // the user content BEFORE the managed block is preserved unchanged
    let before = &after_second[..after_second.find(MARKER_START).unwrap()];
    assert_eq!(
        before.trim_end(),
        original.trim_end(),
        "user content outside the markers must be byte-identical to the original"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test 4 (T-07-22): a pre-existing `.getdev.toml` and pre-commit hook are
/// NEVER overwritten — init skips them with a message (creates-new-files /
/// appends-managed-blocks-only contract, REQ-cmd-init).
#[test]
fn does_not_clobber_existing() {
    let dir = tmp_dir("noclobber");
    git_init(&dir);

    // a valid-but-sentinel config (comment-only parses as default config, so
    // config resolution still succeeds and init actually runs)
    let config_sentinel = "# SENTINEL-getdev-toml — must survive\n";
    std::fs::write(dir.join(".getdev.toml"), config_sentinel).unwrap();

    let hooks = dir.join(".git").join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    let hook_sentinel = "#!/bin/sh\n# SENTINEL-precommit — must survive\n";
    let pre_commit = hooks.join("pre-commit");
    std::fs::write(&pre_commit, hook_sentinel).unwrap();

    run_init_all(&dir);

    assert_eq!(
        std::fs::read_to_string(dir.join(".getdev.toml")).unwrap(),
        config_sentinel,
        "a pre-existing .getdev.toml must not be overwritten"
    );
    assert_eq!(
        std::fs::read_to_string(&pre_commit).unwrap(),
        hook_sentinel,
        "a pre-existing pre-commit hook must not be overwritten"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test 5: with no CLAUDE.md/AGENTS.md/.cursorrules present, init creates no
/// managed block — the block is only ever APPENDED to a file that exists.
#[test]
fn no_agent_file_no_managed_block() {
    let dir = tmp_dir("noagent");
    git_init(&dir);

    run_init_all(&dir);

    for name in ["CLAUDE.md", "AGENTS.md", ".cursorrules"] {
        assert!(
            !dir.join(name).exists(),
            "init must not create {name} when it did not already exist"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test 6 (T-07-21 static gate): `commands/init.rs` never bypasses
/// `core::mutate` with a bare filesystem write. The executable-bit fix-up uses
/// `set_permissions`, which is not a content write.
#[test]
fn init_source_has_no_bare_filesystem_write() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let init_src = std::fs::read_to_string(manifest.join("src/commands/init.rs")).unwrap();
    assert!(
        !init_src.contains("fs::write"),
        "commands/init.rs must route every write through core::mutate — found a bare fs::write"
    );
}

/// Test 7 (a): plain `getdev init` (no `--all`) writes ONLY `.getdev.toml`,
/// prints the one-line extras hint, and installs NONE of the extras — no
/// pre-commit hook, no post-checkout hook, and no managed block even when an
/// agent file is present. Config is optional; the extras are opt-in.
#[test]
fn plain_init_writes_only_config_and_prints_hint() {
    let dir = tmp_dir("plain");
    git_init(&dir);
    // An agent file IS present — plain init must still leave it untouched.
    let agent = "# My Project\n\nkeep me verbatim\n";
    std::fs::write(dir.join("CLAUDE.md"), agent).unwrap();

    let cache_dir = dir.join(".cache-init-it");
    let output = getdev()
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .args(["init", "--no-color", "--path"])
        .arg(&dir)
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // config written…
    assert!(
        dir.join(".getdev.toml").is_file(),
        "plain init must still write .getdev.toml"
    );
    // …but NONE of the extras.
    assert!(
        !dir.join(".git").join("hooks").join("pre-commit").exists(),
        "plain init must NOT install the pre-commit hook"
    );
    assert!(
        !dir.join(".git")
            .join("hooks")
            .join("post-checkout")
            .exists(),
        "plain init must NOT install the post-checkout hook"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("CLAUDE.md")).unwrap(),
        agent,
        "plain init must NOT upsert a managed block into an existing agent file"
    );
    assert!(
        !std::fs::read_to_string(dir.join("CLAUDE.md"))
            .unwrap()
            .contains(MARKER_START),
        "no managed block markers on the plain path"
    );

    // and the one-line extras hint points at `--all`.
    assert!(
        stdout.contains("run `getdev init --all` to install"),
        "plain init must print the extras hint, got:\n{stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test 8 (b): `--yes` is a back-compat alias for `--all` — it installs the same
/// extras (pre-commit + post-checkout hooks, and the managed block into a
/// pre-existing CLAUDE.md).
#[test]
fn yes_alias_installs_the_same_extras_as_all() {
    let dir = tmp_dir("yes-alias");
    git_init(&dir);
    std::fs::write(dir.join("CLAUDE.md"), "# Proj\n\nnotes\n").unwrap();

    run_init(&dir, &["--yes"]);

    assert!(
        dir.join(".git").join("hooks").join("pre-commit").is_file(),
        "--yes must install the pre-commit hook (alias of --all)"
    );
    assert!(
        dir.join(".git")
            .join("hooks")
            .join("post-checkout")
            .is_file(),
        "--yes must install the post-checkout hook (alias of --all)"
    );
    assert!(
        std::fs::read_to_string(dir.join("CLAUDE.md"))
            .unwrap()
            .contains(MARKER_START),
        "--yes must upsert the managed block into an existing CLAUDE.md"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test 9 (d, B-07 regression): `getdev init` with empty/piped stdin must NEVER
/// block on a read and must exit 0. The old `offer()` `read_line` was the
/// blind-cursor hang; init is non-interactive now, so a closed stdin (here an
/// empty pipe, the assert_cmd equivalent of `< /dev/null`) can never stall it.
#[test]
fn plain_init_never_blocks_on_piped_stdin() {
    let dir = tmp_dir("no-hang");
    git_init(&dir);
    let cache_dir = dir.join(".cache-init-it");

    // write_stdin("") hands the child an immediately-closed (EOF) stdin — if any
    // code path still tried to read a prompt answer, it would see EOF, not hang.
    getdev()
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .args(["init", "--no-color", "--path"])
        .arg(&dir)
        .write_stdin("")
        .assert()
        .success();

    // Same for the extras path — --all with a closed stdin must also complete.
    getdev()
        .env("GETDEV_CACHE_DIR", &cache_dir)
        .args(["init", "--all", "--no-color", "--path"])
        .arg(&dir)
        .write_stdin("")
        .assert()
        .success();

    let _ = std::fs::remove_dir_all(&dir);
}
