//! Lifecycle behaviors of `getdev_gitx::snap::materialize` (Phase 14, D-05 —
//! the one genuinely new gitx surface). `materialize()` unpacks a snapshot's
//! tree into a caller-supplied absolute dest dir, reusing `restore()`'s
//! `read-tree`/`checkout-index` primitives with `--prefix=<dest>/`. These tests
//! prove it faithfully reproduces the snapshotted scope (tracked +
//! untracked-non-ignored, gitignored EXCLUDED, nested structure preserved),
//! that a bad snap-id is a clean `NoSuchSnapshot` (never a partial materialize),
//! and that an empty-tree snapshot is a valid, non-error outcome.
//!
//! Self-contained per the workspace convention (no shared test-support crate —
//! see `snap_lifecycle.rs`'s header): every helper is inlined here, and each
//! test builds its own throwaway git repo.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use getdev_gitx::snap::{materialize, snapshot, GitxError, Namespace};

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// A fresh, empty temp directory (removed if a stale one exists).
fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-gitx-materialize-{tag}-{}-{}",
        std::process::id(),
        nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// An absolute dest path that does NOT exist yet — `materialize` must create it
/// (and any nested parents) itself via `checkout-index --prefix`.
fn fresh_dest(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "getdev-gitx-materialize-dest-{tag}-{}-{}",
        std::process::id(),
        nanos()
    ))
}

fn write(dir: &Path, rel: &str, content: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

/// Run raw `git` in `dir` for test setup (NOT through the lib).
fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap()
}

/// A repo with a committed tracked file, an untracked-non-ignored file, a
/// gitignored file (+ `.gitignore`), and a NESTED tracked file — mirrors
/// `snap_lifecycle.rs`'s `mixed_repo` fixture, plus a subdirectory so nested
/// structure preservation is exercised.
fn mixed_repo(tag: &str) -> PathBuf {
    let dir = tempdir(tag);
    assert!(git(&dir, &["init", "--quiet"]).status.success());
    assert!(git(&dir, &["config", "user.name", "Test User"])
        .status
        .success());
    assert!(git(&dir, &["config", "user.email", "test@example.com"])
        .status
        .success());
    write(&dir, ".gitignore", "ignored.txt\nsecret/\n");
    write(&dir, "tracked.txt", "tracked content\n");
    write(&dir, "src/nested.txt", "nested content\n");
    write(&dir, "untracked.txt", "untracked content\n");
    write(&dir, "ignored.txt", "ignored content\n");
    write(&dir, "secret/leak.txt", "sensitive\n");
    assert!(git(
        &dir,
        &["add", "tracked.txt", "src/nested.txt", ".gitignore"]
    )
    .status
    .success());
    assert!(git(&dir, &["commit", "-q", "-m", "initial"])
        .status
        .success());
    dir
}

/// A snapshot materializes faithfully into a fresh (non-pre-existing) absolute
/// dest: tracked + untracked-non-ignored files present with correct content,
/// gitignored file/dir ABSENT (never entered the tree), nested directory
/// structure preserved.
#[test]
fn materialize_reproduces_the_snapshotted_scope_into_a_fresh_dest() {
    let dir = mixed_repo("faithful");
    let snap = snapshot(&dir, Namespace::Snaps, "base", false, 20).unwrap();

    let dest = fresh_dest("faithful");
    assert!(!dest.exists(), "precondition: dest does not pre-exist");

    materialize(&dir, snap.id, &dest).unwrap();

    // dest was created by checkout-index --prefix itself (no pre-mkdir).
    assert!(dest.is_dir(), "materialize must create the dest dir");

    // tracked file — present with byte-exact content.
    assert_eq!(
        std::fs::read_to_string(dest.join("tracked.txt")).unwrap(),
        "tracked content\n",
        "tracked file must materialize with correct content"
    );
    // nested tracked file — directory structure preserved.
    assert_eq!(
        std::fs::read_to_string(dest.join("src/nested.txt")).unwrap(),
        "nested content\n",
        "nested tracked file must materialize under its subdirectory"
    );
    // untracked-non-ignored file — a snapshot is `add -A`, so it IS captured.
    assert_eq!(
        std::fs::read_to_string(dest.join("untracked.txt")).unwrap(),
        "untracked content\n",
        "untracked-non-ignored file must materialize (snapshot captures add -A)"
    );
    // gitignored file — NEVER entered the tree, so it is absent from dest.
    assert!(
        !dest.join("ignored.txt").exists(),
        "a gitignored file must be ABSENT from the materialized tree"
    );
    assert!(
        !dest.join("secret").exists(),
        "a gitignored directory must be ABSENT from the materialized tree"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dest);
}

/// A bad snap-id is a clean `NoSuchSnapshot` — the target is resolved BEFORE any
/// write, so nothing is materialized (never a partial dest).
#[test]
fn materialize_bad_snap_id_is_no_such_snapshot_and_writes_nothing() {
    let dir = mixed_repo("bad-id");
    // Create snap #1 so the repo has refs, then ask for a non-existent id.
    let _ = snapshot(&dir, Namespace::Snaps, "base", false, 20).unwrap();

    let dest = fresh_dest("bad-id");
    let err = materialize(&dir, 999, &dest).unwrap_err();
    assert!(
        matches!(err, GitxError::NoSuchSnapshot { id: 999 }),
        "a bad snap-id must be NoSuchSnapshot, got {err:?}"
    );
    assert!(
        !dest.exists(),
        "a bad id must never partially materialize a dest"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// WR-01: `checkout-index --prefix` is not `-C`-aware, so a RELATIVE dest would
/// resolve against the repo root and clobber the live working tree. `materialize`
/// must refuse a non-absolute dest up front (before any git write) — the
/// documented safety invariant is enforced, not merely assumed by the caller.
#[test]
fn materialize_refuses_a_relative_dest() {
    let dir = mixed_repo("relative-dest");
    let snap = snapshot(&dir, Namespace::Snaps, "base", false, 20).unwrap();

    let err = materialize(&dir, snap.id, Path::new("relative/dest")).unwrap_err();
    assert!(
        matches!(err, GitxError::RelativeDest { .. }),
        "a relative dest must be refused as RelativeDest, got {err:?}"
    );
    assert!(
        !dir.join("relative").exists(),
        "a refused relative dest must never have been written under the repo root"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// An empty-tree snapshot (a snapshot of an empty project) materializes without
/// error — `read-tree <empty>` + `checkout-index -a -f --prefix` exits 0 and
/// writes zero files. git creates NO directory when the index is empty, so the
/// contract is simply: `Ok(())`, and no files materialize under dest.
#[test]
fn materialize_empty_tree_snapshot_is_ok_and_writes_no_files() {
    let dir = tempdir("empty");
    // A fresh repo with no files → `snapshot` builds the empty tree.
    let snap = snapshot(&dir, Namespace::Snaps, "empty", false, 20).unwrap();

    let dest = fresh_dest("empty");
    // Must not error.
    materialize(&dir, snap.id, &dest).unwrap();

    // No files materialized (git writes nothing for an empty index; the dir may
    // or may not be created — either way, zero regular files is the contract).
    let file_count = std::fs::read_dir(&dest)
        .map(|rd| rd.filter_map(Result::ok).count())
        .unwrap_or(0);
    assert_eq!(
        file_count, 0,
        "an empty-tree snapshot must materialize zero entries"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dest);
}

/// The source repo is never mutated by a materialize: HEAD, the index/working
/// status, and the ref namespaces are byte-identical before and after.
#[test]
fn materialize_never_mutates_the_source_repo() {
    let dir = mixed_repo("readonly");
    let snap = snapshot(&dir, Namespace::Snaps, "base", false, 20).unwrap();

    let head_before = std::fs::read(dir.join(".git/HEAD")).unwrap();
    let status_before = git(&dir, &["status", "--porcelain"]).stdout;
    let refs_before = git(
        &dir,
        &["for-each-ref", "--format=%(refname)", "refs/getdev"],
    )
    .stdout;

    let dest = fresh_dest("readonly");
    materialize(&dir, snap.id, &dest).unwrap();

    let head_after = std::fs::read(dir.join(".git/HEAD")).unwrap();
    let status_after = git(&dir, &["status", "--porcelain"]).stdout;
    let refs_after = git(
        &dir,
        &["for-each-ref", "--format=%(refname)", "refs/getdev"],
    )
    .stdout;

    assert_eq!(head_before, head_after, "HEAD must not change");
    assert_eq!(
        status_before, status_after,
        "index/working status must not change"
    );
    assert_eq!(refs_before, refs_after, "getdev refs must not change");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dest);
}
