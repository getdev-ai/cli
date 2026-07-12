//! Lifecycle behaviors of `getdev_gitx::snap::snapshot` (05-VALIDATION per-task
//! map): no-repo/unborn-HEAD bootstrap, never touching the user's real
//! HEAD/index/stash, auto-snap dedupe, content-addressing determinism,
//! per-namespace independent retention, and the D-10 "refs-only, never gc"
//! guarantee.
//!
//! Self-contained per the workspace convention (no shared test-support crate
//! exists — see `getdev-core/tests/audit_perf.rs`/`audit_fixtures.rs`): every
//! helper is inlined here, and each test builds its own throwaway git repo.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use getdev_gitx::snap::{list, prune, restore, snapshot, Namespace};

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// A fresh, empty temp directory (removed if a stale one exists).
fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-gitx-{tag}-{}-{}",
        std::process::id(),
        nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, rel: &str, content: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

/// Run raw `git` in `dir` for test setup/inspection (NOT through the lib — the
/// lib deliberately neutralizes config and never touches the real index; these
/// helpers exercise the *user's* real repo state so we can assert it is
/// untouched).
fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap()
}

/// A repo with a committed tracked file, an untracked-non-ignored file, and a
/// gitignored file (+ `.gitignore`). HEAD has one real user commit.
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
    write(&dir, "untracked.txt", "untracked content\n");
    write(&dir, "ignored.txt", "ignored content\n");
    assert!(git(&dir, &["add", "tracked.txt", ".gitignore"])
        .status
        .success());
    assert!(git(&dir, &["commit", "-q", "-m", "initial"])
        .status
        .success());
    dir
}

fn ref_count(dir: &Path, prefix: &str) -> usize {
    let out = git(dir, &["for-each-ref", "--format=%(refname)", prefix]);
    String::from_utf8_lossy(&out.stdout).lines().count()
}

fn tree_of(dir: &Path, reference: &str) -> String {
    let out = git(dir, &["rev-parse", &format!("{reference}^{{tree}}")]);
    assert!(
        out.status.success(),
        "rev-parse {reference}^{{tree}} failed"
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn commit_of(dir: &Path, reference: &str) -> String {
    let out = git(dir, &["rev-parse", reference]);
    assert!(out.status.success(), "rev-parse {reference} failed");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn count_entries(dir: &Path) -> usize {
    std::fs::read_dir(dir).map(|rd| rd.count()).unwrap_or(0)
}

/// No-repo case: the first `snap` in a fresh dir runs `git init` silently and
/// leaves HEAD unborn — the user gets a snapshot ref without an accidental
/// commit on their (nonexistent) branch.
#[test]
fn first_snap_in_fresh_dir_leaves_head_unborn() {
    let dir = tempdir("fresh");
    write(&dir, "a.txt", "hello\n");
    assert!(!dir.join(".git").exists(), "precondition: no repo yet");

    let outcome = snapshot(&dir, Namespace::Snaps, "first", false, 20).unwrap();
    assert_eq!(outcome.id, 1);
    assert!(!outcome.skipped_noop);

    assert!(dir.join(".git").exists(), "git init should have run");

    // HEAD is a symbolic ref to an (unborn) branch...
    let head = git(&dir, &["symbolic-ref", "HEAD"]);
    assert!(head.status.success(), "HEAD should be a symbolic ref");
    // ...but no commit exists on it: rev-parse HEAD fails.
    let rev = git(&dir, &["rev-parse", "--verify", "--quiet", "HEAD"]);
    assert!(
        !rev.status.success(),
        "HEAD must stay unborn (no user commit)"
    );

    // the snapshot itself was recorded.
    assert_eq!(ref_count(&dir, "refs/getdev/snaps"), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A `snap` in a repo with a real commit, a staged index change, and a stash
/// entry must leave HEAD, the index/working status, and the stash byte-for-byte
/// unchanged (T-05-03 / D-01).
#[test]
fn user_head_index_stash_never_touched() {
    let dir = mixed_repo("untouched");

    // a stash entry
    write(&dir, "tracked.txt", "modified for stash\n");
    assert!(git(&dir, &["stash", "push", "-q", "-m", "wip"])
        .status
        .success());
    // a staged index change
    write(&dir, "tracked.txt", "staged change\n");
    assert!(git(&dir, &["add", "tracked.txt"]).status.success());
    // an unstaged working-tree change
    write(&dir, "untracked.txt", "changed untracked\n");

    let head_before = std::fs::read(dir.join(".git/HEAD")).unwrap();
    let rev_before = commit_of(&dir, "HEAD");
    let status_before = git(&dir, &["status", "--porcelain"]).stdout;
    let stash_before = git(&dir, &["stash", "list"]).stdout;

    let outcome = snapshot(&dir, Namespace::Snaps, "snap", false, 20).unwrap();
    assert!(!outcome.skipped_noop);

    let head_after = std::fs::read(dir.join(".git/HEAD")).unwrap();
    let rev_after = commit_of(&dir, "HEAD");
    let status_after = git(&dir, &["status", "--porcelain"]).stdout;
    let stash_after = git(&dir, &["stash", "list"]).stdout;

    assert_eq!(head_before, head_after, "HEAD file must not change");
    assert_eq!(rev_before, rev_after, "HEAD commit must not change");
    assert_eq!(
        status_before, status_after,
        "index/working status must not change"
    );
    assert_eq!(stash_before, stash_after, "stash must not change");

    let _ = std::fs::remove_dir_all(&dir);
}

/// An auto-snap over an unchanged tree is a no-op dedupe (D-07): the second
/// call creates no new ref and reports `skipped_noop`.
#[test]
fn autosnap_dedupe_skips_when_tree_unchanged() {
    let dir = mixed_repo("dedupe");

    let first = snapshot(&dir, Namespace::Auto, "auto: 1", true, 20).unwrap();
    assert!(!first.skipped_noop);

    // no intervening change
    let second = snapshot(&dir, Namespace::Auto, "auto: 2", true, 20).unwrap();
    assert!(second.skipped_noop, "unchanged tree must dedupe to a no-op");
    assert_eq!(second.id, first.id, "dedupe returns the existing id");

    assert_eq!(
        ref_count(&dir, "refs/getdev/auto"),
        1,
        "only one auto ref should exist after a deduped second snap"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Content-addressing determinism (DEC-01): two snapshots of identical content
/// share a tree oid even though their commit oids differ.
#[test]
fn identical_trees_produce_identical_tree_ids() {
    let dir = mixed_repo("identical");

    let a = snapshot(&dir, Namespace::Snaps, "one", false, 20).unwrap();
    // no change between snaps; distinct messages guarantee distinct commit oids
    let b = snapshot(&dir, Namespace::Snaps, "two", false, 20).unwrap();
    assert_ne!(a.id, b.id);

    let tree_a = tree_of(&dir, &Namespace::Snaps.ref_path(a.id));
    let tree_b = tree_of(&dir, &Namespace::Snaps.ref_path(b.id));
    assert_eq!(
        tree_a, tree_b,
        "identical content must yield an identical tree oid"
    );

    let commit_a = commit_of(&dir, &Namespace::Snaps.ref_path(a.id));
    let commit_b = commit_of(&dir, &Namespace::Snaps.ref_path(b.id));
    assert_ne!(
        commit_a, commit_b,
        "commit oids should differ (different messages)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Retention budgets are independent per namespace (D-09): with `keep=2`,
/// three manual + three auto snaps leave exactly two refs in EACH namespace —
/// manual retention never touches auto refs and vice versa.
#[test]
fn retention_budgets_are_independent_per_namespace() {
    let dir = mixed_repo("retention");

    for i in 0..3 {
        write(&dir, "tracked.txt", &format!("manual {i}\n"));
        snapshot(&dir, Namespace::Snaps, &format!("m{i}"), false, 2).unwrap();
    }
    for i in 0..3 {
        write(&dir, "tracked.txt", &format!("auto {i}\n"));
        snapshot(&dir, Namespace::Auto, &format!("a{i}"), false, 2).unwrap();
    }

    assert_eq!(
        ref_count(&dir, "refs/getdev/snaps"),
        2,
        "snaps namespace should keep exactly 2"
    );
    assert_eq!(
        ref_count(&dir, "refs/getdev/auto"),
        2,
        "auto namespace should keep exactly 2, independent of snaps"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// D-05 exact-not-additive: a file created AFTER the snapshot, within the
/// snapshotted scope, is REMOVED on `back` (restore is not merely additive) —
/// and the removal is reported in the outcome.
#[test]
fn created_since_snapshot_is_removed_on_back() {
    let dir = mixed_repo("created-since");
    let snap = snapshot(&dir, Namespace::Snaps, "base", false, 20).unwrap();

    // a NEW in-scope (untracked-non-ignored) file created since the snapshot
    write(&dir, "newfile.txt", "created since the snapshot\n");
    assert!(
        dir.join("newfile.txt").exists(),
        "precondition: file created"
    );

    let outcome = restore(&dir, snap.id).unwrap();

    assert!(
        !dir.join("newfile.txt").exists(),
        "a file created since the snapshot must be removed on back (D-05)"
    );
    assert_eq!(
        outcome.removed, 1,
        "restore should report exactly the one created-since file removed"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// CR-01 regression: a created-since file whose name contains NON-ASCII bytes
/// (git C-quotes it under the default `core.quotePath`, e.g. `"caf\303\251.txt"`)
/// must still be removed on `back`. Before the `-z` fix, `restore` parsed the
/// human-quoted `diff-tree` text and `root.join`-ed the mojibake string, so the
/// real `café.txt` was never located and the file survived (silent NotFound),
/// violating D-05 exact-not-additive. Every fixture in the proptest is ASCII,
/// which is why the gap slipped through until now.
#[test]
fn created_since_snapshot_with_non_ascii_name_is_removed_on_back() {
    let dir = mixed_repo("non-ascii-created");
    let snap = snapshot(&dir, Namespace::Snaps, "base", false, 20).unwrap();

    // a NEW in-scope (untracked-non-ignored) file with a non-ASCII name.
    write(&dir, "café.txt", "created since the snapshot\n");
    assert!(
        dir.join("café.txt").exists(),
        "precondition: non-ASCII file created"
    );

    let outcome = restore(&dir, snap.id).unwrap();

    assert!(
        !dir.join("café.txt").exists(),
        "a non-ASCII-named file created since the snapshot must be removed on back (CR-01 / D-05)"
    );
    assert_eq!(
        outcome.removed, 1,
        "restore should report exactly the one created-since file removed"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// WR-01 / WR-02 regression: `keep` is floored at 1 on every getdev retention
/// path, so even `prune(keep = 0)` keeps the newest ref, and `next_id` (which
/// reads live refs) never restarts at 1 — ids are never reused after a prune
/// cycle (D-01).
#[test]
fn ids_never_reused_across_prune() {
    let dir = mixed_repo("no-reuse");

    write(&dir, "tracked.txt", "v0\n");
    let a = snapshot(&dir, Namespace::Snaps, "s0", false, 20).unwrap();
    write(&dir, "tracked.txt", "v1\n");
    let b = snapshot(&dir, Namespace::Snaps, "s1", false, 20).unwrap();
    write(&dir, "tracked.txt", "v2\n");
    let c = snapshot(&dir, Namespace::Snaps, "s2", false, 20).unwrap();
    assert!(a.id < b.id && b.id < c.id, "ids allocate monotonically");

    // Prune as hard as the config allows — `keep = 0` is floored to 1 (WR-01),
    // so the newest (highest-id) ref must survive rather than emptying the ns.
    let pruned = prune(&dir, Namespace::Snaps, 0).unwrap();
    assert!(
        !pruned.deleted_ids.contains(&c.id),
        "the newest ref must survive the keep floor (WR-01)"
    );
    assert_eq!(
        ref_count(&dir, "refs/getdev/snaps"),
        1,
        "keep = 0 must floor to 1, never emptying the namespace"
    );

    // The next snapshot must allocate a FRESH id above every id ever handed out,
    // never restarting at 1 after the prune (WR-02 / D-01 no-reuse).
    write(&dir, "tracked.txt", "v3\n");
    let d = snapshot(&dir, Namespace::Snaps, "s3", false, 20).unwrap();
    assert!(
        d.id > c.id,
        "id must not be reused after prune (WR-02 / D-01): got {} after {}",
        d.id,
        c.id
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// D-05 / T-05-09: a gitignored path created or modified after the snapshot
/// keeps its post-mutation content on `back` — restore never reverts or removes
/// it, because ignored paths never enter a tree and so are never classified.
#[test]
fn gitignored_paths_survive_back_untouched() {
    let dir = tempdir("ignored-survive");
    // `.gitignore` covering `secret.local` must exist before the snapshot.
    write(&dir, ".gitignore", "secret.local\n");
    write(&dir, "tracked.txt", "tracked content\n");

    // snapshot taken with secret.local absent
    let snap = snapshot(&dir, Namespace::Snaps, "base", false, 20).unwrap();

    // create + populate the gitignored file AFTER the snapshot
    write(&dir, "secret.local", "sensitive post-snapshot content\n");

    restore(&dir, snap.id).unwrap();

    let content = std::fs::read_to_string(dir.join("secret.local")).unwrap();
    assert_eq!(
        content, "sensitive post-snapshot content\n",
        "a gitignored path must keep its post-mutation content (never reverted or removed)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `snap list` shows manual snapshots ONLY (D-06 — the auto safety net stays
/// invisible): with 2 manual and 2 auto snaps interleaved over the shared id
/// counter, `list` returns exactly the 2 manual rows, ordered ascending by id,
/// each carrying its original message.
#[test]
fn list_reports_manual_only() {
    let dir = mixed_repo("list-manual");

    // Interleave manual/auto over the shared counter; distinct content per snap
    // so every call creates a fresh ref (no dedupe collisions).
    write(&dir, "tracked.txt", "m0\n");
    snapshot(&dir, Namespace::Snaps, "manual one", false, 20).unwrap();
    write(&dir, "tracked.txt", "a0\n");
    snapshot(&dir, Namespace::Auto, "auto one", false, 20).unwrap();
    write(&dir, "tracked.txt", "m1\n");
    snapshot(&dir, Namespace::Snaps, "manual two", false, 20).unwrap();
    write(&dir, "tracked.txt", "a1\n");
    snapshot(&dir, Namespace::Auto, "auto two", false, 20).unwrap();

    let rows = list(&dir).unwrap();

    assert_eq!(
        rows.len(),
        2,
        "list must return only the 2 manual snapshots, never auto (D-06)"
    );
    assert!(
        rows[0].id < rows[1].id,
        "rows must be ordered ascending by id"
    );
    assert_eq!(rows[0].message, "manual one");
    assert_eq!(rows[1].message, "manual two");

    let _ = std::fs::remove_dir_all(&dir);
}

/// `snap prune` is idempotent and refs-only (D-09/D-10): pruning 5 manual snaps
/// to `keep=2` deletes the 3 oldest and keeps 2; a second prune deletes nothing.
/// Neither prune repacks the object store or writes a `gc.log` (A1 / D-10 — ref
/// deletes only, never `git gc`/`prune`/`repack`).
#[test]
fn prune_is_idempotent_refs_only() {
    let dir = mixed_repo("prune-idem");
    let pack_dir = dir.join(".git/objects/pack");
    let gc_log = dir.join(".git/gc.log");

    // Create 5 manual snapshots that all survive creation (high keep), so prune
    // has real work to do.
    for i in 0..5 {
        write(&dir, "tracked.txt", &format!("v{i}\n"));
        snapshot(&dir, Namespace::Snaps, &format!("s{i}"), false, 20).unwrap();
    }
    assert_eq!(
        ref_count(&dir, "refs/getdev/snaps"),
        5,
        "precondition: 5 manual refs before prune"
    );

    let packs_before = count_entries(&pack_dir);

    // First prune to keep=2: the 3 oldest deleted, the 2 newest kept.
    let first = prune(&dir, Namespace::Snaps, 2).unwrap();
    assert_eq!(first.deleted_ids.len(), 3, "3 oldest refs must be pruned");
    assert_eq!(first.kept, 2, "2 newest refs must be kept");
    assert_eq!(ref_count(&dir, "refs/getdev/snaps"), 2);

    // Second prune over the already-trimmed namespace is a no-op (idempotent).
    let second = prune(&dir, Namespace::Snaps, 2).unwrap();
    assert!(
        second.deleted_ids.is_empty(),
        "a second prune must delete nothing (idempotent)"
    );
    assert_eq!(second.kept, 2);
    assert_eq!(ref_count(&dir, "refs/getdev/snaps"), 2);

    // D-10: refs-only — no repack, no gc across either prune (A1 assertion).
    let packs_after = count_entries(&pack_dir);
    assert_eq!(
        packs_before, packs_after,
        "prune must not repack the object store (D-10)"
    );
    assert!(
        !gc_log.exists(),
        "prune must not run gc (no gc.log expected)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Empirical check of Assumption A1 / D-10: a `snap` never triggers a repack or
/// gc — no new `.git/objects/pack/` entries appear and no `.git/gc.log` is
/// written. Only ref creates/deletes and loose-object writes happen.
#[test]
fn snap_never_invokes_gc() {
    let dir = mixed_repo("nogc");
    let pack_dir = dir.join(".git/objects/pack");
    let gc_log = dir.join(".git/gc.log");

    let packs_before = count_entries(&pack_dir);
    snapshot(&dir, Namespace::Snaps, "snap", false, 20).unwrap();
    let packs_after = count_entries(&pack_dir);

    assert_eq!(
        packs_before, packs_after,
        "snap must not repack the object store (D-10)"
    );
    assert!(
        !gc_log.exists(),
        "snap must not run gc (no gc.log expected)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
