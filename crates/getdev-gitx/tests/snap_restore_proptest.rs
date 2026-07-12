//! Exit-gate property test for REQ-cmd-snap-back (05-VALIDATION): `snap →
//! arbitrary mutate → back` yields a byte-identical in-scope file set (both
//! content and presence/absence) over 1000 iterations, while gitignored paths
//! keep their post-mutation state (never reverted).
//!
//! This is the HARNESS. It is expected RED now — `restore()` returns
//! `NotImplemented` until 05-03 fills it in — and turns GREEN when restore
//! lands. The exit-gate config is explicit `cases: 1000` (NOT the proptest
//! default of 256) to literally satisfy "1000 proptest iterations".
//!
//! Self-contained per the workspace convention: helpers inlined, each case
//! builds its own throwaway repo. `snapshot` auto-inits the repo, so no
//! separate git setup is needed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use getdev_gitx::snap::{restore, snapshot, Namespace};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

/// Number of in-scope files the baseline/mutations range over.
const INSCOPE_FILES: usize = 4;
/// Number of gitignored files (under `ignored/`, which `.gitignore` excludes).
const IGNORED_FILES: usize = 2;

/// One mutation applied after the baseline snapshot. Gitignored mutations must
/// survive `back` untouched; in-scope mutations must be fully reverted.
#[derive(Debug, Clone)]
enum Mutation {
    /// Create-or-overwrite an in-scope file `f{idx}.txt`.
    Write { idx: usize, content: Vec<u8> },
    /// Delete an in-scope file `f{idx}.txt` (created-since-snapshot inverse).
    Delete { idx: usize },
    /// Create-or-overwrite a gitignored file `ignored/g{idx}.bin`.
    WriteIgnored { idx: usize, content: Vec<u8> },
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

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

fn write_bytes(dir: &Path, rel: &str, content: &[u8]) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

/// Create (or replace) an in-scope symlink `link` → `target` (Pitfall 6: git
/// stores symlinks as mode-120000 blobs; restore must reproduce the symlink,
/// not a dereferenced copy). Unix-only — Windows symlink fidelity is a
/// documented residual limitation.
#[cfg(unix)]
fn write_symlink(dir: &Path, link: &str, target: &str) {
    let path = dir.join(link);
    let _ = std::fs::remove_file(&path);
    std::os::unix::fs::symlink(target, &path).unwrap();
}

/// A stable fingerprint of a `(path, bytes)` list — the in-scope file set,
/// already in ascending index order (V6: reuse `sha2`, never hand-roll a hash).
fn hash_fileset(files: &[(String, Vec<u8>)]) -> String {
    let mut hasher = Sha256::new();
    for (name, bytes) in files {
        hasher.update(name.as_bytes());
        hasher.update([0u8]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    format!("{:x}", hasher.finalize())
}

/// The in-scope set implied by the baseline (all files present).
fn expected_inscope(baseline: &[Vec<u8>]) -> Vec<(String, Vec<u8>)> {
    baseline
        .iter()
        .enumerate()
        .map(|(i, c)| (format!("f{i}.txt"), c.clone()))
        .collect()
}

/// The in-scope set currently on disk (missing files simply omitted).
fn actual_inscope(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for i in 0..INSCOPE_FILES {
        let name = format!("f{i}.txt");
        if let Ok(bytes) = std::fs::read(dir.join(&name)) {
            out.push((name, bytes));
        }
    }
    out
}

/// The gitignored set's on-disk state (`None` = absent).
fn ignored_state(dir: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    (0..IGNORED_FILES)
        .map(|i| {
            let name = format!("ignored/g{i}.bin");
            (name.clone(), std::fs::read(dir.join(&name)).ok())
        })
        .collect()
}

fn small_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..64)
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (0..INSCOPE_FILES, small_bytes())
            .prop_map(|(idx, content)| Mutation::Write { idx, content }),
        (0..INSCOPE_FILES).prop_map(|idx| Mutation::Delete { idx }),
        (0..IGNORED_FILES, small_bytes())
            .prop_map(|(idx, content)| Mutation::WriteIgnored { idx, content }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, ..ProptestConfig::default() })]

    /// EXIT GATE (RED until 05-03): snapshot a mixed baseline, apply arbitrary
    /// mutations (incl. gitignored-path mutations), restore, and assert the
    /// in-scope file set is byte-identical to the baseline while gitignored
    /// paths retain their post-mutation state.
    #[test]
    fn snapshot_then_mutate_then_restore_is_byte_identical(
        baseline in prop::collection::vec(small_bytes(), INSCOPE_FILES),
        ignored_baseline in prop::collection::vec(small_bytes(), IGNORED_FILES),
        mutations in prop::collection::vec(mutation(), 0..8),
    ) {
        let dir = tempdir("proptest");
        // `.gitignore` must exist before the snapshot so `ignored/` is excluded.
        write_bytes(&dir, ".gitignore", b"ignored/\n");
        for (i, content) in baseline.iter().enumerate() {
            write_bytes(&dir, &format!("f{i}.txt"), content);
        }
        for (i, content) in ignored_baseline.iter().enumerate() {
            write_bytes(&dir, &format!("ignored/g{i}.bin"), content);
        }
        // An in-scope symlink in the baseline (Pitfall 6).
        #[cfg(unix)]
        write_symlink(&dir, "slink.txt", "f0.txt");

        let outcome = snapshot(&dir, Namespace::Snaps, "base", false, 20)
            .map_err(|e| TestCaseError::fail(format!("snapshot failed: {e}")))?;

        for m in &mutations {
            match m {
                Mutation::Write { idx, content } => {
                    write_bytes(&dir, &format!("f{idx}.txt"), content);
                }
                Mutation::Delete { idx } => {
                    let _ = std::fs::remove_file(dir.join(format!("f{idx}.txt")));
                }
                Mutation::WriteIgnored { idx, content } => {
                    write_bytes(&dir, &format!("ignored/g{idx}.bin"), content);
                }
            }
        }

        // Gitignored state as it stands AFTER mutation — restore must not touch it.
        let ignored_after_mutation = ignored_state(&dir);

        // Corrupt the in-scope symlink into a regular file post-snapshot; restore
        // must revert the typechange back to a symlink (exercises checkout-index
        // symlink materialization, Pitfall 6).
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(dir.join("slink.txt"));
            write_bytes(&dir, "slink.txt", b"no longer a symlink");
        }

        // RED until 05-03 implements restore(); GREEN thereafter.
        restore(&dir, outcome.id)
            .map_err(|e| TestCaseError::fail(format!("restore failed: {e}")))?;

        // The symlink must be restored AS a symlink pointing at its target.
        #[cfg(unix)]
        {
            let meta = std::fs::symlink_metadata(dir.join("slink.txt"))
                .map_err(|e| TestCaseError::fail(format!("slink.txt missing after restore: {e}")))?;
            prop_assert!(
                meta.file_type().is_symlink(),
                "restore must reproduce slink.txt as a symlink, not a dereferenced file"
            );
            let target = std::fs::read_link(dir.join("slink.txt"))
                .map_err(|e| TestCaseError::fail(format!("read_link(slink.txt) failed: {e}")))?;
            prop_assert_eq!(
                target,
                PathBuf::from("f0.txt"),
                "restored symlink must point at its original target"
            );
        }

        let expected = hash_fileset(&expected_inscope(&baseline));
        let actual = hash_fileset(&actual_inscope(&dir));
        prop_assert_eq!(
            actual,
            expected,
            "in-scope file set is not byte-identical to the baseline after restore"
        );

        prop_assert_eq!(
            ignored_state(&dir),
            ignored_after_mutation,
            "gitignored paths must retain their post-mutation state (never reverted)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
