//! Criterion benchmark for `getdev snap` (docs/PLAN.md §3.5, REQ-perf-budgets:
//! `snap` < 1 s on a repo ≈ 500 files / 100k LOC). Times [`snapshot`] — a
//! `refs/getdev/` parentless checkpoint of the full working tree — over a
//! synthetic reference repo, with criterion. REPORTING only, never failing.
//!
//! Placed in `getdev-gitx` (not `getdev-core`) BY DESIGN: `snapshot` is a
//! getdev-gitx operation, and benching it from a getdev-core bench would force
//! a getdev-core → getdev-gitx dependency edge that does not (and must not)
//! exist (CLAUDE.md workspace map — getdev-core depends only on
//! getdev-grammars). The bench lives where the operation legitimately lives.
//!
//! The ENFORCEABLE gate that fails on a regression lives separately in
//! `../tests/snap_perf.rs` (a release-strict `#[test]`); this bench is the
//! criterion surface the CI `bench` job smoke-runs and can regression-track
//! against a saved baseline (docs/CI.md). It deliberately duplicates
//! `snap_perf.rs`'s generator — no shared test-support crate exists, and a
//! bench target cannot depend on a `tests/` integration-test file.
//!
//! Self-contained and offline: the tree is synthesized into a temp dir and
//! removed afterward. Unlike the analyzer benches this is a plain text tree —
//! git does not parse content, so realistic file/line counts are all that
//! matter. Each iteration snapshots with `dedupe = false` (so it always does
//! real work, never a D-07 no-op) into the `Snaps` namespace with a small
//! retention budget so accumulated refs stay pruned across criterion's samples.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use getdev_gitx::snap::{snapshot, Namespace};

/// Sized to land at the "repo ≈ 500 files / 100k LOC" budget row.
const FILE_COUNT: usize = 500;
/// 500 × 200 = 100k lines.
const LINES_PER_FILE: usize = 200;
/// Retention budget passed to `snapshot` — small so the refs created across
/// criterion's many samples stay pruned (each iteration is a fresh non-dedupe
/// snapshot); does not affect the timed single-snapshot cost.
const KEEP: u32 = 20;

fn tempdir_path(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create bench tempdir");
    dir
}

/// Writes a ~500-file / ~100k-LOC plain-text tree spread across
/// `src/module_<n>/` subdirectories, plus a `.gitignore` so `add -A` exercises
/// ignore handling as it would on a real project.
fn generate_tree(root: &Path) {
    std::fs::write(root.join(".gitignore"), "node_modules/\n*.log\n").expect("write .gitignore");
    for i in 0..FILE_COUNT {
        let dir = root.join("src").join(format!("module_{}", i / 20));
        std::fs::create_dir_all(&dir).expect("create module dir");
        let mut content = String::with_capacity(LINES_PER_FILE * 48);
        for l in 0..LINES_PER_FILE {
            content.push_str(&format!(
                "line {l} of file {i}: lorem ipsum dolor sit amet consectetur\n"
            ));
        }
        std::fs::write(dir.join(format!("file_{i}.txt")), content).expect("write generated file");
    }
}

fn bench_snap(c: &mut Criterion) {
    let root = tempdir_path("snap-bench");
    generate_tree(&root);

    // Prime once (ensures the repo exists + the first-commit cost is out of the
    // timed samples) so the bench measures the steady-state snapshot cost.
    let primed = snapshot(&root, Namespace::Snaps, "prime", false, KEEP)
        .expect("prime snapshot must succeed");
    assert!(
        !primed.skipped_noop,
        "a fresh snapshot must not be a dedupe no-op"
    );

    c.bench_function("snap::snapshot 500-file/100k-LOC", |b| {
        b.iter(|| {
            let outcome = snapshot(black_box(&root), Namespace::Snaps, "bench", false, KEEP)
                .expect("snapshot must succeed");
            black_box(outcome.id);
        });
    });

    let _ = std::fs::remove_dir_all(&root);
}

criterion_group!(benches, bench_snap);
criterion_main!(benches);
