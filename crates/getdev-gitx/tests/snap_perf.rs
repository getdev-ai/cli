//! Wall-clock perf gate (docs/PLAN.md §3.5, REQ-perf-budgets): `getdev snap`
//! must complete in < 1 s on a repo ≈ 500 files / 100k LOC. Mirrors
//! `getdev-core/tests/audit_perf.rs`'s enforceable-`#[test]` pattern and its
//! `RELEASE_BUDGET`/`DEBUG_BUDGET` dual-threshold split: the shipped-binary
//! number is asserted at full strictness only when this test is compiled with
//! optimizations, with a wider ceiling for an ordinary dev-profile
//! `cargo test` run so it stays a meaningful regression check without flaking.
//!
//! Self-contained (no shared test-support crate): the tree is synthesized into
//! a temp dir and removed afterward. Unlike `audit_perf.rs` this generates a
//! plain text tree — git does not parse content, so no framework/rule-pack
//! seeding is needed, just realistic file/line counts.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use getdev_gitx::snap::{snapshot, Namespace};

/// Sized to land at the "repo ≈ 500 files / 100k LOC" budget row.
const FILE_COUNT: usize = 500;
/// 500 × 200 = 100k lines.
const LINES_PER_FILE: usize = 200;

/// docs/PLAN.md §3.5: `snap < 1s`. Asserted at full strictness whenever this
/// test is compiled with optimizations (`cargo test --release`).
const RELEASE_BUDGET: Duration = Duration::from_secs(1);
/// A dev-profile `cargo test` (no LTO, debug assertions on) is not the shipped
/// artifact; the dominant cost here is the external `git` binary regardless of
/// our profile, but a wider ceiling keeps this from flaking on slow CI while
/// still catching a genuine blowup. The number CI/release enforces is
/// `RELEASE_BUDGET`, asserted whenever this test is optimized.
const DEBUG_BUDGET: Duration = Duration::from_secs(10);

/// GitHub-hosted CI runners (2-core shared VMs) are consistently 2–4× slower
/// than the development hardware these budgets are tuned on — and the external
/// `git` subprocess cost that dominates this gate is several times higher again
/// on Windows runners. Scale the ceiling under `CI` so the gate measures the
/// code, not the runner; local runs keep the strict docs/PLAN.md §3.5 numbers.
fn ci_scaled(budget: Duration) -> Duration {
    if std::env::var_os("CI").is_some() {
        budget * 3
    } else {
        budget
    }
}

fn tempdir_path(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create perf-test tempdir");
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

/// The enforceable perf gate: one `snapshot` over the generated tree must land
/// under the docs/PLAN.md §3.5 `< 1 s` budget (strict when optimized, wider on
/// a dev-profile build).
#[test]
fn snap_completes_under_1s_on_500_file_100k_loc_tree() {
    let root = tempdir_path("snap-perf");
    generate_tree(&root);

    let start = Instant::now();
    let outcome =
        snapshot(&root, Namespace::Snaps, "perf", false, 20).expect("snapshot must succeed");
    let elapsed = start.elapsed();

    let _ = std::fs::remove_dir_all(&root);

    assert!(
        !outcome.skipped_noop,
        "a fresh snapshot must not be a dedupe no-op"
    );

    let budget = ci_scaled(if cfg!(debug_assertions) {
        DEBUG_BUDGET
    } else {
        RELEASE_BUDGET
    });
    assert!(
        elapsed < budget,
        "getdev snap exceeded its {budget:?} budget (docs/PLAN.md §3.5's < 1s release-profile \
         target{}) — took {elapsed:?} over {FILE_COUNT} files",
        if cfg!(debug_assertions) {
            ", widened for an unoptimized dev-profile build"
        } else {
            ""
        }
    );
}
