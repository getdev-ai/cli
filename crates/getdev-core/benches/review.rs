//! Criterion benchmark for `core::review::run` (docs/PLAN.md §3.5,
//! REQ-perf-budgets: `getdev audit`/`review` (no network) < 2 s on a repo
//! ≈ 500 files / 100k LOC). Generates a synthetic JS/TS/Python tree once
//! (outside the timed loop) and times `review::run` in `ReviewScope::All`
//! (the whole-tree "treat every file as introduced" worst case — every file
//! parsed, every function fingerprinted, the whole-project reference index
//! built) with criterion — reporting only, never failing. The ENFORCEABLE
//! gate that fails `cargo test --workspace` on a regression lives separately
//! in `../tests/review_perf.rs`, which deliberately duplicates the same
//! generator (no shared test-support crate exists in this workspace, and a
//! bench target cannot depend on a `tests/` integration-test file).
//!
//! Deterministic and fully offline: review is network-free by construction,
//! there is no dependency on `testdata/corpus/`, and the tree is synthesized
//! fresh into a temp dir on every run and removed afterward.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use getdev_core::review::{self, ReviewOptions, ReviewScope};

/// Files in the generated tree — sized to land at the "repo ≈ 500 files /
/// 100k LOC" budget row (docs/PLAN.md §3.5) at `LINES_PER_FILE` each.
const FILE_COUNT: usize = 500;
/// Lines of body content per generated file (500 × 200 ≈ 100k LOC).
const LINES_PER_FILE: usize = 200;

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

/// Writes a ~500-file / ~100k-LOC JS/TS/Python tree under `root`, the same
/// realistic-density mix `review_perf.rs`/`audit`'s generator uses. No
/// manifests are needed: `review::run` in `ReviewScope::All` walks the source
/// tree directly with no `deps`/`frameworks` pre-pass.
fn generate_synthetic_tree(root: &Path) {
    for i in 0..FILE_COUNT {
        let dir = root.join("src").join(format!("module_{}", i / 20));
        std::fs::create_dir_all(&dir).expect("create module dir");
        let (name, content) = match i % 3 {
            0 => (format!("file_{i}.js"), js_file(i)),
            1 => (format!("file_{i}.ts"), ts_file(i)),
            _ => (format!("file_{i}.py"), py_file(i)),
        };
        std::fs::write(dir.join(name), content).expect("write generated file");
    }
}

/// A realistic-density mix: most lines are AST-cheap, with an actual
/// function/class/conditional/loop/map construct only every 10th line —
/// proportioned to look like a real ≈500-file/100k-LOC repo rather than a
/// pathologically AST-dense one.
fn js_body(seed: usize) -> String {
    let mut s = String::with_capacity(LINES_PER_FILE * 32);
    for i in 0..LINES_PER_FILE {
        match i % 10 {
            0 => s.push_str(&format!(
                "function compute_{seed}_{i}(a, b) {{ return a + b * {i}; }}\n"
            )),
            1 if i % 40 == 1 => s.push_str(&format!(
                "class Widget_{seed}_{i} {{ constructor(x) {{ this.x = x; }} }}\n"
            )),
            2 if i % 30 == 2 => s.push_str(&format!(
                "if (compute_{seed}_{i}(1, 2) > {i}) {{ noop('ok'); }}\n"
            )),
            3 if i % 30 == 3 => {
                s.push_str(&format!("for (let j = 0; j < {i}; j++) {{ noop(); }}\n"));
            }
            4 if i % 20 == 4 => s.push_str(&format!(
                "const list_{seed}_{i} = [1, 2, 3].map((n) => n + {i});\n"
            )),
            5 => s.push_str(&format!("const label_{seed}_{i} = \"value-{i}\";\n")),
            6 => s.push_str(&format!("config.field_{i} = {i};\n")),
            7 => s.push('\n'),
            8 => s.push_str(&format!("const flag_{seed}_{i} = true;\n")),
            _ => s.push_str(&format!("// comment line {i} for module {seed}\n")),
        }
    }
    s
}

fn js_file(seed: usize) -> String {
    let mut s = format!("// generated module {seed}\nconst express = require('express');\n");
    s.push_str(&js_body(seed));
    s
}

fn ts_body(seed: usize) -> String {
    let mut s = String::with_capacity(LINES_PER_FILE * 32);
    for i in 0..LINES_PER_FILE {
        match i % 10 {
            0 => s.push_str(&format!(
                "function compute_{seed}_{i}(a: number, b: number): number {{ return a + b * {i}; }}\n"
            )),
            1 if i % 40 == 1 => s.push_str(&format!(
                "class Widget_{seed}_{i} {{ x: number; constructor(x: number) {{ this.x = x; }} }}\n"
            )),
            2 if i % 30 == 2 => s.push_str(&format!(
                "if (compute_{seed}_{i}(1, 2) > {i}) {{ noop('ok'); }}\n"
            )),
            3 if i % 30 == 3 => {
                s.push_str(&format!("for (let j = 0; j < {i}; j++) {{ noop(); }}\n"));
            }
            4 if i % 20 == 4 => s.push_str(&format!(
                "const list_{seed}_{i}: number[] = [1, 2, 3].map((n) => n + {i});\n"
            )),
            5 => s.push_str(&format!("const label_{seed}_{i}: string = \"value-{i}\";\n")),
            6 => s.push_str(&format!("config.field_{i} = {i};\n")),
            7 => s.push('\n'),
            8 => s.push_str(&format!("const flag_{seed}_{i}: boolean = true;\n")),
            _ => s.push_str(&format!("// comment line {i} for module {seed}\n")),
        }
    }
    s
}

fn ts_file(seed: usize) -> String {
    let mut s = format!("// generated module {seed}\nimport express from 'express';\n");
    s.push_str(&ts_body(seed));
    s
}

fn py_file(seed: usize) -> String {
    let mut s = format!("# generated module {seed}\nimport os\n");
    for i in 0..LINES_PER_FILE {
        match i % 10 {
            0 => s.push_str(&format!(
                "def compute_{seed}_{i}(a, b):\n    return a + b * {i}\n"
            )),
            1 if i % 40 == 1 => s.push_str(&format!(
                "class Widget_{seed}_{i}:\n    def __init__(self, x):\n        self.x = x\n"
            )),
            2 if i % 30 == 2 => {
                s.push_str(&format!(
                    "if compute_{seed}_{i}(1, 2) > {i}:\n    noop('ok')\n"
                ));
            }
            3 if i % 30 == 3 => s.push_str(&format!("for j in range({i}):\n    pass\n")),
            5 => s.push_str(&format!("label_{seed}_{i} = \"value-{i}\"\n")),
            6 => s.push_str(&format!("config[\"field_{i}\"] = {i}\n")),
            7 => s.push('\n'),
            8 => s.push_str(&format!("flag_{seed}_{i} = True\n")),
            _ => s.push_str(&format!("# comment line {i} for module {seed}\n")),
        }
    }
    s
}

fn bench_review(c: &mut Criterion) {
    let root = tempdir_path("review-bench");
    generate_synthetic_tree(&root);

    let opts = ReviewOptions::default();

    c.bench_function("review::run 500-file/100k-LOC (ReviewScope::All)", |b| {
        b.iter(|| {
            let (findings, _skipped) =
                review::run(black_box(&root), &ReviewScope::All, &opts).expect("review run");
            black_box(findings.len());
        });
    });

    let _ = std::fs::remove_dir_all(&root);
}

criterion_group!(benches, bench_review);
criterion_main!(benches);
