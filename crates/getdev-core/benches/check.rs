//! Criterion benchmark for the warm `getdev check` aggregate path
//! (docs/SPEC-COMMANDS.md §check, REQ-perf-budgets: `check` warm < 3 s on a
//! repo ≈ 500 files / 100k LOC). `check` (07-04) is a THIN orchestrator: it
//! builds ONE [`ScanContext`] (walk + parse EXACTLY once) and fans it into
//! every offline analyzer leg as a read-only visitor, running the independent
//! legs concurrently over the shared `&ScanContext` via rayon (07-07 — the
//! change that brought warm under 3 s). This bench reproduces that assembly in
//! `getdev-core` terms and times the whole aggregation with criterion —
//! REPORTING only, never failing.
//!
//! The ENFORCEABLE gate that fails on a regression lives separately in
//! `../tests/check_perf.rs` (a release-strict `#[test]`); this bench is the
//! criterion surface the CI `bench` job smoke-runs and can regression-track
//! against a saved baseline (docs/CI.md — >10% vs baseline = red; do not
//! assert absolute wall-clock on shared runners). It deliberately duplicates
//! `check_perf.rs`'s synthetic-tree generator — no shared test-support crate
//! exists in this workspace, and a bench target cannot depend on a `tests/`
//! integration-test file.
//!
//! Deterministic and fully offline: no network call (`real`'s registry hop is
//! excluded — the budget is defined over the offline analysis cost), no
//! dependency on `testdata/corpus/`; the tree is synthesized fresh into a temp
//! dir on every run and removed afterward.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use getdev_core::audit::{self, AuditOptions};
use getdev_core::env::{self, EnvOptions};
use getdev_core::findings::Severity;
use getdev_core::review::{self, ReviewOptions};
use getdev_core::scan::ScanContext;
use getdev_core::{apisurface, deps, frameworks, rules};

/// Files in the generated tree — sized to land at the "repo ≈ 500 files /
/// 100k LOC" budget row (docs/SPEC-COMMANDS.md §check) at `LINES_PER_FILE` each.
const FILE_COUNT: usize = 500;
/// Lines of body content per generated file (500 × 200 ≈ 100k LOC).
const LINES_PER_FILE: usize = 200;
/// Every 25th file gets one rule-triggering snippet appended, cycling through a
/// handful of AST-matcher shapes — "some rules match and most do not", never a
/// majority-FP-storm tree.
const INJECTION_STRIDE: usize = 25;

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

/// Writes a ~500-file / ~100k-LOC JS/TS/Python tree under `root`: a
/// `package.json` (express + next), a `requirements.txt` (fastapi + flask), one
/// `firestore.rules` file, a seeded App-Router `route.ts`, and `FILE_COUNT`
/// generated source files across `src/module_<n>/` subdirectories — identical
/// in shape to `check_perf.rs`'s generator so all four analyzer legs have real
/// work to do over the shared context.
fn generate_synthetic_tree(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"check-bench-corpus","private":true,"dependencies":{"express":"^4.18.0","next":"^14.0.0"}}"#,
    )
    .expect("write package.json");
    std::fs::write(
        root.join("requirements.txt"),
        "fastapi==0.109.0\nflask==3.0.0\n",
    )
    .expect("write requirements.txt");

    let api_dir = root.join("app/api/hello");
    std::fs::create_dir_all(&api_dir).expect("create app/api/hello");
    std::fs::write(
        api_dir.join("route.ts"),
        "export async function GET(request) {\n  return new Response('ok');\n}\n",
    )
    .expect("write route.ts");

    let firebase_dir = root.join("firebase");
    std::fs::create_dir_all(&firebase_dir).expect("create firebase dir");
    std::fs::write(
        firebase_dir.join("firestore.rules"),
        "service cloud.firestore {\n  match /{document=**} {\n    allow read, write: if true;\n  }\n}\n",
    )
    .expect("write firestore.rules");

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
/// pathologically AST-dense one (04-07's lesson).
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
                "if (compute_{seed}_{i}(1, 2) > {i}) {{ console.log('ok'); }}\n"
            )),
            3 if i % 30 == 3 => {
                s.push_str(&format!("for (let j = 0; j < {i}; j++) {{ noop(); }}\n"))
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

// Each string below is inert fixture text written verbatim into a generated
// `.js`/`.ts` file for `getdev audit`'s AST rules to scan — never executed by
// this benchmark or by any getdev code path (getdev never runs project code;
// CLAUDE.md "Non-negotiable principles").
const JS_INJECTIONS: &[&str] = &[
    "eval(userInput);\n",
    "child_process.exec(cmd);\n",
    "cors({ origin: \"*\" });\n",
    "res.cookie(\"session\", token);\n",
    "el.checkValidity();\n",
    "child_process.exec(`rm -rf ${dir}`);\n",
    "const NEXT_PUBLIC_STRIPE_KEY = \"sk_live_FAKEFAKEFAKE1234\";\n",
    "createClient(url, serviceRoleKey);\n",
];

fn js_file(seed: usize) -> String {
    let mut s = format!("// generated module {seed}\nconst express = require('express');\n");
    s.push_str(&js_body(seed));
    if seed.is_multiple_of(INJECTION_STRIDE) {
        s.push_str(JS_INJECTIONS[(seed / INJECTION_STRIDE) % JS_INJECTIONS.len()]);
    }
    s
}

/// Same realistic-density rationale as [`js_body`], typed variant.
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
                "if (compute_{seed}_{i}(1, 2) > {i}) {{ console.log('ok'); }}\n"
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
    if seed.is_multiple_of(INJECTION_STRIDE) {
        s.push_str(JS_INJECTIONS[(seed / INJECTION_STRIDE) % JS_INJECTIONS.len()]);
    }
    s
}

const PY_INJECTIONS: &[&str] = &[
    "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
    "app.debug = True\n",
    "os.system(cmd)\n",
];

/// Same realistic-density rationale as [`js_body`] — Python variant.
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
                    "if compute_{seed}_{i}(1, 2) > {i}:\n    print('ok')\n"
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
    if seed.is_multiple_of(INJECTION_STRIDE) {
        s.push_str(PY_INJECTIONS[(seed / INJECTION_STRIDE) % PY_INJECTIONS.len()]);
    }
    s
}

/// One full `getdev check` aggregation over the tree at `root`, reproducing
/// 07-04's orchestrator in `getdev-core` terms: build ONE parse-once
/// [`ScanContext`] and fan it into every OFFLINE analyzer leg concurrently via
/// rayon (mirrors `check_perf.rs::run_check_aggregation`). Returns the total
/// finding count (a non-zero sanity signal that the analyzers actually ran).
/// `real`'s registry network hop is intentionally excluded (offline/cache-only)
/// so the measurement is hermetic.
fn run_check_aggregation(root: &Path) -> usize {
    // ONE shared parse-once context — the single walk + parse for the whole
    // aggregation (there is exactly one `ScanContext::build` here; every
    // analyzer below reads from it as a read-only visitor).
    let ctx = ScanContext::build(root).expect("build scan context");

    let (graph, _manifest_skipped) =
        deps::build_graph_with_context(&ctx, root).expect("build dependency graph");
    let detected = frameworks::detect(&graph, root);
    let pack = rules::load_embedded().expect("load embedded pack");

    let audit_options = AuditOptions {
        severity_min: Severity::Info,
    };
    let review_options = ReviewOptions {
        severity_min: Severity::Info,
    };
    let env_options = EnvOptions::default();

    // Fan the independent read-only legs out over the shared `&ScanContext`
    // with rayon — EXACTLY as `getdev-cli::commands::check` does (07-07).
    let ((usages, audit_out), (env_findings, review_out)) = rayon::join(
        || {
            rayon::join(
                || apisurface::collect_usages_with_context(&ctx),
                || {
                    audit::run(&ctx, &pack, &detected, &audit_options)
                        .expect("audit run must succeed")
                },
            )
        },
        || {
            rayon::join(
                || {
                    let env_plan =
                        env::plan_from_context(&ctx, &env_options).expect("env plan must succeed");
                    env::findings(&env_plan, &env_options)
                },
                || review::run_all(&ctx, &review_options).expect("review run must succeed"),
            )
        },
    );
    let (audit_findings, _audit_skipped) = audit_out;
    let (review_findings, _review_skipped) = review_out;

    usages.len() + audit_findings.len() + env_findings.len() + review_findings.len()
}

fn bench_check(c: &mut Criterion) {
    let root = tempdir_path("check-bench");
    generate_synthetic_tree(&root);

    // Prime once so the timed samples measure the established warm state (OS
    // page cache hot, allocator warmed) — the < 3 s "warm" budget row, not the
    // first cold from-scratch aggregation.
    let primed = run_check_aggregation(&root);
    assert!(
        primed > 0,
        "the generated tree seeds rule-triggering snippets across all four \
         analyzers — an empty aggregation would signal a broken generator/leg"
    );

    c.bench_function("check::aggregate warm 500-file/100k-LOC", |b| {
        b.iter(|| {
            let total = run_check_aggregation(black_box(&root));
            black_box(total);
        });
    });

    let _ = std::fs::remove_dir_all(&root);
}

criterion_group!(benches, bench_check);
criterion_main!(benches);
