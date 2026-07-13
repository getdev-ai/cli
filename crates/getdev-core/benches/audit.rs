//! Criterion benchmark for `core::audit::run` (docs/PLAN.md §3.5,
//! REQ-perf-budgets: `getdev audit`/`review` (no network) < 2 s on a repo
//! ≈ 500 files / 100k LOC). Generates a synthetic JS/TS/Python tree once
//! (outside the timed loop), loads the full embedded v0.1 rule pack, and
//! times `audit::run` over it with criterion — reporting only, never
//! failing. The ENFORCEABLE gate that fails `cargo test --workspace` on a
//! regression lives separately in `../tests/audit_perf.rs`, which
//! deliberately duplicates the same generator (04-07-PLAN.md Task 2 — no
//! shared test-support crate exists in this workspace, and a bench target
//! cannot depend on a `tests/` integration-test file).
//!
//! Deterministic and fully offline: no network call, no dependency on
//! `testdata/corpus/` — the tree is synthesized fresh into a temp dir on
//! every run and removed afterward.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use getdev_core::audit::{self, AuditOptions};
use getdev_core::{deps, frameworks, rules};

/// Files in the generated tree — sized to land at the "repo ≈ 500 files /
/// 100k LOC" budget row (docs/PLAN.md §3.5) at `LINES_PER_FILE` each.
const FILE_COUNT: usize = 500;
/// Lines of body content per generated file (500 × 200 ≈ 100k LOC).
const LINES_PER_FILE: usize = 200;
/// Every 25th file gets one rule-triggering snippet appended, cycling
/// through a handful of AST-matcher shapes — "some rules match and most do
/// not" (04-07-PLAN.md Task 2), never a majority-FP-storm tree.
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
/// `package.json` (express + next, so `frameworks::detect` registers
/// Express and — combined with the seeded `app/api/hello/route.ts` —
/// Next.js's App Router API-route convention) and a `requirements.txt`
/// (fastapi + flask), one `firestore.rules` file for the text-regex
/// `audit/firebase-open-rules` matcher kind, and `FILE_COUNT` generated
/// source files spread across `src/module_<n>/` subdirectories.
fn generate_synthetic_tree(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"audit-perf-corpus","private":true,"dependencies":{"express":"^4.18.0","next":"^14.0.0"}}"#,
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

/// A realistic-density mix: most lines are AST-cheap (blank, a comment, a
/// simple const/property assignment or string literal — the bulk of a
/// typical file), with an actual function/class/conditional/loop/map
/// construct only every 10th line — proportioned to look like a real
/// ≈500-file/100k-LOC JS/TS/Python repo rather than a pathologically
/// AST-dense one (a file that is *every* line a call/conditional/loop is
/// not representative of real code and would overstate `audit::run`'s wall
/// time relative to docs/PLAN.md §3.5's actual budget target).
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

// Each string below is inert fixture text written verbatim into a generated
// `.js`/`.ts` file for `getdev audit`'s AST rules to scan — never executed
// by this benchmark or by any getdev code path (getdev never runs project
// code; CLAUDE.md "Non-negotiable principles"). The `eval(userInput)` entry
// exists solely to exercise `audit/eval-user-input`'s own detection query.
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

fn bench_audit(c: &mut Criterion) {
    let root = tempdir_path("audit-bench");
    generate_synthetic_tree(&root);

    let pack = rules::load_embedded().expect("load embedded pack");
    let (graph, _skipped) = deps::build_graph(&root).expect("build dependency graph");
    let detected = frameworks::detect(&graph, &root);
    let opts = AuditOptions::default();

    c.bench_function("audit::run 500-file/100k-LOC", |b| {
        b.iter(|| {
            // Parse-once: the walk + parse now live in `ScanContext::build`;
            // build it inside the timed loop so the bench keeps reporting the
            // full command cost (walk + parse + analyze) after 07-02.
            let ctx = getdev_core::scan::ScanContext::build(black_box(&root))
                .expect("build scan context");
            let (findings, _skipped) =
                audit::run(&ctx, &pack, &detected, &opts).expect("audit run");
            black_box(findings.len());
        });
    });

    let _ = std::fs::remove_dir_all(&root);
}

criterion_group!(benches, bench_audit);
criterion_main!(benches);
