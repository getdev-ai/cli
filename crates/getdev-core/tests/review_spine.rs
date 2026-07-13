//! Spine tests for `core::review::run` — the parse-once walk, the `All` vs
//! `Diff` scopes, and the added-line-range OVERLAP post-filter that scopes
//! declarative rules to introduced content.
//!
//! These drive `run` against a real temp directory (hence they live in an
//! integration test, not inline in `src/review/mod.rs`, which the phase's
//! "review never mutates" grep gate keeps free of any `fs::write` token).
//! The declarative-rule fixture gate is separate: `tests/review_fixtures.rs`.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use getdev_core::review::{
    self, ReviewChangeStatus, ReviewChangedFile, ReviewOptions, ReviewScope,
};

fn unique_tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-review-spine-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn all_scope_fires_debug_leftover_on_the_whole_file() {
    let dir = unique_tempdir("all_scope");
    std::fs::write(
        dir.join("app.js"),
        "function f() {\n  console.log('x');\n}\n",
    )
    .unwrap();

    let (findings, skipped) =
        review::run(&dir, &ReviewScope::All, &ReviewOptions::default()).unwrap();
    assert!(skipped.is_empty());
    let debug: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "review/debug-leftover")
        .collect();
    assert_eq!(
        debug.len(),
        1,
        "console.log must fire under --all: {findings:?}"
    );
    assert_eq!(debug[0].command, "review");
    assert_eq!(debug[0].file, "app.js");
    assert_eq!(debug[0].line, Some(2));
}

#[test]
fn diff_scope_overlap_scopes_debug_leftover_to_introduced_lines() {
    // Two console.log calls; only line 2 is in the added range. The overlap
    // filter must fire on line 2 and stay silent on the pre-existing line 4.
    let dir = unique_tempdir("diff_scope");
    let src = "function f() {\n  console.log('new');\n}\nconsole.log('old');\n";
    std::fs::write(dir.join("app.js"), src).unwrap();

    let scope = ReviewScope::Diff(vec![ReviewChangedFile {
        path: "app.js".to_owned(),
        status: ReviewChangeStatus::Modified,
        added_ranges: vec![(2, 2)],
    }]);

    let (findings, skipped) = review::run(&dir, &scope, &ReviewOptions::default()).unwrap();
    assert!(skipped.is_empty());
    let debug: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "review/debug-leftover")
        .collect();
    assert_eq!(
        debug.len(),
        1,
        "only the introduced console.log fires: {findings:?}"
    );
    assert_eq!(debug[0].line, Some(2));
}

#[test]
fn diff_scope_todo_fires_only_on_introduced_comment() {
    let dir = unique_tempdir("diff_todo");
    // TODO on line 1 (introduced), FIXME on line 3 (pre-existing).
    let src = "// TODO: wire this up\nconst a = 1;\n// FIXME: old marker\nconst b = 2;\n";
    std::fs::write(dir.join("m.js"), src).unwrap();

    let scope = ReviewScope::Diff(vec![ReviewChangedFile {
        path: "m.js".to_owned(),
        status: ReviewChangeStatus::Modified,
        added_ranges: vec![(1, 1)],
    }]);

    let (findings, _skipped) = review::run(&dir, &scope, &ReviewOptions::default()).unwrap();
    let todo: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "review/todo-introduced")
        .collect();
    assert_eq!(
        todo.len(),
        1,
        "only the introduced TODO fires: {findings:?}"
    );
    assert_eq!(todo[0].line, Some(1));
}

#[test]
fn deleted_file_is_never_read() {
    // A deleted file with a bogus path must be skipped before any read —
    // never an error or panic.
    let dir = unique_tempdir("deleted");
    let scope = ReviewScope::Diff(vec![ReviewChangedFile {
        path: "gone.js".to_owned(),
        status: ReviewChangeStatus::Deleted,
        added_ranges: vec![],
    }]);
    let (findings, skipped) = review::run(&dir, &scope, &ReviewOptions::default()).unwrap();
    assert!(findings.is_empty());
    assert!(skipped.is_empty());
}

#[test]
fn parent_dir_escaping_path_is_refused() {
    // A `..`-escaping diff path must be skipped, never resolved outside root.
    let dir = unique_tempdir("traversal");
    let scope = ReviewScope::Diff(vec![ReviewChangedFile {
        path: "../evil.js".to_owned(),
        status: ReviewChangeStatus::Added,
        added_ranges: vec![(1, 1)],
    }]);
    let (findings, skipped) = review::run(&dir, &scope, &ReviewOptions::default()).unwrap();
    assert!(findings.is_empty());
    assert!(skipped.is_empty());
}
