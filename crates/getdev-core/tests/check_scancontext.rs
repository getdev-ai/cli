//! Context-level parse-once + skip-semantics proof for `core::scan::ScanContext`
//! (07-01, Phase 7 Success Criterion 1: "ONE shared scan pass"). Proves the
//! new parse-once primitive:
//!   * walks once and yields exactly one [`ScannedFile`] per eligible source
//!     file, preserving `project_walker`'s gitignore/prune + `Lang::from_path`
//!     gate + the `MAX_SCAN_FILE_BYTES` size cap unchanged;
//!   * carries a real (non-error) parse per file (`parses_each_file_once`);
//!   * feeds a string-assignment collector that is byte-equivalent to the
//!     legacy walking collector it replaces in `check`;
//!   * folds per-file skips into the SAME [`ScanError`] variants as the walk.
//!
//! The cross-analyzer end-to-end "each file parsed exactly once across the
//! whole `check` run" proof is completed by the no-reparse grep gates in
//! 07-02/07-03 and the wall-clock perf gate in 07-07; this file pins the
//! guarantee at the `ScanContext` level, where it originates.
//!
//! Self-contained (no checked-in fixtures): each test synthesizes a fresh temp
//! dir, mirroring `audit_perf.rs`/`review_perf.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use getdev_core::scan::{
    self, collect_string_assignments, string_assignments_from_context, ScanContext, ScanError,
    StringAssignment, MAX_SCAN_FILE_BYTES,
};

fn tempdir_path(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-scancontext-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scancontext-test tempdir");
    dir
}

fn write(root: &Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

/// The K eligible+readable source files every test seeds — one per supported
/// language, each carrying exactly one `name = "literal"` assignment so the
/// collector-equivalence test has real material to compare.
fn seed_eligible_sources(root: &Path) {
    write(
        root,
        "a.js",
        "const apiKey = \"sk_live_aaa\";\nfunction f() {}\n",
    );
    write(root, "src/b.ts", "const token = \"ghp_bbb\";\nexport {};\n");
    write(
        root,
        "src/c.tsx",
        "const key = \"secret_ccc\";\nexport {};\n",
    );
    write(
        root,
        "d.py",
        "password = \"hunter2_ddd\"\ndef g():\n    pass\n",
    );
}

const ELIGIBLE_COUNT: usize = 4;

/// A single-walk, single-parse ScanContext yields exactly one `ScannedFile`
/// per eligible source file and NOTHING else: a gitignored source file and a
/// non-source `.md` appear in neither `.files` nor `.skipped`, while an
/// oversized eligible file lands in `.skipped` (cap preserved) — the exact
/// walk/prune/cap semantics of the legacy per-analyzer loop (Pitfall 1 / T-07-02).
#[test]
fn one_scanned_file_per_source() {
    let root = tempdir_path("one_per_source");
    seed_eligible_sources(&root);

    // gitignored source (honored even without `git init` — project_walker
    // sets require_git(false)); a non-source doc; and one over-cap eligible file.
    write(&root, ".gitignore", "ignored.js\n");
    write(
        &root,
        "ignored.js",
        "const leaked = \"should_not_be_walked\";\n",
    );
    write(&root, "notes.md", "# not a source file\n");
    let oversized = "x".repeat(usize::try_from(MAX_SCAN_FILE_BYTES).unwrap() + 1);
    write(&root, "huge.js", &format!("// {oversized}\n"));

    let ctx = ScanContext::build(&root).unwrap();

    assert_eq!(
        ctx.files.len(),
        ELIGIBLE_COUNT,
        "exactly one ScannedFile per eligible readable source file"
    );

    // Every `rel` is distinct and project-relative (never absolute).
    let mut rels: Vec<&Path> = ctx.files.iter().map(|f| f.rel.as_path()).collect();
    rels.sort();
    rels.dedup();
    assert_eq!(
        rels.len(),
        ELIGIBLE_COUNT,
        "each ScannedFile has a distinct rel"
    );
    for f in &ctx.files {
        assert!(
            f.rel.is_relative(),
            "rel must be project-relative, got {:?}",
            f.rel
        );
        assert!(f.abs.is_absolute() || f.abs.starts_with(&root));
    }

    // Oversized eligible file is skipped (cap preserved), not parsed.
    assert!(
        ctx.skipped
            .iter()
            .any(|e| matches!(e, ScanError::TooLarge { .. })
                && e.path().is_some_and(|p| p.ends_with("huge.js"))),
        "oversized file must land in .skipped as TooLarge"
    );

    // The gitignored source and the non-source doc appear in NEITHER bucket.
    for excluded in ["ignored.js", "notes.md"] {
        assert!(
            !ctx.files.iter().any(|f| f.rel.ends_with(excluded)),
            "{excluded} must not be in .files"
        );
        assert!(
            !ctx.skipped
                .iter()
                .any(|e| e.path().is_some_and(|p| p.ends_with(excluded))),
            "{excluded} must not be in .skipped"
        );
    }
}

/// Structural parse-once proof at the context level: every `.files` entry
/// carries a real parsed `Tree` whose root is the language's root node
/// ("program" for JS/TS/TSX, "module" for Python), and the number of parsed
/// trees equals the number of eligible sources — no file parsed zero times,
/// none parsed into an error placeholder.
#[test]
fn parses_each_file_once() {
    let root = tempdir_path("parse_once");
    seed_eligible_sources(&root);

    let ctx = ScanContext::build(&root).unwrap();
    assert_eq!(ctx.files.len(), ELIGIBLE_COUNT);

    for f in &ctx.files {
        let kind = f.tree.root_node().kind();
        let expected = match f.lang {
            scan::Lang::Python => "module",
            _ => "program",
        };
        assert_eq!(
            kind, expected,
            "{:?} ({}) must parse to a `{expected}` root, got `{kind}`",
            f.rel, f.lang
        );
        // The seeded files are syntactically valid — no error recovery.
        assert!(
            !f.tree.root_node().has_error(),
            "seeded {:?} parsed with unexpected syntax errors",
            f.rel
        );
    }
}

/// Order-insensitive comparison key for a `StringAssignment` — its `value`
/// stays out of any failure message a derived comparison might print, but is
/// still compared for equality.
fn key(a: &StringAssignment) -> (PathBuf, String, String, u32, u32, (usize, usize)) {
    (
        a.path.clone(),
        a.name.clone(),
        a.value.clone(),
        a.line,
        a.column,
        a.value_span,
    )
}

/// The ScanContext-fed collector is behavior-equivalent to the legacy walking
/// collector it replaces in `check` (env-detect + real model matcher): same
/// assignments, order-insensitive, with NO second walk or second parse.
#[test]
fn string_assignments_from_context_matches_walk() {
    let root = tempdir_path("collector_equiv");
    seed_eligible_sources(&root);

    let ctx = ScanContext::build(&root).unwrap();
    let from_ctx = string_assignments_from_context(&ctx);

    let (from_walk, skipped) = collect_string_assignments(&root).unwrap();
    assert!(skipped.is_empty(), "clean fixture should skip nothing");

    assert_eq!(
        from_ctx.len(),
        ELIGIBLE_COUNT,
        "one seeded assignment per eligible file"
    );

    let mut ctx_keys: Vec<_> = from_ctx.iter().map(key).collect();
    let mut walk_keys: Vec<_> = from_walk.iter().map(key).collect();
    ctx_keys.sort();
    walk_keys.sort();
    assert_eq!(
        ctx_keys, walk_keys,
        "ScanContext-fed collector must match the walking collector exactly"
    );
}

/// A skip preserves the SAME `ScanError` variant (and path) the legacy walking
/// collector would have produced — the cap/skip contract is byte-identical
/// between the two code paths (T-07-01).
#[test]
fn skipped_preserves_scanerror_variants() {
    let root = tempdir_path("skip_variants");
    write(&root, "small.js", "const ok = \"fine\";\n");
    let oversized = "x".repeat(usize::try_from(MAX_SCAN_FILE_BYTES).unwrap() + 1);
    write(&root, "huge.js", &format!("// {oversized}\n"));

    let ctx = ScanContext::build(&root).unwrap();
    let (_walk, walk_skipped) = collect_string_assignments(&root).unwrap();

    // Both paths skip exactly the oversized file, as TooLarge, same path.
    let ctx_skip: Vec<&ScanError> = ctx.skipped.iter().collect();
    assert_eq!(ctx_skip.len(), 1, "only the oversized file is skipped");
    assert_eq!(walk_skipped.len(), 1);

    assert!(matches!(ctx_skip[0], ScanError::TooLarge { .. }));
    assert!(matches!(walk_skipped[0], ScanError::TooLarge { .. }));

    let ctx_path = ctx_skip[0].path().unwrap();
    let walk_path = walk_skipped[0].path().unwrap();
    assert!(ctx_path.ends_with("huge.js"));
    assert_eq!(
        ctx_path, walk_path,
        "both code paths skip the same file with the same variant"
    );
}
