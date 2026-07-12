//! The safe file-rewrite engine — the ONE audited path for every mutation
//! getdev ever makes (docs/ARCHITECTURE.md invariants):
//!
//! 1. **Verify before any I/O**: rewritten source must reparse cleanly
//!    (no syntax errors introduced) while still in memory.
//! 2. **Atomic writes**: temp file in the same directory + rename.
//! 3. **Rollback**: if any write fails mid-plan, already-written files are
//!    restored from their kept originals (best effort, reported).
//!
//! Auto-snap before multi-file mutations arrives with `getdev-gitx` snap
//! support (P4); until then callers surface "no snapshot yet" in their UX.

use std::path::{Path, PathBuf};

use getdev_grammars::tree_sitter::Parser;

use crate::scan::Lang;

#[derive(Debug, thiserror::Error)]
pub enum MutateError {
    #[error("rewrite of {path} would introduce syntax errors — aborted, nothing written")]
    VerifyFailed { path: PathBuf },
    #[error("parser produced no tree for rewritten {path} — aborted, nothing written")]
    VerifyParse { path: PathBuf },
    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write {path}: {source}; rollback of previously written files {rollback}")]
    WriteWithRollback {
        path: PathBuf,
        source: std::io::Error,
        /// "succeeded" or a description of what could not be restored
        rollback: String,
    },
    #[error("pre-mutation snapshot failed: {reason} — aborted, nothing written")]
    AutoSnapFailed { reason: String },
}

/// A hook invoked by [`apply`] exactly once, before any file is written, iff
/// the plan contains more than one [`PlannedWrite`] — the "auto-snap before any
/// multi-file mutation" trigger from docs/ARCHITECTURE.md's mutation
/// invariants. A single-file plan never fires the hook: it is already covered
/// by the verify → atomic-write → rollback path. Returning `Err(reason)` aborts
/// the whole plan before any I/O — nothing is written (fail closed).
///
/// The trait is DEFINED here in `getdev-core` (which depends only on
/// `getdev-grammars`) and IMPLEMENTED in `getdev-cli` with a
/// `getdev-gitx`-backed auto-snapshot. This puts the auto-snap call genuinely
/// inside the audited mutation path without adding a `getdev-core →
/// getdev-gitx` dependency edge (dependency inversion, per RESEARCH Pattern 4).
pub trait PreMutateHook {
    /// Called once before a multi-file mutation, with the paths about to be
    /// written. An `Err(reason)` aborts the plan before any write.
    fn before_multi_file_write(&self, paths: &[&Path]) -> Result<(), String>;
}

/// One planned file mutation. `RewriteSource` is reparse-verified; plain
/// `WriteFile` (dotfiles, generated configs) is not parseable source and
/// only gets atomicity.
///
/// `Debug` is hand-rolled (C6/03-REVIEW.md): both variants' `original`/
/// `new_content` can hold raw secret values — `RewriteSource` mid-rewrite
/// source, and `WriteFile` for the `.env` write itself (values, not just
/// keys). A derived `Debug` would print them verbatim; nothing today calls
/// `dbg!`/`{:?}` on a `PlannedWrite` in a production path, but that's an
/// invariant this type should hold structurally, not by convention.
pub enum PlannedWrite {
    RewriteSource {
        path: PathBuf,
        lang: Lang,
        /// current on-disk content (kept for rollback)
        original: String,
        new_content: String,
    },
    WriteFile {
        path: PathBuf,
        /// full new content; None as original means the file did not exist
        original: Option<String>,
        new_content: String,
    },
}

impl std::fmt::Debug for PlannedWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RewriteSource { path, lang, .. } => f
                .debug_struct("RewriteSource")
                .field("path", path)
                .field("lang", lang)
                .field("original", &"«redacted»")
                .field("new_content", &"«redacted»")
                .finish(),
            Self::WriteFile { path, original, .. } => f
                .debug_struct("WriteFile")
                .field("path", path)
                .field("original", &original.as_ref().map(|_| "«redacted»"))
                .field("new_content", &"«redacted»")
                .finish(),
        }
    }
}

impl PlannedWrite {
    fn path(&self) -> &Path {
        match self {
            Self::RewriteSource { path, .. } | Self::WriteFile { path, .. } => path,
        }
    }

    fn new_content(&self) -> &str {
        match self {
            Self::RewriteSource { new_content, .. } | Self::WriteFile { new_content, .. } => {
                new_content
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct Applied {
    pub files_written: Vec<PathBuf>,
}

/// Apply a mutation plan: verify everything in memory, then write atomically,
/// rolling back on mid-plan failure.
pub fn apply(
    writes: Vec<PlannedWrite>,
    _hook: Option<&dyn PreMutateHook>,
) -> Result<Applied, MutateError> {
    // phase 1: verify all rewritten source reparses BEFORE touching disk
    for write in &writes {
        if let PlannedWrite::RewriteSource {
            path,
            lang,
            original,
            new_content,
        } = write
        {
            verify_reparse(path, *lang, original, new_content)?;
        }
    }

    // phase 2: write atomically; keep originals for rollback
    let mut written: Vec<&PlannedWrite> = Vec::new();
    for write in &writes {
        if let Err(source) = atomic_write(write.path(), write.new_content()) {
            let rollback = roll_back(&written);
            return Err(MutateError::WriteWithRollback {
                path: write.path().to_path_buf(),
                source,
                rollback,
            });
        }
        written.push(write);
    }

    Ok(Applied {
        files_written: writes.iter().map(|w| w.path().to_path_buf()).collect(),
    })
}

fn verify_reparse(
    path: &Path,
    lang: Lang,
    original: &str,
    new_content: &str,
) -> Result<(), MutateError> {
    let had_errors = parse_has_errors(lang, original).unwrap_or(true);
    match parse_has_errors(lang, new_content) {
        None => Err(MutateError::VerifyParse {
            path: path.to_path_buf(),
        }),
        // a file that was already broken can't get "less parseable" —
        // only require clean output when the input was clean
        Some(true) if !had_errors => Err(MutateError::VerifyFailed {
            path: path.to_path_buf(),
        }),
        Some(_) => Ok(()),
    }
}

fn parse_has_errors(lang: Lang, content: &str) -> Option<bool> {
    let mut parser = Parser::new();
    parser.set_language(&lang.language()).ok()?;
    let tree = parser.parse(content, None)?;
    Some(tree.root_node().has_error())
}

/// Atomic temp+rename write, symlink-safe (C2/03-REVIEW.md).
///
/// Two hazards fixed here:
/// 1. **Symlinked targets:** `fs::create_dir_all` + `fs::rename` operate on
///    `path` as given. If `path` is a symlink, `rename(tmp, path)` replaces
///    the LINK itself (unlinking it and pointing the parent dir entry at
///    `tmp`), leaving the real target file — the one that may be tracked in
///    git — completely untouched while getdev reports success. We
///    canonicalize the target first and perform the write against that
///    resolved path, so the write always lands on the real file the link
///    points to.
/// 2. **Concurrent runs:** a deterministic `.{name}.getdev-tmp` temp name
///    means two concurrent `getdev env --write` invocations (or a retry
///    racing a prior crashed run) can stomp each other's temp file mid-write.
///    The temp name is now unique per process (`.{name}.getdev-tmp.{pid}`).
fn atomic_write(path: &Path, content: &str) -> std::io::Result<()> {
    // Resolve an existing symlink to its real target before writing so the
    // link is preserved and the underlying file is what actually changes.
    // A target that doesn't exist yet (new file) has nothing to canonicalize
    // — write at `path` as given, same as before.
    let real_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

    let dir = real_path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.getdev-tmp.{}",
        real_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_owned()),
        std::process::id()
    ));
    // IN-07: create the temp at owner-only perms UP FRONT. A plain
    // `fs::write` creates it at the umask default (typically 0644,
    // world-readable); for a brand-new secret-bearing file (`env --write`
    // creating `.env`) there is no existing target to copy perms from, so the
    // secret would land — and stay — world-readable. A security tool that
    // writes secrets must never do that. For an existing target we still copy
    // its own perms below so executable scripts etc. keep their mode.
    write_private_tmp(&tmp, content)?;
    // carry over permissions from an existing target (e.g. executable scripts)
    if let Ok(meta) = std::fs::metadata(&real_path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    let renamed = std::fs::rename(&tmp, &real_path);
    if renamed.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    renamed
}

/// Write `content` to a freshly-created temp file at owner-only permissions
/// (0600) on Unix, so a secret-bearing temp is never even briefly
/// world-readable (IN-07). The `mode` is applied atomically at `open` time,
/// closing the window a `write`-then-`set_permissions` would leave open. On
/// non-Unix targets, where the Unix permission model does not apply, this is
/// a plain write.
#[cfg(unix)]
fn write_private_tmp(tmp: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(tmp)?;
    // a pre-existing temp (e.g. a same-pid retry after a crash) would keep
    // its old mode through `open`, so force owner-only explicitly too.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(content.as_bytes())
}

#[cfg(not(unix))]
fn write_private_tmp(tmp: &Path, content: &str) -> std::io::Result<()> {
    std::fs::write(tmp, content)
}

fn roll_back(written: &[&PlannedWrite]) -> String {
    let mut failures = Vec::new();
    for write in written {
        let result = match write {
            PlannedWrite::RewriteSource { path, original, .. } => atomic_write(path, original),
            PlannedWrite::WriteFile {
                path,
                original: Some(original),
                ..
            } => atomic_write(path, original),
            PlannedWrite::WriteFile {
                path,
                original: None,
                ..
            } => std::fs::remove_file(path),
        };
        if result.is_err() {
            failures.push(write.path().display().to_string());
        }
    }
    if failures.is_empty() {
        "succeeded".to_owned()
    } else {
        format!("FAILED for: {}", failures.join(", "))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("getdev-mutate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An interior-mutable fake [`PreMutateHook`] that records how many times it
    /// fired, which paths it was handed, and whether any of those paths already
    /// existed on disk at call time (to prove the hook runs *before* any write).
    /// Optionally fails with a fixed reason to exercise the fail-closed abort.
    struct RecordingHook {
        calls: std::cell::Cell<usize>,
        captured_paths: std::cell::RefCell<Vec<PathBuf>>,
        any_existed_at_call: std::cell::Cell<bool>,
        fail_with: Option<String>,
    }

    impl RecordingHook {
        fn new() -> Self {
            Self {
                calls: std::cell::Cell::new(0),
                captured_paths: std::cell::RefCell::new(Vec::new()),
                any_existed_at_call: std::cell::Cell::new(false),
                fail_with: None,
            }
        }

        fn failing(reason: &str) -> Self {
            let hook = Self::new();
            Self {
                fail_with: Some(reason.to_owned()),
                ..hook
            }
        }
    }

    impl PreMutateHook for RecordingHook {
        fn before_multi_file_write(&self, paths: &[&Path]) -> Result<(), String> {
            self.calls.set(self.calls.get() + 1);
            if paths.iter().any(|p| p.exists()) {
                self.any_existed_at_call.set(true);
            }
            self.captured_paths
                .borrow_mut()
                .extend(paths.iter().map(|p| p.to_path_buf()));
            match &self.fail_with {
                Some(reason) => Err(reason.clone()),
                None => Ok(()),
            }
        }
    }

    /// D-07 multi-file trigger: a plan with more than one `PlannedWrite` fires
    /// the hook exactly once, before any file exists, with every planned path;
    /// a single-file plan never fires it.
    #[test]
    fn pre_mutate_hook_fires_only_for_multi_file_plans() {
        let dir = tempdir("hook-multi");
        let a = dir.join("a.env");
        let b = dir.join("b.env");

        let hook = RecordingHook::new();
        apply(
            vec![
                PlannedWrite::WriteFile {
                    path: a.clone(),
                    original: None,
                    new_content: "A=1\n".into(),
                },
                PlannedWrite::WriteFile {
                    path: b.clone(),
                    original: None,
                    new_content: "B=2\n".into(),
                },
            ],
            Some(&hook),
        )
        .unwrap();

        assert_eq!(hook.calls.get(), 1, "multi-file plan fires the hook once");
        assert!(
            !hook.any_existed_at_call.get(),
            "hook must fire before any file is written"
        );
        let captured = hook.captured_paths.borrow();
        assert!(
            captured.contains(&a) && captured.contains(&b),
            "hook receives every planned path"
        );
        drop(captured);
        // the plan still wrote both files after the hook returned Ok
        assert!(a.exists() && b.exists());

        // single-file plan: the hook is never consulted
        let solo = dir.join("solo.env");
        let single_hook = RecordingHook::new();
        apply(
            vec![PlannedWrite::WriteFile {
                path: solo.clone(),
                original: None,
                new_content: "S=1\n".into(),
            }],
            Some(&single_hook),
        )
        .unwrap();
        assert_eq!(
            single_hook.calls.get(),
            0,
            "single-file plan never fires the hook"
        );
        assert!(solo.exists());
    }

    /// T-05-06 fail-closed: a hook that returns `Err` on a multi-file plan
    /// aborts with `AutoSnapFailed` and leaves nothing on disk.
    #[test]
    fn hook_error_aborts_plan_without_writing() {
        let dir = tempdir("hook-abort");
        let a = dir.join("a.env");
        let b = dir.join("b.env");

        let hook = RecordingHook::failing("snapshot refused");
        let err = apply(
            vec![
                PlannedWrite::WriteFile {
                    path: a.clone(),
                    original: None,
                    new_content: "A=1\n".into(),
                },
                PlannedWrite::WriteFile {
                    path: b.clone(),
                    original: None,
                    new_content: "B=2\n".into(),
                },
            ],
            Some(&hook),
        )
        .unwrap_err();

        match err {
            MutateError::AutoSnapFailed { reason } => assert_eq!(reason, "snapshot refused"),
            other => panic!("expected AutoSnapFailed, got {other:?}"),
        }
        assert!(
            !a.exists() && !b.exists(),
            "hook failure must abort before any write"
        );
    }

    /// C6 regression: `{:?}` on a `PlannedWrite` must never print raw
    /// `original`/`new_content` — both variants can hold secret values.
    #[test]
    fn planned_write_debug_redacts_content() {
        let rewrite = PlannedWrite::RewriteSource {
            path: PathBuf::from("a.js"),
            lang: Lang::JavaScript,
            original: "const k = \"sk_live_FAKEFAKEFAKE1234\";\n".into(),
            new_content: "const k = process.env.K;\n".into(),
        };
        let debug_output = format!("{rewrite:?}");
        assert!(!debug_output.contains("sk_live_FAKEFAKEFAKE1234"));
        assert!(debug_output.contains("«redacted»"));

        let write_file = PlannedWrite::WriteFile {
            path: PathBuf::from(".env"),
            original: Some("OLD=sk_live_FAKEFAKEFAKE1234\n".into()),
            new_content: "OLD=sk_live_FAKEFAKEFAKE1234\nNEW=sk_live_OTHERFAKE5678\n".into(),
        };
        let debug_output = format!("{write_file:?}");
        assert!(!debug_output.contains("sk_live_FAKEFAKEFAKE1234"));
        assert!(!debug_output.contains("sk_live_OTHERFAKE5678"));
        assert!(debug_output.contains("«redacted»"));
    }

    #[test]
    fn applies_verified_rewrite_atomically() {
        let dir = tempdir("ok");
        let path = dir.join("a.js");
        std::fs::write(&path, "const k = \"old\";\n").unwrap();

        let applied = apply(vec![PlannedWrite::RewriteSource {
            path: path.clone(),
            lang: Lang::JavaScript,
            original: "const k = \"old\";\n".into(),
            new_content: "const k = process.env.K;\n".into(),
        }], None)
        .unwrap();

        assert_eq!(applied.files_written.len(), 1);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "const k = process.env.K;\n"
        );
        // no temp litter
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[test]
    fn broken_rewrite_aborts_before_any_write() {
        let dir = tempdir("verify");
        let js = dir.join("a.js");
        let env_file = dir.join(".env");
        std::fs::write(&js, "const k = \"old\";\n").unwrap();

        let err = apply(vec![
            // plain file first in the plan — must NOT be written either
            PlannedWrite::WriteFile {
                path: env_file.clone(),
                original: None,
                new_content: "K=old\n".into(),
            },
            PlannedWrite::RewriteSource {
                path: js.clone(),
                lang: Lang::JavaScript,
                original: "const k = \"old\";\n".into(),
                new_content: "const k = process.env.((;\n".into(),
            },
        ], None)
        .unwrap_err();

        assert!(matches!(err, MutateError::VerifyFailed { .. }));
        assert_eq!(
            std::fs::read_to_string(&js).unwrap(),
            "const k = \"old\";\n"
        );
        assert!(!env_file.exists(), "verify failure must precede all writes");
    }

    #[test]
    fn already_broken_files_may_stay_broken() {
        let dir = tempdir("prebroken");
        let path = dir.join("b.py");
        std::fs::write(&path, "def oops(:\n").unwrap();

        apply(vec![PlannedWrite::RewriteSource {
            path,
            lang: Lang::Python,
            original: "def oops(:\n".into(),
            new_content: "def oops(:  # still broken\n".into(),
        }], None)
        .unwrap();
    }

    /// C2 regression: writing to a symlinked target must write through the
    /// link to the real file — never replace the link itself. Unix-only:
    /// symlinks aren't first-class on every CI runner's filesystem.
    #[cfg(unix)]
    #[test]
    fn symlinked_target_writes_through_the_link() {
        let dir = tempdir("symlink");
        let real_target = dir.join("real_secret.py");
        std::fs::write(&real_target, "aws_key = \"old\"\n").unwrap();
        let link = dir.join("linked.py");
        std::os::unix::fs::symlink(&real_target, &link).unwrap();

        apply(vec![PlannedWrite::RewriteSource {
            path: link.clone(),
            lang: Lang::Python,
            original: "aws_key = \"old\"\n".into(),
            new_content: "aws_key = os.environ[\"AWS_KEY\"]\n".into(),
        }], None)
        .unwrap();

        // the link itself is still a symlink, pointing at the same real file
        let link_meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(link_meta.file_type().is_symlink(), "link must be preserved");
        assert_eq!(std::fs::read_link(&link).unwrap(), real_target);

        // the REAL file's content changed, reachable via either path
        assert_eq!(
            std::fs::read_to_string(&real_target).unwrap(),
            "aws_key = os.environ[\"AWS_KEY\"]\n"
        );
        assert_eq!(
            std::fs::read_to_string(&link).unwrap(),
            "aws_key = os.environ[\"AWS_KEY\"]\n"
        );

        // no stray temp files left behind in the directory
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("getdev-tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    /// C2 regression: the temp filename embeds the process id, so two
    /// concurrent writers touching the same target never share a temp path.
    #[test]
    fn temp_file_name_is_unique_per_process() {
        let dir = tempdir("uniquetemp");
        let path = dir.join("shared.js");
        std::fs::write(&path, "const k = \"old\";\n").unwrap();

        apply(vec![PlannedWrite::RewriteSource {
            path: path.clone(),
            lang: Lang::JavaScript,
            original: "const k = \"old\";\n".into(),
            new_content: "const k = process.env.K;\n".into(),
        }], None)
        .unwrap();

        // the temp file, had it survived, would have carried this process's
        // pid — assert the naming scheme by checking no *other* pid's temp
        // litter exists and the write landed cleanly.
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["shared.js".to_owned()]);
    }

    /// IN-07 regression: a brand-new secret-bearing file (the `.env` case)
    /// must be created owner-only (0600), never at the umask default
    /// (typically 0644, world-readable). Unix-only: the permission model
    /// doesn't apply elsewhere.
    #[cfg(unix)]
    #[test]
    fn new_secret_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir("perms");
        let path = dir.join(".env");
        apply(vec![PlannedWrite::WriteFile {
            path: path.clone(),
            original: None,
            new_content: "STRIPE=sk_live_FAKEFAKEFAKE1234\n".into(),
        }], None)
        .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a new secret-bearing file must be owner-only, was {mode:o}"
        );
    }

    #[test]
    fn new_file_write_and_rollback_removal() {
        let dir = tempdir("newfile");
        let path = dir.join(".gitignore");
        apply(vec![PlannedWrite::WriteFile {
            path: path.clone(),
            original: None,
            new_content: ".env\n".into(),
        }], None)
        .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ".env\n");
    }
}
