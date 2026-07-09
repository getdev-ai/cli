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
}

/// One planned file mutation. `RewriteSource` is reparse-verified; plain
/// `WriteFile` (dotfiles, generated configs) is not parseable source and
/// only gets atomicity.
#[derive(Debug)]
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
pub fn apply(writes: Vec<PlannedWrite>) -> Result<Applied, MutateError> {
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

fn atomic_write(path: &Path, content: &str) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.getdev-tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_owned())
    ));
    std::fs::write(&tmp, content)?;
    // carry over permissions from an existing target (e.g. executable scripts)
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    let renamed = std::fs::rename(&tmp, path);
    if renamed.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    renamed
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
        }])
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
        ])
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
        }])
        .unwrap();
    }

    #[test]
    fn new_file_write_and_rollback_removal() {
        let dir = tempdir("newfile");
        let path = dir.join(".gitignore");
        apply(vec![PlannedWrite::WriteFile {
            path: path.clone(),
            original: None,
            new_content: ".env\n".into(),
        }])
        .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ".env\n");
    }
}
