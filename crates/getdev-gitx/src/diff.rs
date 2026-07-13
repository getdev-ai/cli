//! Diff-extraction substrate for `getdev review` (06-01): resolve a
//! [`DiffScope`] into a `Vec<`[`ChangedFile`]`>`, each carrying its
//! [`ChangeStatus`] and the 1-based-inclusive **added** line ranges parsed from
//! a single `git diff -U0` invocation (plus untracked-file inclusion). This is
//! the foundation every `review/*` rule scopes against — the one genuinely new
//! git primitive of Phase 6 (06-RESEARCH § Summary / § Don't Hand-Roll).
//!
//! Unlike `snap.rs`, whose every call points `GIT_INDEX_FILE` at a throwaway
//! path so the user's real index is never touched, diff extraction must READ
//! (never write) the REAL index: `git diff --staged` has nothing to diff against
//! an empty throwaway index, and the default working-tree-vs-HEAD scope would
//! misreport (06-RESEARCH § Pitfall 1). So this module has its own read-only
//! command constructor [`git_command_diff`] that shares snap's determinism
//! discipline (blanked global/system config) but sets NO `GIT_INDEX_FILE`.
//!
//! Everything here is read-only and network-free: it invokes only `git diff`
//! and `git ls-files`, and writes nothing. A hostile or corrupt repo degrades
//! to a `GitxError` or an empty result — never a panic (CLAUDE.md hard rule 1).

use std::path::Path;
use std::process::{Command, Stdio};

use crate::snap::{capture, null_device, require_repo, GitxError};

/// Which two states to diff. Exactly three variants — there is deliberately NO
/// `All` variant: `review --all` ("whole tree, not just diff") bypasses git
/// entirely and is synthesized by the `core::review` walker as a full
/// `[1, EOF]` range per file (06-RESEARCH § Pattern 3 / § Pitfall 3, LOCKED);
/// it never reaches this primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffScope {
    /// The working tree vs `HEAD` (staged + unstaged changes to tracked files,
    /// plus untracked-non-ignored files as whole-file additions). The default.
    WorkingTreeVsHead,
    /// The index vs `HEAD` (`--staged`). Untracked files are NOT included — an
    /// untracked file is by definition not staged.
    Staged,
    /// The working tree vs an arbitrary ref (`--against <ref>`, e.g. `main`,
    /// `HEAD~3`). 06-RESEARCH § Open Q1 (LOCKED): working tree vs `<ref>`, with
    /// the same untracked-file inclusion as the default scope.
    Against(String),
}

/// How a changed file relates to the base state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeStatus {
    /// The file did not exist in the base (new file / untracked).
    Added,
    /// The file existed and its content changed.
    Modified,
    /// The file existed in the base and is gone now (no added lines).
    Deleted,
}

/// One changed file plus the line ranges it introduced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedFile {
    /// Project-relative path with forward slashes (git emits `/`-separated
    /// repo-relative paths on every platform, and `core.quotePath=false` keeps
    /// non-ASCII names raw rather than C-quoted).
    pub path: String,
    /// Add / modify / delete classification.
    pub status: ChangeStatus,
    /// 1-based **inclusive** added line ranges, in file order. EMPTY for a
    /// [`ChangeStatus::Deleted`] file, and empty for a binary / mode-only change.
    pub added_ranges: Vec<(u32, u32)>,
}

/// Per-file line-count ceiling for the untracked-file whole-file range: mirrors
/// `getdev-core`'s `MAX_SCAN_FILE_BYTES` (5 MiB). `getdev-gitx` cannot depend on
/// `getdev-core`, so the constant is duplicated here. An untracked file over the
/// cap is SKIPPED (not ranged) so a huge file can never be slurped whole into
/// memory (T-06-02, denial-of-service mitigation).
const MAX_UNTRACKED_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// A `git` invocation rooted at `root` for DIFF extraction: global/system config
/// blanked and line-ending translation disabled (determinism, exactly as the
/// rest of `getdev-gitx`), `--no-optional-locks` so git never opportunistically
/// rewrites the stat-cache in `.git/index` on a read, and — critically — NO
/// `GIT_INDEX_FILE` redirection, so `git diff`/`git ls-files` read the user's
/// REAL index (06-RESEARCH § Pitfall 1). Arguments are built via the
/// `.arg()`/`.args([...])` array API only — never a shell string (T-06-01).
///
/// `--no-optional-locks` is a top-level git option (git rejects it as a `diff`
/// subcommand flag), so it is set HERE on the base command, ahead of the
/// subcommand the caller appends.
fn git_command_diff(root: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("--no-optional-locks")
        .arg("-C")
        .arg(root)
        .env("GIT_CONFIG_GLOBAL", null_device())
        .env("GIT_CONFIG_SYSTEM", null_device())
        .args(["-c", "core.quotePath=false", "-c", "core.autocrlf=false"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Deliberately NO `.env("GIT_INDEX_FILE", ...)`: diff must read the real
    // index (this is the one place in the crate that must, and the source
    // assertion that distinguishes it from snap.rs's constructors).
    cmd
}

/// Resolve `scope` into the set of files changed relative to its base, each with
/// its status and its introduced (added) line ranges.
///
/// - Not a git repo → `Ok(vec![])` (a brand-new folder legitimately has no diff;
///   `require_repo` never `git init`s, unlike snap's `ensure_repo`).
/// - ONE whole-diff `git diff -U0 --no-renames` call (never per-file N+1 spawns
///   — 06-RESEARCH § Alternatives); `--no-renames` is mandatory so a rename
///   surfaces as a clean delete+add pair (§ Pitfall 2).
/// - For [`DiffScope::WorkingTreeVsHead`] and [`DiffScope::Against`] (NOT
///   `Staged`), untracked-non-ignored files are appended as whole-file `[1, EOF]`
///   additions via `git ls-files --others --exclude-standard -z`.
pub fn changed_files(root: &Path, scope: &DiffScope) -> Result<Vec<ChangedFile>, GitxError> {
    // Absence of a repo means there is nothing to compare — degrade to empty,
    // never error (06-01 Task 1).
    if !require_repo(root)? {
        return Ok(Vec::new());
    }

    let mut cmd = git_command_diff(root);
    cmd.args(["diff", "--no-color", "-U0", "--no-renames"]);
    match scope {
        DiffScope::WorkingTreeVsHead => {
            cmd.arg("HEAD");
        }
        DiffScope::Staged => {
            // index vs HEAD. Pass the ref via the array API (never a shell
            // string) even though it is a literal here.
            cmd.args(["--staged", "HEAD"]);
        }
        DiffScope::Against(reference) => {
            // Working tree vs <ref>. The ref is user-controlled (`--against`);
            // it crosses into git ONLY via `.arg()`, never a shell string
            // (T-06-01 command-injection mitigation).
            cmd.arg(reference);
        }
    }
    let stdout = capture(&mut cmd, "diff")?;
    let mut files = parse_added_ranges(&stdout);

    // Untracked files are additions but never appear in `git diff`; fold them in
    // for every scope EXCEPT Staged (an untracked file is not staged).
    if !matches!(scope, DiffScope::Staged) {
        append_untracked(root, &mut files)?;
    }

    Ok(files)
}

/// Append untracked-non-ignored files as whole-file `[1, EOF]` additions.
fn append_untracked(root: &Path, files: &mut Vec<ChangedFile>) -> Result<(), GitxError> {
    let stdout = capture(
        git_command_diff(root).args(["ls-files", "--others", "--exclude-standard", "-z"]),
        "ls-files",
    )?;
    for raw in stdout.split(|&b| b == 0) {
        if raw.is_empty() {
            continue;
        }
        let path = String::from_utf8_lossy(raw).into_owned();
        if let Some(range) = untracked_added_range(root, &path) {
            files.push(ChangedFile {
                path,
                status: ChangeStatus::Added,
                added_ranges: vec![range],
            });
        }
    }
    Ok(())
}

/// The whole-file added range `[1, EOF]` for untracked file `rel` under `root`,
/// or `None` if it should be skipped (not a regular file, over the size cap, or
/// unreadable). An EMPTY file yields `(1, 1)`.
fn untracked_added_range(root: &Path, rel: &str) -> Option<(u32, u32)> {
    // Path-traversal guard (T-06-04): git never emits a `..`-escaping tracked
    // path, but never trust a diff-reported path as safe to read regardless.
    if Path::new(rel)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return None;
    }
    let full = root.join(rel);
    let meta = std::fs::metadata(&full).ok()?;
    if !meta.is_file() {
        return None;
    }
    if meta.len() > MAX_UNTRACKED_FILE_BYTES {
        return None; // over the cap → skipped, never slurped whole (T-06-02)
    }
    let bytes = std::fs::read(&full).ok()?;
    Some((1, line_count(&bytes)))
}

/// The last line number of a file's byte content, 1-based. An empty file is
/// `1` (so an empty untracked file ranges as `(1, 1)`). A trailing newline does
/// NOT add a phantom empty final line.
fn line_count(bytes: &[u8]) -> u32 {
    if bytes.is_empty() {
        return 1;
    }
    let newlines = bytes.iter().filter(|&&b| b == b'\n').count();
    let lines = if bytes.last() == Some(&b'\n') {
        newlines
    } else {
        newlines + 1
    };
    u32::try_from(lines.max(1)).unwrap_or(u32::MAX)
}

/// A file boundary under construction while walking the unified diff.
struct CurFile {
    path: String,
    status: ChangeStatus,
    added_ranges: Vec<(u32, u32)>,
}

impl CurFile {
    fn finish(mut self) -> ChangedFile {
        // A deleted file has no introduced content, regardless of any stray
        // hunk math — enforce the invariant defensively.
        if matches!(self.status, ChangeStatus::Deleted) {
            self.added_ranges.clear();
        }
        ChangedFile {
            path: self.path,
            status: self.status,
            added_ranges: self.added_ranges,
        }
    }
}

/// Parse the stdout of `git diff --no-color -U0 --no-renames <base>` into one
/// [`ChangedFile`] per `diff --git` boundary, each with its added ranges.
///
/// Defensive by construction (06-RESEARCH § Anti-Pattern "parsing unified diff
/// as a generic string blob", § Pitfall 2): a header that fails to parse is
/// skipped, binary / mode-only entries yield empty `added_ranges`, and the
/// `\ No newline at end of file` / `Binary files … differ` / index lines are
/// ignored. Never indexes past the end of a malformed header — never panics.
fn parse_added_ranges(diff_stdout: &[u8]) -> Vec<ChangedFile> {
    let text = String::from_utf8_lossy(diff_stdout);
    let mut files: Vec<ChangedFile> = Vec::new();
    let mut cur: Option<CurFile> = None;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            if let Some(prev) = cur.take() {
                files.push(prev.finish());
            }
            cur = Some(CurFile {
                path: diff_git_dest_path(rest),
                status: ChangeStatus::Modified, // refined by the markers below
                added_ranges: Vec::new(),
            });
            continue;
        }

        let Some(f) = cur.as_mut() else {
            // Preamble before the first `diff --git` (or malformed input) — skip.
            continue;
        };

        if line.starts_with("new file mode ") || line == "--- /dev/null" {
            // `--- /dev/null` = the OLD side is absent → the file is new.
            f.status = ChangeStatus::Added;
        } else if line.starts_with("deleted file mode ") || line == "+++ /dev/null" {
            // `+++ /dev/null` = the NEW side is absent → the file is deleted.
            f.status = ChangeStatus::Deleted;
        } else if line.starts_with("@@") {
            if let Some(range) = hunk_added_range(line) {
                f.added_ranges.push(range);
            }
        }
        // Everything else (`index …`, `--- a/…`, `+++ b/…`, `Binary files …`,
        // `old mode`/`new mode`, `\ No newline …`, `+`/`-` body lines) is ignored.
    }

    if let Some(prev) = cur.take() {
        files.push(prev.finish());
    }
    files
}

/// The destination (`b/…`) path from a `diff --git a/X b/Y` line's tail
/// (`"a/X b/Y"`). With `--no-renames`, `X == Y`, so the effective path is `Y`.
/// Splitting on the LAST `" b/"` tolerates a path that itself contains spaces.
fn diff_git_dest_path(rest: &str) -> String {
    if let Some(idx) = rest.rfind(" b/") {
        return rest[idx + 3..].to_owned();
    }
    // Defensive fallback for an unexpected shape: strip a leading `a/` if any.
    rest.strip_prefix("a/").unwrap_or(rest).to_owned()
}

/// The added range `[c, c + d - 1]` from a `@@ -a,b +c,d @@ …` hunk header, or
/// `None` when the header carries no added lines (`d == 0`, a pure-deletion
/// hunk) or fails to parse (malformed / truncated — skipped, never a panic).
/// A `+c` form without `,d` (a single added line) is treated as `d == 1`.
fn hunk_added_range(line: &str) -> Option<(u32, u32)> {
    let after = line.strip_prefix("@@")?;
    // Tokens are like ["-a,b", "+c,d", "@@", "<section heading>"…]; take the
    // `+`-prefixed one. `find` never indexes past the end of a short header.
    let plus = after.split_whitespace().find(|t| t.starts_with('+'))?;
    let body = plus.get(1..)?; // strip the leading '+'
    let mut parts = body.split(',');
    let start: u32 = parts.next()?.parse().ok()?;
    let count: u32 = match parts.next() {
        Some(c) => c.parse().ok()?,
        None => 1, // "+c" without ",d" → single added line
    };
    if count == 0 {
        return None; // pure-deletion hunk — no added lines
    }
    Some((start, start + count - 1))
}
