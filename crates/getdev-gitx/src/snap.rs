//! git-hidden working-tree checkpoints under `refs/getdev/`, built entirely
//! from git *plumbing* shelled through the `git` binary (DEC-02 — never
//! git2/gix, never porcelain against `HEAD`/a branch).
//!
//! Everything here is designed around one invariant: the user's real
//! `.git/index`, `HEAD`, branches, and stash are NEVER read or written. Every
//! git call sets an explicit, absolute, throwaway `GIT_INDEX_FILE` and blanks
//! `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` so snapshot behavior depends only on
//! the repo's own `.gitignore` — not a machine-global excludes file, autocrlf
//! setting, or clean/smudge filter (05-RESEARCH § Pitfall 2/4). Snapshot
//! commits are parentless root commits (no `-p`) so a pruned ref's objects
//! become genuinely unreachable (D-10 / § Pitfall 3), and carry a fixed
//! `getdev` identity so `commit-tree` cannot fail with "unable to auto-detect
//! email address" once global config is blanked (§ Pitfall 5).
//!
//! `snapshot()` is the substrate every later primitive reuses: `restore`
//! (05-03) and `list`/`diff`/`prune` (05-04) build a tree the same way
//! (`build_current_tree`) and address refs the same way (`Namespace`).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Where a snapshot ref lives. Ids are allocated from a single shared counter
/// across both namespaces (see [`next_id`]) so a given id is never present in
/// both at once, but each namespace's retention budget is independent (D-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    /// User checkpoints: `refs/getdev/snaps/<N>`.
    Snaps,
    /// Auto-snaps (pre-mutate / pre-restore): `refs/getdev/auto/<N>`.
    Auto,
}

impl Namespace {
    /// The ref-name prefix for this namespace, without a trailing slash.
    pub fn ref_prefix(self) -> &'static str {
        match self {
            Namespace::Snaps => "refs/getdev/snaps",
            Namespace::Auto => "refs/getdev/auto",
        }
    }

    /// The full ref path for snapshot `id` in this namespace.
    pub fn ref_path(self, id: u32) -> String {
        format!("{}/{}", self.ref_prefix(), id)
    }
}

/// Every failure mode of the snap/back plumbing. `thiserror` in libs
/// (CLAUDE.md hard rule 1); no panics cross this boundary.
#[derive(Debug, thiserror::Error)]
pub enum GitxError {
    #[error(
        "git is not installed or not on PATH — install git (>= 2.32) and re-run: \
         https://git-scm.com/downloads"
    )]
    GitAbsent,
    #[error(
        "git {found} is too old — getdev snapshots need git >= 2.32 for \
         GIT_CONFIG_GLOBAL/SYSTEM support; upgrade git"
    )]
    GitTooOld { found: String },
    #[error("no snapshot with id {id}")]
    NoSuchSnapshot { id: u32 },
    #[error("git {op} failed (exit {code:?}): {stderr}")]
    Command {
        op: &'static str,
        code: Option<i32>,
        stderr: String,
    },
    #[error("i/o error invoking git: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },
    /// Placeholder for a primitive not yet implemented in this plan
    /// (`restore`/`list`/`diff`/`prune` land in 05-03/05-04). Returned instead
    /// of `todo!()`/`unimplemented!()`/`panic!` (CLAUDE.md hard rule 1).
    #[error("{op} is not implemented yet")]
    NotImplemented { op: &'static str },
}

/// Result of a [`snapshot`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapOutcome {
    pub id: u32,
    /// `true` when dedupe found the tree unchanged and no new ref was created.
    pub skipped_noop: bool,
    pub namespace: Namespace,
}

/// One row of `snap list` (05-04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapMeta {
    pub id: u32,
    pub age_secs: u64,
    pub message: String,
    pub files_changed: usize,
}

/// Summary of `snap diff <id>` (05-04).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiffSummary {
    pub added: usize,
    pub deleted: usize,
    pub modified: usize,
    /// `(status_char, path)` for each change: `'A'`/`'D'`/`'M'`.
    pub paths: Vec<(char, String)>,
}

/// Result of a `back`/`restore` (05-03).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestoreOutcome {
    pub restored: usize,
    pub removed: usize,
    pub readded: usize,
}

/// Result of `snap prune` (05-04).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PruneOutcome {
    pub deleted_ids: Vec<u32>,
    pub kept: usize,
}

#[cfg(unix)]
fn null_device() -> &'static str {
    "/dev/null"
}

#[cfg(not(unix))]
fn null_device() -> &'static str {
    "NUL"
}

/// An absolute, per-call-unique path under the system temp dir for a throwaway
/// `GIT_INDEX_FILE`. ALWAYS absolute — a relative `GIT_INDEX_FILE` resolves
/// inconsistently across git versions (05-RESEARCH § Pitfall 4). Mirrors the
/// `.{name}.getdev-tmp.{pid}` unique-temp pattern from `core::mutate`.
fn temp_index_path(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        ".getdev-snap-index.{tag}.{}.{nanos}",
        std::process::id()
    ))
}

/// Removes a throwaway index file on drop so the temp dir is never littered.
struct TempIndex {
    path: PathBuf,
}

impl TempIndex {
    fn new(tag: &str) -> Self {
        TempIndex {
            path: temp_index_path(tag),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempIndex {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A `git` invocation rooted at `root` for a CONTENT-touching op (`add`,
/// `write-tree`, `read-tree`, `checkout-index`): global/system config blanked,
/// line-ending/filemode translation disabled, and `GIT_INDEX_FILE` pointed at
/// the given absolute throwaway path. Byte-identity depends on this
/// neutralization (05-RESEARCH § Pitfall 2). Arguments are built via the
/// `.arg()`/`.args()` array API only — never a shell string (T-05-01).
fn git_command(root: &Path, index_file: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(root)
        .env("GIT_CONFIG_GLOBAL", null_device())
        .env("GIT_CONFIG_SYSTEM", null_device())
        .args([
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.safecrlf=false",
            "-c",
            "core.fileMode=false",
        ])
        .env("GIT_INDEX_FILE", index_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// A `git` invocation for a ref-store / metadata op (`for-each-ref`,
/// `update-ref`, `rev-parse`, `commit-tree`, `init`) — same global/system
/// config blanking, but without the content flags. Still sets an absolute
/// throwaway `GIT_INDEX_FILE`: even a read-only call must never fall back to
/// the real index (a stray stat-cache refresh would rewrite `.git/index`).
/// These ops never actually create the index file, so no cleanup is needed.
fn git_command_readonly(root: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(root)
        .env("GIT_CONFIG_GLOBAL", null_device())
        .env("GIT_CONFIG_SYSTEM", null_device())
        .env("GIT_INDEX_FILE", temp_index_path("ro"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Run a built command, returning its stdout on success or a
/// [`GitxError::Command`] carrying the captured stderr on failure.
fn capture(cmd: &mut Command, op: &'static str) -> Result<Vec<u8>, GitxError> {
    let out = cmd.output()?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(GitxError::Command {
            op,
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        })
    }
}

/// `(major, minor)` parsed from `git --version`; `GitAbsent` if git can't run.
fn git_version() -> Result<(u32, u32), GitxError> {
    let out = Command::new("git")
        .arg("--version")
        .output()
        .map_err(|_| GitxError::GitAbsent)?;
    if !out.status.success() {
        return Err(GitxError::GitAbsent);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let parsed = text.split_whitespace().find_map(|tok| {
        let mut parts = tok.split('.');
        let major = parts.next()?.parse::<u32>().ok()?;
        let minor = parts.next()?.parse::<u32>().ok()?;
        Some((major, minor))
    });
    parsed.ok_or_else(|| GitxError::GitTooOld {
        found: text.trim().to_owned(),
    })
}

/// Whether `root` is inside a git repository.
fn is_repo(root: &Path) -> bool {
    git_command_readonly(root)
        .args(["rev-parse", "--git-dir"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Ensure `root` can hold snapshots: git present and >= 2.32, and a repo
/// exists — running `git init --quiet` (leaving HEAD unborn) if none does.
/// The >= 2.32 gate is enforced HERE, at the point of use, not by widening
/// `doctor`'s contract (Open Q3 / CLAUDE.md hard rule 6). Never touches an
/// existing repo's config, HEAD, index, or branches.
fn ensure_repo(root: &Path) -> Result<(), GitxError> {
    let (major, minor) = git_version()?;
    if major < 2 || (major == 2 && minor < 32) {
        return Err(GitxError::GitTooOld {
            found: format!("{major}.{minor}"),
        });
    }
    if !is_repo(root) {
        capture(git_command_readonly(root).args(["init", "--quiet"]), "init")?;
    }
    Ok(())
}

/// The next snapshot id, allocated from a SHARED monotonic counter across both
/// `refs/getdev/snaps/` and `refs/getdev/auto/` — so a given id can never
/// exist in both namespaces (Open Q1/A2). Retention budgets stay independent;
/// only allocation is shared. Ids are never reused after prune (D-01) because
/// the counter only ever moves forward past the highest ref ever seen — but
/// note this reads only live refs, so it is monotonic across a session as long
/// as refs are not resurrected out of band (they are not).
fn next_id(root: &Path) -> Result<u32, GitxError> {
    let mut max_seen: u32 = 0;
    for prefix in [Namespace::Snaps.ref_prefix(), Namespace::Auto.ref_prefix()] {
        let stdout = capture(
            git_command_readonly(root).args(["for-each-ref", "--format=%(refname)", prefix]),
            "for-each-ref",
        )?;
        for line in String::from_utf8_lossy(&stdout).lines() {
            if let Some(n) = line.rsplit('/').next().and_then(|s| s.parse::<u32>().ok()) {
                max_seen = max_seen.max(n);
            }
        }
    }
    Ok(max_seen + 1)
}

/// The highest existing id within a single namespace, or `None` if empty.
fn highest_id(root: &Path, ns: Namespace) -> Result<Option<u32>, GitxError> {
    let stdout = capture(
        git_command_readonly(root).args(["for-each-ref", "--format=%(refname)", ns.ref_prefix()]),
        "for-each-ref",
    )?;
    let max = String::from_utf8_lossy(&stdout)
        .lines()
        .filter_map(|line| line.rsplit('/').next().and_then(|s| s.parse::<u32>().ok()))
        .max();
    Ok(max)
}

/// The tree oid a ref points at (`<ref>^{tree}`), or `None` if the ref is
/// absent. Trailing whitespace trimmed.
fn rev_parse_tree(root: &Path, reference: &str) -> Result<Option<String>, GitxError> {
    let out = git_command_readonly(root)
        .args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{reference}^{{tree}}"),
        ])
        .output()?;
    if !out.status.success() {
        return Ok(None);
    }
    let tree = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if tree.is_empty() {
        Ok(None)
    } else {
        Ok(Some(tree))
    }
}

/// Build a tree oid from the CURRENT working state: fresh throwaway index →
/// `add -A` (honors the repo's own `.gitignore`) → `write-tree`. This is the
/// exact sequence restore/diff reuse — content-addressing makes two identical
/// trees produce identical oids (DEC-01).
fn build_current_tree(root: &Path) -> Result<String, GitxError> {
    let index = TempIndex::new("build");
    capture(git_command(root, index.path()).args(["add", "-A"]), "add")?;
    let out = capture(
        git_command(root, index.path()).args(["write-tree"]),
        "write-tree",
    )?;
    Ok(String::from_utf8_lossy(&out).trim().to_owned())
}

/// Create a PARENTLESS (root) commit of `tree` with a fixed getdev identity.
/// NO `-p` ever — a parent chain keeps pruned objects reachable, defeating
/// D-10 (§ Pattern 2 / Pitfall 3). The fixed identity sidesteps git's
/// "unable to auto-detect email address" once global config is blanked
/// (§ Pitfall 5) and attributes the commit to getdev, not the user.
fn commit_tree(root: &Path, tree: &str, message: &str) -> Result<String, GitxError> {
    let out = capture(
        git_command_readonly(root)
            .env("GIT_AUTHOR_NAME", "getdev")
            .env("GIT_AUTHOR_EMAIL", "noreply@getdev.ai")
            .env("GIT_COMMITTER_NAME", "getdev")
            .env("GIT_COMMITTER_EMAIL", "noreply@getdev.ai")
            .args(["commit-tree", tree, "-m", message]),
        "commit-tree",
    )?;
    Ok(String::from_utf8_lossy(&out).trim().to_owned())
}

/// Enforce a namespace's retention budget: keep the newest `keep` ids, delete
/// the rest oldest-first. Deletes refs ONLY via `update-ref -d` — never
/// `git gc`/`prune`/`repack` (D-10). Operates on one namespace at a time, so
/// each namespace's budget is independent (D-09). This is the same idempotent
/// logic `snap prune` will expose in 05-04.
fn enforce_retention(root: &Path, ns: Namespace, keep: u32) -> Result<(), GitxError> {
    let stdout = capture(
        git_command_readonly(root).args(["for-each-ref", "--format=%(refname)", ns.ref_prefix()]),
        "for-each-ref",
    )?;
    let mut ids: Vec<u32> = String::from_utf8_lossy(&stdout)
        .lines()
        .filter_map(|line| line.rsplit('/').next().and_then(|s| s.parse::<u32>().ok()))
        .collect();
    ids.sort_unstable();
    let keep = keep as usize;
    if ids.len() <= keep {
        return Ok(());
    }
    let doomed = ids.len() - keep;
    for id in ids.into_iter().take(doomed) {
        capture(
            git_command_readonly(root).args(["update-ref", "-d", &ns.ref_path(id)]),
            "update-ref",
        )?;
    }
    Ok(())
}

/// Checkpoint the full working tree (tracked + untracked-non-ignored, excl.
/// gitignored) as a parentless commit under `ns`'s ref namespace.
///
/// - `ensure_repo` (git present + >= 2.32; `git init` an unborn-HEAD repo if
///   none exists).
/// - Build the current tree; if `dedupe` and it equals the newest snapshot's
///   tree in `ns`, return `skipped_noop` WITHOUT creating a ref (D-07).
/// - Otherwise allocate a shared-counter id, write a parentless fixed-identity
///   commit, point `refs/getdev/<ns>/<id>` at it, and enforce `keep` retention.
///
/// The user's real index/HEAD/branches/stash are never touched.
pub fn snapshot(
    root: &Path,
    ns: Namespace,
    message: &str,
    dedupe: bool,
    keep: u32,
) -> Result<SnapOutcome, GitxError> {
    ensure_repo(root)?;
    let tree = build_current_tree(root)?;

    if dedupe {
        if let Some(prev_id) = highest_id(root, ns)? {
            if let Some(prev_tree) = rev_parse_tree(root, &ns.ref_path(prev_id))? {
                if prev_tree == tree {
                    return Ok(SnapOutcome {
                        id: prev_id,
                        skipped_noop: true,
                        namespace: ns,
                    });
                }
            }
        }
    }

    let id = next_id(root)?;
    let commit = commit_tree(root, &tree, message)?;
    capture(
        git_command_readonly(root).args(["update-ref", &ns.ref_path(id), &commit]),
        "update-ref",
    )?;
    enforce_retention(root, ns, keep)?;

    Ok(SnapOutcome {
        id,
        skipped_noop: false,
        namespace: ns,
    })
}

/// Restore the working tree to snapshot `id` (byte-identical over the
/// snapshotted scope). Implemented in 05-03.
pub fn restore(root: &Path, id: u32) -> Result<RestoreOutcome, GitxError> {
    let _ = (root, id);
    Err(GitxError::NotImplemented { op: "restore" })
}

/// The id of the most recent manual snapshot (`refs/getdev/snaps/<N>`), the
/// target of a bare `back`. Implemented in 05-03.
pub fn latest_manual(root: &Path) -> Result<Option<u32>, GitxError> {
    let _ = root;
    Err(GitxError::NotImplemented {
        op: "latest_manual",
    })
}

/// All manual snapshots, newest first, for `snap list`. Implemented in 05-04.
pub fn list(root: &Path) -> Result<Vec<SnapMeta>, GitxError> {
    let _ = root;
    Err(GitxError::NotImplemented { op: "list" })
}

/// Files-changed summary of snapshot `id` vs the current tree, for
/// `snap diff <id>`. Implemented in 05-04.
pub fn diff(root: &Path, id: u32) -> Result<DiffSummary, GitxError> {
    let _ = (root, id);
    Err(GitxError::NotImplemented { op: "diff" })
}

/// Manually enforce `keep` retention on `ns` (the same logic snap runs
/// silently). Implemented in 05-04.
pub fn prune(root: &Path, ns: Namespace, keep: u32) -> Result<PruneOutcome, GitxError> {
    let _ = (root, ns, keep);
    Err(GitxError::NotImplemented { op: "prune" })
}
