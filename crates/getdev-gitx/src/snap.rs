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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Process-wide monotonic sequence making every [`temp_index_path`] unique even
/// when two calls land in the same OS clock tick — the timestamp alone is NOT
/// enough (macOS `SystemTime` resolution is coarse), and two concurrent
/// `snapshot()` calls that computed the same path would collide on git's
/// `<index>.lock` (`fatal: Unable to create '…index…lock': File exists`).
static INDEX_SEQ: AtomicU64 = AtomicU64::new(0);

/// Where a snapshot ref lives. Ids are allocated from a single shared counter
/// across both namespaces (see `next_id`) so a given id is never present in
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
    #[error("materialize destination must be an absolute path, got: {dest}")]
    RelativeDest { dest: String },
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
pub(crate) fn null_device() -> &'static str {
    "/dev/null"
}

#[cfg(not(unix))]
pub(crate) fn null_device() -> &'static str {
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
    // pid disambiguates across processes; the atomic seq disambiguates across
    // concurrent calls WITHIN this process (the timestamp can repeat under a
    // coarse clock); nanos stays for human readability / cross-run spread.
    let seq = INDEX_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        ".getdev-snap-index.{tag}.{}.{nanos}.{seq}",
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
pub(crate) fn capture(cmd: &mut Command, op: &'static str) -> Result<Vec<u8>, GitxError> {
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

/// Ensure `root` is usable for READ-ONLY diff extraction: git present and at
/// least version 2.32 (the same GIT_CONFIG_GLOBAL/SYSTEM floor `ensure_repo`
/// enforces). Unlike [`ensure_repo`], this NEVER runs `git init` — a non-repo
/// has no HEAD to diff against, so `diff::changed_files` treats "not a repo" as
/// "nothing to diff" rather than materializing one. Returns `Ok(true)` when
/// `root` is inside a repository, `Ok(false)` when git is present and new enough
/// but `root` is not a repo, and `GitAbsent`/`GitTooOld` when the toolchain
/// itself is unusable. The version gate lives HERE, at the point of use, exactly
/// as in `ensure_repo` (CLAUDE.md hard rule 6 — not widened into `doctor`).
pub(crate) fn require_repo(root: &Path) -> Result<bool, GitxError> {
    let (major, minor) = git_version()?;
    if major < 2 || (major == 2 && minor < 32) {
        return Err(GitxError::GitTooOld {
            found: format!("{major}.{minor}"),
        });
    }
    Ok(is_repo(root))
}

/// The next snapshot id, allocated from a SHARED monotonic counter across both
/// `refs/getdev/snaps/` and `refs/getdev/auto/` — so a given id can never
/// exist in both namespaces (Open Q1/A2). Retention budgets stay independent;
/// only allocation is shared. Ids are never reused after prune (D-01): this
/// reads only LIVE refs, but `enforce_retention` floors `keep` at 1 on every
/// getdev-controlled path (WR-01), so the newest (highest-id) ref in a namespace
/// can never be deleted by getdev — the live-refs max is therefore always the
/// true monotonic high-water mark. The only way to empty a namespace is an
/// out-of-band manual `git update-ref -d`, which is outside getdev's contract.
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
/// each namespace's budget is independent (D-09). Idempotent: a second run over
/// an already-trimmed namespace deletes nothing. This is the exact logic the
/// public [`prune`] exposes — one code path, so manual `snap prune` and
/// automatic end-of-snap retention can never diverge (D-09).
fn enforce_retention(root: &Path, ns: Namespace, keep: u32) -> Result<PruneOutcome, GitxError> {
    let stdout = capture(
        git_command_readonly(root).args(["for-each-ref", "--format=%(refname)", ns.ref_prefix()]),
        "for-each-ref",
    )?;
    let mut ids: Vec<u32> = String::from_utf8_lossy(&stdout)
        .lines()
        .filter_map(|line| line.rsplit('/').next().and_then(|s| s.parse::<u32>().ok()))
        .collect();
    ids.sort_unstable();
    // Floor `keep` at 1 on EVERY getdev-controlled retention path (WR-01): a
    // `keep = 0` (e.g. `[snap] keep = 0` in `.getdev.toml`) would otherwise let
    // `snapshot()` delete the very ref it just created — including the auto-snap
    // that is the mandated fail-closed undo point — while still returning `Ok`.
    // Keeping the newest ref undeletable also makes `next_id`'s live-refs
    // high-water mark monotonic across a full prune, so ids are never reused
    // (WR-02 / D-01): the only way to empty a namespace becomes an out-of-band
    // manual `git update-ref -d`, which is outside getdev's contract.
    let keep = (keep as usize).max(1);
    if ids.len() <= keep {
        return Ok(PruneOutcome {
            deleted_ids: Vec::new(),
            kept: ids.len(),
        });
    }
    let doomed = ids.len() - keep;
    let mut deleted_ids = Vec::with_capacity(doomed);
    for id in ids.into_iter().take(doomed) {
        capture(
            git_command_readonly(root).args(["update-ref", "-d", &ns.ref_path(id)]),
            "update-ref",
        )?;
        deleted_ids.push(id);
    }
    Ok(PruneOutcome {
        deleted_ids,
        kept: keep,
    })
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

/// Resolve snapshot `id` to its `(namespace, commit oid)`. Searches the manual
/// `refs/getdev/snaps/<id>` namespace FIRST, then `refs/getdev/auto/<id>`
/// (Open Q1 / A2: `back <N>` searches snaps then auto over the single
/// shared-counter id space — a given id is only ever in one namespace, but the
/// search order makes a manual id win if both somehow existed). A missing id is
/// `NoSuchSnapshot`, returned via `rev-parse --verify --quiet` (no stderr
/// noise) BEFORE any disk write so a bad id can never partially restore
/// (T-05-10).
fn resolve_ref(root: &Path, id: u32) -> Result<(Namespace, String), GitxError> {
    for ns in [Namespace::Snaps, Namespace::Auto] {
        let out = git_command_readonly(root)
            .args([
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("{}^{{commit}}", ns.ref_path(id)),
            ])
            .output()?;
        if out.status.success() {
            let commit = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if !commit.is_empty() {
                return Ok((ns, commit));
            }
        }
    }
    Err(GitxError::NoSuchSnapshot { id })
}

/// Parse the NUL-delimited output of `diff-tree --name-status -z` into
/// `(status_field, path)` records. With `-z`, git emits — per change — a status
/// field, a NUL, the RAW path, and a NUL; it does NOT apply `core.quotePath`
/// C-quoting (which defaults to on and would mangle any non-ASCII path into
/// e.g. `"caf\303\251.txt"`). Using the raw path is mandatory so a created-since
/// file with a non-ASCII name is located and removed on restore (CR-01 / D-05).
/// Rename/copy statuses (`R`/`C`) carry a source AND a destination path; those
/// only appear when `-M`/`-C` are requested (they are not here), but are parsed
/// defensively so a stray record can never desync the field stream — the
/// destination is taken as the effective path.
fn parse_name_status_z(out: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(out);
    let mut fields = text.split('\0').filter(|s| !s.is_empty());
    let mut records = Vec::new();
    while let Some(status) = fields.next() {
        let rename_or_copy = matches!(status.chars().next(), Some('R') | Some('C'));
        let path = if rename_or_copy {
            // source then destination — the destination is the effective path.
            let _src = fields.next();
            match fields.next() {
                Some(dst) => dst,
                None => break,
            }
        } else {
            match fields.next() {
                Some(p) => p,
                None => break,
            }
        };
        records.push((status.to_owned(), path.to_owned()));
    }
    records
}

/// Restore the working tree to snapshot `id` (byte-identical over the
/// snapshotted scope; D-05 exact-not-additive semantics).
///
/// The restore plan is derived entirely from a `diff-tree` between the CURRENT
/// working state and the target snapshot's tree — never a filesystem walk
/// (§ Pattern 3). Because gitignored paths never enter either tree, they can
/// never be classified for overwrite or removal, so restore leaves them
/// untouched for free (T-05-09 / D-05). Plumbing only — never `git
/// checkout`/`git restore` (porcelain moves HEAD and runs hooks); every git
/// call sets an explicit throwaway `GIT_INDEX_FILE`.
pub fn restore(root: &Path, id: u32) -> Result<RestoreOutcome, GitxError> {
    // Resolve the target BEFORE touching the working tree or building a tree —
    // a bad id must be a clean `NoSuchSnapshot`, never a partial restore
    // (T-05-10).
    let (_, target_commit) = resolve_ref(root, id)?;
    let target_tree = {
        let out = capture(
            git_command_readonly(root).args([
                "rev-parse",
                "--verify",
                &format!("{target_commit}^{{tree}}"),
            ]),
            "rev-parse",
        )?;
        String::from_utf8_lossy(&out).trim().to_owned()
    };

    // Current working state as a tree (temp index #1 — used only for diffing).
    let current_tree = build_current_tree(root)?;

    // Classify every in-scope path via a RECURSIVE diff-tree (Pitfall 1: `-r` is
    // mandatory or only top-level tree entries are reported). Orientation:
    // current is the FIRST tree, target the SECOND, so a change transforming
    // current → target reads as: `A` = present only in target → recreate,
    // `D` = present only in current → created since the snapshot → remove,
    // `M`/`T` = differs → overwrite from target.
    let diff = capture(
        git_command_readonly(root).args([
            "diff-tree",
            "--no-commit-id",
            "-r",
            "-z",
            "--name-status",
            &current_tree,
            &target_tree,
        ]),
        "diff-tree",
    )?;

    let mut restored = 0usize; // `M`/`T` overwritten from target
    let mut removed = 0usize; // `D` created-since, deleted from disk
    let mut readded = 0usize; // `A` target-only, recreated
    let mut created_since: Vec<PathBuf> = Vec::new();
    for (status, path) in parse_name_status_z(&diff) {
        match status.chars().next() {
            Some('A') => readded += 1,
            Some('M' | 'T') => restored += 1,
            Some('D') => {
                removed += 1;
                created_since.push(root.join(path));
            }
            _ => {}
        }
    }

    // Materialize the target with a SECOND, distinct temp index (never reuse
    // index #1 across diff and checkout — Anti-Pattern / Pitfall): `read-tree`
    // loads the target tree into the index, `checkout-index -a -f` writes every
    // target path to disk, overwriting `M`/`T` and recreating target-only `A`
    // paths in one pass.
    let index = TempIndex::new("back");
    capture(
        git_command(root, index.path()).args(["read-tree", &target_tree]),
        "read-tree",
    )?;
    capture(
        git_command(root, index.path()).args(["checkout-index", "-a", "-f"]),
        "checkout-index",
    )?;

    // Remove every path present now but absent in the target (created since the
    // snapshot) — D-05's exact-not-additive semantics. Each path is in-scope by
    // construction (ignored paths never entered either tree). A missing file is
    // fine (already gone); any other i/o error is surfaced.
    for path in &created_since {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(GitxError::Io { source: e }),
        }
    }

    Ok(RestoreOutcome {
        restored,
        removed,
        readded,
    })
}

/// Materialize snapshot `snap_id`'s tree into `dest` — a plain "unpack this
/// tree here", NOT an in-place restore (D-05). Reuses `restore()`'s exact
/// primitives — `resolve_ref` → `rev-parse <commit>^{tree}` → `read-tree` into
/// a fresh throwaway `TempIndex` → `checkout-index -a -f` — but writes under
/// `--prefix=<dest>/` into a caller-supplied dest dir instead of over the live
/// working tree. Because a snapshot captures tracked + untracked-non-ignored
/// files (`build_current_tree` = `add -A`) and gitignored paths never entered
/// the tree, `dest` faithfully reproduces the project as it was at the snapshot,
/// with gitignored paths excluded for free (the same guarantee `restore` relies
/// on). Read-only with respect to the source repo: it never mutates HEAD, the
/// index, refs, or the live working tree.
///
/// `dest` MUST be an ABSOLUTE path. `git_command` sets `-C root`, so a RELATIVE
/// `dest` would resolve against `root` — not the caller's intended location —
/// and the `--prefix` value MUST carry a trailing slash or it fuses onto the
/// first checked-out path segment (05-RESEARCH § Pitfall 4). Do NOT pre-create
/// `dest`: `checkout-index --prefix` creates it and every nested subdirectory
/// itself (an empty-tree snapshot writes nothing, leaving `dest` uncreated — a
/// valid, non-error outcome). The target is resolved BEFORE any write, so a bad
/// id is a clean [`GitxError::NoSuchSnapshot`], never a partial materialize
/// (mirrors `restore`'s T-05-10). Unlike `snapshot()`, this NEVER `git init`s a
/// missing repo — reading a snapshot from a non-repo is a clean error, not a
/// bootstrap (mirrors `require_repo`'s read-only philosophy). No new
/// `GitxError` variant is needed: `NoSuchSnapshot`/`Command`/`Io` cover every
/// failure mode.
pub fn materialize(root: &Path, snap_id: u32, dest: &Path) -> Result<(), GitxError> {
    // WR-01: `checkout-index --prefix` is NOT `-C`-aware — a RELATIVE prefix
    // resolves against `root`, so a relative `dest` would unpack the snapshot
    // INTO the live repo and clobber the working tree. Enforce the documented
    // absolute-path invariant up front (this `pub fn` is earmarked for Phase 15
    // `fix`/`guard` reuse — the guard must not depend on the caller being careful).
    if !dest.is_absolute() {
        return Err(GitxError::RelativeDest {
            dest: dest.display().to_string(),
        });
    }
    // Resolve the target BEFORE touching `dest` — a bad id must be a clean
    // `NoSuchSnapshot`, never a partial materialize (mirrors restore, T-05-10).
    let (_, target_commit) = resolve_ref(root, snap_id)?;
    let target_tree =
        rev_parse_tree(root, &target_commit)?.ok_or(GitxError::NoSuchSnapshot { id: snap_id })?;

    // A FRESH throwaway index (never reuse one across operations — snap.rs
    // pitfall): `read-tree` loads the target tree, `checkout-index -a -f` writes
    // every entry under `--prefix=<dest>/`, creating `dest` + nested dirs.
    let index = TempIndex::new("materialize");
    let dest_prefix = format!("{}/", dest.to_string_lossy());
    capture(
        git_command(root, index.path()).args(["read-tree", &target_tree]),
        "read-tree",
    )?;
    capture(
        git_command(root, index.path()).args([
            "checkout-index",
            "-a",
            "-f",
            &format!("--prefix={dest_prefix}"),
        ]),
        "checkout-index",
    )?;
    Ok(())
}

/// The id of the most recent manual snapshot (`refs/getdev/snaps/<N>`), the
/// target of a bare `back`, or `None` when no manual snapshot exists (D-02).
pub fn latest_manual(root: &Path) -> Result<Option<u32>, GitxError> {
    highest_id(root, Namespace::Snaps)
}

/// The oid of git's empty tree, computed from this repo's object format (so it
/// is correct for both SHA-1 and SHA-256 repos rather than hard-coding the
/// SHA-1 constant). git always resolves the empty tree even when unstored, so
/// this is a safe left-hand side for a "full file count" diff.
fn empty_tree(root: &Path) -> Result<String, GitxError> {
    let out = capture(
        git_command_readonly(root).args(["hash-object", "-t", "tree", null_device()]),
        "hash-object",
    )?;
    Ok(String::from_utf8_lossy(&out).trim().to_owned())
}

/// The A/D/M name-status changes transforming `from_tree` into `to_tree`, via a
/// RECURSIVE `diff-tree` (Pitfall 1: `-r` is mandatory or only top-level tree
/// entries are reported). This is the same name-status sequence `restore` folds
/// (Pattern 3); `list` counts the rows and `diff` folds them. `'T'` (type
/// change) collapses to `'M'`. Read-only.
fn diff_tree_name_status(
    root: &Path,
    from_tree: &str,
    to_tree: &str,
) -> Result<Vec<(char, String)>, GitxError> {
    let out = capture(
        git_command_readonly(root).args([
            "diff-tree",
            "--no-commit-id",
            "-r",
            "-z",
            "--name-status",
            from_tree,
            to_tree,
        ]),
        "diff-tree",
    )?;
    let mut changes = Vec::new();
    for (status, path) in parse_name_status_z(&out) {
        let c = match status.chars().next() {
            Some('A') => 'A',
            Some('D') => 'D',
            Some('M' | 'T') => 'M',
            _ => continue,
        };
        changes.push((c, path));
    }
    Ok(changes)
}

/// All manual snapshots (`refs/getdev/snaps/` ONLY — the auto safety net stays
/// invisible, D-06), ordered ascending by id. Each row carries its id, the
/// commit subject (message), an `age_secs` derived from the committer timestamp
/// (the ONE time-derived human field permitted by DEC-01 — ids/messages stay
/// deterministic), and a `files_changed` count recomputed at list-time by
/// diffing each snapshot against its numeric PREDECESSOR snapshot tree (Open
/// Q2 — storage-free; the lowest id diffs against the empty tree, so its count
/// is the full file count). Read-only; prints nothing (the CLI renders).
pub fn list(root: &Path) -> Result<Vec<SnapMeta>, GitxError> {
    let stdout = capture(
        git_command_readonly(root).args([
            "for-each-ref",
            "--format=%(refname)%09%(committerdate:unix)%09%(contents:subject)",
            Namespace::Snaps.ref_prefix(),
        ]),
        "for-each-ref",
    )?;

    let mut rows: Vec<(u32, u64, String)> = Vec::new();
    for line in String::from_utf8_lossy(&stdout).lines() {
        let mut fields = line.splitn(3, '\t');
        let refname = fields.next().unwrap_or("");
        let ts = fields
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let message = fields.next().unwrap_or("").to_owned();
        let id = match refname
            .rsplit('/')
            .next()
            .and_then(|s| s.parse::<u32>().ok())
        {
            Some(n) => n,
            None => continue,
        };
        rows.push((id, ts, message));
    }
    rows.sort_by_key(|row| row.0);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut prev_tree = empty_tree(root)?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, ts, message) in rows {
        let tree = rev_parse_tree(root, &Namespace::Snaps.ref_path(id))?
            .ok_or(GitxError::NoSuchSnapshot { id })?;
        let files_changed = diff_tree_name_status(root, &prev_tree, &tree)?.len();
        out.push(SnapMeta {
            id,
            age_secs: now.saturating_sub(ts),
            message,
            files_changed,
        });
        prev_tree = tree;
    }
    Ok(out)
}

/// Summarize the changes between snapshot `id` and the CURRENT working tree
/// (`snap diff <id>` — summary-only; v0.1 emits no per-file patches). Resolves
/// the target BEFORE building any tree, so a bad id is a clean `NoSuchSnapshot`
/// with no side effects (T-05-13). Orientation: the snapshot is the FIRST tree
/// and the current state the SECOND, so `A` = created since the snapshot,
/// `D` = removed since, `M` = modified since. Read-only; prints nothing.
pub fn diff(root: &Path, id: u32) -> Result<DiffSummary, GitxError> {
    let (_, commit) = resolve_ref(root, id)?;
    let target_tree = rev_parse_tree(root, &commit)?.ok_or(GitxError::NoSuchSnapshot { id })?;
    let current_tree = build_current_tree(root)?;

    let mut summary = DiffSummary::default();
    for (status, path) in diff_tree_name_status(root, &target_tree, &current_tree)? {
        match status {
            'A' => summary.added += 1,
            'D' => summary.deleted += 1,
            'M' => summary.modified += 1,
            _ => {}
        }
        summary.paths.push((status, path));
    }
    Ok(summary)
}

/// Manually enforce `keep` retention on `ns` — a thin wrapper over the SAME
/// `enforce_retention` every `snapshot` runs, so manual `snap prune` and
/// automatic end-of-snap retention are provably one code path (D-09). Deletes
/// refs only via `update-ref -d`, never `git gc`/`prune`/`repack` (D-10), and
/// is idempotent. Returns the deleted ids and the kept count.
pub fn prune(root: &Path, ns: Namespace, keep: u32) -> Result<PruneOutcome, GitxError> {
    enforce_retention(root, ns, keep)
}
