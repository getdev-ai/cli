//! git interaction for getdev: snapshots under `refs/getdev/` and diff
//! extraction, by shelling out to the git binary (no git2/gix — settled
//! decision). Snap/back land in P4; diff extraction in P5.

pub mod snap;

use std::path::Path;
use std::process::{Command, Stdio};

/// Whether `relative` is tracked by git in the repository containing `root`.
/// Returns false when git is absent or `root` is not inside a repository —
/// callers treat "unknown" as "not tracked".
pub fn is_tracked(root: &Path, relative: &str) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "--error-unmatch", "--", relative])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untracked_paths_and_non_repos_are_false() {
        let tmp = std::env::temp_dir();
        assert!(!is_tracked(&tmp, "definitely-not-a-file-getdev-test"));
    }
}
