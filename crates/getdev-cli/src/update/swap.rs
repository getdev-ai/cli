//! The final step of `getdev update`: extract the verified release archive and
//! atomically replace the running binary with the new one.
//!
//! **Ordering invariant (research Pattern 2 — "never partially swap"):** this
//! module is only ever called by [`super::run`] AFTER both verification gates
//! (checksum + cosign signature) have fully passed. Nothing here re-downloads
//! or re-verifies; it operates purely on already-trusted bytes. If extraction
//! fails, the running binary is left untouched (the swap never begins); the
//! swap itself is delegated to the `self-replace` crate, which owns the
//! platform-specific atomicity (Unix rename-over-inode / Windows
//! delete-on-close) — the exact class of TOCTOU/lock bugs it exists to solve.
//!
//! Unix ships a `.tar.xz`; Windows ships a `.zip`. The Unix path is fully
//! implemented and covered; the Windows `.zip` extraction is deferred to
//! 08-08's 3-OS smoke (which also embeds the real release key and needs a live
//! published prior release), and returns a typed
//! [`UpdateError::WindowsArchiveUnsupported`] until then — fail-closed, never a
//! partial swap.
//!
//! Wired into the engine by 08-04; the engine is only reached from tests +
//! 08-05's CLI command, so the surface is `dead_code` in the bin until then.
#![allow(dead_code)]

use super::signature::UpdateError;

/// The name of the binary to locate inside the extracted archive tree. cargo-
/// dist archives contain `getdev-<target>/getdev` (plus README/LICENSE), so the
/// engine walks for a regular file with exactly this name.
const BINARY_NAME: &str = "getdev";

/// Extract the verified archive and atomically self-replace the running binary.
///
/// Unix only: `.tar.xz` → decompress (xz) → untar → locate `getdev` → atomic
/// swap via `self-replace`. Any failure BEFORE the swap leaves the running
/// binary untouched.
#[cfg(unix)]
pub fn apply_update(archive_bytes: &[u8]) -> Result<(), UpdateError> {
    let extracted = extract_getdev_binary(archive_bytes)?;
    // Only now — after a clean extraction — perform the atomic replacement.
    self_replace::self_replace(&extracted.binary).map_err(|e| UpdateError::Swap(e.to_string()))?;
    Ok(())
}

/// Windows `.zip` self-update extraction is deferred to 08-08 (see module docs).
/// Returns a typed, fail-closed error so the swap can never happen partially.
#[cfg(windows)]
pub fn apply_update(_archive_bytes: &[u8]) -> Result<(), UpdateError> {
    Err(UpdateError::WindowsArchiveUnsupported)
}

/// A scratch directory that best-effort self-cleans on drop, so a failed or
/// successful update never leaves extraction debris in the temp dir. It must
/// outlive the `self-replace` call (self-replace reads the new binary from
/// this path), which is why [`Extracted`] owns it.
#[cfg(unix)]
struct ScratchDir {
    path: std::path::PathBuf,
}

#[cfg(unix)]
impl ScratchDir {
    fn new() -> Result<Self, UpdateError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        // A process-wide counter guarantees uniqueness even when two callers
        // (or two parallel tests) hit the same nanosecond — a bare pid+nanos
        // name can collide and let two extractions share a directory.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "getdev-update-{}-{nonce}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).map_err(|e| UpdateError::Extract(e.to_string()))?;
        Ok(Self { path })
    }
}

#[cfg(unix)]
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The located new binary plus the scratch dir it lives in (kept alive until
/// the swap completes).
#[cfg(unix)]
struct Extracted {
    _scratch: ScratchDir,
    binary: std::path::PathBuf,
}

/// Decompress the `.tar.xz`, unpack it into a scratch dir, and locate the
/// `getdev` binary within. Pure filesystem work — no network, so it is fully
/// unit-testable with an in-memory archive.
#[cfg(unix)]
fn extract_getdev_binary(archive_bytes: &[u8]) -> Result<Extracted, UpdateError> {
    use std::io::Cursor;

    // 1. xz-decompress into the raw tar bytes.
    let mut tar_bytes = Vec::new();
    lzma_rs::xz_decompress(&mut Cursor::new(archive_bytes), &mut tar_bytes)
        .map_err(|e| UpdateError::Extract(format!("xz decompress failed: {e}")))?;

    // 2. unpack the tar into a scratch dir.
    let scratch = ScratchDir::new()?;
    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    archive
        .unpack(&scratch.path)
        .map_err(|e| UpdateError::Extract(format!("tar unpack failed: {e}")))?;

    // 3. locate the `getdev` binary inside the extracted tree.
    let binary = find_file(&scratch.path, BINARY_NAME)?;
    Ok(Extracted {
        _scratch: scratch,
        binary,
    })
}

/// Depth-first search for a regular file named `name` under `root`. Bounded by
/// the (small, trusted) extracted tree; returns a typed error if absent so the
/// engine aborts rather than swapping in nothing. No `unwrap`/`expect`.
#[cfg(unix)]
fn find_file(root: &std::path::Path, name: &str) -> Result<std::path::PathBuf, UpdateError> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| UpdateError::Extract(e.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|e| UpdateError::Extract(e.to_string()))?;
            let file_type = entry
                .file_type()
                .map_err(|e| UpdateError::Extract(e.to_string()))?;
            let path = entry.path();
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() && entry.file_name().to_string_lossy() == name {
                return Ok(path);
            }
        }
    }
    Err(UpdateError::Extract(format!(
        "no `{name}` binary found inside the extracted update archive"
    )))
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::io::Cursor;

    /// Build an in-memory `.tar.xz` containing `getdev-<triple>/<name>` with the
    /// given contents — mirrors cargo-dist's archive layout so the extractor is
    /// exercised against a realistic tree, fully hermetically (no fixtures, no
    /// network).
    fn make_tar_xz(entry_path: &str, contents: &[u8]) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, entry_path, contents)
                .unwrap();
            builder.finish().unwrap();
        }
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(&tar_buf), &mut xz).unwrap();
        xz
    }

    #[test]
    fn extracts_and_locates_the_getdev_binary() {
        let payload = b"#!/bin/sh\necho fake getdev\n";
        let archive = make_tar_xz("getdev-aarch64-apple-darwin/getdev", payload);

        let extracted = extract_getdev_binary(&archive).unwrap();
        assert_eq!(
            extracted.binary.file_name().unwrap().to_string_lossy(),
            "getdev"
        );
        let read = std::fs::read(&extracted.binary).unwrap();
        assert_eq!(read, payload);
    }

    #[test]
    fn scratch_dir_is_cleaned_up_on_drop() {
        let archive = make_tar_xz("getdev-x/getdev", b"x");
        let path = {
            let extracted = extract_getdev_binary(&archive).unwrap();
            extracted._scratch.path.clone()
            // `extracted` dropped here → scratch removed.
        };
        assert!(!path.exists(), "scratch dir should be removed on drop");
    }

    #[test]
    fn archive_without_a_getdev_binary_is_a_typed_extract_error() {
        // A well-formed tar.xz that simply doesn't contain `getdev`.
        let archive = make_tar_xz("getdev-x/README.md", b"docs only");
        assert!(matches!(
            extract_getdev_binary(&archive),
            Err(UpdateError::Extract(_))
        ));
    }

    #[test]
    fn non_xz_bytes_fail_as_a_typed_extract_error_not_a_panic() {
        assert!(matches!(
            extract_getdev_binary(b"this is not an xz stream"),
            Err(UpdateError::Extract(_))
        ));
    }
}
