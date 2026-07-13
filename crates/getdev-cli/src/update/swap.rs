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
//! Unix ships a `.tar.xz`; Windows ships a `.zip`. Both paths are fully
//! implemented and covered: the Unix path decompresses xz + untars, the Windows
//! path inflates the zip (pure-Rust deflate). The extraction logic is exercised
//! hermetically on every platform — the Windows extractor's tests run on the
//! dev host via the `zip` dev-dependency — so neither path can silently regress.
//!
//! Wired into the engine by 08-04 and reached live from `getdev update` since
//! 08-05, so the module-level `dead_code` allow is gone.

use super::signature::UpdateError;

/// The name of the binary to locate inside a Unix `.tar.xz` archive tree. cargo-
/// dist archives contain `getdev-<target>/getdev` (plus README/LICENSE), so the
/// engine walks for a regular file with exactly this name.
#[cfg(unix)]
const BINARY_NAME: &str = "getdev";

/// The name of the binary to locate inside a Windows `.zip` archive tree
/// (`getdev-<target>/getdev.exe`). Available under `cfg(test)` too so the
/// hermetic zip test can drive the extractor on the (unix) dev host.
#[cfg(any(windows, test))]
const WINDOWS_BINARY_NAME: &str = "getdev.exe";

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

/// Extract the verified `.zip` release archive and atomically self-replace the
/// running binary.
///
/// Windows only: inflate the zip (pure-Rust deflate) into a scratch dir →
/// locate `getdev.exe` → atomic swap via `self-replace`. Mirrors the Unix
/// `.tar.xz` path exactly, including the "any failure BEFORE the swap leaves the
/// running binary untouched" ordering invariant.
#[cfg(windows)]
pub fn apply_update(archive_bytes: &[u8]) -> Result<(), UpdateError> {
    let extracted = extract_getdev_binary_zip(archive_bytes, WINDOWS_BINARY_NAME)?;
    // Only now — after a clean extraction — perform the atomic replacement.
    self_replace::self_replace(&extracted.binary).map_err(|e| UpdateError::Swap(e.to_string()))?;
    Ok(())
}

/// Inflate a `.zip` release archive into a scratch dir and locate the named
/// binary within. Pure filesystem + in-memory deflate — no network — so it is
/// fully unit-testable with an in-memory archive on any platform (the test path
/// is why this is `cfg(any(windows, test))`, not `cfg(windows)`).
///
/// Guards against zip-slip (a malicious entry name escaping the scratch dir via
/// `..`/absolute paths) with `enclosed_name`, even though this runs only on an
/// already checksum+signature-verified archive — defense in depth for the one
/// code path that writes attacker-influenceable bytes to disk.
#[cfg(any(windows, test))]
fn extract_getdev_binary_zip(
    archive_bytes: &[u8],
    binary_name: &str,
) -> Result<Extracted, UpdateError> {
    use std::io::{Cursor, Read};

    let scratch = ScratchDir::new()?;
    let mut archive = zip::ZipArchive::new(Cursor::new(archive_bytes))
        .map_err(|e| UpdateError::Extract(format!("zip open failed: {e}")))?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| UpdateError::Extract(format!("zip entry read failed: {e}")))?;
        if entry.is_dir() {
            continue;
        }
        // Reject any entry whose name would escape the scratch dir (zip-slip).
        let rel = entry
            .enclosed_name()
            .ok_or_else(|| UpdateError::Extract("zip entry has an unsafe path".to_string()))?;
        let out_path = scratch.path.join(rel);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| UpdateError::Extract(e.to_string()))?;
        }
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| UpdateError::Extract(format!("zip inflate failed: {e}")))?;
        std::fs::write(&out_path, &buf).map_err(|e| UpdateError::Extract(e.to_string()))?;
    }

    let binary = find_file(&scratch.path, binary_name)?;
    Ok(Extracted {
        _scratch: scratch,
        binary,
    })
}

/// A scratch directory that best-effort self-cleans on drop, so a failed or
/// successful update never leaves extraction debris in the temp dir. It must
/// outlive the `self-replace` call (self-replace reads the new binary from
/// this path), which is why [`Extracted`] owns it.
#[cfg(any(unix, windows))]
struct ScratchDir {
    path: std::path::PathBuf,
}

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The located new binary plus the scratch dir it lives in (kept alive until
/// the swap completes).
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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

    // ---- Windows `.zip` extraction path -----------------------------------
    // These run on the (unix) dev host via the `zip` dev-dependency, so the
    // Windows self-update extractor is proven hermetically without a Windows
    // runner. The extractor itself is `cfg(any(windows, test))`, so on a real
    // Windows build these same code paths ship and run.

    /// Build an in-memory `.zip` containing `entry_path` with `contents`,
    /// DEFLATE-compressed — mirroring cargo-dist's Windows archive layout
    /// (`getdev-<triple>/getdev.exe`), fully hermetically.
    fn make_zip(entry_path: &str, contents: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zw.start_file(entry_path, opts).unwrap();
            zw.write_all(contents).unwrap();
            zw.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[test]
    fn extracts_and_locates_the_getdev_exe_from_a_zip() {
        let payload = b"MZ\x90\x00fake windows getdev binary";
        let archive = make_zip("getdev-x86_64-pc-windows-msvc/getdev.exe", payload);

        let extracted = extract_getdev_binary_zip(&archive, WINDOWS_BINARY_NAME).unwrap();
        assert_eq!(
            extracted.binary.file_name().unwrap().to_string_lossy(),
            WINDOWS_BINARY_NAME
        );
        let read = std::fs::read(&extracted.binary).unwrap();
        assert_eq!(read, payload);
    }

    #[test]
    fn zip_scratch_dir_is_cleaned_up_on_drop() {
        let archive = make_zip("getdev-x/getdev.exe", b"x");
        let path = {
            let extracted = extract_getdev_binary_zip(&archive, WINDOWS_BINARY_NAME).unwrap();
            extracted._scratch.path.clone()
            // `extracted` dropped here → scratch removed.
        };
        assert!(!path.exists(), "zip scratch dir should be removed on drop");
    }

    #[test]
    fn zip_without_a_getdev_binary_is_a_typed_extract_error() {
        let archive = make_zip("getdev-x/README.md", b"docs only");
        assert!(matches!(
            extract_getdev_binary_zip(&archive, WINDOWS_BINARY_NAME),
            Err(UpdateError::Extract(_))
        ));
    }

    #[test]
    fn non_zip_bytes_fail_as_a_typed_extract_error_not_a_panic() {
        assert!(matches!(
            extract_getdev_binary_zip(b"this is not a zip archive", WINDOWS_BINARY_NAME),
            Err(UpdateError::Extract(_))
        ));
    }
}
