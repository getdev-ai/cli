//! Gate 1 of `getdev update`: the SHA-256 checksum verification of a downloaded
//! release archive against the signed `SHA256SUMS` manifest.
//!
//! The two gates run in strict order (see [`super::run`]): gate 1 here proves
//! the archive bytes match the hash the manifest claims; gate 2
//! (`super::signature::verify_detached`) proves the *manifest itself* was
//! signed by the embedded release key. Only when BOTH pass does the engine
//! extract + swap. A failure in either is a typed [`UpdateError`] and the
//! running binary is never touched (research Pattern 2 — "never partially
//! swap").
//!
//! This module is pure/offline: it does no I/O and no network, so every path
//! is unit-testable hermetically with in-memory bytes.
//!
//! Wired into the engine by 08-04 and reached live from `getdev update` since
//! 08-05, so the module-level `dead_code` allow is gone.

use sha2::{Digest, Sha256};

use super::signature::UpdateError;

/// Verify a downloaded archive's SHA-256 against the hex digest the manifest
/// records for it (gate 1). Case-insensitive hex compare; a whitespace-trimmed
/// `expected` tolerates manifest formatting. Any mismatch is a closed failure —
/// the caller aborts before extraction/swap.
pub fn verify_checksum(archive_bytes: &[u8], expected_hex: &str) -> Result<(), UpdateError> {
    let actual = hex::encode(Sha256::digest(archive_bytes));
    let expected = expected_hex.trim();
    // A genuine SHA-256 is 64 hex chars; a malformed/empty `expected` can never
    // match a real digest, so `eq_ignore_ascii_case` naturally fails closed.
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(UpdateError::ChecksumMismatch {
            expected: expected.to_owned(),
            actual,
        })
    }
}

/// Extract the expected hex digest for `asset_name` from a `SHA256SUMS` blob.
///
/// The manifest is the `sha256sum`/coreutils format one entry per line:
/// `"<64-hex>  <filename>"` (two spaces = binary mode, or one space + `*` =
/// text mode; both tolerated). Matching is on the exact file *basename* so a
/// `./`-prefixed or path-qualified manifest entry still resolves. Returns
/// [`UpdateError::ManifestEntryMissing`] when the asset is absent — the engine
/// then aborts rather than silently skipping gate 1.
pub fn parse_manifest_entry(manifest: &[u8], asset_name: &str) -> Result<String, UpdateError> {
    let text = std::str::from_utf8(manifest).map_err(|_| UpdateError::ManifestEntryMissing {
        asset: asset_name.to_owned(),
    })?;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Split into "<hex>" and "<name>" on the first run of whitespace.
        let mut parts = line.splitn(2, char::is_whitespace);
        let (Some(hex), Some(rest)) = (parts.next(), parts.next()) else {
            continue;
        };
        // The name field may lead with `*` (text mode) and/or a path prefix.
        let name = rest.trim().trim_start_matches('*').trim();
        let basename = name.rsplit(['/', '\\']).next().unwrap_or(name);
        if basename == asset_name {
            // Reject an entry whose hash field isn't a plausible SHA-256 so a
            // malformed manifest can't smuggle a short/garbage digest past
            // gate 1's compare.
            if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Ok(hex.to_owned());
            }
        }
    }

    Err(UpdateError::ManifestEntryMissing {
        asset: asset_name.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    // A real SHA-256: echo -n "getdev" | sha256sum → deterministic vector.
    const PAYLOAD: &[u8] = b"getdev-update-archive-bytes";

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn matching_checksum_verifies() {
        let expected = sha256_hex(PAYLOAD);
        assert_eq!(verify_checksum(PAYLOAD, &expected), Ok(()));
    }

    #[test]
    fn checksum_is_case_insensitive_and_whitespace_tolerant() {
        let expected = sha256_hex(PAYLOAD).to_uppercase();
        assert_eq!(verify_checksum(PAYLOAD, &format!("  {expected}\n")), Ok(()));
    }

    #[test]
    fn one_bit_off_archive_fails_closed() {
        let expected = sha256_hex(PAYLOAD);
        let mut tampered = PAYLOAD.to_vec();
        tampered[0] ^= 0x01;
        assert!(matches!(
            verify_checksum(&tampered, &expected),
            Err(UpdateError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn empty_expected_hex_never_matches() {
        assert!(matches!(
            verify_checksum(PAYLOAD, ""),
            Err(UpdateError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn parse_manifest_extracts_the_right_line() {
        let a = sha256_hex(b"archive-a");
        let b = sha256_hex(b"archive-b");
        let manifest = format!(
            "{a}  getdev-aarch64-apple-darwin.tar.xz\n\
             {b}  getdev-x86_64-unknown-linux-gnu.tar.xz\n"
        );
        assert_eq!(
            parse_manifest_entry(
                manifest.as_bytes(),
                "getdev-x86_64-unknown-linux-gnu.tar.xz"
            )
            .unwrap(),
            b
        );
    }

    #[test]
    fn parse_manifest_tolerates_star_and_path_prefixes() {
        let a = sha256_hex(b"archive-a");
        // text-mode `*` marker and a `./` path prefix both resolve on basename.
        let manifest = format!("{a} *./dist/getdev-x86_64-pc-windows-msvc.zip\n");
        assert_eq!(
            parse_manifest_entry(manifest.as_bytes(), "getdev-x86_64-pc-windows-msvc.zip").unwrap(),
            a
        );
    }

    #[test]
    fn parse_manifest_missing_asset_is_typed_error() {
        let a = sha256_hex(b"archive-a");
        let manifest = format!("{a}  getdev-aarch64-apple-darwin.tar.xz\n");
        assert!(matches!(
            parse_manifest_entry(manifest.as_bytes(), "getdev-not-a-real-target.tar.xz"),
            Err(UpdateError::ManifestEntryMissing { .. })
        ));
    }

    #[test]
    fn parse_manifest_rejects_a_short_or_garbage_hash_field() {
        // Right filename, but the hash field isn't a 64-char hex digest — must
        // NOT be accepted (a malformed manifest can't weaken gate 1).
        let manifest = "deadbeef  getdev-aarch64-apple-darwin.tar.xz\n";
        assert!(matches!(
            parse_manifest_entry(manifest.as_bytes(), "getdev-aarch64-apple-darwin.tar.xz"),
            Err(UpdateError::ManifestEntryMissing { .. })
        ));
    }

    /// End-to-end gate 1: parse the manifest entry, then verify the archive
    /// against it — the exact two-call sequence `run` performs.
    #[test]
    fn manifest_entry_then_checksum_is_the_gate_1_happy_path() {
        let archive = b"the-real-archive-bytes";
        let digest = sha256_hex(archive);
        let manifest = format!("{digest}  getdev-aarch64-apple-darwin.tar.xz\n");
        let expected =
            parse_manifest_entry(manifest.as_bytes(), "getdev-aarch64-apple-darwin.tar.xz")
                .unwrap();
        assert_eq!(verify_checksum(archive, &expected), Ok(()));
    }
}
