//! Detached signature verification for `getdev update`.
//!
//! This is the single highest-value supply-chain mitigation in the whole
//! tool: it is what stops a backdoored/tampered release manifest from being
//! accepted by `getdev update` (08-04 gates the binary swap on it, treating
//! ANY `Err` here as "abort, leave the running binary untouched").
//!
//! **Approach (locked decision D-01):** self-update signatures are produced
//! CI-side by *keyed* cosign (`cosign sign-blob --key`) and verified in-process
//! with pure-Rust RustCrypto (`p256`/`ecdsa`/`signature`) against an embedded
//! public key. There is NO async `sigstore` crate and NO `tokio` — DEC-01 (no
//! async runtime) is preserved literally. cosign's `ecdsa-sha2-256-nistp256`
//! signer emits base64(ASN.1-DER ECDSA-P256) over `sha256(blob)`; verification
//! is the exact mirror image (see `verify_detached`).
//!
//! 08-01 de-risked and *locked* the verify API; 08-04 wires it as gate 2 of the
//! self-update engine (`update::run`). That engine is, in turn, only reached
//! from unit tests + the imminent 08-05 CLI command wiring, so from the *bin's*
//! non-test perspective this surface (and the engine `UpdateError` variants it
//! shares) is still `dead_code` until `main.rs` dispatches `getdev update`.
//! The allow is intentional and removed in 08-05.
#![allow(dead_code)]

use base64::Engine;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

/// The release public key `getdev update` verifies every downloaded
/// `SHA256SUMS` manifest against. It is embedded (not fetched) so verification
/// is a pure local computation with zero network calls, keeping `--offline`
/// meaningful and adding no fourth network destination beyond
/// npm/PyPI/GitHub-Releases.
///
/// PLACEHOLDER — replaced with the real release public key in 08-08. Nothing
/// verifies against this yet; the 08-01 tests use the committed test vector's
/// `cosign.pub`, never this const.
pub const EMBEDDED_COSIGN_PUBKEY: &str = "\
-----BEGIN PUBLIC KEY-----
PLACEHOLDER-REPLACED-WITH-THE-REAL-RELEASE-PUBLIC-KEY-IN-08-08==
-----END PUBLIC KEY-----
";

/// The shared error type for the whole `getdev update` engine (08-04). Every
/// variant is a *closed* failure — the self-update orchestrator aborts on any
/// of them and leaves the running binary untouched (never a partial swap).
///
/// The signature variants are deliberately coarse: the caller only needs
/// "verified" vs. "not verified (why)"; they must never leak enough detail to
/// help forge a signature. The engine variants carry a human-readable message
/// (rather than the underlying `io`/`reqwest` error) so the whole enum stays
/// `PartialEq`/`Eq` — the hermetic tests assert exact `Err(..)` values, and an
/// error message is never proof of anything about a release.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UpdateError {
    /// The base64/DER signature blob could not be decoded into an ECDSA-P256
    /// signature (corrupt, truncated, or not a signature at all).
    #[error("signature is malformed (not decodable base64/DER ECDSA-P256)")]
    SignatureMalformed,

    /// The public key PEM could not be parsed as an SPKI ECDSA-P256 key.
    #[error("public key is malformed (not a valid SPKI-PEM ECDSA-P256 key)")]
    PublicKeyMalformed,

    /// The signature is well-formed but does not verify against the manifest
    /// under this key — a tampered manifest, a signature from a different key,
    /// or an otherwise invalid signature. Fails closed.
    #[error("signature does not verify against the manifest under this key")]
    SignatureMismatch,

    /// The release for the running platform's target triple had no matching
    /// archive asset. Abort — never guess or install a wrong-arch binary.
    #[error("no release asset found for this platform ({target})")]
    AssetNotFound { target: String },

    /// The `SHA256SUMS` manifest had no line for the resolved archive — the
    /// manifest and the asset list disagree; refuse rather than skip gate 1.
    #[error("checksum manifest has no entry for {asset}")]
    ManifestEntryMissing { asset: String },

    /// Gate 1 failed: the downloaded archive's SHA-256 does not match the
    /// manifest. Fails closed — never swap a mismatched archive.
    #[error("archive checksum mismatch (expected {expected}, got {actual})")]
    ChecksumMismatch { expected: String, actual: String },

    /// A resolved release version could not be parsed as semver.
    #[error("release version {version} is not valid semver")]
    VersionUnparseable { version: String },

    /// The resolved target version is OLDER than the running binary and
    /// `[update] allow_downgrade` is not set — a refused downgrade (T-08-11).
    #[error(
        "refusing to downgrade from {current} to {target} \
         — set [update] allow_downgrade = true to override"
    )]
    DowngradeRefused { current: String, target: String },

    /// A network/transport failure talking to GitHub Releases. Message only
    /// (io/reqwest errors aren't `PartialEq`); never proof about a release.
    #[error("release request failed: {0}")]
    Download(String),

    /// Extracting the verified archive (or locating the binary inside it)
    /// failed AFTER both gates passed — the running binary is still untouched.
    #[error("failed to extract the verified update archive: {0}")]
    Extract(String),

    /// The atomic self-replace of the running binary failed. `self-replace`
    /// maps the platform specifics; the original binary is left in place.
    #[error("atomic binary swap failed: {0}")]
    Swap(String),

    /// Windows `.zip` self-update extraction is not yet wired (deferred to
    /// 08-08's 3-OS smoke). The verify-then-swap core is proven on Unix;
    /// Windows users reinstall via the installer/scoop until then. Fails
    /// closed — the gates still run, but the swap never happens partially.
    #[error(
        "windows self-update archive handling is not yet available \
         — reinstall via the installer/scoop (tracked for 08-08)"
    )]
    WindowsArchiveUnsupported,
}

/// Verify a detached keyed-cosign signature over a manifest.
///
/// Implements the exact chain a genuine `cosign sign-blob --key` output
/// requires: base64-decode `sig_b64` → [`Signature::from_der`] →
/// `VerifyingKey::from_public_key_pem` → verify the `SHA-256` prehash of
/// `manifest` (cosign signs the digest). Returns `Ok(())` only for a genuine
/// signature; every failure is a typed [`UpdateError`], never a panic (no
/// `unwrap`/`expect`), so an attacker-supplied blob can never crash the
/// updater.
pub fn verify_detached(
    manifest: &[u8],
    sig_b64: &str,
    pubkey_pem: &str,
) -> Result<(), UpdateError> {
    // 1. base64-decode the detached signature (cosign emits standard base64).
    let der = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .map_err(|_| UpdateError::SignatureMalformed)?;

    // 2. parse the ASN.1-DER ECDSA-P256 signature.
    let signature = Signature::from_der(&der).map_err(|_| UpdateError::SignatureMalformed)?;

    // 3. parse the SPKI-PEM public key.
    let verifying_key = VerifyingKey::from_public_key_pem(pubkey_pem)
        .map_err(|_| UpdateError::PublicKeyMalformed)?;

    // 4. verify against the SHA-256 prehash of the manifest (cosign signs the
    //    digest, not the raw bytes). Any mismatch fails closed.
    let prehash = Sha256::digest(manifest);
    verifying_key
        .verify_prehash(&prehash, &signature)
        .map_err(|_| UpdateError::SignatureMismatch)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    // The committed REAL keyed-cosign vector (see
    // testdata/update/signature/README.md). Paths are relative to THIS source
    // file: crates/getdev-cli/src/update/ → repo root is four levels up.
    const MANIFEST: &[u8] = include_bytes!("../../../../testdata/update/signature/SHA256SUMS");
    const SIGNATURE: &str = include_str!("../../../../testdata/update/signature/SHA256SUMS.sig");
    const PUBKEY: &str = include_str!("../../../../testdata/update/signature/cosign.pub");

    /// De-risk proof (locked D-01 DE-RISK clause): a genuine
    /// `cosign sign-blob --key`-produced signature verifies against its
    /// public key with pure-Rust `p256` — the exact base64→DER→SHA-256-prehash
    /// encoding parses and validates. This is the load-bearing assumption for
    /// the whole self-update crypto core.
    #[test]
    fn real_cosign_vector_verifies_ok() {
        assert_eq!(verify_detached(MANIFEST, SIGNATURE, PUBKEY), Ok(()));
    }

    // ---- Tamper resistance: verification must fail CLOSED for every vector,
    //      always a typed `UpdateError`, never `Ok`, never a panic. 08-04
    //      treats any `Err` as "abort before swap, leave the binary untouched"
    //      (STRIDE T-08-01 Tampering / T-08-02 Spoofing / T-08-03 DoS). ----

    /// A single flipped manifest byte must break verification — this is the
    /// core anti-tampering property (a backdoored SHA256SUMS must be rejected).
    #[test]
    fn flipped_manifest_byte_is_mismatch() {
        let mut tampered = MANIFEST.to_vec();
        tampered[0] ^= 0x01; // flip one bit of the first byte
        assert_eq!(
            verify_detached(&tampered, SIGNATURE, PUBKEY),
            Err(UpdateError::SignatureMismatch)
        );
    }

    /// Non-base64 garbage in the signature slot decodes to nothing — malformed,
    /// never a crash.
    #[test]
    fn garbage_base64_signature_is_malformed() {
        assert_eq!(
            verify_detached(MANIFEST, "!!! not base64 @@@", PUBKEY),
            Err(UpdateError::SignatureMalformed)
        );
    }

    /// Valid base64 that does not decode to an ASN.1-DER ECDSA signature
    /// (here: a truncated prefix of the genuine signature) is malformed.
    #[test]
    fn valid_base64_but_not_der_is_malformed() {
        // Re-encode just the first few bytes of the real signature: valid
        // base64, but a truncated/garbage DER body.
        let der = base64::engine::general_purpose::STANDARD
            .decode(SIGNATURE.trim())
            .unwrap();
        let truncated = base64::engine::general_purpose::STANDARD.encode(&der[..4]);
        assert_eq!(
            verify_detached(MANIFEST, &truncated, PUBKEY),
            Err(UpdateError::SignatureMalformed)
        );
    }

    /// An empty signature is malformed, not a panic.
    #[test]
    fn empty_signature_is_malformed() {
        assert_eq!(
            verify_detached(MANIFEST, "", PUBKEY),
            Err(UpdateError::SignatureMalformed)
        );
    }

    /// The genuine signature checked against a DIFFERENT public key must be
    /// rejected — only the single embedded key is trusted (spoofing/forgery
    /// under another key fails closed). The wrong key is derived deterministically
    /// in-test (a fixed non-zero scalar), no committed second key or RNG needed.
    #[test]
    fn signature_under_wrong_key_is_mismatch() {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let wrong_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let wrong_pem = wrong_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        assert_eq!(
            verify_detached(MANIFEST, SIGNATURE, &wrong_pem),
            Err(UpdateError::SignatureMismatch)
        );
    }

    /// A malformed PEM public key is rejected before any verification is
    /// attempted — typed error, never a crash.
    #[test]
    fn malformed_pem_public_key_is_malformed() {
        let bad_pem = "-----BEGIN PUBLIC KEY-----\nnot a real key\n-----END PUBLIC KEY-----\n";
        assert_eq!(
            verify_detached(MANIFEST, SIGNATURE, bad_pem),
            Err(UpdateError::PublicKeyMalformed)
        );
    }
}
