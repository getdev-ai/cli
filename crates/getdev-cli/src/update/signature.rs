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
//! is the exact mirror image (see [`verify_detached`]).
//!
//! This plan (08-01) de-risks and *locks* the verify API; the first caller is
//! 08-04's self-update engine. Until that lands, `verify_detached`/
//! `UpdateError`/`EMBEDDED_COSIGN_PUBKEY` are exercised only by this module's
//! own tests, so the not-yet-wired public surface is `dead_code`-allowed here
//! with intent (removed when 08-04 wires the swap gate).
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

/// Why a signature verification failed. Every variant is a *closed* failure —
/// 08-04 aborts the swap on any of them and leaves the running binary
/// untouched. Deliberately coarse: the caller only needs "verified" vs. "not
/// verified (why)"; it must never leak enough detail to help forge a signature.
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
}

/// Verify a detached keyed-cosign signature over a manifest.
///
/// Implements the exact chain a genuine `cosign sign-blob --key` output
/// requires: base64-decode `sig_b64` → [`Signature::from_der`] →
/// [`VerifyingKey::from_public_key_pem`] → verify the `SHA-256` prehash of
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
}
