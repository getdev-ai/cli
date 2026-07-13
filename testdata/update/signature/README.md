# `getdev update` signature test vector

A **real** keyed-`cosign` signing vector, committed so
`crates/getdev-cli/src/update/signature.rs`'s tests regression-guard the exact
encoding that `getdev update` (08-04) will verify at self-update time.

This proves the load-bearing crypto assumption for Phase 8: a genuine
`cosign sign-blob --key`-produced detached signature verifies in-process with
pure-Rust RustCrypto (`p256`/`ecdsa`/`signature`) — **no async, no `sigstore`
crate, no `tokio`** (DEC-01 preserved literally; locked decision D-01).

## Files

| File           | What it is                                                        |
| -------------- | ----------------------------------------------------------------- |
| `SHA256SUMS`   | A small, realistic release manifest (`<sha256>  <asset>` lines).  |
| `SHA256SUMS.sig` | `cosign sign-blob` output: base64(ASN.1-DER ECDSA-P256) over `sha256(SHA256SUMS)`. |
| `cosign.pub`   | The SPKI-PEM public key. This is the **verification** key.        |

The private key (`cosign.key`) is **never** committed — it exists only for the
throwaway moment of producing this vector and is deleted immediately after.

## The verification chain (what `verify_detached` implements)

`cosign sign-blob` (algorithm `ecdsa-sha2-256-nistp256`) signs the SHA-256
digest of the blob and emits base64 of the ASN.1-DER ECDSA signature. Verifying
is the mirror image:

```
base64-decode SHA256SUMS.sig      -> DER bytes
Signature::from_der(der)          -> p256::ecdsa::Signature
VerifyingKey::from_public_key_pem(cosign.pub)
verify_prehash(sha256(SHA256SUMS), sig)  -> Ok(())
```

## Regenerating the vector

Requires **cosign 2.x** (the 2.x `sign-blob` still emits the plain detached
base64 signature; cosign 3.x defaults to the new Sigstore bundle format).
Official binary: <https://github.com/sigstore/cosign/releases> (`v2.4.3` used
to produce the committed vector).

```bash
cd testdata/update/signature
export COSIGN_PASSWORD=""            # throwaway, unencrypted local key
cosign generate-key-pair            # writes cosign.key (secret) + cosign.pub
cosign sign-blob --key cosign.key --yes --tlog-upload=false \
  --output-signature SHA256SUMS.sig SHA256SUMS
cosign verify-blob --key cosign.pub --signature SHA256SUMS.sig \
  --insecure-ignore-tlog=true SHA256SUMS      # -> "Verified OK"
rm -f cosign.key                    # NEVER commit the private key
```

`--tlog-upload=false` / `--insecure-ignore-tlog=true` keep the vector fully
offline (no Rekor transparency-log round-trip) — this is a keyed vector, not
the keyless OIDC flow. The keyless manual-verify path in `docs/RELEASING.md`
("Verifying a release") is a **separate**, user-facing mechanism; the automated
self-update path is keyed per D-01.

> Note: `cosign.pub` here is a **test** key. The real embedded release public
> key (`EMBEDDED_COSIGN_PUBKEY` in `signature.rs`) is a placeholder until 08-08
> wires in the actual release key.
