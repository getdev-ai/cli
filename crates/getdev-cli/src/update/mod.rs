//! GitHub Releases version probe.
//!
//! This is the ONLY place `getdev-cli` itself touches the network
//! (docs/ARCHITECTURE.md "Network boundary rule", DEC-05 — every other
//! network call in the workspace lives in `getdev-registry`). This module is
//! deliberately small: it is the seed of Phase 8's full self-update module,
//! not that module itself.
//!
//! 08-04 grows this from the bare probe into the full self-update engine
//! (`run`, asset resolution, the two verification gates, the atomic swap). The
//! probe (`latest_release_version`) is live via `doctor`, but the new engine
//! surface is only reached from unit tests + the imminent 08-05 CLI command
//! wiring, so it is `dead_code`-allowed at the module level with intent until
//! `main.rs` dispatches `getdev update` (the allow is removed in 08-05). This
//! mirrors 08-01's same-reasoned allow on `signature.rs`.
#![allow(dead_code)]

/// Detached keyed-cosign signature verification (pure-Rust p256) — the crypto
/// gate 08-04's self-update engine runs after the SHA-256 checksum gate.
pub mod signature;

/// Gate 1: SHA-256 checksum verification of the downloaded archive against the
/// signed `SHA256SUMS` manifest (runs before the signature gate).
pub mod checksum;

/// The final step: extract the verified archive and atomically self-replace the
/// running binary (only after BOTH gates pass — research Pattern 2).
pub mod swap;

use std::cmp::Ordering;
use std::time::Duration;

use serde::Deserialize;

use getdev_core::config::UpdateConfig;

use signature::UpdateError;

/// The compile-time target triple of THIS binary (injected by `build.rs` from
/// Cargo's `TARGET`), e.g. `aarch64-apple-darwin`. The running binary uses it
/// to fetch its own platform's release asset — never another arch's (which
/// would install a binary that cannot execute). cargo-dist names release
/// archives `getdev-<target>.tar.xz` (`.zip` on Windows), so the triple is the
/// substring the asset resolver matches on.
pub const TARGET_TRIPLE: &str = env!("GETDEV_TARGET");

/// A single downloadable asset attached to a GitHub release. Extends the
/// probe's minimal [`ReleaseResponse`] (which needed only `tag_name`) with the
/// per-asset fields the self-update engine resolves and downloads.
#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
}

/// The full release payload the self-update engine needs: the tag plus the
/// list of attached assets (archives + `SHA256SUMS` + `SHA256SUMS.sig`). This
/// is the same GitHub Releases JSON the probe reads, just deserialized with the
/// asset detail the probe deliberately omitted.
#[derive(Debug, Clone, Deserialize)]
pub struct FullReleaseResponse {
    pub tag_name: String,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

/// Resolve the archive asset matching `target_triple` — the binary's own
/// platform. Excludes the sidecar `.sha256` per-file checksums and the
/// `SHA256SUMS`/`.sig` manifest files so it never mistakes a checksum/manifest
/// for the archive. Returns `None` when the release has no asset for this
/// platform (the caller turns that into a typed [`signature::UpdateError`]).
pub fn asset_for_target<'a>(
    release: &'a FullReleaseResponse,
    target_triple: &str,
) -> Option<&'a ReleaseAsset> {
    release.assets.iter().find(|a| {
        a.name.contains(target_triple)
            && !a.name.ends_with(".sha256")
            && !a.name.ends_with(".sig")
            && !a.name.starts_with("SHA256SUMS")
    })
}

/// Resolve a release asset by exact file name — used to locate the shared
/// `SHA256SUMS` manifest and its `SHA256SUMS.sig` detached signature (gate 1
/// input and gate 2 input respectively).
pub fn asset_by_name<'a>(release: &'a FullReleaseResponse, name: &str) -> Option<&'a ReleaseAsset> {
    release.assets.iter().find(|a| a.name == name)
}

/// The canonical file names of the shared release manifest + its detached
/// keyed-cosign signature (produced CI-side in 08-07 by `cosign sign-blob
/// --key` over `SHA256SUMS`).
const MANIFEST_NAME: &str = "SHA256SUMS";
const MANIFEST_SIG_NAME: &str = "SHA256SUMS.sig";

/// Downloads are larger than the version probe's 5s window; give them a longer
/// (but still bounded) budget. Still a hard cap — a stalled connection can
/// never hang the updater indefinitely.
const DOWNLOAD_TIMEOUT_SECS: u64 = 60;

/// GitHub Releases list endpoint (all releases, newest first) — used for the
/// prerelease channel and for resolving a pinned tag. The probe already owns
/// `/releases/latest` ([`releases_api_url`]) for the stable channel.
fn releases_list_url() -> String {
    format!("https://api.github.com/repos/{REPO_SLUG}/releases")
}

/// What `getdev update` did. Every arm is an explicit, user-reportable outcome
/// (Pitfall 4: `Skipped` is a first-class no-op, never a stale "up to date").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// `--offline`/`GETDEV_OFFLINE` — no network was touched, nothing changed.
    Skipped,
    /// The running version already matches the resolved target.
    UpToDate { version: String },
    /// The binary was atomically replaced.
    Updated { from: String, to: String },
}

/// The verified-download bundle handed to the verify-then-swap core. Holding it
/// as plain bytes makes the core pure and hermetically testable (no network).
struct DownloadedRelease {
    target_version: String,
    asset_name: String,
    archive: Vec<u8>,
    manifest: Vec<u8>,
    signature_b64: String,
}

/// The forward/equal/backward relationship of a resolved target vs the running
/// binary — the downgrade guard's decision (T-08-11).
#[derive(Debug, PartialEq, Eq)]
enum VersionDecision {
    UpToDate,
    Forward,
    Downgrade,
}

/// Semver-compare a resolved target against the current version (both may carry
/// a leading `v`). Uses `semver` so pre-release precedence (e.g. `0.1.0-dev`
/// < `0.1.0`) is handled correctly rather than by naive string/number
/// comparison. An unparseable version fails closed — never treated as an
/// upgrade.
fn compare_versions(current: &str, target: &str) -> Result<VersionDecision, UpdateError> {
    let parse = |raw: &str| {
        semver::Version::parse(raw.trim().trim_start_matches('v')).map_err(|_| {
            UpdateError::VersionUnparseable {
                version: raw.to_owned(),
            }
        })
    };
    let current = parse(current)?;
    let target = parse(target)?;
    Ok(match target.cmp(&current) {
        Ordering::Equal => VersionDecision::UpToDate,
        Ordering::Greater => VersionDecision::Forward,
        Ordering::Less => VersionDecision::Downgrade,
    })
}

/// The self-update entry point (SC1). Full flow, structured so EVERY
/// verification gate completes before any swap (research Pattern 2 — never a
/// partial update):
///
/// 1. offline guard → explicit [`UpdateOutcome::Skipped`] BEFORE any client is
///    built (Pitfall 4).
/// 2. resolve the release per `[update]` channel/pin; semver-guard against the
///    running version → [`UpdateOutcome::UpToDate`] if equal, refuse a
///    downgrade unless `allow_downgrade`.
/// 3. download the platform archive + `SHA256SUMS` + `SHA256SUMS.sig`.
/// 4. gate 1: SHA-256 vs the manifest.
/// 5. gate 2: the manifest's detached cosign signature vs the embedded key.
/// 6. only now: extract + atomic self-replace.
///
/// Any failure in 3–5 aborts BEFORE 6 — the running binary is untouched. All
/// network is blocking `reqwest`, confined to this module (DEC-05), no async
/// (DEC-01). Typed [`UpdateError`] only — `anyhow` stays at the 08-05 CLI
/// boundary.
pub fn run(offline: bool, cfg: &UpdateConfig) -> Result<UpdateOutcome, UpdateError> {
    // 1. offline is a first-class no-op — short-circuit before ANY client.
    if offline || std::env::var_os("GETDEV_OFFLINE").is_some() {
        return Ok(UpdateOutcome::Skipped);
    }

    let client = build_download_client()?;
    let release = fetch_release(&client, cfg)?;
    let current = env!("CARGO_PKG_VERSION");
    let target_version = release.tag_name.trim_start_matches('v').to_owned();

    // 2. version guard BEFORE downloading anything.
    match compare_versions(current, &target_version)? {
        VersionDecision::UpToDate => {
            return Ok(UpdateOutcome::UpToDate {
                version: current.to_owned(),
            })
        }
        VersionDecision::Downgrade if !cfg.allow_downgrade => {
            return Err(UpdateError::DowngradeRefused {
                current: current.to_owned(),
                target: target_version,
            })
        }
        _ => {}
    }

    // resolve the three assets (own platform archive + shared manifest + sig).
    let archive_asset =
        asset_for_target(&release, TARGET_TRIPLE).ok_or_else(|| UpdateError::AssetNotFound {
            target: TARGET_TRIPLE.to_owned(),
        })?;
    let manifest_asset = asset_by_name(&release, MANIFEST_NAME).ok_or_else(|| {
        UpdateError::ManifestEntryMissing {
            asset: MANIFEST_NAME.to_owned(),
        }
    })?;
    let sig_asset = asset_by_name(&release, MANIFEST_SIG_NAME)
        .ok_or_else(|| UpdateError::Download(format!("release is missing {MANIFEST_SIG_NAME}")))?;

    // 3. download (blocking, bounded).
    let archive = download_bytes(&client, &archive_asset.browser_download_url)?;
    let manifest = download_bytes(&client, &manifest_asset.browser_download_url)?;
    let signature_b64 =
        String::from_utf8(download_bytes(&client, &sig_asset.browser_download_url)?).map_err(
            |_| UpdateError::Download(format!("{MANIFEST_SIG_NAME} was not valid UTF-8")),
        )?;

    let downloaded = DownloadedRelease {
        target_version,
        asset_name: archive_asset.name.clone(),
        archive,
        manifest,
        signature_b64,
    };

    // 4 + 5 + 6: verify-then-swap. The embedded key is 08-01's placeholder
    // until 08-08 wires the real release key.
    verify_then_apply(
        &downloaded,
        current,
        cfg.allow_downgrade,
        signature::EMBEDDED_COSIGN_PUBKEY,
        swap::apply_update,
    )
}

/// The pure verify-then-swap core (research Pattern 2). Given already-downloaded
/// bytes it runs the version guard + BOTH gates strictly in order, and only
/// then invokes `apply` (extract + self-replace). `apply` is injected so the
/// hermetic tests can prove it is UNREACHABLE on any failed gate without ever
/// replacing the test runner's own binary.
fn verify_then_apply(
    downloaded: &DownloadedRelease,
    current_version: &str,
    allow_downgrade: bool,
    pubkey_pem: &str,
    apply: impl FnOnce(&[u8]) -> Result<(), UpdateError>,
) -> Result<UpdateOutcome, UpdateError> {
    // Re-assert the version guard here too so this core is self-contained and
    // independently testable (cheap; the network path already guarded once).
    match compare_versions(current_version, &downloaded.target_version)? {
        VersionDecision::UpToDate => {
            return Ok(UpdateOutcome::UpToDate {
                version: current_version.to_owned(),
            })
        }
        VersionDecision::Downgrade if !allow_downgrade => {
            return Err(UpdateError::DowngradeRefused {
                current: current_version.to_owned(),
                target: downloaded.target_version.clone(),
            })
        }
        _ => {}
    }

    // gate 1: the archive's SHA-256 matches the manifest entry for it.
    let expected = checksum::parse_manifest_entry(&downloaded.manifest, &downloaded.asset_name)?;
    checksum::verify_checksum(&downloaded.archive, &expected)?;

    // gate 2: the manifest itself is signed by the embedded release key.
    signature::verify_detached(&downloaded.manifest, &downloaded.signature_b64, pubkey_pem)?;

    // Both gates passed — and ONLY now — extract + atomically swap.
    apply(&downloaded.archive)?;
    Ok(UpdateOutcome::Updated {
        from: current_version.to_owned(),
        to: downloaded.target_version.clone(),
    })
}

/// The blocking download client. Unlike the probe (fixed host, NO redirects),
/// asset downloads MUST follow GitHub's 302 from `github.com/.../releases/
/// download/...` to its asset CDN, so a bounded redirect policy is allowed;
/// the hop count is capped and the timeout is hard.
fn build_download_client() -> Result<reqwest::blocking::Client, UpdateError> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
        .user_agent(format!("getdev/{}", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| UpdateError::Download(e.to_string()))
}

/// Resolve the release to install per the `[update]` channel/pin:
/// * `pin` set → the exact tag (matched on the list endpoint, `v`-insensitive),
/// * `channel = "prerelease"` → the newest release including prereleases,
/// * otherwise (stable) → `/releases/latest` (excludes prereleases/drafts).
fn fetch_release(
    client: &reqwest::blocking::Client,
    cfg: &UpdateConfig,
) -> Result<FullReleaseResponse, UpdateError> {
    if let Some(pin) = &cfg.pin {
        let wanted = pin.trim().trim_start_matches('v');
        let releases: Vec<FullReleaseResponse> = get_json(client, &releases_list_url())?;
        return releases
            .into_iter()
            .find(|r| r.tag_name.trim_start_matches('v') == wanted)
            .ok_or_else(|| UpdateError::Download(format!("pinned release {pin} not found")));
    }

    if cfg.channel == "prerelease" {
        let releases: Vec<FullReleaseResponse> = get_json(client, &releases_list_url())?;
        return releases
            .into_iter()
            .next()
            .ok_or_else(|| UpdateError::Download("no releases published yet".to_owned()));
    }

    // Stable (default / any unrecognized channel — fail safe, never silently
    // opt into prereleases).
    get_json(client, &releases_api_url())
}

/// GET + parse JSON from a GitHub API endpoint, mapping any transport/status/
/// parse failure to a typed [`UpdateError::Download`]. A non-200 is never
/// treated as evidence about a release.
fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::blocking::Client,
    url: &str,
) -> Result<T, UpdateError> {
    let response = client
        .get(url)
        .send()
        .map_err(|e| UpdateError::Download(e.to_string()))?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(UpdateError::Download(format!(
            "github api returned status {status}"
        )));
    }
    response
        .json::<T>()
        .map_err(|e| UpdateError::Download(e.to_string()))
}

/// Download an asset's raw bytes (following the redirect to GitHub's asset
/// CDN). A non-success status aborts — the caller never verifies partial/error
/// bodies.
fn download_bytes(client: &reqwest::blocking::Client, url: &str) -> Result<Vec<u8>, UpdateError> {
    let response = client
        .get(url)
        .send()
        .map_err(|e| UpdateError::Download(e.to_string()))?;
    if !response.status().is_success() {
        return Err(UpdateError::Download(format!(
            "asset download returned status {}",
            response.status().as_u16()
        )));
    }
    response
        .bytes()
        .map(|b| b.to_vec())
        .map_err(|e| UpdateError::Download(e.to_string()))
}

/// Single source of truth for the CLI repo slug (audit F2) — `doctor.rs`
/// calls [`releases_page_url`] rather than hardcoding its own copy, so a
/// future repo move only ever needs one edit. Verified against `git remote
/// -v` at fix time: matches the actual origin.
const REPO_SLUG: &str = "getdev-ai/cli";
const REQUEST_TIMEOUT_SECS: u64 = 5;

fn releases_api_url() -> String {
    format!("https://api.github.com/repos/{REPO_SLUG}/releases/latest")
}

/// Human-facing releases page, shared with `doctor.rs`'s "outdated" row.
pub fn releases_page_url() -> String {
    format!("https://github.com/{REPO_SLUG}/releases")
}

/// Outcome of a version-vs-latest probe. `NoReleasesYet` (GitHub's 404 for a
/// repo with no published release) is distinct from `Unreachable` — the
/// project has no releases published yet pre-launch, and that is expected
/// state, not a failure (03-RESEARCH.md "Environment Availability").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseCheck {
    /// `--offline` / `GETDEV_OFFLINE=1` — no request was made.
    Skipped,
    UpToDate,
    Outdated {
        latest: String,
    },
    /// GitHub Releases returned 404 for `/releases/latest` — the repo has
    /// no published release yet. Pre-launch expected state, not a failure.
    NoReleasesYet,
    /// Transport error, timeout, or a non-200/404 status. Never treated as
    /// proof of anything about the release itself.
    Unreachable,
}

#[derive(Debug, Deserialize)]
struct ReleaseResponse {
    tag_name: String,
}

/// Probe GitHub Releases for the latest published `getdev` version. Fixed
/// host, no redirects, a 5s hard timeout — `offline` short-circuits before
/// any client is even built, so `--offline`/`GETDEV_OFFLINE=1` is provably
/// networkless here too, matching `getdev-registry`'s contract.
pub fn latest_release_version(offline: bool) -> ReleaseCheck {
    if offline || std::env::var_os("GETDEV_OFFLINE").is_some() {
        return ReleaseCheck::Skipped;
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .user_agent(format!("getdev/{}", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(_) => return ReleaseCheck::Unreachable,
    };

    let response = match client.get(releases_api_url()).send() {
        Ok(response) => response,
        Err(_) => return ReleaseCheck::Unreachable,
    };

    let status = response.status().as_u16();
    classify_status(status, || response.json::<ReleaseResponse>().ok())
}

/// The pure status-code -> [`ReleaseCheck`] mapping, pulled out of
/// [`latest_release_version`] so it is unit-testable without an actual HTTP
/// roundtrip (D5, 03-REVIEW.md): the previous integration test at this
/// contract only asserted an adjacent, always-true fact ("doctor doesn't
/// crash when the cache dir doesn't exist yet") while claiming 404
/// coverage it never exercised. Calling this function directly with a
/// synthetic status code exercises the exact same production code path
/// GitHub's real 404-for-no-releases-yet response would hit, with no mock
/// HTTP server required. `parse_body` is only invoked for a 200 status
/// (lazy — a 404/other status never attempts to parse a body that was
/// never fetched as JSON).
fn classify_status(
    status: u16,
    parse_body: impl FnOnce() -> Option<ReleaseResponse>,
) -> ReleaseCheck {
    match status {
        200 => parse_body().map_or(ReleaseCheck::Unreachable, |release| {
            classify(release.tag_name.trim_start_matches('v'))
        }),
        404 => ReleaseCheck::NoReleasesYet,
        _ => ReleaseCheck::Unreachable,
    }
}

fn classify(latest: &str) -> ReleaseCheck {
    if latest == env!("CARGO_PKG_VERSION") {
        ReleaseCheck::UpToDate
    } else {
        ReleaseCheck::Outdated {
            latest: latest.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn offline_flag_skips_without_building_a_client() {
        assert_eq!(latest_release_version(true), ReleaseCheck::Skipped);
    }

    #[test]
    fn classify_matches_current_version_as_up_to_date() {
        assert_eq!(classify(env!("CARGO_PKG_VERSION")), ReleaseCheck::UpToDate);
    }

    #[test]
    fn classify_differing_version_is_outdated() {
        assert_eq!(
            classify("999.999.999"),
            ReleaseCheck::Outdated {
                latest: "999.999.999".to_owned()
            }
        );
    }

    /// D5: genuine, hermetic coverage of the 404 path — GitHub Releases'
    /// 404-for-no-published-release-yet must map to `NoReleasesYet`, not
    /// `Unreachable` (pre-launch expected state, not a failure).
    #[test]
    fn status_404_is_no_releases_yet_not_a_failure() {
        assert_eq!(classify_status(404, || None), ReleaseCheck::NoReleasesYet);
    }

    #[test]
    fn status_500_is_unreachable_never_treated_as_release_evidence() {
        assert_eq!(classify_status(500, || None), ReleaseCheck::Unreachable);
    }

    #[test]
    fn status_200_with_an_unparseable_body_is_unreachable_not_a_crash() {
        assert_eq!(classify_status(200, || None), ReleaseCheck::Unreachable);
    }

    #[test]
    fn status_200_with_a_valid_release_body_classifies_normally() {
        assert_eq!(
            classify_status(200, || Some(ReleaseResponse {
                tag_name: "v999.999.999".to_owned()
            })),
            ReleaseCheck::Outdated {
                latest: "999.999.999".to_owned()
            }
        );
    }

    // ---- Self-update asset resolution (08-04) ----

    fn asset(name: &str) -> ReleaseAsset {
        ReleaseAsset {
            name: name.to_owned(),
            browser_download_url: format!(
                "https://github.com/getdev-ai/cli/releases/download/v1/{name}"
            ),
        }
    }

    fn release_with_assets(names: &[&str]) -> FullReleaseResponse {
        FullReleaseResponse {
            tag_name: "v0.1.2".to_owned(),
            prerelease: false,
            assets: names.iter().map(|n| asset(n)).collect(),
        }
    }

    #[test]
    fn asset_for_target_picks_the_matching_archive() {
        let release = release_with_assets(&[
            "getdev-aarch64-apple-darwin.tar.xz",
            "getdev-aarch64-apple-darwin.tar.xz.sha256",
            "getdev-x86_64-unknown-linux-gnu.tar.xz",
            "SHA256SUMS",
            "SHA256SUMS.sig",
        ]);
        let found = asset_for_target(&release, "aarch64-apple-darwin").unwrap();
        assert_eq!(found.name, "getdev-aarch64-apple-darwin.tar.xz");
    }

    #[test]
    fn asset_for_target_never_returns_a_checksum_or_manifest() {
        // Only the sidecar `.sha256` and the manifest are present for this
        // triple — there is NO real archive, so resolution must be `None`
        // rather than mistakenly returning the checksum/manifest file.
        let release = release_with_assets(&[
            "getdev-aarch64-apple-darwin.tar.xz.sha256",
            "SHA256SUMS",
            "SHA256SUMS.sig",
        ]);
        assert!(asset_for_target(&release, "aarch64-apple-darwin").is_none());
    }

    #[test]
    fn asset_for_target_absent_platform_is_none() {
        let release = release_with_assets(&["getdev-x86_64-unknown-linux-gnu.tar.xz"]);
        assert!(asset_for_target(&release, "aarch64-apple-darwin").is_none());
    }

    #[test]
    fn asset_by_name_resolves_the_manifest_and_signature() {
        let release = release_with_assets(&[
            "getdev-aarch64-apple-darwin.tar.xz",
            "SHA256SUMS",
            "SHA256SUMS.sig",
        ]);
        assert_eq!(
            asset_by_name(&release, "SHA256SUMS").unwrap().name,
            "SHA256SUMS"
        );
        assert_eq!(
            asset_by_name(&release, "SHA256SUMS.sig").unwrap().name,
            "SHA256SUMS.sig"
        );
        assert!(asset_by_name(&release, "nope").is_none());
    }

    #[test]
    fn target_triple_is_populated_by_build_script() {
        // build.rs injects the running platform's triple; it must be a non-empty
        // arch-vendor-os string so the asset resolver has something to match.
        assert!(!TARGET_TRIPLE.is_empty());
        assert!(TARGET_TRIPLE.contains('-'));
    }

    // ---- Version guard / downgrade decision (08-04) ----

    #[test]
    fn compare_versions_orders_forward_equal_and_downgrade() {
        assert_eq!(
            compare_versions("0.1.0", "0.1.2").unwrap(),
            VersionDecision::Forward
        );
        assert_eq!(
            compare_versions("0.1.2", "0.1.2").unwrap(),
            VersionDecision::UpToDate
        );
        assert_eq!(
            compare_versions("0.2.0", "0.1.9").unwrap(),
            VersionDecision::Downgrade
        );
    }

    #[test]
    fn compare_versions_respects_prerelease_precedence() {
        // A real release (0.1.0) is NEWER than the current pre-release build
        // (0.1.0-dev) — naive numeric compare would call this "equal".
        assert_eq!(
            compare_versions("0.1.0-dev", "0.1.0").unwrap(),
            VersionDecision::Forward
        );
    }

    #[test]
    fn compare_versions_unparseable_fails_closed() {
        assert!(matches!(
            compare_versions("0.1.0", "not-a-version"),
            Err(UpdateError::VersionUnparseable { .. })
        ));
    }

    // ---- Offline no-op (08-04): short-circuits before any client ----

    #[test]
    fn run_offline_is_a_skip_no_op() {
        let cfg = UpdateConfig::default();
        // No network: this must return Skipped purely from the guard.
        assert_eq!(run(true, &cfg), Ok(UpdateOutcome::Skipped));
    }

    // ---- verify-then-swap ordering: the swap is UNREACHABLE on a failed gate,
    //      proven with an injected `apply` that records whether it was called.
    //      All hermetic: manifests are crafted and signed with an in-test key
    //      (no network, no committed fixtures beyond the crypto vector). ----

    use base64::Engine as _;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::{EncodePublicKey, LineEnding};
    use sha2::{Digest, Sha256};

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    /// Sign `manifest` exactly the way `verify_detached` expects (base64(DER
    /// ECDSA-P256) over sha256(manifest)) using a deterministic in-test key,
    /// returning `(signature_b64, public_key_pem)`.
    fn sign_manifest(manifest: &[u8], key_seed: [u8; 32]) -> (String, String) {
        let signing = SigningKey::from_slice(&key_seed).unwrap();
        let prehash = Sha256::digest(manifest);
        let sig: Signature = signing.sign_prehash(&prehash).unwrap();
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes());
        let pem = signing
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        (sig_b64, pem)
    }

    struct ApplySpy {
        called: std::cell::Cell<bool>,
    }
    impl ApplySpy {
        fn new() -> Self {
            Self {
                called: std::cell::Cell::new(false),
            }
        }
        fn apply(&self) -> impl FnOnce(&[u8]) -> Result<(), UpdateError> + '_ {
            move |_bytes: &[u8]| {
                self.called.set(true);
                Ok(())
            }
        }
    }

    const ASSET: &str = "getdev-test.tar.xz";
    const CURRENT: &str = "0.1.0";

    #[test]
    fn downgrade_refused_before_any_gate_or_swap() {
        let archive = b"archive-bytes";
        let manifest = format!("{}  {ASSET}\n", sha256_hex(archive)).into_bytes();
        let (sig, pem) = sign_manifest(&manifest, [3u8; 32]);
        let dl = DownloadedRelease {
            target_version: "0.0.9".to_owned(), // OLDER than CURRENT (0.1.0)
            asset_name: ASSET.to_owned(),
            archive: archive.to_vec(),
            manifest,
            signature_b64: sig,
        };
        let spy = ApplySpy::new();
        let res = verify_then_apply(&dl, CURRENT, false, &pem, spy.apply());
        assert!(matches!(res, Err(UpdateError::DowngradeRefused { .. })));
        assert!(
            !spy.called.get(),
            "swap must not run on a refused downgrade"
        );
    }

    #[test]
    fn downgrade_allowed_proceeds_past_the_version_check() {
        // allow_downgrade=true: the older target passes the version guard and
        // the flow reaches gate 1 (which here fails on a bad checksum) —
        // proving the guard was bypassed, not that the whole update succeeds.
        let archive = b"archive-bytes";
        let manifest = format!("{}  {ASSET}\n", sha256_hex(b"DIFFERENT")).into_bytes();
        let (sig, pem) = sign_manifest(&manifest, [4u8; 32]);
        let dl = DownloadedRelease {
            target_version: "0.0.9".to_owned(),
            asset_name: ASSET.to_owned(),
            archive: archive.to_vec(),
            manifest,
            signature_b64: sig,
        };
        let spy = ApplySpy::new();
        let res = verify_then_apply(&dl, CURRENT, true, &pem, spy.apply());
        assert!(
            matches!(res, Err(UpdateError::ChecksumMismatch { .. })),
            "with allow_downgrade it should get PAST the version guard to gate 1"
        );
        assert!(!spy.called.get());
    }

    #[test]
    fn checksum_mismatch_aborts_before_swap() {
        let archive = b"the-real-archive";
        // Manifest records the hash of DIFFERENT bytes → gate 1 fails.
        let manifest = format!("{}  {ASSET}\n", sha256_hex(b"tampered")).into_bytes();
        let (sig, pem) = sign_manifest(&manifest, [5u8; 32]);
        let dl = DownloadedRelease {
            target_version: "9.9.9".to_owned(), // forward, so version guard passes
            asset_name: ASSET.to_owned(),
            archive: archive.to_vec(),
            manifest,
            signature_b64: sig,
        };
        let spy = ApplySpy::new();
        let res = verify_then_apply(&dl, CURRENT, false, &pem, spy.apply());
        assert!(matches!(res, Err(UpdateError::ChecksumMismatch { .. })));
        assert!(!spy.called.get(), "swap must not run on a checksum failure");
    }

    #[test]
    fn signature_mismatch_aborts_before_swap() {
        let archive = b"the-real-archive";
        // Correct checksum (gate 1 passes) …
        let manifest = format!("{}  {ASSET}\n", sha256_hex(archive)).into_bytes();
        // … but sign with key A and VERIFY against key B → gate 2 fails.
        let (sig, _pem_a) = sign_manifest(&manifest, [6u8; 32]);
        let (_sig_b, pem_b) = sign_manifest(&manifest, [7u8; 32]);
        let dl = DownloadedRelease {
            target_version: "9.9.9".to_owned(),
            asset_name: ASSET.to_owned(),
            archive: archive.to_vec(),
            manifest,
            signature_b64: sig,
        };
        let spy = ApplySpy::new();
        let res = verify_then_apply(&dl, CURRENT, false, &pem_b, spy.apply());
        assert!(matches!(res, Err(UpdateError::SignatureMismatch)));
        assert!(
            !spy.called.get(),
            "swap must not run on a signature failure"
        );
    }

    #[test]
    fn both_gates_pass_then_and_only_then_apply_runs() {
        let archive = b"the-verified-archive-bytes";
        let manifest = format!("{}  {ASSET}\n", sha256_hex(archive)).into_bytes();
        let (sig, pem) = sign_manifest(&manifest, [8u8; 32]);
        let dl = DownloadedRelease {
            target_version: "9.9.9".to_owned(),
            asset_name: ASSET.to_owned(),
            archive: archive.to_vec(),
            manifest,
            signature_b64: sig,
        };
        let spy = ApplySpy::new();
        let res = verify_then_apply(&dl, CURRENT, false, &pem, spy.apply());
        assert_eq!(
            res,
            Ok(UpdateOutcome::Updated {
                from: CURRENT.to_owned(),
                to: "9.9.9".to_owned()
            })
        );
        assert!(spy.called.get(), "apply must run once both gates pass");
    }
}
