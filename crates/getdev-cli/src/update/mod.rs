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

use std::time::Duration;

use serde::Deserialize;

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
pub fn asset_by_name<'a>(
    release: &'a FullReleaseResponse,
    name: &str,
) -> Option<&'a ReleaseAsset> {
    release.assets.iter().find(|a| a.name == name)
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
            browser_download_url: format!("https://github.com/getdev-ai/cli/releases/download/v1/{name}"),
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
        assert_eq!(asset_by_name(&release, "SHA256SUMS").unwrap().name, "SHA256SUMS");
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
}
