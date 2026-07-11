//! GitHub Releases version probe.
//!
//! This is the ONLY place `getdev-cli` itself touches the network
//! (docs/ARCHITECTURE.md "Network boundary rule", DEC-05 — every other
//! network call in the workspace lives in `getdev-registry`). This module is
//! deliberately small: it is the seed of Phase 8's full self-update module,
//! not that module itself.

use std::time::Duration;

use serde::Deserialize;

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

    match response.status().as_u16() {
        200 => response
            .json::<ReleaseResponse>()
            .ok()
            .map_or(ReleaseCheck::Unreachable, |release| {
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
}
