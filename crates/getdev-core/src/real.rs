//! Network-free `real` finding builders (docs/PLAN.md §2.3, the six
//! contractual `real/*` rule IDs). **This module imports NO
//! `getdev_registry` type** — docs/ARCHITECTURE.md fixes the crate
//! dependency direction (`getdev-core` depends only on `getdev-grammars`),
//! so every builder here takes plain DATA that the CLI tier
//! (`getdev-cli::commands::real`, the only crate allowed to call the
//! registry) fills in from the real `getdev_registry::RegistryVerdict`.
//!
//! Contractual rule IDs (do not deviate — 03-PATTERNS.md used stale names):
//! `real/nonexistent-package`, `real/typosquat-suspect`,
//! `real/phantom-import`, `real/nonexistent-api`, `real/version-mismatch-api`,
//! `real/unknown-model-string`.

use crate::apisurface::{ApiResult, ApiResultKind, SurfaceTier};
use crate::deps::{ImportRef, ImportResolution, StackHint};
use crate::findings::{Confidence, Finding, Severity};
use crate::models::ModelVerdict;

/// Which check groups a `real` run covers — the CLI narrows this for
/// `--deps-only`/`--apis-only`/`--models-only`; all `true` is a full run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealScope {
    pub deps: bool,
    pub apis: bool,
    pub models: bool,
}

impl Default for RealScope {
    fn default() -> Self {
        Self {
            deps: true,
            apis: true,
            models: true,
        }
    }
}

/// A core-local mirror of `getdev_registry::Existence` — plain data, no
/// dependency on the registry crate's type. `Inconclusive` (network
/// failure/timeout/offline-miss) must NEVER be treated as `Missing`: a
/// finding fabricated from a failed lookup is worse than no finding at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistenceLite {
    Found,
    Missing,
    Inconclusive,
}

/// A core-local mirror of `getdev_registry::TyposquatHit` — plain data,
/// `reasons` already rendered to human-readable strings so this module
/// never depends on `getdev_registry::TyposquatReason`.
#[derive(Debug, Clone)]
pub struct TyposquatLite {
    pub nearest: String,
    pub distance: usize,
    pub reasons: Vec<String>,
}

/// Everything `nonexistent_package_finding`/`typosquat_finding` need for one
/// declared-or-imported package name, filled in by the CLI tier from a
/// `RegistryVerdict` plus the `deps` reconciliation.
#[derive(Debug, Clone)]
pub struct PackageVerdictInput {
    /// "npm" | "pypi" — display only
    pub ecosystem: String,
    pub name: String,
    /// project-relative path, forward slashes
    pub file: String,
    pub line: Option<u32>,
    pub existence: ExistenceLite,
    pub downloads: Option<u64>,
    pub created_at: Option<i64>,
    pub typosquat: Option<TyposquatLite>,
    /// present in a manifest/lockfile
    pub declared: bool,
    /// found at an import/require site
    pub imported: bool,
}

/// `real/nonexistent-package` — critical/high confidence, but ONLY when
/// `existence == Missing`. `Inconclusive` (a network failure, timeout, or
/// offline cache-miss) yields NO finding: a 5xx or an unreachable registry
/// is never proof the package doesn't exist (the network-failure guard,
/// T-3-14).
pub fn nonexistent_package_finding(input: &PackageVerdictInput) -> Option<Finding> {
    if input.existence != ExistenceLite::Missing {
        return None;
    }
    let where_found = match (input.declared, input.imported) {
        (true, true) => "declared in the manifest and imported",
        (true, false) => "declared in the manifest",
        (false, true) => "imported",
        (false, false) => "referenced",
    };
    // A15: "did you mean" — the CLI-supplied typosquat hit already carries
    // the embedded top-N dataset's nearest name; a distance of 1-2 is the
    // same near-name threshold `typosquat::score` uses to fire its own
    // `NearName` reason, so any hit with that distance implies a
    // genuinely close candidate exists (never surfaced for a hit that only
    // fired on low-downloads/new-package heuristics against a distant
    // nearest name).
    let suggestion = input
        .typosquat
        .as_ref()
        .filter(|hit| (1..=2).contains(&hit.distance))
        .map(|hit| format!("did you mean '{}'?", hit.nearest));
    Some(Finding {
        id: "real/nonexistent-package".to_owned(),
        command: "real".to_owned(),
        severity: Severity::Critical,
        confidence: Confidence::High,
        file: input.file.clone(),
        line: input.line,
        column: None,
        end_line: input.line,
        message: format!(
            "Package '{}' does not exist on {}",
            input.name, input.ecosystem
        ),
        detail: Some(format!(
            "{where_found}. No package with this name has ever been published on {}.",
            input.ecosystem
        )),
        suggestion,
        remediation: Some(
            "remove the dependency or replace it with a real package providing the needed \
             functionality"
                .to_owned(),
        ),
        fixable: false,
        refs: vec!["https://getdev.ai/rules/real/nonexistent-package".to_owned()],
        fingerprint: None,
    })
}

/// `real/typosquat-suspect` — high severity/medium confidence, present only
/// when the CLI-supplied `TyposquatLite` fired. `detail` surfaces every
/// heuristic reason (near-name distance / low downloads / new package) per
/// FP policy §9.2 — heuristic rules must show their reasoning.
pub fn typosquat_finding(input: &PackageVerdictInput) -> Option<Finding> {
    let hit = input.typosquat.as_ref()?;
    let reasons = hit.reasons.join(", ");
    Some(Finding {
        id: "real/typosquat-suspect".to_owned(),
        command: "real".to_owned(),
        severity: Severity::High,
        confidence: Confidence::Medium,
        file: input.file.clone(),
        line: input.line,
        column: None,
        end_line: input.line,
        message: format!(
            "'{}' closely resembles the popular package '{}'",
            input.name, hit.nearest
        ),
        detail: Some(format!(
            "flagged because: {reasons} (nearest match: '{}', edit distance {})",
            hit.nearest, hit.distance
        )),
        suggestion: Some(format!("did you mean '{}'?", hit.nearest)),
        remediation: Some(format!(
            "confirm '{}' is the package you intended; if not, replace it with '{}'",
            input.name, hit.nearest
        )),
        fixable: false,
        refs: vec!["https://getdev.ai/rules/real/typosquat-suspect".to_owned()],
        fingerprint: None,
    })
}

/// `real/phantom-import` — high/high, for imports that resolve to neither a
/// declared dependency, a language builtin, nor a local module. Returns
/// `None` for anything but `ImportResolution::Phantom` so callers can map
/// every `ImportRef` through this without pre-filtering.
pub fn phantom_import_finding(import_ref: &ImportRef) -> Option<Finding> {
    if import_ref.resolution != ImportResolution::Phantom {
        return None;
    }
    Some(Finding {
        id: "real/phantom-import".to_owned(),
        command: "real".to_owned(),
        severity: Severity::High,
        confidence: Confidence::High,
        file: import_ref.file.clone(),
        line: Some(import_ref.line),
        column: None,
        end_line: Some(import_ref.line),
        message: format!(
            "Import '{}' resolves to no declared dependency, builtin, or local module",
            import_ref.module
        ),
        detail: Some(
            "this import is neither a manifest-declared package, a language builtin, nor a \
             local project module — a likely hallucinated or since-removed dependency"
                .to_owned(),
        ),
        suggestion: None,
        remediation: Some(format!(
            "declare '{}' as a dependency, or remove the import if it was never needed",
            import_ref.module
        )),
        fixable: false,
        refs: vec!["https://getdev.ai/rules/real/phantom-import".to_owned()],
        fingerprint: None,
    })
}

/// `real/unknown-model-string` — medium/medium, for a literal the
/// `models::ModelMatcher` could not match to any known vendor family.
pub fn unknown_model_finding(
    model_verdict: &ModelVerdict,
    file: &str,
    line: Option<u32>,
) -> Finding {
    Finding {
        id: "real/unknown-model-string".to_owned(),
        command: "real".to_owned(),
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        file: file.to_owned(),
        line,
        column: None,
        end_line: line,
        message: format!(
            "Model string '{}' matches no known vendor family",
            model_verdict.literal
        ),
        detail: Some(
            "no vendor family prefix (Anthropic/OpenAI/Google/Mistral/Meta/Cohere/xAI/DeepSeek) \
             matched this literal — it may be a hallucinated, deprecated, or newly-released \
             model id"
                .to_owned(),
        ),
        suggestion: model_verdict.nearest_family.clone(),
        remediation: Some(
            "verify this model id exists with the provider before shipping".to_owned(),
        ),
        fixable: false,
        refs: vec!["https://getdev.ai/rules/real/unknown-model-string".to_owned()],
        fingerprint: None,
    }
}

/// `real/nonexistent-api` / `real/version-mismatch-api` — maps every
/// `apisurface::ApiResult` straight through, deriving each finding's
/// *severity* from the surface tier `apisurface::check` computed (audit A2):
/// a [`SurfaceTier::Resolved`] exact miss is `high` severity; every other
/// tier (`Dynamic`/`NotInstalled`/`Unreadable`) downgrades to `info` per
/// docs/PLAN.md §2.3 ("dynamic/`__getattr__`-style packages downgraded to
/// `info` with a note") — confidence is carried through unchanged from
/// `result.confidence`, never re-derived here.
pub fn api_findings(api_results: &[ApiResult]) -> Vec<Finding> {
    api_results.iter().map(api_finding).collect()
}

fn api_finding(result: &ApiResult) -> Finding {
    let id = match result.kind {
        ApiResultKind::NonexistentApi => "real/nonexistent-api",
        ApiResultKind::VersionMismatchApi => "real/version-mismatch-api",
    };
    let severity = match result.tier {
        SurfaceTier::Resolved => Severity::High,
        SurfaceTier::Dynamic | SurfaceTier::NotInstalled | SurfaceTier::Unreadable => {
            Severity::Info
        }
    };
    // A3: an aggregated NotInstalled/Unreadable result rolls up every usage
    // site of the package into one finding with NO single member to name
    // (`apisurface::check` always sets `member: String::new()` for these,
    // regardless of how many usage sites were rolled up — audit-exposed
    // residual bug, corpus fix pass 7: discriminating on `usage_count > 1`
    // left the `usage_count == 1` aggregated case falling through to the
    // per-usage-site branch below with an empty member, producing a
    // dangling-dot message like "'acme-metrics.' does not exist"). The
    // correct discriminator is whether there IS a member to name at all.
    let (message, remediation) = if result.member.is_empty() {
        (
            format!(
                "could not verify {} usage(s) of '{}' on the installed package's surface",
                result.usage_count, result.package
            ),
            format!(
                "verify these usages manually, or install/upgrade '{}' so its surface can be \
                 checked",
                result.package
            ),
        )
    } else {
        (
            format!(
                "'{}.{}' does not exist on the installed package's surface",
                result.package, result.member
            ),
            format!(
                "verify '{}' exists in the installed version of '{}', or pin/upgrade to a \
                 version that has it",
                result.member, result.package
            ),
        )
    };
    Finding {
        id: id.to_owned(),
        command: "real".to_owned(),
        severity,
        confidence: result.confidence,
        file: result.file.clone(),
        line: Some(result.line),
        column: None,
        end_line: Some(result.line),
        message,
        detail: Some(result.detail.clone()),
        suggestion: None,
        remediation: Some(remediation),
        fixable: false,
        refs: vec![format!("https://getdev.ai/rules/{id}")],
        fingerprint: None,
    }
}

/// An explicit info finding for an unsupported stack (REQ-language-support,
/// docs/ARCHITECTURE.md §3.3) — never a silent, empty partial result.
pub fn unsupported_stack_finding(stack_hint: &StackHint) -> Finding {
    Finding {
        id: "real/unsupported-stack".to_owned(),
        command: "real".to_owned(),
        severity: Severity::Info,
        confidence: Confidence::High,
        file: ".".to_owned(),
        line: None,
        column: None,
        end_line: None,
        message: format!(
            "'{}' stack not yet supported for deep analysis",
            stack_hint.detected
        ),
        detail: Some(
            "getdev real currently analyzes JavaScript/TypeScript and Python projects only; \
             this project's dominant language was not recognized (docs/ARCHITECTURE.md \
             language support matrix)"
                .to_owned(),
        ),
        suggestion: None,
        remediation: None,
        fixable: false,
        refs: vec!["https://getdev.ai/rules/real/unsupported-stack".to_owned()],
        fingerprint: None,
    }
}
