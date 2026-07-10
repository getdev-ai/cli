//! Integration tests for `getdev-core::real`'s pure, network-free finding
//! builders (docs/PLAN.md §2.3). Asserts the network-failure guard
//! (`Inconclusive` never fabricates a finding), the contractual rule IDs,
//! and that heuristic reasoning + apisurface confidence tiers survive the
//! mapping into `Finding`.

#![allow(clippy::unwrap_used)]

use getdev_core::apisurface::{ApiResult, ApiResultKind};
use getdev_core::deps::{Ecosystem, ImportRef, ImportResolution};
use getdev_core::findings::{Confidence, Severity};
use getdev_core::real::{
    api_findings, nonexistent_package_finding, phantom_import_finding, typosquat_finding,
    ExistenceLite, PackageVerdictInput, TyposquatLite,
};

fn package_input(existence: ExistenceLite) -> PackageVerdictInput {
    PackageVerdictInput {
        ecosystem: "pypi".to_owned(),
        name: "requests-auth-helper".to_owned(),
        file: "requirements.txt".to_owned(),
        line: Some(12),
        existence,
        downloads: None,
        created_at: None,
        typosquat: None,
        declared: true,
        imported: true,
    }
}

#[test]
fn missing_existence_yields_a_critical_nonexistent_package_finding() {
    let input = package_input(ExistenceLite::Missing);
    let finding = nonexistent_package_finding(&input).unwrap();
    assert_eq!(finding.id, "real/nonexistent-package");
    assert_eq!(finding.command, "real");
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::High);
    assert!(!finding.fixable);
}

#[test]
fn inconclusive_existence_never_fabricates_a_finding() {
    // The network-failure guard (T-3-14): a 5xx/timeout/offline-miss must
    // NEVER be treated as proof a package doesn't exist.
    let input = package_input(ExistenceLite::Inconclusive);
    assert!(nonexistent_package_finding(&input).is_none());
}

#[test]
fn found_existence_never_fabricates_a_finding() {
    let input = package_input(ExistenceLite::Found);
    assert!(nonexistent_package_finding(&input).is_none());
}

#[test]
fn typosquat_finding_surfaces_its_heuristic_reasons() {
    let mut input = package_input(ExistenceLite::Found);
    input.typosquat = Some(TyposquatLite {
        nearest: "requests".to_owned(),
        distance: 2,
        reasons: vec![
            "near-name distance 2".to_owned(),
            "low downloads".to_owned(),
        ],
    });
    let finding = typosquat_finding(&input).unwrap();
    assert_eq!(finding.id, "real/typosquat-suspect");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Medium);
    let detail = finding.detail.unwrap();
    assert!(detail.contains("near-name distance 2"));
    assert!(detail.contains("low downloads"));
    assert!(finding.suggestion.unwrap().contains("requests"));
}

#[test]
fn no_typosquat_hit_yields_no_finding() {
    let input = package_input(ExistenceLite::Found);
    assert!(typosquat_finding(&input).is_none());
}

#[test]
fn phantom_import_is_flagged_high_high() {
    let import_ref = ImportRef {
        module: "totally-hallucinated-pkg".to_owned(),
        file: "src/app.py".to_owned(),
        line: 4,
        ecosystem: Ecosystem::Pypi,
        resolution: ImportResolution::Phantom,
    };
    let finding = phantom_import_finding(&import_ref).unwrap();
    assert_eq!(finding.id, "real/phantom-import");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::High);
    assert_eq!(finding.file, "src/app.py");
    assert_eq!(finding.line, Some(4));
}

#[test]
fn non_phantom_imports_never_fire() {
    for resolution in [
        ImportResolution::Declared,
        ImportResolution::Builtin,
        ImportResolution::Local,
    ] {
        let import_ref = ImportRef {
            module: "os".to_owned(),
            file: "src/app.py".to_owned(),
            line: 1,
            ecosystem: Ecosystem::Pypi,
            resolution,
        };
        assert!(phantom_import_finding(&import_ref).is_none());
    }
}

#[test]
fn api_findings_preserve_confidence_tier_and_map_kind_to_rule_id() {
    let results = vec![
        ApiResult {
            kind: ApiResultKind::NonexistentApi,
            package: "typed-pkg".to_owned(),
            member: "fakeFn".to_owned(),
            file: "src/a.ts".to_owned(),
            line: 2,
            confidence: Confidence::High,
            detail: "'fakeFn' is not present in typed-pkg's statically enumerated exports"
                .to_owned(),
        },
        ApiResult {
            kind: ApiResultKind::NonexistentApi,
            package: "dynamic-pkg".to_owned(),
            member: "anything".to_owned(),
            file: "main.py".to_owned(),
            line: 1,
            confidence: Confidence::Low,
            detail: "dynamic-pkg's surface could not be fully resolved statically".to_owned(),
        },
    ];
    let findings = api_findings(&results);
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].id, "real/nonexistent-api");
    assert_eq!(findings[0].confidence, Confidence::High);
    assert_eq!(findings[1].confidence, Confidence::Low);
    assert!(findings[1]
        .detail
        .as_ref()
        .unwrap()
        .contains("could not be fully resolved"));
}

#[test]
fn version_mismatch_kind_maps_to_its_own_rule_id() {
    let results = vec![ApiResult {
        kind: ApiResultKind::VersionMismatchApi,
        package: "some-pkg".to_owned(),
        member: "oldFn".to_owned(),
        file: "src/a.ts".to_owned(),
        line: 3,
        confidence: Confidence::High,
        detail: "exists in another major version".to_owned(),
    }];
    let findings = api_findings(&results);
    assert_eq!(findings[0].id, "real/version-mismatch-api");
}

#[test]
fn findings_json_never_contains_internal_transport_details() {
    // Masking-discipline generalization (docs/SPEC-FINDINGS.md): findings
    // never leak an HTTP body or a local cache filesystem path — the plain
    // data structs `real` builders consume simply carry no such fields, so
    // this pins that invariant down at the JSON boundary.
    let input = package_input(ExistenceLite::Missing);
    let finding = nonexistent_package_finding(&input).unwrap();
    let json = serde_json::to_string(&finding).unwrap();
    for leaked in ["cache.sqlite3", "http://", "https://registry.npmjs.org"] {
        assert!(
            !json.contains(leaked),
            "leaked '{leaked}' into finding JSON"
        );
    }
}
