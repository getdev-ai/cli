//! WR-03: PEP 503 name normalization is implemented twice — once in
//! `getdev-core` (`deps::normalize_pep503`, which builds the lookup key the
//! CLI hands to the registry) and once in `getdev-registry`
//! (`client::normalize_pep503`, which builds the cache/typosquat key). Core
//! must NOT depend on registry (docs/ARCHITECTURE.md fixed dependency
//! direction), so the copy is a deliberate mirror rather than a shared fn.
//!
//! A mirror that can silently diverge is a latent bug: if one copy is edited
//! (e.g. to strip leading/trailing separators) the CLI would key lookups
//! under one normalization while the cache stores/reads under another, so
//! `Django`/`django` could stop sharing a cache row (03-RESEARCH.md Pitfall
//! 3, resurfacing silently). `getdev` (the CLI) is the one crate that depends
//! on BOTH, so it is the natural place to pin the two against a shared vector
//! table. If this test ever fails, the two implementations have drifted and
//! MUST be reconciled before release.

use getdev_core::deps::normalize_pep503 as core_normalize;
use getdev_registry::normalize_pep503 as registry_normalize;

/// (input, expected PEP 503 normal form) vectors exercised through BOTH
/// implementations. Covers case folding, each separator (`-`/`_`/`.`), and
/// collapsing of mixed/repeated separator runs.
const VECTORS: &[(&str, &str)] = &[
    ("Django", "django"),
    ("django", "django"),
    ("DJANGO", "django"),
    ("typing_extensions", "typing-extensions"),
    ("typing-extensions", "typing-extensions"),
    ("Typing_Extensions", "typing-extensions"),
    ("a..b__c--d", "a-b-c-d"),
    ("a..b__c", "a-b-c"),
    ("ruamel.yaml", "ruamel-yaml"),
    ("zope.interface", "zope-interface"),
    ("Flask-SQLAlchemy", "flask-sqlalchemy"),
    ("PyYAML", "pyyaml"),
    ("backports.zoneinfo", "backports-zoneinfo"),
    ("A_-.B", "a-b"),
    ("", ""),
    ("no-separators-here", "no-separators-here"),
    ("UPPER_lower.Mixed", "upper-lower-mixed"),
];

#[test]
fn core_and_registry_pep503_agree_on_shared_vectors() {
    for (input, expected) in VECTORS {
        let core = core_normalize(input);
        let registry = registry_normalize(input);
        assert_eq!(
            core, *expected,
            "getdev-core normalize_pep503({input:?}) diverged from expected"
        );
        assert_eq!(
            registry, *expected,
            "getdev-registry normalize_pep503({input:?}) diverged from expected"
        );
        assert_eq!(
            core, registry,
            "core and registry normalize_pep503 disagree on {input:?} \
             (cache-key drift risk — reconcile both copies)"
        );
    }
}
