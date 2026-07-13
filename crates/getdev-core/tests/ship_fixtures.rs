//! Fixture gate for `core::ship`'s three PROGRAMMATIC validators
//! (`ship/missing-env-declaration`, `ship/hardcoded-port`,
//! `ship/blocking-findings`) — the audit/review ≥3-positive + ≥3-negative
//! fixture discipline (CLAUDE.md rule 3) applied to hand-written Rust
//! detectors rather than YAML `fixtures:` blocks.
//!
//! Unlike `audit_fixtures.rs` (which discovers `rules/audit/*.yaml`), ship's
//! checks are code, not data — so each fixture here is an inline temp project
//! (source files ± a `.env.example`) run through a real
//! [`ScanContext`], with the assertion that every positive fires its expected
//! `ship/<id>` finding and every negative is silent.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use getdev_core::scan::ScanContext;
use getdev_core::ship::{blocking_findings, hardcoded_port, missing_env_declaration};

/// Materialize an inline temp project: each `(relative_path, contents)` pair
/// is written under a fresh, per-test-name tempdir (nested paths created as
/// needed). Returns the project root.
fn project(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "getdev-ship-fixtures-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (name, contents) in files {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }
    dir
}

fn ids(findings: &[getdev_core::findings::Finding]) -> Vec<String> {
    findings.iter().map(|f| f.id.clone()).collect()
}

// ---------------------------------------------------------------------------
// ship/missing-env-declaration — ≥3 positive + ≥3 negative
// ---------------------------------------------------------------------------

/// Each positive is a source file referencing an env var, WITHOUT a
/// `.env.example` declaring it. Spans JS member access, JS subscript access,
/// and Python `os.getenv`.
const MISSING_ENV_POSITIVES: &[(&str, &[(&str, &str)])] = &[
    (
        "js-member",
        &[("app.js", "const a = process.env.UNDECLARED_A;\n")],
    ),
    (
        "js-subscript",
        &[("app.js", "const b = process.env[\"UNDECLARED_B\"];\n")],
    ),
    (
        "py-getenv",
        &[("app.py", "import os\nc = os.getenv(\"UNDECLARED_C\")\n")],
    ),
];

/// Each negative either declares the referenced var in `.env.example`, or
/// references no env var at all.
const MISSING_ENV_NEGATIVES: &[(&str, &[(&str, &str)])] = &[
    (
        "js-declared",
        &[
            ("app.js", "const a = process.env.DECLARED_A;\n"),
            (".env.example", "DECLARED_A=\n"),
        ],
    ),
    (
        "py-declared",
        &[
            ("app.py", "import os\nc = os.environ[\"DECLARED_C\"]\n"),
            (
                ".env.example",
                "# a comment\nexport DECLARED_C=some-default\n",
            ),
        ],
    ),
    (
        "no-env-access",
        &[("app.js", "function pure() { return 1 + 2; }\n")],
    ),
];

#[test]
fn missing_env_declaration_fixtures_pos_and_neg() {
    assert!(MISSING_ENV_POSITIVES.len() >= 3);
    assert!(MISSING_ENV_NEGATIVES.len() >= 3);

    for (tag, files) in MISSING_ENV_POSITIVES {
        let dir = project(&format!("missing-env-pos-{tag}"), files);
        let ctx = ScanContext::build(&dir).unwrap();
        let findings = missing_env_declaration(&ctx, &dir);
        assert!(
            findings
                .iter()
                .any(|f| f.id == "ship/missing-env-declaration"),
            "positive `{tag}` must fire ship/missing-env-declaration, got {:?}",
            ids(&findings)
        );
    }

    for (tag, files) in MISSING_ENV_NEGATIVES {
        let dir = project(&format!("missing-env-neg-{tag}"), files);
        let ctx = ScanContext::build(&dir).unwrap();
        let findings = missing_env_declaration(&ctx, &dir);
        assert!(
            findings.is_empty(),
            "negative `{tag}` must be silent, got {:?}",
            ids(&findings)
        );
    }
}

// ---------------------------------------------------------------------------
// ship/hardcoded-port — ≥3 positive + ≥3 negative
// ---------------------------------------------------------------------------

const HARDCODED_PORT_POSITIVES: &[(&str, &[(&str, &str)])] = &[
    ("js-listen", &[("server.js", "app.listen(3000);\n")]),
    (
        "py-uvicorn",
        &[("main.py", "import uvicorn\nuvicorn.run(app, port=8000)\n")],
    ),
    ("py-flask-run", &[("app.py", "app.run(port=5000)\n")]),
];

const HARDCODED_PORT_NEGATIVES: &[(&str, &[(&str, &str)])] = &[
    (
        "js-env-port",
        &[("server.js", "app.listen(process.env.PORT);\n")],
    ),
    (
        "py-env-port",
        &[(
            "main.py",
            "import os, uvicorn\nuvicorn.run(app, port=int(os.environ[\"PORT\"]))\n",
        )],
    ),
    (
        "js-unrelated-call",
        &[("util.js", "function foo(n) { return n; }\nfoo(3000);\n")],
    ),
];

#[test]
fn hardcoded_port_fixtures_pos_and_neg() {
    assert!(HARDCODED_PORT_POSITIVES.len() >= 3);
    assert!(HARDCODED_PORT_NEGATIVES.len() >= 3);

    for (tag, files) in HARDCODED_PORT_POSITIVES {
        let dir = project(&format!("port-pos-{tag}"), files);
        let ctx = ScanContext::build(&dir).unwrap();
        let findings = hardcoded_port(&ctx);
        assert!(
            findings.iter().any(|f| f.id == "ship/hardcoded-port"),
            "positive `{tag}` must fire ship/hardcoded-port, got {:?}",
            ids(&findings)
        );
    }

    for (tag, files) in HARDCODED_PORT_NEGATIVES {
        let dir = project(&format!("port-neg-{tag}"), files);
        let ctx = ScanContext::build(&dir).unwrap();
        let findings = hardcoded_port(&ctx);
        assert!(
            findings.is_empty(),
            "negative `{tag}` must be silent, got {:?}",
            ids(&findings)
        );
    }
}

// ---------------------------------------------------------------------------
// ship/blocking-findings — ≥3 positive + ≥3 negative
//
// Positives carry an outstanding audit CRITICAL (hardcoded secret in JS/PY,
// or an open Firebase security rule). Negatives are clean projects with no
// critical audit finding.
// ---------------------------------------------------------------------------

const BLOCKING_POSITIVES: &[(&str, &[(&str, &str)])] = &[
    (
        "js-stripe-secret",
        &[(
            "config.js",
            "const stripeKey = \"sk_live_FAKEFAKEFAKE1234\";\n",
        )],
    ),
    (
        "py-stripe-secret",
        &[(
            "settings.py",
            "stripe_key = \"sk_live_FAKEFAKEFAKE1234\"\n",
        )],
    ),
    (
        "firebase-open-rules",
        &[(
            "firestore.rules",
            "service cloud.firestore {\n  match /{document=**} {\n    allow read, write: if true;\n  }\n}\n",
        )],
    ),
];

const BLOCKING_NEGATIVES: &[(&str, &[(&str, &str)])] = &[
    (
        "clean-js",
        &[("app.js", "function add(a, b) { return a + b; }\n")],
    ),
    (
        "clean-py",
        &[("app.py", "def add(a, b):\n    return a + b\n")],
    ),
    (
        "clean-mixed",
        &[
            ("index.js", "export const answer = 42;\n"),
            ("util.py", "VERSION = \"1.0.0\"\n"),
        ],
    ),
];

#[test]
fn blocking_findings_fixtures_pos_and_neg() {
    assert!(BLOCKING_POSITIVES.len() >= 3);
    assert!(BLOCKING_NEGATIVES.len() >= 3);

    for (tag, files) in BLOCKING_POSITIVES {
        let dir = project(&format!("blocking-pos-{tag}"), files);
        let ctx = ScanContext::build(&dir).unwrap();
        let findings = blocking_findings(&ctx, &dir);
        assert!(
            findings.iter().any(|f| f.id == "ship/blocking-findings"),
            "positive `{tag}` must fire ship/blocking-findings, got {:?}",
            ids(&findings)
        );
        // Never leak a raw secret value through the re-emitted finding.
        let json = serde_json::to_string(&findings).unwrap();
        assert!(
            !json.contains("FAKEFAKEFAKE1234"),
            "positive `{tag}` must not echo the raw secret value"
        );
    }

    for (tag, files) in BLOCKING_NEGATIVES {
        let dir = project(&format!("blocking-neg-{tag}"), files);
        let ctx = ScanContext::build(&dir).unwrap();
        let findings = blocking_findings(&ctx, &dir);
        assert!(
            findings.is_empty(),
            "negative `{tag}` must be silent, got {:?}",
            ids(&findings)
        );
    }
}
