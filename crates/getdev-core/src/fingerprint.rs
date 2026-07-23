//! Shift-stable finding identity — the `gdv1:` fingerprint (docs/SPEC-FINDINGS.md
//! §"Fingerprint identity (`gdv1:`)").
//!
//! The fingerprint is a **content-keyed, shift-stable** identity token that
//! survives cosmetic edits (reformats, blank-line insertions, rule rewordings)
//! so committed baselines (Phase 13) and `guard`'s regression signal (Phase 14)
//! do not churn. It is the wire contract every downstream v0.2 phase keys on.
//!
//! ## Recipe (normative — see the spec)
//! `gdv1:<32-hex>` with an optional ascending `#N` occurrence suffix. The digest
//! is **SHA-256 truncated to 128 bits (32 hex chars)** over these fields,
//! **NUL-delimited** (`\0`) to prevent field-boundary collisions:
//! ```text
//! "gdv1"  ∥  rule_id  ∥  forward-slash relative path  ∥  node_kind  ∥  normalized matched text
//! ```
//! No raw line or column enters the hash (D-06) — line shifts must not change
//! identity. Line/column are used *only* to order byte-identical-seed siblings
//! for the deterministic `#N` occurrence index (D-04).
//!
//! ## Identity seed (D-05/D-11)
//! The [`FingerprintSeed`] carried on every [`Finding`] is a crate-internal,
//! `#[serde(skip)]` value with a hand-rolled redacting [`std::fmt::Debug`]: for
//! `env`/`audit` hardcoded-secret findings its `matched_text` **is the raw
//! secret value**, so two distinct secrets on one line differentiate
//! intrinsically — but the raw value is fed to the hasher only and never
//! reaches any field, renderer, or the wire (upholds SPEC-FINDINGS Invariant 2).

use sha2::{Digest, Sha256};

use crate::findings::Finding;

/// The internal identity seed carried on a [`Finding`]. Never serialized
/// (`#[serde(skip)]` on the field) and never printed verbatim — the hand-rolled
/// [`Debug`](std::fmt::Debug) below redacts `matched_text` unconditionally
/// (type-level redaction, mirroring `env::PlanEntry`; D-05 Pitfall 2), because
/// for secret findings `matched_text` holds the raw secret value.
#[derive(Clone, Default)]
pub struct FingerprintSeed {
    /// The tree-sitter node kind at the finding site, or a synthetic label for
    /// node-less findings (e.g. `"secret_literal"`, `"message_fallback"`).
    pub node_kind: &'static str,
    /// The matched source text of the anchor node/span (or the fallback
    /// message). May be the raw secret value — hashed only, never serialized.
    pub matched_text: String,
}

impl std::fmt::Debug for FingerprintSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Unconditional redaction (never call-site discipline): `matched_text`
        // may hold a raw secret. `node_kind` is a safe static label.
        f.debug_struct("FingerprintSeed")
            .field("node_kind", &self.node_kind)
            .field("matched_text", &"«redacted»")
            .finish()
    }
}

/// Normalize matched text so a Windows checkout and a Unix checkout of
/// identical code hash identically (D-07): CRLF→LF, lone `\r`→`\n`, and trim
/// trailing whitespace inside the span.
fn normalize_matched_text(raw: &str) -> String {
    raw.replace("\r\n", "\n")
        .replace('\r', "\n")
        .trim_end()
        .to_owned()
}

/// The base `gdv1:` digest for a finding: the 32-hex (128-bit) SHA-256 truncation
/// over the D-03 canonical input, WITHOUT the `gdv1:` prefix or any `#N` suffix.
///
/// CRITICAL (Pitfall 3): the hash is a pure function of
/// `(id, file, node_kind, normalized matched_text)` — no line, no column, no
/// occurrence count ever enters the hasher. That is what makes the digest
/// byte-identical across line shifts and across every member of an
/// identical-seed sibling group; the `#N` is appended to the finished string.
fn compute_hash(finding: &Finding) -> String {
    let normalized_seed = normalize_matched_text(&finding.seed.matched_text);
    let mut hasher = Sha256::new();
    hasher.update(b"gdv1");
    hasher.update(b"\0");
    hasher.update(finding.id.as_bytes());
    hasher.update(b"\0");
    // `file` is already forward-slash project-relative (SPEC-FINDINGS
    // invariant) — do not re-normalize.
    hasher.update(finding.file.as_bytes());
    hasher.update(b"\0");
    hasher.update(finding.seed.node_kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(normalized_seed.as_bytes());
    // SHA-256 → 64 hex chars; truncate to 128 bits / 32 hex chars (D-08). The
    // slice is safe: `{:x}` of a Sha256 digest is always exactly 64 ASCII hex
    // chars, so `[..32]` never splits a char and never panics.
    let full = format!("{:x}", hasher.finalize());
    full[..32].to_owned()
}

/// The D-10 batch pass — the **sole writer** of `Finding.fingerprint`. Assigns
/// each finding its `gdv1:` token over the finalized, fixed-order slice.
///
/// Distinct matched content differentiates automatically (different digests).
/// Only when two findings share a **byte-identical seed** (same id, same file,
/// identical node_kind + normalized matched text) is a deterministic occurrence
/// index appended: `#0`, `#1`, … in **ascending (line, column) order** (D-04).
/// The base digest before `#` is identical for every member of a group and is
/// independent of ordering entirely, so upstream rayon reordering cannot corrupt
/// it. Infallible — no `Result`, no `unwrap`/`expect`.
pub fn assign_fingerprints(findings: &mut [Finding]) {
    use std::collections::HashMap;

    // Group finding indices by canonical identity (D-04: "byte-identical seed").
    let mut groups: HashMap<(String, String, &'static str, String), Vec<usize>> = HashMap::new();
    for (idx, finding) in findings.iter().enumerate() {
        let key = (
            finding.id.clone(),
            finding.file.clone(),
            finding.seed.node_kind,
            normalize_matched_text(&finding.seed.matched_text),
        );
        groups.entry(key).or_default().push(idx);
    }

    // Writing to explicit indices makes the per-index result independent of the
    // (non-deterministic) HashMap iteration order.
    for (_key, mut indices) in groups {
        // Stable sort by (line, column): shift-invariant (inserting blank lines
        // above shifts every sibling equally, so relative order is preserved).
        indices.sort_by_key(|&i| (findings[i].line, findings[i].column));
        let base = compute_hash(&findings[indices[0]]);
        if indices.len() == 1 {
            findings[indices[0]].fingerprint = Some(format!("gdv1:{base}"));
        } else {
            for (n, &i) in indices.iter().enumerate() {
                findings[i].fingerprint = Some(format!("gdv1:{base}#{n}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::findings::{Confidence, FindingsReport, ProjectInfo, Severity};
    use proptest::prelude::*;

    /// Build a minimal seeded [`Finding`] for the identity tests.
    fn seed_finding(
        id: &str,
        file: &str,
        line: Option<u32>,
        column: Option<u32>,
        node_kind: &'static str,
        matched_text: &str,
    ) -> Finding {
        Finding {
            id: id.to_owned(),
            command: "audit".to_owned(),
            severity: Severity::High,
            confidence: Confidence::High,
            file: file.to_owned(),
            line,
            column,
            end_line: line,
            message: "identity test finding".to_owned(),
            detail: None,
            suggestion: None,
            remediation: None,
            fixable: false,
            refs: vec![],
            seed: FingerprintSeed {
                node_kind,
                matched_text: matched_text.to_owned(),
            },
            fingerprint: None,
        }
    }

    /// Assign fingerprints to a one-element slice and return the resulting token.
    fn fp_of(mut finding: Finding) -> String {
        assign_fingerprints(std::slice::from_mut(&mut finding));
        finding.fingerprint.clone().unwrap()
    }

    /// D-14 #1: inserting/removing blank lines above a finding leaves its
    /// fingerprint byte-identical (the base `gdv1:` token, before any `#N`).
    #[test]
    fn reformat_stability() {
        let a = seed_finding(
            "audit/hardcoded-secret",
            "src/app.ts",
            Some(12),
            Some(7),
            "string",
            "sk_live_ABCDEF",
        );
        // Same finding shifted down 100 lines (blank lines inserted above).
        let b = seed_finding(
            "audit/hardcoded-secret",
            "src/app.ts",
            Some(112),
            Some(7),
            "string",
            "sk_live_ABCDEF",
        );
        assert_eq!(fp_of(a), fp_of(b), "line shift must not change identity");
    }

    /// D-14 #2: two findings on the same line with different matched content
    /// (or a different rule id) get distinct digests with NO positional input;
    /// two secrets on one line differ (closes 05-REVIEW).
    #[test]
    fn same_line_differentiation() {
        let line = Some(9);
        let col = Some(4);
        // Different matched text, same rule/file/line.
        let a = seed_finding("audit/x", "src/a.ts", line, col, "string", "aaaa");
        let b = seed_finding("audit/x", "src/a.ts", line, col, "string", "bbbb");
        assert_ne!(fp_of(a), fp_of(b), "distinct content must differ");

        // Different rule id, identical everything else.
        let c = seed_finding("audit/x", "src/a.ts", line, col, "string", "same");
        let d = seed_finding("audit/y", "src/a.ts", line, col, "string", "same");
        assert_ne!(fp_of(c), fp_of(d), "distinct rule id must differ");

        // Two DISTINCT secrets on the same line — the 05-REVIEW collision case.
        let s1 = seed_finding(
            "audit/hardcoded-secret",
            "src/a.ts",
            line,
            col,
            "secret_literal",
            "sk_live_ONESECRETVALUE",
        );
        let s2 = seed_finding(
            "audit/hardcoded-secret",
            "src/a.ts",
            line,
            col,
            "secret_literal",
            "sk_live_TWOSECRETVALUE",
        );
        assert_ne!(
            fp_of(s1),
            fp_of(s2),
            "two distinct secrets on one line must get distinct fingerprints"
        );
    }

    // D-14 #3 (proptest): N byte-identical-seed siblings receive `#0..#{N-1}`
    // in ascending (line, column) order, and the base digest before `#` is
    // identical for all N. (Plain `//` — rustdoc cannot attach a doc comment to
    // a macro invocation.)
    proptest! {
        #[test]
        fn occurrence_index_prop(mut lines in prop::collection::vec(1u32..10_000, 2..12)) {
            // Distinct, shuffled positions for byte-identical-seed siblings.
            lines.sort_unstable();
            lines.dedup();
            prop_assume!(lines.len() >= 2);
            let n = lines.len();

            // Present them to the batch pass in reverse (worst-case) order.
            let mut findings: Vec<Finding> = lines
                .iter()
                .rev()
                .map(|&l| {
                    seed_finding(
                        "audit/dup",
                        "src/dup.ts",
                        Some(l),
                        Some(1),
                        "string",
                        "IDENTICAL",
                    )
                })
                .collect();
            assign_fingerprints(&mut findings);

            // Peel base + index off each token and check the invariants.
            let mut bases: Vec<String> = Vec::new();
            // Map line -> assigned index.
            let mut by_line: Vec<(u32, usize)> = Vec::new();
            for f in &findings {
                let token = f.fingerprint.clone().unwrap();
                let rest = token.strip_prefix("gdv1:").unwrap();
                let (base, idx) = rest.split_once('#').unwrap();
                bases.push(base.to_owned());
                by_line.push((f.line.unwrap(), idx.parse::<usize>().unwrap()));
            }
            // Base identical for every member.
            prop_assert!(bases.iter().all(|b| b == &bases[0]));
            // Indices are exactly 0..N assigned in ascending line order.
            by_line.sort_by_key(|&(line, _)| line);
            for (expected, (_line, got)) in by_line.iter().enumerate() {
                prop_assert_eq!(expected, *got);
            }
            prop_assert_eq!(by_line.len(), n);
        }
    }

    /// D-14 #4: a matched text containing literal `\r\n` hashes identically to
    /// its `\n`-only equivalent, and the digest is a pure function of the inputs
    /// (same inputs → same digest across two independent calls).
    #[test]
    fn crlf_and_path_normalization() {
        let crlf = seed_finding(
            "review/dup",
            "src/x.ts",
            Some(3),
            Some(1),
            "block",
            "line one\r\nline two   \r\n",
        );
        let lf = seed_finding(
            "review/dup",
            "src/x.ts",
            Some(3),
            Some(1),
            "block",
            "line one\nline two",
        );
        assert_eq!(
            fp_of(crlf),
            fp_of(lf),
            "CRLF + trailing whitespace must normalize away before hashing"
        );

        // Purity: two independent calls on equal inputs give equal digests.
        let one = seed_finding("real/pkg", "a/b.ts", Some(1), Some(1), "id", "left-pad");
        let two = seed_finding("real/pkg", "a/b.ts", Some(9), Some(9), "id", "left-pad");
        assert_eq!(
            fp_of(one),
            fp_of(two),
            "pure fn of (id, file, node_kind, text)"
        );
    }

    /// D-14 #5 / D-05: two co-located findings with distinct raw secret seeds —
    /// serializing the report to JSON never contains a raw secret substring,
    /// while both `gdv1:` fingerprints ARE present and distinct; and
    /// `format!("{:?}", seed)` shows the redaction placeholder, not the secret.
    #[test]
    fn secret_never_serialized() {
        // Build raw secrets from pieces so the absence assertion is not
        // self-defeating (no literal secret token in this test source).
        let secret_a = format!("sk_live_{}{}", "AAAA", "SECRETBODYONE1234");
        let secret_b = format!("sk_live_{}{}", "BBBB", "SECRETBODYTWO5678");

        let mut findings = vec![
            seed_finding(
                "audit/hardcoded-secret",
                "src/config.ts",
                Some(5),
                Some(10),
                "secret_literal",
                &secret_a,
            ),
            seed_finding(
                "audit/hardcoded-secret",
                "src/config.ts",
                Some(5),
                Some(40),
                "secret_literal",
                &secret_b,
            ),
        ];
        assign_fingerprints(&mut findings);

        let fp_a = findings[0].fingerprint.clone().unwrap();
        let fp_b = findings[1].fingerprint.clone().unwrap();
        assert!(
            fp_a.starts_with("gdv1:"),
            "fingerprint must be a gdv1: token"
        );
        assert!(
            fp_b.starts_with("gdv1:"),
            "fingerprint must be a gdv1: token"
        );
        assert_ne!(fp_a, fp_b, "distinct secrets → distinct fingerprints");

        // The redacting Debug hides the secret.
        let dbg = format!("{:?}", findings[0].seed);
        assert!(dbg.contains("«redacted»"), "Debug must redact matched_text");
        assert!(
            !dbg.contains("SECRETBODYONE"),
            "Debug must not leak the secret"
        );

        // Serialize the full report — the seed field is #[serde(skip)], so no
        // raw secret substring may appear, but both fingerprints must.
        let report = FindingsReport::new(
            "0.1.0-dev",
            ProjectInfo {
                path: ".".into(),
                stack: vec!["node".into()],
            },
            findings,
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains(&secret_a), "raw secret A leaked into JSON");
        assert!(!json.contains(&secret_b), "raw secret B leaked into JSON");
        assert!(
            !json.contains("SECRETBODYONE"),
            "secret A body leaked into JSON"
        );
        assert!(
            !json.contains("SECRETBODYTWO"),
            "secret B body leaked into JSON"
        );
        assert!(json.contains(&fp_a), "fingerprint A must be on the wire");
        assert!(json.contains(&fp_b), "fingerprint B must be on the wire");
    }
}
