//! Persisted baseline suppression — the committable `.getdev-baseline` file
//! (v0.2, LOOP-03; docs/SPEC-CONFIG.md §"Baseline suppression").
//!
//! A *baseline* is a set of pre-existing finding fingerprints that `check`
//! subtracts from the current run so an agent running getdev in a loop sees
//! only the findings **it** introduced. This module is the pure-core primitive:
//! it parses/serializes the `.getdev-baseline` file and filters a finding set
//! against the baseline — with **no** network, git, or CLI dependency (mirrors
//! [`crate::suppress`]). The `check` CLI owns the flag surface and the
//! compose-after seam.
//!
//! **Fingerprint-keyed, never recomputed (D-02/D-12):** [`filter_by_baseline`]
//! reads the STORED [`Finding::fingerprint`] (the canonical `gdv1:` token
//! written once by [`crate::fingerprint::assign_fingerprints`]) — exactly like
//! [`crate::suppress::filter_findings`] — and never re-hashes a finding here.
//!
//! **File format (D-01):** a `#`-comment header followed by one `gdv1:`
//! fingerprint per line, sorted (a [`BTreeSet`] gives the sort for free) so
//! regeneration produces minimal diffs. On read, blank lines and `#`-comment
//! lines are ignored; every remaining line must be a whole `gdv1:` token
//! (including any `#N` occurrence suffix) or the file is rejected as
//! [`ConfigError::BaselineMalformed`] (exit 3, mirroring a malformed config).

use std::collections::BTreeSet;
use std::path::Path;

use crate::config::{ConfigError, MAX_CONFIG_FILE_BYTES};
use crate::findings::Finding;

/// The outcome of filtering a finding set against a baseline — the baseline
/// analogue of [`crate::suppress::FilterOutcome`]. `kept` flows on to
/// `FindingsReport::new`/`ship_score`; `suppressed` is surfaced under `check
/// -v` (never silent, SC-3); `stale` are baseline entries that matched nothing
/// this run (D-09: surfaced under `-v`, auto-pruned by `--update-baseline`).
#[derive(Debug, Default)]
pub struct BaselineOutcome {
    /// Findings NOT present in the baseline — the surviving, scored set.
    pub kept: Vec<Finding>,
    /// Findings suppressed because their stored `gdv1:` fingerprint is in the
    /// baseline.
    pub suppressed: Vec<Finding>,
    /// Baseline fingerprints that matched no finding this run (the finding was
    /// fixed or removed) — the "matched nothing" note.
    pub stale: Vec<String>,
}

/// Read a `.getdev-baseline` file, enforcing [`MAX_CONFIG_FILE_BYTES`] the same
/// way [`crate::config`]'s `read_config_capped` guards `.getdev.toml`: the
/// baseline lives in the SAME attacker-controllable scanned repo, so it gets
/// the identical unbounded-read DoS treatment (V5/T-14-01) — a regular-file
/// gate BEFORE trusting `len()`, and a `.take()`-bounded read, not just a
/// metadata pre-check. A missing file yields `Ok(None)` (the caller decides
/// whether that is a silent no-op or a [`ConfigError::BaselineMissing`]); an
/// oversize or non-regular file is a hard [`ConfigError::TooLarge`].
pub fn read_baseline_capped(path: &Path) -> Result<Option<String>, ConfigError> {
    use std::io::Read;
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    // Refuse anything that isn't a regular file: a FIFO/device (or symlink to
    // one) reports a bogus small `len()`, defeating a metadata-only cap and
    // letting the read run unbounded (OOM) or block forever (hang).
    if !metadata.is_file() {
        return Err(ConfigError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    // Bound the READ ITSELF (`take`), not just the metadata pre-check: read
    // cap+1 so an exactly-at-cap file is accepted and one byte over is rejected.
    let mut buf = Vec::new();
    match std::fs::File::open(path).and_then(|f| {
        f.take(MAX_CONFIG_FILE_BYTES.saturating_add(1))
            .read_to_end(&mut buf)
    }) {
        Ok(_) => {}
        // vanished between stat and open → treat as absent, not an error.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            })
        }
    }
    if buf.len() as u64 > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    match String::from_utf8(buf) {
        Ok(text) => Ok(Some(text)),
        Err(err) => Err(ConfigError::Read {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, err.utf8_error()),
        }),
    }
}

/// Is `token` a whole `gdv1:` fingerprint token (D-01)? The shape is
/// `gdv1:<hex digest>` with an optional trailing `#<n>` occurrence suffix. The
/// digest must be non-empty lowercase hex; the suffix, if present, non-empty
/// ASCII digits. This is deliberately format-shaped (not a length-pinned
/// equality on 32 chars) so it stays valid if the digest width ever changes,
/// while still rejecting arbitrary garbage.
fn is_gdv1_token(token: &str) -> bool {
    let Some(rest) = token.strip_prefix("gdv1:") else {
        return false;
    };
    let (digest, suffix) = match rest.split_once('#') {
        Some((digest, index)) => (digest, Some(index)),
        None => (rest, None),
    };
    if digest.is_empty() || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    match suffix {
        Some(index) => !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()),
        None => true,
    }
}

/// Parse a `.getdev-baseline` file body into its sorted fingerprint set. Blank
/// lines and `#`-comment lines are ignored; every remaining line must be a
/// whole `gdv1:` token or the file is rejected as
/// [`ConfigError::BaselineMalformed`] carrying the 1-based line number. A
/// comment-only / empty file is a valid EMPTY set — never an error (a
/// just-initialized baseline is legitimately empty).
pub fn parse_baseline(text: &str, path: &Path) -> Result<BTreeSet<String>, ConfigError> {
    let mut set = BTreeSet::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !is_gdv1_token(line) {
            return Err(ConfigError::BaselineMalformed {
                path: path.to_path_buf(),
                line_no: idx + 1,
                line: line.to_owned(),
            });
        }
        set.insert(line.to_owned());
    }
    Ok(set)
}

/// Serialize a fingerprint set to the committable `.getdev-baseline` format: a
/// `#`-comment provenance header, then one fingerprint per line in sorted
/// order (the [`BTreeSet`] iterates sorted, so regeneration is deterministic
/// and diffs are minimal). `tool_version` is stamped into the header.
#[must_use]
pub fn serialize_baseline(baseline: &BTreeSet<String>, tool_version: &str) -> String {
    let mut out = String::new();
    out.push_str("# getdev baseline v1 — pre-existing findings suppressed by fingerprint.\n");
    out.push_str(&format!(
        "# Generated by `getdev check --update-baseline` (getdev {tool_version}).\n"
    ));
    out.push_str("# Keyed on the gdv1: fingerprint (not line/column). Do not hand-edit digests;\n");
    out.push_str("# re-run `getdev check --update-baseline` to refresh.\n");
    for fingerprint in baseline {
        out.push_str(fingerprint);
        out.push('\n');
    }
    out
}

/// Filter `findings` against `baseline`, mirroring
/// [`crate::suppress::filter_findings`]: a finding whose STORED
/// [`Finding::fingerprint`] is in the baseline moves to `suppressed`, everything
/// else is `kept`, and baseline entries that matched nothing are reported as
/// `stale`. A finding with no fingerprint (unreachable once the batch pass has
/// run) simply never matches — exactly like `suppress`'s `[[suppress]]` branch.
/// This function NEVER recomputes a hash (D-02/D-12/SC-4).
#[must_use]
pub fn filter_by_baseline(findings: Vec<Finding>, baseline: &BTreeSet<String>) -> BaselineOutcome {
    let mut outcome = BaselineOutcome::default();
    let mut matched: BTreeSet<String> = BTreeSet::new();
    for finding in findings {
        if let Some(fingerprint) = finding.fingerprint.as_deref() {
            if baseline.contains(fingerprint) {
                matched.insert(fingerprint.to_owned());
                outcome.suppressed.push(finding);
                continue;
            }
        }
        outcome.kept.push(finding);
    }
    outcome.stale = baseline.difference(&matched).cloned().collect();
    outcome
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::findings::{Confidence, Severity};

    /// A minimal seeded finding, mirroring `suppress.rs`'s test builder. `seed`
    /// gives the batch fingerprint pass real content to hash.
    fn finding(id: &str, file: &str, line: Option<u32>, matched: &str) -> Finding {
        Finding {
            id: id.to_owned(),
            command: id.split('/').next().unwrap_or("").to_owned(),
            severity: Severity::High,
            confidence: Confidence::High,
            file: file.to_owned(),
            line,
            column: None,
            end_line: None,
            message: "test finding".to_owned(),
            detail: None,
            suggestion: None,
            remediation: None,
            fixable: false,
            refs: vec![],
            seed: crate::fingerprint::FingerprintSeed {
                node_kind: "string",
                matched_text: matched.to_owned(),
            },
            fingerprint: None,
        }
    }

    /// Assign and return the canonical stored `gdv1:` token for a finding.
    fn fp_of(mut f: Finding) -> String {
        crate::fingerprint::assign_fingerprints(std::slice::from_mut(&mut f));
        f.fingerprint.clone().unwrap()
    }

    #[test]
    fn parse_valid_file_ignores_blanks_and_comments_and_sorts() {
        let text = "\
# getdev baseline v1
gdv1:bb22cc33dd44ee55ff6677889900aa11

# a stray comment
gdv1:aa11bb22cc33dd44ee55ff6677889900
gdv1:3f9a1c02d7b48e6510af2c93e1d70b8a#2
";
        let set = parse_baseline(text, Path::new(".getdev-baseline")).unwrap();
        // Sorted BTreeSet iteration order.
        let got: Vec<&str> = set.iter().map(String::as_str).collect();
        assert_eq!(
            got,
            vec![
                "gdv1:3f9a1c02d7b48e6510af2c93e1d70b8a#2",
                "gdv1:aa11bb22cc33dd44ee55ff6677889900",
                "gdv1:bb22cc33dd44ee55ff6677889900aa11",
            ]
        );
    }

    #[test]
    fn parse_comment_only_or_empty_file_is_an_empty_set_not_an_error() {
        // An easy off-by-one is to reject a just-initialized (all-comment) file
        // as malformed — it is legitimately an empty baseline.
        let comment_only = "# getdev baseline v1\n# nothing yet\n\n";
        assert!(parse_baseline(comment_only, Path::new("b"))
            .unwrap()
            .is_empty());
        assert!(parse_baseline("", Path::new("b")).unwrap().is_empty());
    }

    #[test]
    fn parse_malformed_line_reports_the_one_based_line_no() {
        let text = "# header\ngdv1:aa11bb22cc33dd44ee55ff6677889900\nnot-a-fingerprint\n";
        let err = parse_baseline(text, Path::new(".getdev-baseline")).unwrap_err();
        match err {
            ConfigError::BaselineMalformed { line_no, line, .. } => {
                assert_eq!(line_no, 3, "the garbage is on the 3rd line (1-based)");
                assert_eq!(line, "not-a-fingerprint");
            }
            other => panic!("expected BaselineMalformed, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_a_non_gdv1_token_but_accepts_the_occurrence_suffix() {
        // A bare sha256: entry (the old scheme) is not a gdv1: token → rejected.
        assert!(parse_baseline("sha256:abcdef\n", Path::new("b")).is_err());
        // A gdv1: with a non-hex digest → rejected.
        assert!(parse_baseline("gdv1:zzzz\n", Path::new("b")).is_err());
        // A gdv1: with a #N occurrence suffix → accepted.
        assert!(
            parse_baseline("gdv1:aa11bb22cc33dd44ee55ff6677889900#10\n", Path::new("b"))
                .unwrap()
                .len()
                == 1
        );
    }

    #[test]
    fn read_cap_rejects_an_oversized_baseline_file() {
        // Mirror config.rs's read_config_capped TooLarge test: one byte over the
        // cap must be refused via the bounded read, not slurped whole (T-14-01).
        let dir = tmp_dir("oversized");
        let path = dir.join(".getdev-baseline");
        let oversized =
            "# ".to_owned() + &"a".repeat(usize::try_from(MAX_CONFIG_FILE_BYTES).unwrap() + 1);
        std::fs::write(&path, oversized).unwrap();
        let err = read_baseline_capped(&path).unwrap_err();
        assert!(matches!(err, ConfigError::TooLarge { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_missing_baseline_file_is_ok_none() {
        let dir = tmp_dir("missing");
        let path = dir.join(".getdev-baseline");
        assert!(read_baseline_capped(&path).unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn read_cap_refuses_a_non_regular_file() {
        // A char device (/dev/null) reports len()==0 yet reads unbounded — the
        // regular-file gate must refuse it, same as config.rs.
        let err = read_baseline_capped(Path::new("/dev/null")).unwrap_err();
        assert!(matches!(err, ConfigError::TooLarge { .. }));
    }

    #[test]
    fn serialize_is_sorted_carries_the_header_and_round_trips() {
        let mut set = BTreeSet::new();
        set.insert("gdv1:bb22cc33dd44ee55ff6677889900aa11".to_owned());
        set.insert("gdv1:aa11bb22cc33dd44ee55ff6677889900".to_owned());
        let text = serialize_baseline(&set, "0.2.0");
        assert!(text.starts_with("# getdev baseline v1"));
        assert!(text.contains("(getdev 0.2.0)"));
        // Sorted: aa11 before bb22 in the body.
        let aa = text.find("gdv1:aa11").unwrap();
        let bb = text.find("gdv1:bb22").unwrap();
        assert!(aa < bb, "entries must be written in sorted order");
        // Round-trip: parse(serialize(set)) == set.
        let reparsed = parse_baseline(&text, Path::new(".getdev-baseline")).unwrap();
        assert_eq!(reparsed, set);
    }

    #[test]
    fn filter_moves_matches_to_suppressed_keeps_the_rest_and_reports_stale() {
        let mut kept = finding("real/phantom-import", "src/app.js", Some(3), "keep-me");
        let mut baselined = finding("audit/x", "src/b.js", Some(9), "suppress-me");
        crate::fingerprint::assign_fingerprints(std::slice::from_mut(&mut kept));
        crate::fingerprint::assign_fingerprints(std::slice::from_mut(&mut baselined));
        let baselined_fp = baselined.fingerprint.clone().unwrap();

        let mut baseline = BTreeSet::new();
        baseline.insert(baselined_fp.clone());
        // A fingerprint that matches nothing this run → stale.
        baseline.insert("gdv1:00000000000000000000000000000000".to_owned());

        let outcome = filter_by_baseline(vec![kept, baselined], &baseline);
        assert_eq!(outcome.kept.len(), 1);
        assert_eq!(outcome.kept[0].file, "src/app.js");
        assert_eq!(outcome.suppressed.len(), 1);
        assert_eq!(
            outcome.suppressed[0].fingerprint.as_deref(),
            Some(baselined_fp.as_str())
        );
        assert_eq!(
            outcome.stale,
            vec!["gdv1:00000000000000000000000000000000".to_owned()]
        );
    }

    #[test]
    fn filter_reads_the_stored_fingerprint_a_none_fingerprint_never_matches() {
        // A finding with NO stored fingerprint must never be suppressed — the
        // filter reads the field, it never recomputes a hash (SC-4/D-12).
        let no_fp = finding("audit/x", "src/b.js", Some(9), "suppress-me");
        assert!(no_fp.fingerprint.is_none());
        // Even if the baseline contains what its fingerprint WOULD be, an
        // unfingerprinted finding is kept.
        let would_be = fp_of(finding("audit/x", "src/b.js", Some(9), "suppress-me"));
        let mut baseline = BTreeSet::new();
        baseline.insert(would_be);
        let outcome = filter_by_baseline(vec![no_fp], &baseline);
        assert_eq!(outcome.kept.len(), 1);
        assert!(outcome.suppressed.is_empty());
    }

    /// #N-occurrence-shift regression (RESEARCH Focus Area 2): the `#N` suffix
    /// is assigned per-run over the WHOLE byte-identical-seed sibling group in
    /// ascending (line, column) order. Inserting a new sibling ABOVE an existing
    /// pair re-sorts the group, shifting the suffixes of the otherwise-unchanged
    /// siblings — so a byte-identical finding can look "new" against a baseline
    /// taken at the smaller group size. This documents that inherited `gdv1:`
    /// property (out of scope to change) as EXPECTED behavior, so a "false new"
    /// finding in a `--since`/`--baseline` diff is understood, not mistaken for a
    /// Phase 14 bug.
    #[test]
    fn occurrence_index_shift_is_documented_not_a_baseline_bug() {
        // Baseline run: two identical-seed siblings at lines 10, 20 → #0, #1.
        let mut two = vec![
            finding("audit/dup", "src/dup.js", Some(10), "IDENTICAL"),
            finding("audit/dup", "src/dup.js", Some(20), "IDENTICAL"),
        ];
        crate::fingerprint::assign_fingerprints(&mut two);
        let baseline: BTreeSet<String> =
            two.iter().map(|f| f.fingerprint.clone().unwrap()).collect();
        assert_eq!(baseline.len(), 2);

        // Later run: a THIRD identical-seed sibling is inserted ABOVE both
        // (line 5) → the group re-sorts to #0(line5), #1(line10), #2(line20).
        let mut three = vec![
            finding("audit/dup", "src/dup.js", Some(5), "IDENTICAL"),
            finding("audit/dup", "src/dup.js", Some(10), "IDENTICAL"),
            finding("audit/dup", "src/dup.js", Some(20), "IDENTICAL"),
        ];
        crate::fingerprint::assign_fingerprints(&mut three);

        let outcome = filter_by_baseline(three, &baseline);
        // The line-20 finding was #1 at baseline time but is #2 now, and line-10
        // was #0 but is #1 now — BOTH shifted, so the baseline (which held the
        // old #0/#1 tokens) suppresses only the tokens that still exist: the new
        // group's #0 (base#0) and #1 (base#1) match the baseline's two entries,
        // while base#2 is "new". This asserts the CURRENT, documented behavior:
        // exactly one finding survives as "new" despite no content change.
        assert_eq!(
            outcome.kept.len(),
            1,
            "the occurrence-index shift leaves exactly one byte-identical finding looking new"
        );
        assert_eq!(outcome.suppressed.len(), 2);
    }

    fn tmp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-core-baseline-ut-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
