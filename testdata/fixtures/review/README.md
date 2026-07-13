# review fixtures

Whole-file positive/negative fixtures for the **declarative** `review/*` rules
only — `review/debug-leftover` and `review/todo-introduced`. Each is a small,
standalone source file referenced from its rule's `fixtures.positive` /
`fixtures.negative` list in `rules/review/*.yaml`, and exercised by the
data-driven gate `crates/getdev-core/tests/review_fixtures.rs` (which runs
`review::run` in `ReviewScope::All` mode over this directory, so the added-line
overlap filter passes for the whole file).

Invariant (CLAUDE.md hard rule 3 / SPEC-RULES): every declarative rule ships
**≥3 positive + ≥3 negative** fixtures here.

## What does NOT belong here

The four **programmatic** review detectors —
`review/duplicate-helper`, `review/dead-code-introduced`,
`review/commented-code-block`, `review/orphan-file` — are NOT declarative rules
and have **no** YAML `fixtures:` block. Their inputs are unit-test source files
constructed inline in the detector modules (`fingerprint.rs`, `deadcode.rs`,
`commented_code.rs`, `orphan.rs`) in Wave 3 (06-03/06-04), because they need
cross-file / fingerprint / re-parse reasoning that a single whole-file
declarative fixture cannot express. Do **not** try to force them into the
declarative `fixtures.positive/negative` YAML field — that field only drives
`core::rules`-engine rules.
