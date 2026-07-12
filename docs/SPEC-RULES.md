# SPEC-RULES.md — Rule YAML Format

Normative specification of the declarative rule format used by all rule packs (`rules/audit/`, `rules/real/`, `rules/review/`, `rules/ship/`).

> **Source:** distilled from the project master plan (internal) Appendix B, §2.3, §3.2, §9.2, §10; this doc is normative for rule file structure, fixture requirements, and the declarative-only constraint.

---

## Principles

- **Rules are data, never code.** Rule packs (embedded and user-supplied via `--rules`) are declarative YAML only — they can never execute code. This is a security boundary (hostile rule packs) and the community-contribution path (contributors never need to write Rust).
- **Matcher types are defined in `core::rules`.** If a detection can't be expressed with existing matcher types, the correct change is a **new matcher type in `core::rules` plus an update to this spec** — never a hardcoded check in an analyzer.
- Rule YAML is validated against a JSON Schema at load time (`jsonschema` crate). Embedded packs ship in the binary via `include_dir!`; `--rules <dir>` merges user packs.

## Annotated example

```yaml
id: audit/cors-wildcard
severity: high
confidence: high
languages: [javascript, typescript, python]
description: CORS configured with wildcard origin while credentials are enabled
message: "CORS allows any origin ('*')"
remediation: >
  Restrict allowed origins to your actual frontend domain(s).
  Wildcard origins allow any website to call this API from a browser.
refs:
  - https://getdev.ai/rules/audit/cors-wildcard
matchers:
  - language: javascript
    query: |            # tree-sitter query
      (call_expression
        function: (identifier) @fn (#eq? @fn "cors")
        arguments: (arguments (object
          (pair key: (property_identifier) @k (#eq? @k "origin")
                value: (string) @v (#eq? @v "\"*\"")))))
fixtures:
  positive: [fixtures/cors_wildcard_express.js, fixtures/cors_wildcard_fastapi.py]
  negative: [fixtures/cors_specific_origin.js]
```

(Note: a shipped rule needs ≥ 3 positive and ≥ 3 negative fixtures — the example above is abbreviated.)

## Field reference

| Field | Required | Type | Meaning |
|---|---|---|---|
| `id` | yes | string | `<command>/<rule-name>` — prefix is one of `real/`, `audit/`, `review/`, `ship/` |
| `severity` | yes | enum | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `confidence` | yes | enum | `high` \| `medium` \| `low` — separate from severity; heuristic rules can be high-severity/low-confidence (rendered distinctly) |
| `languages` | yes | list | Languages the rule applies to (v0.1: `javascript`, `typescript`, `python`) |
| `description` | yes | string | What the rule detects (also feeds generated docs pages) |
| `message` | yes | string | Short finding message shown to the user |
| `remediation` | yes | string | Actionable fix guidance |
| `refs` | yes | list | Documentation links — per-rule page at `https://getdev.ai/rules/<id>` (generated from this YAML) |
| `frameworks` | no | list | Optional project-level framework gate, parallel to `languages`: `express` \| `nextjs` \| `fastapi` \| `flask`. The rule only activates at all if the project's static, declared-dependency-based framework detection reports at least one listed framework present — never a hardcoded `if is_express` branch in an analyzer (CLAUDE.md rule 7) |
| `path_glob` | no | list | Optional list of glob patterns (`globset` syntax) restricting which file paths the rule's matchers run against — for path-convention-scoped rules (e.g. Next.js API routes: `pages/api/**`, `app/api/**/route.ts`) where the tree-sitter query alone cannot see the file's path |
| `matchers` | yes | list | Each entry is **exactly one** of three matcher kinds (`oneOf`, enforced by `rules/audit/schema.json`): **AST** — `language` (`javascript` \| `typescript` \| `tsx` \| `python`) + tree-sitter `query`; **text-regex** — `file_glob` (glob, `globset` syntax) + `text_pattern` (whole-file regex evaluated over capped file bytes, no tree-sitter grammar — for config files with no supported grammar, e.g. Firebase `.rules`/`database.rules.json`); **secret** — `secret: true` (wraps `core::secrets`'s existing provider-regex + Shannon-entropy classifier; used only by `audit/hardcoded-secret`). A matcher entry that mixes fields from more than one kind (e.g. both `query` and `text_pattern` present) is a schema violation, rejected at load time |
| `fixtures.positive` | yes | list | ≥ 3 files that MUST trigger the rule |
| `fixtures.negative` | yes | list | ≥ 3 files that MUST NOT trigger the rule |

## Predicate support

A `query:` matcher's tree-sitter predicates (`#eq?`, `#match?`, `#any-of?`, etc.) are evaluated **automatically** by the Rust `tree-sitter` binding inside `QueryCursor::matches()` — `core::rules` contains no custom predicate evaluator. Only the following predicate names are auto-evaluated and therefore usable in a rule's `query:`:

`#eq?` `#not-eq?` `#any-eq?` `#any-not-eq?` `#match?` `#not-match?` `#any-match?` `#any-not-match?` `#any-of?` `#not-any-of?`

`#is?` and `#is-not?` are **NOT** supported: the `tree-sitter` binding parses them into *property predicates* (metadata assertions for external consumers), not *text predicates*, so `QueryCursor::matches()` never evaluates them — a rule using one would match unconditionally on that constraint. They are therefore rejected at load time, exactly like any other unsupported predicate.

Any other predicate name — a typo (`#matches?`), a property predicate (`#is?`/`#is-not?`), or a genuinely unsupported predicate — is rejected as a load-time error (`RuleLoadError::UnsupportedPredicate`) naming the offending predicate. It is never silently ignored: an unevaluated predicate would otherwise make the surrounding pattern match unconditionally, turning a typo into a rule that fires on everything.

## Pack merge & collisions

A `--rules <dir>` user pack is merged with the embedded pack at load time (`core::rules::merge`). A user rule whose `id` matches an embedded rule's `id` **overrides** the embedded rule entirely (severity, matchers, fixtures — the whole rule), and a load-time warning is emitted naming the collision. Collisions are never silently ambiguous.

## Fixture requirements (no exceptions)

- Every shipped rule has **≥ 3 positive + ≥ 3 negative fixtures**.
- Fixtures live under `testdata/fixtures/` (paths in the YAML resolve there).
- Every rule is **registered in tests** — the table-driven fixture test suite must cover 100 % of shipped rules (see `docs/TESTING.md`).
- Fixture tests are part of `cargo test --workspace` and gate CI.

## False-positive policy tie-in

Every rule ships with a measured FP rate on the sentinel corpus (10 real OSS repos, `docs/PLAN.md` §9.1). A rule exceeding **5 % FP** on the sentinels is demoted to `low`/`info` severity or `confidence: low` until improved. Heuristic rules must surface their reasoning in the finding's `detail` field.

## Adding a rule (checklist)

1. Write the YAML in the correct pack directory (`rules/<command>/<name>.yaml`).
2. Add ≥ 3 positive + ≥ 3 negative fixtures under `testdata/fixtures/`.
3. Register the rule in the fixture test suite.
4. Run the sentinel corpus; record the FP rate (> 5 % → demote per policy).
5. Findings produced must conform to `docs/SPEC-FINDINGS.md` (never include raw secret values — masked previews only).
