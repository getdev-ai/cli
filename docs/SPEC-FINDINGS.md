# SPEC — Findings schema (v1)

The unified findings format every analyzer produces, every renderer consumes, and `--json`
emits. **This document is normative**; the implementation is `crates/getdev-core/src/findings.rs`
and the two must never drift (a PR changing one must change both).

Source: distilled from the project master plan (internal) §4.

## Envelope

Serializing a `FindingsReport` (pretty-printed, trailing newline) IS the `--json` output:

```json
{
  "schema_version": "1",
  "tool_version": "0.1.0",
  "generated_at": "2026-07-08T12:00:00Z",
  "project": { "path": ".", "stack": ["node", "nextjs"] },
  "score": 43,
  "summary": { "critical": 2, "high": 3, "medium": 5, "low": 4, "info": 1, "fixable": 6 },
  "findings": [
    {
      "id": "real/nonexistent-package",
      "command": "real",
      "severity": "critical",
      "confidence": "high",
      "file": "src/api/client.py",
      "line": 12,
      "column": 8,
      "end_line": 12,
      "message": "Package 'requests-auth-helper' does not exist on PyPI",
      "detail": "Imported on line 12 and declared in requirements.txt. No package with this name has ever been published.",
      "suggestion": "Did you mean 'requests-oauthlib' (98M downloads/month)?",
      "remediation": "Remove the dependency or replace it with a real package providing the needed functionality.",
      "fixable": false,
      "refs": ["https://getdev.ai/rules/real/nonexistent-package"],
      "fingerprint": "gdv1:3f9a1c02d7b48e6510af2c93e1d70b8a"
    }
  ]
}
```

## Envelope fields

| Field | Type | Rules |
|---|---|---|
| `schema_version` | string | `"1"`. Versioned independently of the tool; bumped only for breaking shape changes. Declared stable at tool v1.0. |
| `tool_version` | string | getdev version that produced the report |
| `generated_at` | string | RFC 3339 UTC, seconds precision |
| `project.path` | string | scan root as the user gave it |
| `project.stack` | string[] | detected stack identifiers (e.g. `["node", "nextjs"]`); empty if undetected |
| `score` | int 0–100 | **`check` only** — omitted (not `null`) for every other command |
| `summary` | object | per-severity counts + `fixable` count; always present, all six keys always present |
| `findings` | array | sorted severity-desc, then file, then line — the stable presentation order shared by all renderers |
| `applied` | object | **`env --write` only** (F4 audit fix) — omitted (not `null`) unless the command actually mutated something. `{ vars_written, vars_skipped_stale, files_rewritten, env_file, env_file_created, gitignore_patched, example_file }`, mirroring the terminal renderer's "applied: N var(s) → …" summary. `vars_skipped_stale` (C9 audit fix) counts planned vars whose `.env` line was skipped because a same-named key already existed at apply time — always present, `0` when nothing was skipped. Kept so `env --json --write` is a single valid JSON document instead of the apply summary going to a second, non-JSON stream. |
| `skipped` | array | omitted (empty array serializes as `[]`, never present as `null`) when nothing was skipped — one `{ path, reason }` entry per unreadable file (`env`, `real`); `path` is optional (some skip reasons, e.g. a grammar-load failure, aren't about one file). Previously terminal/`-v`-only; F4 audit fix. |

## Finding fields

| Field | Type | Required | Rules |
|---|---|---|---|
| `id` | string | ✅ | `<command>/<rule-name>`, kebab-case (`audit/hardcoded-secret`) |
| `command` | string | ✅ | `real` \| `audit` \| `review` \| `env` \| `ship` |
| `severity` | string | ✅ | `critical` \| `high` \| `medium` \| `low` \| `info` — how bad it is if real |
| `confidence` | string | ✅ | `high` \| `medium` \| `low` — how sure the rule is. Orthogonal to severity: heuristic rules can be high-severity/low-confidence; renderers must visually distinguish confidence < high. (v0.4 adds an `llm` tier for LLM-produced findings, never mixed silently with deterministic ones.) |
| `file` | string | ✅ | project-relative path, forward slashes |
| `line`, `column`, `end_line` | int | optional | 1-based; omitted when not meaningful (e.g. project-level findings) |
| `message` | string | ✅ | one-line summary. **Never contains a secret value — masked previews only (`sk_live_…9f2a`).** This is a hard rule: `--json` output must be safe to attach to public CI logs. |
| `detail` | string | optional | longer explanation; heuristic rules MUST surface their reasoning here (FP policy §9.2) |
| `suggestion` | string | optional | "did you mean…" style hint |
| `remediation` | string | optional | how to fix, may name a getdev command (`run: getdev env --write`) |
| `fixable` | bool | ✅ | a getdev command can fix this automatically |
| `refs` | string[] | optional (omitted if empty) | rule documentation URLs (`https://getdev.ai/rules/<id>`) |
| `fingerprint` | string | populated for every finding on `--json` | A **shift-stable identity token**, `gdv1:<32-hex>` with an optional ascending `#N` occurrence suffix. See **Fingerprint identity (`gdv1:`)** below for the full contract. Enables baselines (`.getdev-baseline`, `--since`, v0.2) and `guard`'s regression diff. Was omitted before v0.2; now set on **every** finding (Invariant 3's omit-not-null still governs the theoretical none case). |

## Fingerprint identity (`gdv1:`)

The `fingerprint` is a **content-keyed, shift-stable** identity that survives cosmetic edits
(reformats, blank-line insertions, rule rewordings) so committed baselines and `guard`'s
regression signal do not churn. It is the wire contract every downstream v0.2 phase keys on.

**Wire format.** `gdv1:<32-hex>` — a `gdv1:` version tag, a colon, then a 32-character
lowercase-hex digest, with an optional `#N` occurrence suffix (e.g. `gdv1:3f9a…b8a#1`).

**Opaque version tag (consumers MUST NOT parse the digest).** Everything up to and including
the first `:` is an **opaque version tag**. Consumers (baseline reconcilers, `[[suppress]]`
matchers, `guard`) MUST compare fingerprints as whole strings and MUST NOT parse, decode, or
depend on the internal structure of the digest. A future `gdv2:` formula may coexist with
`gdv1:` tokens in the same baseline; the tag is the signal for which algorithm produced a stored
fingerprint. An unrecognized tag is treated as "not mine" (no match), never an error.

**Canonical hash input.** The digest is **SHA-256 truncated to 128 bits (32 hex chars)** over
these fields, **NUL-delimited** (`\0`) to prevent field-boundary collisions:

```
"gdv1"  ∥  rule_id  ∥  forward-slash relative path  ∥  seed
```

where `seed` is the **identity seed** — normally an AST anchor: the tree-sitter `node_kind` at
the finding site ∥ the normalized matched source text of that node/span. Normalization strips
`\r` (CRLF→LF) and trailing whitespace inside the span, so a Windows checkout and a Unix
checkout of identical code hash identically. **No raw line or column enters the hash** — line
shifts must not change identity. 128-bit truncation keeps birthday-collision probability
negligible (~1e-27 at 1e6 findings).

**Node-less fallback.** Project-level findings with no line/node (e.g. `ship` findings,
`env`-file-committed) have no AST anchor and do not line-shift, so their seed falls back to the
`normalize(message)` of that finding. This fallback is explicit, not silent.

**Occurrence index (`#N`).** Distinct matched content differentiates automatically — two
findings from the same rule whose matched source differs get different digests with no
positional input. Only when two findings share a **byte-identical seed** (same rule, same file,
identical matched text — e.g. two identical string literals on one line) is a deterministic
occurrence index appended: `#0`, `#1`, … in **ascending byte-offset order**. The `#N` suffix is
**never** a line number, and distinct findings are never collapsed onto one fingerprint.

**Identity seed is internal and never serialized.** The seed (which for `env` hardcoded-secret
findings *is the raw secret value*, so two distinct secrets differentiate intrinsically) is fed
to the hasher only. It is a crate-internal, `#[serde(skip)]` value with a redacting `Debug` and
never reaches any field, any renderer, or the wire — only the one-way `gdv1:` digest is
serialized. This upholds Invariant 2 (secrets never appear).

## Renderers

There are **three renderers**, all consuming the one `FindingsReport` / `Vec<Finding>` schema
(Invariant 1) and all upholding secret masking (Invariant 2) — no renderer has its own shape or
its own finding fields:

- **`human`** — the default terminal render: grouped by file, colored, glyph severities,
  summary-by-default collapse when long (B-06). A human reading aid.
- **`json`** (`--json`, alias `--format=json`) — the serialized envelope above, the full machine
  report.
- **`agent`** (`--format=agent`) — a deterministic, plain-text, ANSI-free, LLM-shaped report:
  `--json` minus the JSON tax, plus a synthesized next-actions checklist. Selected on stdout for
  any findings command (`check`/`real`/`audit`/`review`/`env`/`ship`).

### The `agent` output shape

```
GATE: <pass|fail>[ · score NN/100 < min NN][ · <sev>+ findings ≥ <fail-on>]
SUMMARY: <N> findings · <C> critical · <H> high · <M> medium · <L> low · <I> info · <K> fixable[ · score NN/100]
FINDINGS:
<SEV> <id> <file>:<line>:<col> — <message> [fixable] <gdv1:…[#N]>
… (one line per finding, in the report's existing worst-first total order)
NEXT ACTIONS:
- <deduped remediation 1>
- <deduped remediation 2>
```

- **`GATE:`** — `pass` or `fail`, rendered from the **same** gate evaluation that computes the
  exit code (so the printed verdict and the exit code can never disagree). The `score NN/100 <
  min NN` fragment appears only when `--min-score` set the gate; the `<sev>+ findings ≥ <fail-on>`
  fragment only when `--fail-on` did.
- **`SUMMARY:`** — the severity tally; the `· score NN/100` fragment appears only when
  `report.score` is `Some` (i.e. `check` set it — every other command omits it, mirroring the
  envelope's omit-not-null score).
- **`FINDINGS:`** — one **dense line per finding**, flat (no per-file grouping — a greppable,
  worst-first total-ordered list), carrying `severity · id · file:line:col · message · [fixable]
  · gdv1:…`. Position renders as `file:line:col`, `file:line`, or `file` per the same
  `(line, column)` availability logic as the human renderer, and confidence < high is appended as
  `(confidence: low)` (Finding fields §`confidence`: renderers must distinguish confidence). The
  `gdv1:` fingerprint is embedded **verbatim** so an agent can diff runs / cross-reference a
  baseline without a second `--json` call — this is the whole point of the agent format existing
  alongside `--json`.
- **`NEXT ACTIONS:`** — the **deduped** set of finding remediations, sourced from each finding's
  `suggestion` (falling back to `remediation`), deduped by action string, ordered worst-severity-
  first then by first appearance (deterministic because `findings` is already totally ordered),
  and capped at a small bounded constant with a trailing `… (M more)` line when capped. Findings
  with no suggestion/remediation contribute nothing. This turns N noisy findings into a short,
  actionable checklist.
- **No findings:** `FINDINGS:` and `NEXT ACTIONS:` collapse to a single `no findings — clean` line.
- **No summary-by-default collapse.** Unlike the human render, the agent format has no >25-finding
  collapse (B-06) — it always carries the full machine list, exactly like `--json`.

**Secret masking (Invariant 2).** The agent renderer, like every renderer, prints only the
already-masked `Finding` fields (`message` masked preview, `id`, `file`, position) and the one-way
`gdv1:` digest. It **never** touches the identity seed (`#[serde(skip)]`, redacting `Debug`), which
for `env` findings *is the raw secret value*. Two distinct secrets appear as two distinct `gdv1:`
fingerprints with their raw values absent — the same guarantee as `--json`.

**Size (measured).** The agent format is smaller than `--json` by construction (no JSON
keys/braces/quotes/pretty-print indentation). `len(render_agent) < len(render_json)` on the
reference corpus is a **tested fact** (a real byte/char comparison, not eyeballed); byte length is
the token-count proxy for this ASCII-dominant output.

## `real/nonexistent-api` — installed-surface / degrade-not-fabricate contract

`real/nonexistent-api` claims that an imported member does not exist on the imported package. That
claim is only as trustworthy as getdev's knowledge of the package's real export surface, so the
finding's severity/confidence are contractually tied to how that surface was resolved:

- **Source is the installed surface, never a list.** The export surface is resolved by reading the
  package **as installed** — from `node_modules` (`.d.ts`/`.d.mts`/`.d.cts` type declarations) or
  `site-packages` — directly off disk. It is **never** a static/bundled export list and **never** a
  registry lookup (the registry client only answers package *existence* + typosquat, never surface).
  A finding therefore reflects the version the project actually installed.
- **High is licensed only by a trusted, fully-resolved surface.** A high-severity / high-confidence
  "member does not exist" claim is permitted **only** when the surface is fully resolved from a
  **trusted** types entry point — the package's `package.json` `types`/`typings` field or the
  `exports` map's `types` condition. A trusted entry means getdev enumerated the surface the package
  itself advertises.
- **Guessed or incomplete surfaces degrade — they never fabricate a miss.** When no trusted entry
  is found (only an alphabetical-first `.d.ts` guess) or the surface is otherwise incomplete
  (unresolvable barrel `export *` chains, dynamic/computed exports, an unlocatable entry), the
  surface is treated as **not trustworthy**: the finding **degrades to `info` severity / low
  confidence** rather than asserting the member is absent. getdev never emits a `high` "does not
  exist" claim from a guessed entry point. A genuinely nonexistent member of a correctly-located,
  fully-resolved surface still fires `high` — recall is preserved; only guesses are downgraded.

**Invariant 2 reaffirmed (unaffected by this contract).** This installed-surface framing changes
only `real/nonexistent-api` severity/confidence semantics — it does not read, store, or render any
secret value, and it leaves the secret-masking guarantee (Invariant 2 below) and the `gdv1:`
identity-seed redaction entirely intact.

## Invariants

1. **One schema for everything.** No analyzer emits any other shape; renderers, Ship Score,
   baselines, and future SARIF conversion all consume `Vec<Finding>`. The envelope itself may
   grow additive, optional, command-specific fields (`score`, `applied`, `skipped`) — every one
   of them is omitted (not `null`) when the producing command doesn't apply, so existing
   consumers parsing only `findings`/`summary` are unaffected. This document and
   `findings.rs`/`FindingsReport` must stay in lockstep whenever such a field is added.
2. **Secrets never appear** in any field, in any renderer, ever. The fingerprint identity seed
   (which may be a raw secret value for `env` findings) is internal and never serialized — only
   the one-way `gdv1:` digest reaches the wire.
3. Optional fields are **omitted**, never `null`.
4. Severity ordering is total: `critical > high > medium > low > info` — used by `--fail-on`,
   `--severity`, and sorting.
5. Ship Score deductions (computed by `check`, weights in one versioned source file):
   critical −25 · high −10 · medium −4 · low −1, from 100, floor 0.
