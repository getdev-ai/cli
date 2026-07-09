# SPEC — Findings schema (v1)

The unified findings format every analyzer produces, every renderer consumes, and `--json`
emits. **This document is normative**; the implementation is `crates/getdev-core/src/findings.rs`
and the two must never drift (a PR changing one must change both).

Source: distilled from getdev-development-plan.md §4.

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
      "fingerprint": "sha256:…"
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
| `fingerprint` | string | optional | `sha256:` + stable hash of (rule, file, normalized context). Enables baselines (`--baseline`, v0.2). Omitted until implemented. |

## Invariants

1. **One schema for everything.** No analyzer emits any other shape; renderers, Ship Score,
   baselines, and future SARIF conversion all consume `Vec<Finding>`.
2. **Secrets never appear** in any field, in any renderer, ever.
3. Optional fields are **omitted**, never `null`.
4. Severity ordering is total: `critical > high > medium > low > info` — used by `--fail-on`,
   `--severity`, and sorting.
5. Ship Score deductions (computed by `check`, weights in one versioned source file):
   critical −25 · high −10 · medium −4 · low −1, from 100, floor 0.
