# ROADMAP.md — Phases & Milestones

Phase plan for v0.1 and the milestone sequence through v1.0, including what is explicitly out of scope.

> **Source:** distilled from `getdev-development-plan.md` §6 and §14; this doc is normative for phase ordering, exit criteria, and scope boundaries between versions.

**Current status:** P0 in progress — workspace scaffold + scan walker spike merged 2026-07-09; findings/config/report in progress.

---

## v0.1 — "The Six" (target: 12 weeks from start)

All six core commands (scopes as in `docs/PLAN.md` §2.3) + `check`, `init`, `doctor`, `update`, full global flags, JS/TS + Python. Timeline assumes working (not expert) Rust fluency; if already fluent, compress to 10 weeks by merging P0 into 1.5 weeks and P2 into 1.5.

| Phase | Weeks | Deliverables | Exit criteria |
|---|---|---|---|
| **P0 Spike & Foundation** | 1–2.5 | **Day 1–2 de-risking spike:** walker + tree-sitter (JS+Python) + one query + `cargo-dist` cross-compile to darwin-arm64/linux-x86_64/windows-x86_64 from one CI run. Then: workspace scaffold (`getdev-cli`, `getdev-core`, `getdev-registry`, `getdev-gitx`, `getdev-grammars`), CI, `cargo-dist` release pipeline, `core::scan`, findings schema, config loader, terminal+JSON renderers, `doctor`, `version` | Spike green before any further code; `getdev doctor` runs on all 3 OSes from a release artifact; scan parses the 20-repo corpus (PLAN.md §9.1) without panic |
| **P1 env** | 3–3.5 | Secret detection engine (shared with audit), `env` detect+plan+apply, `core::mutate` | Corpus: ≥ 95 % of seeded secrets detected, 0 broken rewrites (project still parses & tests pass post-`--write`) |
| **P2 real** | 4–6 | Registry client + cache, dependency graph, typosquat detection, API-surface introspection (confidence-tiered), model dataset | Corpus: 100 % of seeded fake packages caught; API-check FP rate < 5 % on real repos; `--offline` fully functional |
| **P3 audit** | 7 | Rule engine (YAML packs), v0.1 rule set (PLAN.md §2.3), framework detection | Every rule has ≥ 3 positive + 3 negative test fixtures; corpus FP review complete |
| **P4 snap** | 8 | gitx plumbing, snap/back/list/diff/prune, no-repo bootstrap | Property test (`proptest`): snap → mutate randomly → back → tree byte-identical, 1000 iterations |
| **P5 review** | 9 | Diff extraction, dead-code/duplicate/debug/todo/orphan rules | Corpus of real agent-session diffs: ≥ 80 % of seeded artifacts caught, FP < 10 % |
| **P6 ship + check + init** | 10–11 | Dockerfile presets, env validation, checklists; check aggregation + Ship Score; init flow | `check` single-pass ≤ perf budgets; `ship --write` output builds via `docker build` for all preset stacks |
| **P7 Hardening & launch** | 12 | Cross-platform QA (incl. Windows paths/CRLF), docs site (rule pages generated from YAML), README security promise, install.sh, brew/scoop/npm wrapper, demo GIFs, launch posts | PLAN.md §9.3 release gate green |

**P0 scope note:** anything not in the current phase is frozen. Features outside `docs/PLAN.md` §2.3 go to the v0.2+ backlog, not into the code.

---

## v0.2 — "Sticky" (weeks 13–16)

Baseline/fingerprint suppression at scale · `check --watch` · score badge JSON · shell completions polish · pre-commit framework integration · GitHub Action published (`getdev-action`, thin wrapper) · Windows first-class hardening · community rule-pack contribution guide + first external rules.

## v0.3 — "Fix" (weeks 17–22)

`clean` (dead code / unused deps removal) · `fix` (cross-command auto-remediation with auto-snap + plan preview) · `audit` git-history secret scan (full) · monorepo/workspaces support.

## v0.4 — "Semantic" (weeks 23–30)

Optional LLM layer — **off by default, explicit `--llm` or config opt-in**: `review` semantic pass (spec-drift vs commit message/PLAN.md, hallucinated-logic detection), `audit` route-reachability reasoning.

LLM boundaries (strict):
- Provider is always the **user's own**: BYO API key (Anthropic/OpenAI/etc.) **or a local model** via OpenAI-compatible endpoint (`llm.base_url` in `.getdev.toml` → Ollama / LM Studio / llama.cpp work out of the box, keeping the semantic layer fully offline for privacy-maximalist users).
- LLM findings carry `confidence: "llm"` and are never silently mixed with deterministic ones.
- Deterministic findings never depend on the LLM.
- Detected secrets are redacted before anything enters a prompt.

## v0.5 — "Breadth" (weeks 31+)

Go language support · `ship` actual deploy drivers (fly/railway APIs) behind explicit confirmation · plugin/rule-pack registry (`getdev rules add <pack>`) · SARIF output for GitHub code scanning.

## v1.0 criteria

6 months of production use · < 1 % crash rate (opt-in crash reports only) · schema and config declared stable · 3+ external maintainers · 2k+ GitHub stars or equivalent adoption signal.

---

## Explicit out of scope (per plan §14)

- Web dashboard, hosted score history, GitHub App backend
- Team/multi-user features, accounts, auth
- VS Code / JetBrains extensions (candidates post-v1.0, thin wrappers over `--json`)
- Windows-native shell installer (MSI) — scoop/winget suffice for the audience
- Languages beyond JS/TS/Python before v0.5
