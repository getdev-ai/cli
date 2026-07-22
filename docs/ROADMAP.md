# ROADMAP.md — Phases & Milestones

Phase plan for v0.1 and the milestone sequence through v1.0, including what is explicitly out of scope.

> **Source:** distilled from the project master plan (internal) §6 and §14; this doc is normative for phase ordering, exit criteria, and scope boundaries between versions.

**Current status:** v0.1 shipped (2026-07-22); latest release **v0.1.4** (v0.1.x hardening & polish). Next milestone: v0.2 "Sticky". The v0.2+ sections below are the forward plan.

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

## Language expansion (post-v0.5)

Go (v0.5) is the first non-JS/Python language. Beyond it, languages are added **one at a time**, each fully fixture-gated (every rule ≥3 positive + ≥3 negative, CLAUDE.md rule 3) — breadth never dilutes the deterministic-quality bar that is getdev's differentiation.

**Selection principle:** priority ≈ *(vibe-coding prevalence × detection-pattern fit × package-registry availability) ÷ port cost*. Detection-pattern fit is high wherever getdev's existing rule shapes recur — shell/command injection (`exec`/`system`/backticks), SQL string concatenation, hardcoded secrets, hallucinated/typosquatted dependencies, missing-auth heuristics. A package registry is what makes `real` (hallucination detection) possible; languages without one get rules-only support.

| Target | Language | Registry (for `real`) | Rationale — why it earns the slot | Port cost |
|---|---|---|---|---|
| **v0.5** | **Go** | Go module proxy / pkg.go.dev | Heavily AI-scaffolded backend/infra; `os/exec`, `database/sql` concat, secret-in-source map 1:1 onto existing rules; mature grammar | Medium |
| **v0.6** | **PHP** | Packagist | Largest low-experience / vibe-coded population; textbook injection surface (SQLi concat, `exec`/`shell_exec`/`system`, `eval`, `include` of `$_GET`/`$_POST`); mature grammar | Medium |
| **v0.6** | **Ruby** | RubyGems | Rails is heavily AI-scaffolded; `system`/backticks/`eval`, mass-assignment, secrets in source; mature grammar | Medium |
| **v0.7** | **Java** | Maven Central | Enterprise + Android backends; `Runtime.exec`, JDBC concat, unsafe deserialization; cost is build-file parsing (`pom.xml` / `build.gradle`) | High |
| **v0.7** | **Kotlin** | Maven Central (Gradle) | Primary Android + growing backend (Ktor/Spring); shares Java's JVM dependency model, so lands cheaply once Java is in | Medium (after Java) |
| **v0.8** | **C#** | NuGet | ASP.NET; `Process.Start`, SQL concat, secrets in `appsettings.json`; grammar available | High |
| **v0.8** | **Dart** | pub.dev | Flutter is one of the most AI-scaffolded mobile stacks; pub.dev enables `real`; grammar exists but less mature | Medium |
| **later** | **Rust** | crates.io | Completes systems coverage, but experienced population + compiler already eliminate much of getdev's payload — lowest mainstream ROI; do after depth work | Medium |
| **later** | **Shell / Bash** | — (none) | Enormous AI-generated command-injection surface, but **rules-only** (no registry → no `real`); good low-cost add for injection/secret rules | Low |
| **eval only** | **Swift** | SwiftPM | iOS/mobile; injection surface thinner, sandbox stronger — evaluate demand before committing | Medium |

**Deliberately out (for now):** **C/C++** — the dominant risk is memory safety, which is a different tool's domain (getdev is a vibe-code verifier, not a memory analyzer); low pattern-fit. Revisit only if demand is concrete.

Per-language port checklist (each is a multi-week slice, not a weekend): tree-sitter grammar in `getdev-grammars` · import + manifest + lockfile parsers in `core::deps` · a package-registry client + typosquat dataset in `getdev-registry` (skipped for rules-only languages) · a full fixture-gated rule port. Each added language is a standing maintenance liability (grammar bumps, registry drift, fixtures) — sequence for ROI, never scatter.

## Agentic / auto-mode workflow (cross-cutting theme, v0.2 → v1.0)

> This is getdev's **primary strategic direction**, not a side feature. getdev is the
> *deterministic guardrail loop* for autonomous coding agents: an agent (Claude Code, Cursor,
> Cline, Aider, Windsurf, or a bespoke harness) generates and edits code faster than a human can
> review it, and getdev is the verification-and-safety layer that makes that speed safe. Because
> getdev is **deterministic, local-first, and network-free**, it is a trustworthy oracle an agent
> can call on *every iteration* — no code leaves the machine, and the loop stays reproducible.

**The loop getdev enables:**

```
agent proposes change
  → getdev snap            reversible checkpoint (the transaction begins)
  → apply
  → getdev check           deterministic verdict: Ship Score + findings
       Ship Score ≥ gate → keep / commit
       findings present  → feed structured findings back → agent fixes → re-check
       broken / regressed→ getdev back   roll back, agent retries
```

Every existing command already has a role in this loop: `snap`/`back` are the transaction +
rollback, `check` is the gate, `real` catches hallucinated/typosquatted packages the agent
invented, `audit` catches the security anti-patterns it introduced, `env` extracts the secrets it
hardcoded, `review` catches the agent-debris it left behind (dead code, debug leftovers, orphans).

**Capabilities to make getdev first-class in agentic auto-mode** (new + already-planned, mapped to
milestones):

| Capability | Milestone | What / why |
|---|---|---|
| **Baseline / fingerprint suppression** | v0.2 | The linchpin: the agent must see ONLY the findings *it* introduced this iteration, not the repo's pre-existing noise — otherwise the loop never converges. |
| **`getdev-action` (CI gate)** | v0.2 | Every agent-generated PR gets a Ship-Score gate automatically — the backstop when the in-loop check is skipped. |
| **`check --watch`** | v0.2 | Continuous re-verification as the agent edits — sub-second feedback without re-invocation. |
| **Score-gate exit contract** | v0.2 | `check --min-score N` + documented exit codes so a loop can `until getdev check --min-score 80; do …; done`. Formalizes what `--fail-on` starts. |
| **Agent integration pack** | v0.2 | First-party, installable integrations: a Claude Code plugin/skill, Cursor/Windsurf/Cline/Aider/Continue rules snippets, and a formalized `AGENTS.md` block (which `init` already seeds). Zero core change; **highest distribution leverage** — this is how getdev gets into agent loops worldwide. |
| **`--format=agent` output** | v0.3 | Structured, instruction-shaped output tuned for LLM consumption (each finding = {what, where, why, fix, fixable}, plus a compact next-actions list and Ship-Score delta). Distinct from `--json` (CI): fewer tokens, higher fix-success rate. |
| **`getdev fix`** | v0.3 | Cross-command auto-remediation with auto-snap + plan preview — the workhorse the agent calls to self-correct instead of hand-editing every finding. |
| **`[agent]` config policy** | v0.3 | One versioned place a team sets the guardrails every agent obeys: min-score gate, blocking vs warning findings, auto-snap cadence, redaction. Deterministic, in `.getdev.toml`. |
| **`getdev guard <cmd>`** | v0.3–v0.4 | The transactional auto-mode primitive: snap → run the agent's command → check → auto-`back` on regression (score drop / broken parse), else keep. One call wrapping safe-apply-verify-rollback — the harness wraps every risky step in it. |
| **MCP server (`getdev-mcp`, thin separate binary)** | v0.3–v0.4 | Exposes check/real/audit/snap/back/env as MCP tools so any MCP-capable agent calls getdev natively. Kept OUT of the deterministic core (which stays blocking + network-free, DEC-01); the MCP transport is a separate, optional layer. |
| **Semantic spec-drift (opt-in LLM)** | v0.4 | The one place an LLM earns a seat in the loop: "the agent did something plausible but *wrong* vs the stated task." Uses the user's own key / local model; findings carry `confidence: "llm"`, never mixed with deterministic ones; secrets redacted first. |
| **Session / trajectory review** | v0.4+ | `review --session`: analyze the whole agent trajectory (all diffs since session start), not just one diff — catches debris an agent accretes across many small edits. |

**Invariants this theme must never break** (they are precisely *why* an agent can trust getdev on
every iteration): the deterministic core stays network-free and async-free (DEC-01) — MCP/agent
layers are thin, separate, optional; same input → same output, so the loop is reproducible; nothing
leaves the machine (no telemetry, no code upload); every non-LLM finding stays deterministic and
every LLM finding is explicitly labelled and opt-in.

## v1.0 criteria

6 months of production use · < 1 % crash rate (opt-in crash reports only) · schema and config declared stable · 3+ external maintainers · 2k+ GitHub stars or equivalent adoption signal.

---

## Explicit out of scope (per plan §14)

- Web dashboard, hosted score history, GitHub App backend
- Team/multi-user features, accounts, auth
- VS Code / JetBrains extensions (candidates post-v1.0, thin wrappers over `--json`)
- Windows-native shell installer (MSI) — scoop/winget suffice for the audience
- Languages beyond JS/TS/Python before v0.5
