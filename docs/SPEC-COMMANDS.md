# SPEC-COMMANDS.md — Command Behavior Specification

Normative behavior spec for every getdev command in v0.1: synopsis, behavior, flags, mutation and network contracts, and golden output examples.

> **Source:** distilled from the project master plan (internal) §2 and Appendix A; this doc is normative for command behavior and output. Command *scopes* are contractual per `docs/PLAN.md` §2.3 — do not add flags or features not listed there. **Golden examples in this doc are normative:** implemented output must match their structure and content.

Global flags (`--json`, `--quiet`, `--verbose`, `--no-color`, `--config`, `--path`, `--fail-on`, `--fix`, `--offline`, `--version`, `--help`) apply to every command and live in `docs/PLAN.md` §2.2, together with the exit-code contract (0 clean · 1 findings ≥ `--fail-on` · 2 execution error · 3 config error).

`-o/--output <FILE>` (v0.1.3, findings commands: `check`/`real`/`audit`/`review`/`env`/`ship`): write the full JSON report (docs/SPEC-FINDINGS.md schema) to FILE while the terminal keeps a short summary — banner + top-3 (check) and the one-line tally, ending with `full report → FILE (N finding(s) · K KB)`. Combined with `--json`, stdout prints only the file path (script-friendly). The file is an explicitly requested artifact — no `--write` gate, overwrite allowed (eslint/trivy `-o` semantics). There is deliberately NO interactive output-format prompt: prompts after a computed report break CI/pipes and determinism; the >25-findings terminal render appends a one-line `-o` tip instead. Format selection beyond JSON (e.g. SARIF) remains the v0.5 `--format` roadmap item.

Cross-cutting contracts:
- **Mutation:** no command mutates project files without explicit `--write`/`--fix`; all mutations go through `core::mutate` (see `docs/ARCHITECTURE.md`).
- **Network:** only `real`, `check` (via real), `doctor` (optional reachability/version check), and `update` may touch the network; destinations limited to npm registry, PyPI, GitHub Releases. `--offline` disables all.
- **Findings:** all findings conform to `docs/SPEC-FINDINGS.md`; secret values are never printed — masked previews only (`sk-…f3a9`).

---

## `getdev check`

**Synopsis:** `getdev check [global flags]`

**What it does:** Umbrella command. Runs `real` + `audit` + `env` (detect) + `review --all` over **one shared scan pass** (single AST parse via ScanContext). Aggregates findings and computes the **Ship Score 0–100**: start at 100, subtract weighted deductions (critical −25, high −10, medium −4, low −1; floor 0; weights live in one versioned source file and are printed with `-v`).

**Output:** score banner, findings grouped by severity, "top 3 things to fix first," fixable-count hint (`getdev env --write`, later `getdev fix`). `getdev check --json --fail-on high` is the canonical CI line.

**Flags:** global flags only (per-analyzer configuration comes from `.getdev.toml`). `--fix` maps to `env --write` in v0.1.

**Mutates:** no (except via `--fix` → env apply path). **Network:** registry (via `real`); cache-only with `--offline`.

**Golden example (normative — v0.1.3 grouped renderer):**

Findings render grouped by FILE (worst file first, per-file severity tally in
the header), each row as `position · severity glyph+word · message · rule-id`,
with the actionable next step on a `→` continuation line. Severity glyphs
(`✖` critical, `▲` high, `●` medium, `○` low, `·` info) are content, not
color — identical under `--no-color`/`NO_COLOR`/piped output.

```
$ getdev check
┌─ getdev check ───────────────────────────────┐
│  Ship Score: 43/100                          │
│  2 critical · 3 high · 5 medium · 4 low      │
└──────────────────────────────────────────────┘
requirements.txt — 1 finding · 1 critical
         4 ✖ critical 'requests-auth-helper' does not exist on PyPI  real/nonexistent-package
           → did you mean 'requests-oauthlib'?

src/payments.ts — 1 finding · 1 critical
      12:3 ✖ critical Stripe live secret key assigned to 'stripeKey' (sk_live_…9f2a)  env/hardcoded-secret
           → extract to STRIPE_SECRET_KEY in .env
...
```

A hardcoded secret is counted ONCE in the aggregate: `audit/hardcoded-secret`
and `env/hardcoded-secret` are the same underlying detection, and `check`
keeps env's fixable finding, dropping audit's twin at the same file:line
(standalone `audit`/`env` runs are unaffected).

---

## `getdev real`

**Synopsis:** `getdev real [--deps-only|--apis-only|--models-only] [global flags]`

**What it does:** Verifies that packages, APIs, and model strings actually exist. Rule ID prefix: **`real/`** (`nonexistent-package`, `typosquat-suspect`, `phantom-import`, `nonexistent-api`, `version-mismatch-api`, `unknown-model-string`, `unsupported-stack` — detection definitions in `docs/PLAN.md` §2.3; `unsupported-stack` sanctioned F1, mandated by the 03-05 must-have).

**Mechanics:**
- Dependency graph from manifests (`package.json`, `requirements.txt`, `pyproject.toml`, lockfiles) **plus** actual imports found by AST walk (agents often import without declaring).
- Registry lookups: npm registry API + PyPI JSON API; responses cached in `~/.getdev/cache/registry/` (SQLite; TTL 7 days existence, 24 h metadata).
- API-surface verification introspects *installed* packages (`node_modules` type definitions/exports; Python `site-packages` via AST — no code execution). Confidence-tiered: exact miss = high severity; dynamic/`__getattr__`-style packages downgraded to `info` with a note.
- Model-string dataset ships in the binary (`crates/getdev-core/rules/models.json`), refreshed each release; `--offline` uses the embedded copy.

**Flags:** `--deps-only`, `--apis-only`, `--models-only`.

**Mutates:** no. **Network:** npm registry + PyPI (the only analyzer that does); fully functional from cache with `--offline`.

**Golden example:** TBD (plan provides finding examples via `check`; see the `check` golden block and the JSON example in `docs/SPEC-FINDINGS.md`).

---

## `getdev audit`

**Synopsis:** `getdev audit [--severity <min>] [--ignore <rule-id>] [--rules <dir>] [global flags]`

**What it does:** Security scan tuned to AI-generated failure patterns. Pure static analysis: tree-sitter AST + declarative YAML rules (`crates/getdev-core/rules/audit/*.yaml`, format in `docs/SPEC-RULES.md`). Rule ID prefix: **`audit/`**. v0.1 rule pack categories: Secrets (`hardcoded-secret`; `secret-in-git-history` DEFERRED to Phase 5, needs gitx diff extraction that lands there — not shipped in the v0.1 audit pack — note: `env-file-committed` is implemented under `env/`, not `audit/`, see `getdev env` below; sanctioned F1), Injection (`sql-string-concat`, `eval-user-input`, `exec-user-input`, `shell-interpolation`), Web config (`cors-wildcard`, `debug-mode-enabled`, `cookie-insecure`, `missing-auth-middleware` — framework-aware: Express, FastAPI, Flask, Next.js API routes), Client/server (`client-only-validation` heuristic `medium` max, `api-key-in-client-bundle`), Platform (`supabase-permissive-rls`, `firebase-open-rules`).

**Flags:** `--severity <min>`, `--ignore <rule-id>` (also configurable), `--rules <dir>` (custom rule packs — declarative-only, never executable).

**Mutates:** no. **Network:** none.

**Golden example:** TBD (see `audit/hardcoded-secret` line in the `check` golden block).

---

## `getdev review`

**Synopsis:** `getdev review [--against <ref>] [--staged] [--all] [global flags]`

**What it does:** Analyzes a diff (working tree vs `HEAD` by default) for agent-session artifacts. Rule ID prefix: **`review/`** (`dead-code-introduced`, `duplicate-helper` ≥ 85 % token-similar via normalized AST fingerprint, `debug-leftover`, `todo-introduced`, `commented-code-block` ≥ 3 lines parsing as code, `orphan-file`). Diff extraction via `getdev-gitx`.

**Flags:** `--against <ref>`, `--staged`, `--all` (whole tree, not just diff).

**v0.1 constraint:** deterministic only — LLM-assisted semantic review is v0.4 (`docs/ROADMAP.md`).

**Mutates:** no. **Network:** none.

**Golden example:** TBD.

---

## `getdev env`

**Synopsis:** `getdev env [--write] [--include-urls] [--env-file <path>] [global flags]`

**What it does:** Pipeline **detect → plan → (apply)**. Rule ID prefix: **`env/`** (`hardcoded-secret`, `env-file-committed` — sanctioned F1; `env-file-committed` was previously listed under `audit/` in earlier drafts of this doc, but is implemented and owned here):
1. **Detect** hardcoded values: secret-pattern matches from the `audit` engine, plus (with `--include-urls`) http(s) URLs and connection strings assigned to identifiers.
2. **Plan:** generate variable names (`STRIPE_SECRET_KEY` from context: identifier name, provider pattern, file path), detect collisions, detect existing `.env`.
3. **Apply** (`--write` only): write/append `.env` (values) and `.env.example` (keys + placeholder comments); rewrite each reference to the idiomatic accessor for the stack (`process.env.X`, `os.environ["X"]`, framework config where detectable); ensure `.env` is in `.gitignore`; if `.env` was previously committed, emit a `critical` finding with key-rotation guidance (never rewrite git history automatically).

**Default is dry-run** — output is the full plan as a findings list.

**Flags:** `--write`, `--include-urls`, `--env-file <path>`. (`check --fix` maps to this command's apply step.)

**Mutates:** only with `--write`, via `core::mutate` (atomic write → reparse-verify → rollback; auto-snap before multi-file rewrites). **Network:** none.

**Golden example:** TBD (Appendix A shows only the invocation: `getdev env --write` → "secrets → .env, refs rewritten, .gitignore patched").

---

## `getdev snap` / `getdev back`

**Synopsis:** `getdev snap [-m <msg>] | snap list | snap diff <id> | snap prune` · `getdev back [<id>]`

**What it does:** Checkpoints for people who don't use git — implemented on git plumbing, invisible to the user.

| Subcommand | Behavior |
|---|---|
| `snap` | Snapshot entire working tree (incl. untracked, excl. `.gitignore`d) → commit object under `refs/getdev/snaps/<n>` |
| `snap -m "msg"` | Labeled snapshot |
| `snap list` | Table: id, age, message, files changed |
| `back` | Restore most recent snapshot (auto-snaps current state first — restore is always reversible) |
| `back <id>` | Restore specific snapshot |
| `snap diff <id>` | Summary of changes since snapshot |
| `snap prune` | Enforce retention (`keep`, default 20) |

**Mechanics:** if no repo exists, `git init` silently with `refs/getdev/` namespace only. Never touches user branches, index, or stash. If the git binary is absent: clear error + install pointer (v0.1 requires git).

**Mutates:** snapshot refs only (`refs/getdev/`); `back` restores working-tree files (always preceded by an auto-snap). **Network:** none.

**Golden example:** TBD.

---

## `getdev ship`

**Synopsis:** `getdev ship [--write] [--target vercel|railway|fly|docker|vps] [--run-build] [global flags]`

**What it does (v0.1 = prepare & validate, no deployment):** Rule ID prefix: **`ship/`**.
1. **Generate** (with `--write`): multi-stage `Dockerfile` + `.dockerignore` for the detected stack (Node/Next.js, Python/FastAPI/Flask/Django presets), `HEALTHCHECK` included.
2. **Validate:** every env var referenced in code exists in `.env.example` (`ship/missing-env-declaration`); port binding uses `PORT` env, not hardcoded (`ship/hardcoded-port`); build succeeds only with `--run-build` (off by default — getdev never executes project code without explicit opt-in); no `audit` criticals outstanding (`ship/blocking-findings`).
3. **Checklist:** per-target markdown checklist (default target auto-detected/`docker`), printed or written to `SHIP.md` with `--write`.

**Flags:** `--write`, `--target <t>`, `--run-build`.

**Mutates:** only with `--write` (Dockerfile, .dockerignore, SHIP.md — via `core::mutate`). **Network:** none. **Executes project code:** only with explicit `--run-build`.

**Golden example:** TBD (Appendix A: `getdev ship --write` → "Dockerfile + SHIP.md checklist").

---

## `getdev init`

**Synopsis:** `getdev init [--yes] [global flags]`

**What it does:** Interactive project setup (`--yes` accepts defaults). Leads with a one-time decorative welcome banner (the getdev wordmark + a promise tagline — no call-to-action per the standing no-CTA/no-telemetry rule), then:
1. Write `.getdev.toml` (detected stack, defaults — see `docs/SPEC-CONFIG.md`).
2. Offer pre-commit hook → `getdev check --quiet --fail-on critical`.
3. Offer agent-context block: append getdev usage guidance to `CLAUDE.md` / `AGENTS.md` / `.cursorrules` if present (marked managed block) — so the user's agent learns to run `getdev snap` before big changes and `getdev check` after.
4. Offer auto-snap hook (post-checkout / pre-agent via documented pattern).

**Welcome banner:** shown once at the top of output. Suppressed under `--quiet` and `--json`; rendered plain (no ANSI) under `--no-color`, `NO_COLOR`, or a non-tty stdout. It is the only place getdev prints decorative art and it never links out or prompts an action.

**Flags:** `--yes`.

**Mutates:** yes — creates new files / appends managed blocks (this is its purpose; each step is offered interactively unless `--yes`). The welcome banner is stdout-only, never a file write. **Network:** none.

**Golden example (plain, `--no-color`):**

```
               __      __
   ____ ____  / /_____/ /__ _   __
  / __ `/ _ \/ __/ __  / _ \ | / /
 / /_/ /  __/ /_/ /_/ /  __/ |/ /
 \__, /\___/\__/\__,_/\___/|___/
/____/
  verify · secure · ship AI-generated code
  v0.1.0 · local-first · nothing leaves your machine

.getdev.toml — written (detected stack: node)
…
getdev is set up — run `getdev check` to see your Ship Score
```

---

## `getdev doctor`

**Synopsis:** `getdev doctor [--fix] [global flags]`

**What it does:** Self-diagnostics. Checks: binary version vs latest (skipped with `--offline`), git availability/version, cache size & integrity, config validity, tree-sitter grammar integrity, registry reachability. Prints a pass/fail table.

**Flags:** `--fix` clears corrupt cache.

**Mutates:** only getdev's own cache (with `--fix`); never project files. **Network:** optional (version check + registry reachability; both skipped with `--offline`).

**Golden example:** TBD (plan specifies "pass/fail table" only).

---

## `getdev update`

**Synopsis:** `getdev update [global flags]`

**What it does:** Self-updates the binary from GitHub Releases with signature check; supports version pinning. Implementation: `self_update` crate or hand-rolled (see `docs/DECISIONS.md`, `docs/RELEASING.md`).

**Flags:** TBD (plan specifies no per-command flags).

**Mutates:** the getdev binary only; never project files. **Network:** yes — GitHub Releases only.

**Golden example:** TBD.

---

## `getdev version` / `getdev help`

**Synopsis:** `getdev version` · `getdev help` / `getdev --help`

**What it does:** Plumbing — print version / usage. **Mutates:** no. **Network:** none.

---

## Deferred to v0.3 (do not implement in v0.1)

| Command | Purpose | Notes |
|---|---|---|
| `getdev clean` | Remove dead code / unused deps / debug artifacts | Mutates only with `--fix` |
| `getdev fix` | Apply auto-fixes across all findings | Cross-command auto-remediation with auto-snap + plan preview |

Their detailed specification is TBD until the v0.3 planning cycle (`docs/ROADMAP.md`).
