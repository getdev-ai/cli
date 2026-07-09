# PLAN.md — Working Plan Reference

Canonical working reference for getdev's product definition: command inventory, global flags, exit codes, contractual per-command scopes, performance budgets, quality gates, and success metrics.

> **Source:** distilled from the project master plan (internal) §2, §3.5, §9, §13; this doc is normative for command scopes (§2.3), global flags and exit codes (§2.2), performance budgets, and quality/release gates. Section numbering intentionally mirrors the master plan.

**§2.3 command scopes are CONTRACTUAL.** Do not add features or flags not listed there. Anything not listed goes to the v0.2+ backlog — propose it in `docs/ROADMAP.md`, do not implement it.

---

## 2. Product Definition — Command Surface

### 2.1 Command inventory

| Command | Purpose | Mutates files | Network | v0.1 |
|---|---|---|---|---|
| `getdev check` | Umbrella: run real+audit+env+review, one scored report | No | Registry | ✅ |
| `getdev real` | Verify packages / APIs / model strings actually exist | No | Registry | ✅ |
| `getdev audit` | Security scan tuned to AI-generated failure patterns | No | None | ✅ |
| `getdev review` | Diff analysis: dead code, duplication, debug leftovers | No | None | ✅ |
| `getdev env` | Extract hardcoded secrets → `.env`, rewrite references | With `--write` | None | ✅ |
| `getdev snap` / `back` | Checkpoint & restore working tree (git hidden) | Snapshot refs only | None | ✅ |
| `getdev ship` | Pre-flight: Dockerfile gen, env validation, build check | With `--write` | None | ✅ (prepare-only) |
| `getdev init` | Project setup: config, hooks, agent-context files | Yes (new files) | None | ✅ |
| `getdev clean` | Remove dead code / unused deps / debug artifacts | With `--fix` | None | v0.3 |
| `getdev fix` | Apply auto-fixes across all findings | Yes | None | v0.3 |
| `getdev doctor` | Self-diagnostics: cache health, git presence, PATH | No | Optional | ✅ |
| `getdev update` | Self-update the binary | Binary only | Yes | ✅ |
| `getdev version` / `help` | Plumbing | No | None | ✅ |

### 2.2 Global flags (every command)

```
--json              machine-readable output (findings schema, docs/SPEC-FINDINGS.md)
--quiet, -q         suppress banner/progress; findings only
--verbose, -v       debug-level detail (repeatable: -vv)
--no-color          disable ANSI colors (also honors NO_COLOR env)
--config <path>     alternate config file (default: ./.getdev.toml)
--path <dir>        run against a directory other than CWD
--fail-on <sev>     exit code 1 if any finding ≥ severity (critical|high|medium|low)
--fix               apply auto-fixes where the command supports them
--offline           never hit the network; use cache only
--version
--help, -h
```

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | clean / below `--fail-on` threshold |
| `1` | findings ≥ `--fail-on` |
| `2` | execution error |
| `3` | config error |

### 2.3 Per-command specification (v0.1 scope) — CONTRACTUAL

These scopes are contractual. Text is carried over essentially verbatim from the master plan.

#### `getdev real`

**Checks (rule ID prefix `real/`):**

| Rule | Detection |
|---|---|
| `real/nonexistent-package` | Declared or imported dependency not found on npm/PyPI |
| `real/typosquat-suspect` | Package within Damerau-Levenshtein distance ≤ 2 of a top-10k package, low download count, or created < 90 days ago |
| `real/phantom-import` | Import that resolves neither to a dependency, stdlib, nor local module |
| `real/nonexistent-api` | Attribute/method call not present in the installed version's public surface |
| `real/version-mismatch-api` | API exists in another major version of the installed package but not the installed one |
| `real/unknown-model-string` | LLM model identifier not in the known-models dataset (Anthropic/OpenAI/Google/Mistral/etc.) |

**Mechanics:**
- Dependency graph from manifest (`package.json`, `requirements.txt`, `pyproject.toml`, lockfiles) **plus** actual imports found by AST walk (agents often import without declaring).
- Registry client: npm registry API + PyPI JSON API. All responses cached in `~/.getdev/cache/registry/` (SQLite, TTL 7 days for existence, 24 h for metadata).
- API-surface verification: introspect *installed* packages — parse `node_modules/<pkg>` type definitions / exports, and Python `site-packages` via AST of the installed source (no code execution). Confidence-tiered: exact miss = high severity; dynamic/`__getattr__`-style packages = downgraded to `info` with a note (see §9.2 false-positive policy).
- Model-string dataset ships in the binary (`rules/models.json`), refreshed each release; `--offline` uses embedded copy.

**Flags:** `--deps-only`, `--apis-only`, `--models-only`.

#### `getdev audit`

**Checks (rule ID prefix `audit/`), v0.1 rule pack:**

| Category | Rules |
|---|---|
| Secrets | `hardcoded-secret` (provider-specific regexes: AWS, Stripe, OpenAI, Anthropic, GitHub, Supabase, etc. + Shannon-entropy fallback), `env-file-committed`, `secret-in-git-history` (HEAD-adjacent only in v0.1) |
| Injection | `sql-string-concat`, `eval-user-input`, `exec-user-input`, `shell-interpolation` |
| Web config | `cors-wildcard`, `debug-mode-enabled`, `cookie-insecure`, `missing-auth-middleware` (framework-aware: Express, FastAPI, Flask, Next.js API routes) |
| Client/server | `client-only-validation` (form handlers with no matching server check — heuristic, `medium` max), `api-key-in-client-bundle` |
| Platform | `supabase-permissive-rls` (detect `service_role` key in client code), `firebase-open-rules` (if rules file present) |

**Mechanics:** pure static analysis — tree-sitter AST + declarative rule files (`rules/audit/*.yaml`). Rules are data, not code → community-contributable. Each rule carries: pattern, severity, message, remediation text, references, test fixtures. See `docs/SPEC-RULES.md`.

**Flags:** `--severity <min>`, `--ignore <rule-id>` (also configurable), `--rules <dir>` (custom rule packs).

#### `getdev review`

Analyzes a diff (working tree vs `HEAD` by default) for agent-session artifacts:

| Rule | Detection |
|---|---|
| `review/dead-code-introduced` | New functions/exports with zero references |
| `review/duplicate-helper` | New function ≥ 85 % token-similar to an existing one (normalized AST fingerprint) |
| `review/debug-leftover` | New `console.log` / `print` / `debugger` / `breakpoint()` outside test files |
| `review/todo-introduced` | New TODO/FIXME/HACK comments |
| `review/commented-code-block` | New blocks of commented-out code (≥ 3 lines parsing as code) |
| `review/orphan-file` | New file imported by nothing |

**Flags:** `--against <ref>`, `--staged`, `--all` (whole tree, not just diff).
**v0.1 constraint:** deterministic only. LLM-assisted semantic review is v0.4 (see `docs/ROADMAP.md`).

#### `getdev env`

Pipeline: **detect → plan → (apply)**.

1. Detect hardcoded values: secret-pattern matches from the `audit` engine, plus (with `--include-urls`) http(s) URLs and connection strings assigned to identifiers.
2. Plan: generate variable names (`STRIPE_SECRET_KEY` from context: identifier name, provider pattern, file path), detect collisions, detect existing `.env`.
3. Apply (`--write` only):
   - Write/append `.env` (values) and `.env.example` (keys + placeholder comments).
   - Rewrite each reference to the idiomatic accessor for the stack (`process.env.X`, `os.environ["X"]`, framework config where detectable).
   - Ensure `.env` in `.gitignore`.
   - If `.env` was previously committed: emit `critical` finding with key-rotation guidance (never rewrite git history automatically).

**Default is dry-run.** Output is the full plan as a findings list. `--write` applies; `--fix` on `check` maps to this.
**Flags:** `--write`, `--include-urls`, `--env-file <path>`.

#### `getdev snap` / `getdev back`

Checkpoints for people who don't use git — implemented on git plumbing, invisible to the user.

| Subcommand | Behavior |
|---|---|
| `snap` | Snapshot entire working tree (incl. untracked, excl. `.gitignore`d) → commit object under `refs/getdev/snaps/<n>` |
| `snap -m "msg"` | Labeled snapshot |
| `snap list` | Table: id, age, message, files changed |
| `back` | Restore most recent snapshot (auto-snaps current state first — restore is always reversible) |
| `back <id>` | Restore specific snapshot |
| `snap diff <id>` | Summary of changes since snapshot |
| `snap prune` | Enforce retention (`keep`, default 20) |

**Mechanics:** if no repo exists, `git init` silently with `refs/getdev/` namespace only — user's world is untouched. Never touches user branches, index, or stash. If git binary absent: clear error + install pointer (v0.1 requires git; git-free object writing via `gix` is a v1.x hardening item).

#### `getdev ship` (v0.1 = prepare & validate, no deployment)

1. **Generate** (with `--write`): multi-stage `Dockerfile` + `.dockerignore` for the detected stack (Node/Next.js, Python/FastAPI/Flask/Django presets), `HEALTHCHECK` included.
2. **Validate:**
   - Every env var referenced in code exists in `.env.example` (`ship/missing-env-declaration`).
   - Port binding: uses `PORT` env / configurable, not hardcoded (`ship/hardcoded-port`).
   - Build succeeds: `npm run build` / `pip install` dry equivalent, executed with `--run-build` (off by default — getdev never executes project code without explicit opt-in).
   - No `audit` criticals outstanding (`ship/blocking-findings`).
3. **Checklist:** per-target markdown checklist (`--target vercel|railway|fly|docker|vps`, default auto-detected/`docker`) printed or written to `SHIP.md` with `--write`.

#### `getdev check`

- Runs `real` + `audit` + `env` (detect) + `review --all` over one shared scan pass (single AST parse — see `docs/ARCHITECTURE.md`).
- Aggregates findings, computes **Ship Score 0–100**: start at 100, subtract weighted deductions (critical −25, high −10, medium −4, low −1; floor 0; weights in one versioned source file, printed with `-v`).
- Output: score banner, findings grouped by severity, "top 3 things to fix first," fixable-count hint (`getdev env --write`, later `getdev fix`).
- This is the flagship screenshot/CI command. `getdev check --json --fail-on high` is the canonical CI line.

#### `getdev init`

Interactive (with `--yes` for defaults):
1. Write `.getdev.toml` (detected stack, defaults).
2. Offer pre-commit hook → `getdev check --quiet --fail-on critical`.
3. Offer agent-context block: append getdev usage guidance to `CLAUDE.md` / `AGENTS.md` / `.cursorrules` if present (marked managed block) — so the user's agent itself learns to run `getdev snap` before big changes and `getdev check` after.
4. Offer auto-snap hook (post-checkout / pre-agent via documented pattern).

#### `getdev doctor`

Checks: binary version vs latest (skipped with `--offline`), git availability/version, cache size & integrity, config validity, tree-sitter grammar integrity, registry reachability. Prints pass/fail table; `--fix` clears corrupt cache.

---

## 3.5 Performance budgets (hard targets, enforced by benchmark CI)

| Operation | Budget (repo ≈ 500 files / 100k LOC) |
|---|---|
| `getdev check` warm cache | < 3 s |
| `getdev check` cold (network) | < 15 s |
| `getdev audit` / `review` (no network) | < 2 s |
| `getdev snap` | < 1 s |
| Binary size | < 25 MB (grammars dominate; release profile: `lto = true`, `strip = true`, `codegen-units = 1`) |
| Memory ceiling | < 500 MB on 1M-LOC repo |

Benchmarks: `cargo bench -p getdev-core` (criterion; see `docs/TESTING.md`).

---

## 9. Quality & Release Gates

### 9.1 The corpus

`testdata/corpus/` = 20+ sample projects that define ground truth:
- 10 synthetic "vibe-coded" apps (Node/Express, Next.js, FastAPI, Flask, Django) with **seeded, cataloged defects** (fake packages, secrets, missing auth, dead code…) — every seeded defect has an expected finding.
- 10 real popular OSS repos (permissive licenses, vendored snapshots) used as **false-positive sentinels**: getdev should stay quiet on healthy code.

### 9.2 False-positive policy (existential for adoption)

- Every rule ships with a measured FP rate on the sentinel set; > 5 % → rule demoted to `low`/`info` or `confidence: low` until improved.
- Heuristic rules must surface their reasoning in `detail`.
- One-command suppression with recorded reason (see `docs/SPEC-CONFIG.md`); suppressions are visible in `check -v` so they don't rot silently.

### 9.3 Release gate (every release)

1. Full CI matrix green, coverage floor met, benchmarks within budget.
2. Corpus: 100 % seeded-defect recall for `real`/`env`; per-rule recall/FP targets met.
3. `docker build` succeeds on all `ship` preset outputs.
4. Manual smoke on the "first five minutes" script (install → init → check → env --write → snap/back) on all 3 OSes.
5. Signed artifacts + checksums + SBOM published; install.sh points at new version only after checksum verification.

---

## 13. Success metrics

| Horizon | Metric | Target |
|---|---|---|
| Launch week | GitHub stars / HN front page | 500+ / yes |
| v0.1 +30 d | Unique installs (release download counts — no telemetry) | 3,000 |
| v0.1 +30 d | Issues filed that are FP reports | < 20 % of total (signal of trust) |
| v0.2 | External rule-pack PRs merged | 5+ |
| v0.3 | Projects with `.getdev.toml` visible on GitHub search | 300+ |
| v1.0 | External maintainers / weekly active CI usage (action runs) | 3+ / 1,000+ |
