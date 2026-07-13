# testdata/corpus — the ground-truth corpus (docs/PLAN.md §9.1, docs/TESTING.md)

Two halves, both exercised by `crates/getdev-cli/tests/corpus.rs`:

- `seeded/` — synthetic "vibe-coded" apps with deliberately seeded fake
  packages/APIs/model-strings. Every seeded defect is cataloged in a
  companion `getdev-expected.json` — recall (100% of seeded fake packages
  caught) is measured against this catalog, per app. A seeded app also
  doubles as its own sentinel on every file it did NOT seed a defect into:
  `seeded_recall_is_100_percent` additionally asserts every finding on a
  seeded app is one of the catalogued `(id, file)` pairs — an extra,
  uncatalogued finding fails the gate even though recall is 100% (D3,
  03-REVIEW.md — "recall passes while drowning in extra false positives").
- `sentinels/` — apps `getdev real` should stay quiet on (the false-positive
  budget, docs/PLAN.md §9.2). Most are real, permissively-licensed OSS
  snapshots vendored small; a few (`py-aliases/`, `js-untyped/`) are small
  synthetic first-party fixtures written specifically to reproduce a FP
  class the Theme A audit found in real-world layouts that the vendored
  snapshots didn't happen to exercise — see "`sentinels/` provenance"
  below. **The FP budget is measured PER RULE ID**, not as one aggregate
  rate across every rule (D3): a rule's warning+ (low/medium/high/critical)
  finding count across every sentinel file, divided by the total number of
  source files scanned across the whole sentinel set, must stay under 5%
  for every rule that fires at all — an aggregate rate can hide one
  badly-behaved rule diluted by several well-behaved ones. Info-severity
  findings (e.g. the A3 aggregated "could not verify N usage(s) of 'pkg' —
  not installed/no readable types" note) are excluded from the count
  entirely: that severity is a deliberate, honest "could not confirm"
  admission, not a false claim that something is wrong — see
  `sentinels/js-untyped/` below.

Both halves are run **fully hermetically**: `GETDEV_OFFLINE=1` +
`GETDEV_CACHE_DIR` pointed at a temp directory seeded from each app's
`getdev-cache-seed.json` before `getdev real --offline --json --path <app>`
runs (see `crates/getdev-cli/tests/real_cli.rs`'s seeding pattern, reused by
`corpus.rs`). No corpus app is ever mutated — the harness only writes to a
throwaway temp cache dir, never into `testdata/corpus/`.

## `seeded/` convention

Each seeded app is a directory under `seeded/<framework>-<n>/` (Node/Express,
Next.js, FastAPI, Flask, Django — at least two apps per framework). Every
seeded app carries:

- **`getdev-expected.json`** — `{ "seeded": [ { "id": "real/nonexistent-package", "file": "requirements.txt", "package": "requests-auth-helper" }, ... ] }`.
  Every seeded defect that `getdev real` should catch is cataloged here; the
  corpus harness's recall test asserts each entry has a matching finding
  (same rule `id` + `file`) in the report.
- **`getdev-cache-seed.json`** — `{ "npm": { "<name>": true|false }, "pypi": { "<name>": true|false } }`.
  Existence rows the harness loads into a temp `GETDEV_CACHE_DIR` before
  running, so `real/nonexistent-package` resolution is deterministic and
  offline (a seeded fake package is a `false` row; real/kept-quiet
  dependencies are seeded `true`). A package with **no** row at all
  deliberately stays `Inconclusive` under `--offline` — proving the harness
  never fabricates a `Missing` verdict from an unconfirmed lookup
  (`corpus_run_is_hermetic`, T-3-07).

Seeded defect types used across the seeded apps (docs/PLAN.md §2.3's six
contractual `real/*` rule IDs):

| Rule ID | Mechanism | Ecosystem coverage |
|---|---|---|
| `real/nonexistent-package` | declared dependency cache-seeded `false` (`Existence::Missing`) | npm + pypi |
| `real/typosquat-suspect` | declared dependency name is a 1–2 edit-distance near-name of an embedded top-N package (`rules/real/npm-top-10k.json` / `pypi-top-5k.json`), cache-seeded `true` so it does not *also* fire `nonexistent-package` — the near-name reason fires from the name alone, no metadata cache row needed | npm + pypi |
| `real/phantom-import` | an import/require that resolves to no declared dependency, builtin, or local module — computed purely from `deps::build_graph`, no registry/cache involvement at all | npm + pypi |
| `real/nonexistent-api` | a declared, cache-seeded-`true` package ships a tiny bundled `node_modules/<pkg>` (`package.json` + `index.d.ts`) or `site-packages/<pkg>` (`__init__.py`) surface stub; the seeded app imports/uses a member the stub does not export | npm + pypi |
| `real/unknown-model-string` | a string literal at a model call-site identifier (`model`/`model_name`/`modelId`/`model_id`/`deployment`, `rules/models.json`) that matches no known vendor-family prefix | JS + Python |

`real/version-mismatch-api` is **not** seeded: `getdev-core::apisurface::check`
documents that this rule is never emitted in v0.1 (no local, network-free
evidence source for "exists in a different installed version" — every
surface miss conservatively resolves to `NonexistentApi` instead, see the
doc-comment on `apisurface::check`). Seeding an app that expects a finding
the analyzer cannot currently produce would make the recall test
unsatisfiable by construction, not a genuine regression signal — so it is
intentionally omitted here and left for whenever version-history evidence
lands.

### The seeded apps

| App | Framework | Seeded defects |
|---|---|---|
| `seeded/express-hello/` | Node/Express | `real/nonexistent-package` (npm), `real/phantom-import` (JS), `real/unknown-model-string` (JS) |
| `seeded/express-api/` | Node/Express | `real/typosquat-suspect` (npm), `real/nonexistent-api` (JS) |
| `seeded/nextjs-blog/` | Next.js | `real/nonexistent-package` (npm), `real/unknown-model-string` (JS) |
| `seeded/nextjs-dashboard/` | Next.js | `real/typosquat-suspect` (npm), `real/phantom-import` (JS) |
| `seeded/fastapi-basic/` | FastAPI | `real/nonexistent-package` (pypi), `real/phantom-import` (Python) |
| `seeded/fastapi-bigapp/` | FastAPI | `real/nonexistent-api` (Python), `real/unknown-model-string` (Python) |
| `seeded/flask-tutorial/` | Flask | `real/typosquat-suspect` (pypi), `real/phantom-import` (Python) |
| `seeded/flask-microblog/` | Flask | `real/nonexistent-package` (pypi), `real/unknown-model-string` (Python) |
| `seeded/django-skeleton/` | Django | `real/nonexistent-package` (pypi), `real/phantom-import` (Python) |
| `seeded/django-rest-tutorial/` | Django | `real/nonexistent-api` (Python), `real/typosquat-suspect` (pypi) |
| `seeded/fastapi-venv-layout/` | FastAPI | `real/nonexistent-package` (pypi) — A1 corpus-realism regression: dependencies installed under a real `.venv/lib/python3.12/site-packages/` layout (not a flat root `site-packages/`), proving venv discovery finds a genuine surface (`typed_lib.real_fn()`) with zero `Unreadable` wall while a genuinely-fake declared dependency still fires |
| `seeded/express-nested/` | Node/Express | `real/nonexistent-package` (npm) — A4/A7 corpus-realism regression: manifest + source live under `backend/` (not root), proving recursive manifest discovery — if it regressed, the fake dependency would misclassify as `real/phantom-import` instead (different rule id, caught by the id+file recall match) |

`fastapi-venv-layout/` and `express-nested/` were added to close a gap the
Theme A audit found: every other seeded app declares dependencies at the
project root with a flat `site-packages/`/root-only manifest, which is the
one layout shape A1/A4 explicitly had to stop assuming (03-REVIEW.md's
"Theme A preamble" — "the fixtures/corpus encode unrealistic layouts").

## `sentinels/` provenance

Every snapshot below was shallow-fetched (`git clone --depth 1`, or
`--filter=blob:none --sparse` + `git sparse-checkout set <subtree>` for large
repos), its `LICENSE`/`LICENSE.md`/`LICENSE.txt` read and confirmed
permissive at fetch time, pinned to the commit SHA below, and trimmed to a
small representative subtree with the nested `.git` removed before copying
in. Per the checkpoint's fetch discipline (T-3-SC), no snapshot is vendored
without a confirmed permissive license.

| Snapshot | Source repo | Commit | License | Framework | Trim |
|---|---|---|---|---|---|
| `express-hello-world/` | `expressjs/express` | `ba006766fb964571723138708eacaba0f55759cd` (branch `master`) | MIT | Express | `examples/hello-world/` (one file) |
| `node-express-boilerplate/` | `hagopj13/node-express-boilerplate` | `179ae84efec61b14206d0305d941daed6c6d07f9` (branch `master`) | MIT | Express | `src/app.js` only (further trimmed from the full `src/` tree — see "Surface stubs" below) |
| `nextjs-hello-world/` | `vercel/next.js` | `8b7b6fea864484684b02b264c7b4919b47c6bccc` (branch `canary`) | MIT | Next.js | `examples/hello-world/` (app router, 2 files) |
| `taxonomy/` | `shadcn-ui/taxonomy` | `298a8857c7128a0d121e7f699dfd729f23b3966d` (branch `main`) | MIT | Next.js | `middleware.ts` only (the full `app/` tree uses `@/*` `tsconfig.json` path aliases that `getdev-core::deps` cannot resolve — a known v0.1 limitation, not a bug in this corpus — which would misclassify every aliased import as `real/phantom-import`; `middleware.ts` uses only real npm-specifier imports) |
| `fastapi-bigger-applications/` | `tiangolo/fastapi` | `7cb06f360dd44efac059848df1a9beee7643b018` (branch `master`) | MIT | FastAPI | `docs_src/bigger_applications/app_an_py310/` (the official "Bigger Applications" tutorial app) |
| `fastapi-full-stack-template/` | `tiangolo/full-stack-fastapi-template` | `4cd0d9e51aebd1af6f82d91ad0df4c9e41f4dea2` (branch `master`) | MIT | FastAPI | `backend/app/models.py` only |
| `flask-tutorial-flaskr/` | `pallets/flask` | `36e4a824f340fdee7ed50937ba8e7f6bc7d17f81` (branch `main`) | BSD-3-Clause | Flask | `examples/tutorial/flaskr/` (`__init__.py`, `auth.py`, `blog.py`, `db.py`; templates/static/schema dropped) |
| `microblog/` | `miguelgrinberg/microblog` | `a975ef64864354867c88e0ed3a17ba7d17dca752` (branch `main`) | MIT | Flask | `app/cli.py` + `app/errors/handlers.py` (further trimmed from the full `app/` tree — see "Surface stubs" below) |
| `django-flatpages/` | `django/django` | `f51347964a85bd4881caabf3c736b2c54d75262f` (branch `main`) | BSD-3-Clause | Django | `django/contrib/flatpages/{models,urls}.py` — **substituted for `cookiecutter/cookiecutter-django`** (see below) |
| `django-rest-framework/` | `encode/django-rest-framework` | `6f0b74def3fcc81e126b87b08e59abdb6c2ad056` (branch `main`) | BSD-3-Clause | Django | `rest_framework/{permissions,exceptions}.py` |

### Synthetic sentinels: `py-aliases/`, `js-untyped/`

Two sentinels are **not** vendored OSS snapshots — they are small,
first-party fixtures written to reproduce specific FP classes the Theme A
audit found in real-world layouts that none of the ten vendored snapshots
above happened to exercise:

- **`py-aliases/`** (A5) — a clean app whose only imports (`yaml`, `PIL`,
  `dotenv`) are exactly the well-known case where the PyPI distribution
  name differs from the Python import name
  (`rules/real/py-import-aliases.json`: `pyyaml`, `pillow`,
  `python-dotenv`). Deliberately plain `import <name>` statements with no
  attribute access, so this sentinel isolates the alias table's
  `deps::build_graph` classification end-to-end — it must produce **zero**
  findings; member-usage/API-surface behavior is a separate concern
  exercised elsewhere.
- **`js-untyped/`** (A3) — a clean app depending on a package that is
  genuinely installed (`node_modules/acme-metrics/` exists, with a real
  `package.json` + `index.js`) but ships no `.d.ts`/`types` field — the
  "installed but untyped" path real npm packages without bundled types (or
  without a `@types/*` package) hit constantly. A named-import member usage
  against it must resolve to `SurfaceTier::Unreadable` and stay
  **info-severity**, never `high` — the package genuinely exists and is
  genuinely used; getdev just cannot read its surface statically. This is
  the fixture the FP budget's severity-counting rule (above) exists for:
  its one `real/nonexistent-api` finding is real and expected, but must
  never count against the 5% budget.

### Substitution: `cookiecutter-django` → `django/django`

The checkpoint's original candidate list named `cookiecutter/cookiecutter-django`
for the second Django slot. Its repository content is a **Cookiecutter
template** — every `.py` file under
`{{cookiecutter.project_slug}}/` contains raw, unrendered Jinja2 syntax
(`{{ cookiecutter.project_slug }}`, `{%- if ... %}` conditionals spliced
into import statements) — not valid, parseable Python source. Vendoring it
as-is would not exercise "healthy real code" at all; it would exercise
tree-sitter's syntax-error recovery on template markup, which is not what
the false-positive sentinel budget is meant to measure. Per the plan's own
swap-allowance ("substitute a comparable permissive repo... note the swap"),
it was substituted with a real, non-template, permissively-licensed
(BSD-3-Clause, same Django Software Foundation license family) subtree of
Django itself — `django/contrib/flatpages`, a small, self-contained,
genuinely-rendered contrib app.

### Surface stubs (why some sentinels have a `node_modules/`/`site-packages/`)

`getdev-core::apisurface` introspects **installed** packages
(`node_modules/<pkg>` `.d.ts` exports / `site-packages/<pkg>` AST) —
by design (docs/PLAN.md §2.3). A vendored source snapshot with no
`npm install`/`pip install` step has no such installed surface, so every
`pkg.member`/`from pkg import member` usage against a *declared* dependency
resolves to `SurfaceTier::Unreadable` and is flagged as `real/nonexistent-api`
— correctly, by design, but a false positive for a sentinel that is meant to
prove "getdev stays quiet on healthy code" (these members genuinely exist on
the real published packages).

Where a trimmed snapshot's declared dependencies are exercised via member
access (`express.json()`, `from flask import Flask`, `from django.db import
models`, ...), a minimal **harness-only surface stub** is vendored alongside
it: a `package.json` + `index.d.ts` (npm) or `__init__.py` (pypi) declaring
*only* the specific members that trimmed snapshot actually uses — nothing
more. These are clearly marked `"""Minimal harness-only surface stub..."""`
in-file and are test scaffolding, not claims about the real package's full
API surface. `express-hello-world/`, `nextjs-hello-world/`,
`fastapi-bigger-applications/`'s own internal `rest_framework`/`django`
self-imports, and a few others need no stub at all — their trimmed source
either uses no member access on a declared package, or (for
`django-rest-framework/`'s own `from rest_framework import ...`
self-references) the PyPI distribution name (`djangorestframework`) never
matches the import name (`rest_framework`) after PEP 503 normalization, so
`apisurface::ecosystem_of` treats it as undeclared and skips it entirely —
a documented quirk of the real analyzer, not a stub gap.

Two of the ten sentinels (`node-express-boilerplate/`, `microblog/`) are
trimmed to a single representative file or two rather than the checkpoint's
literal "drop tests/, keep everything else" instruction — the untrimmed
`src/`/`app/` trees exercise dozens of third-party members (mongoose, joi,
winston, passport, http-status, flask-sqlalchemy, flask-babel, elasticsearch,
redis, rq, ...) that would each need a faithful stub; trimming further to a
single representative file keeps the corpus small (per the checkpoint's own
"keep snapshots small" instruction) while still exercising real, unmodified
framework-wiring code.

## Bug found and fixed while building this harness

Building `corpus.rs` against a plain `.js` sentinel (`express-hello-world/`)
immediately crashed `getdev real` with `invalid tree-sitter query: Query
error at 4:2. Invalid node type import_require_clause` — `apisurface::dts`'s
member-usage query unconditionally referenced `import_require_clause`, a
TypeScript-only grammar node absent from the plain JavaScript grammar. This
broke `getdev real`'s default (non-`--deps-only`) scope on **every**
plain-JS project — the entire Node/Express use case — since no prior test
exercised the full default scope against a `.js`-only fixture. Fixed in
`crates/getdev-core/src/apisurface/dts.rs` by branching the binding query by
language (mirroring `imports_js.rs`'s existing `import_query` pattern),
matching this plan's Rule 1 (auto-fix bugs) — see the plan SUMMARY for
details.

# review/ corpus — the two-state (base/after) agent-session corpus (06-06)

`getdev review` analyzes a **diff**, not a static checkout, so it needs a
fundamentally different corpus shape from the flat single-tree `seeded/`/
`sentinels/` layout above (06-RESEARCH.md Assumption A6). The `real`/`audit`
corpus can express "here is a project, scan it"; it cannot express "here is a
project *before* and *after* an agent session — review only the delta." The
`review/` corpus is that new shape, exercised by
`crates/getdev-cli/tests/review_corpus.rs`.

## Layout

```
testdata/corpus/review/
├── seeded/<app>/
│   ├── base/            complete initial project state (committed by the harness)
│   ├── after/           ONLY the files an "agent session" changed or added
│   └── getdev-expected.json   { "seeded": [ { id, file }, ... ] }
└── sentinels/<app>/
    ├── base/            clean initial state
    └── after/           a LEGITIMATE change — must produce no warning+ finding
```

`base/` is a full tree; `after/` is a **partial overlay** — it carries only
the files that a simulated agent session modified or introduced, so any file
absent from `after/` is guaranteed unchanged (no accidental diff noise).

## How the harness materializes it (review_corpus.rs)

Per app, into a throwaway temp dir (never the checked-in corpus):

1. copy `base/` in, `git init`, commit it under a hermetic `getdev` identity
   with `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` blanked (no CI-host config
   leaks, mirroring `getdev-gitx::snap`);
2. copy `after/` on top of the working tree (overwriting/adding files);
3. run `getdev review --json --path <tmp>` — the default working-tree-vs-HEAD
   scope, so the diff *is* the `base → after` delta.

Fully hermetic: review makes zero network calls by construction (imports no
`getdev_registry` type — 06-05), and the harness only ever writes to a temp
dir, never under `testdata/corpus/review/`.

## `seeded/` — recall (the P5 exit criterion: ≥80% caught)

Each seeded app's `after/` deliberately introduces agent debris as a diff over
`base/`, catalogued in `getdev-expected.json` (matched by `id` + `file`, the
same stable recall criterion `real`/`audit` use). The ten apps span JS/TS and
Python and cover **each of the six `review/*` rule types at least twice**:

| App | Lang | Seeded rule id(s) |
|---|---|---|
| `js-debug-todo/` | JS | `review/debug-leftover`, `review/todo-introduced` |
| `py-debug-todo/` | Python | `review/debug-leftover`, `review/todo-introduced` |
| `ts-deadcode/` | TypeScript | `review/dead-code-introduced` |
| `py-deadcode/` | Python | `review/dead-code-introduced` |
| `js-duplicate/` | JS | `review/duplicate-helper` |
| `py-duplicate/` | Python | `review/duplicate-helper` |
| `js-commented/` | JS | `review/commented-code-block`, `review/debug-leftover` |
| `ts-commented/` | TypeScript | `review/commented-code-block` |
| `js-orphan/` | JS | `review/orphan-file` |
| `py-orphan/` | Python | `review/orphan-file` |

Coverage: debug-leftover ×3, todo-introduced ×2, dead-code-introduced ×2,
duplicate-helper ×2, commented-code-block ×2, orphan-file ×2.

The gate asserts **≥80%** recall (not 100%): containment-scoping legitimately
misses a declaration split across two hunks (06-RESEARCH.md Pattern 2's
documented recall gap), so a hard 100% would be an over-tight gate. A seeded
app also doubles as its own sentinel — the harness surfaces any warning+
finding *outside* the catalogued `(id, file)` pairs, so recall cannot pass by
drowning a real signal in extra false positives.

`review/todo-introduced` is **info** severity (an intentional marker, not a
defect) — like `real`'s info notes it is a recall target but is excluded from
the false-positive budget below.

## `sentinels/` — the false-positive budget (per-rule < 10%)

Each sentinel app's `after/` is a realistic, LEGITIMATE change that must trip
**no** warning+ (`low`/`medium`/`high`/`critical`) finding. They target the
exact FP-guard classes locked in 06-03/06-04 (06-RESEARCH.md Pitfalls 4/5):

| App | FP-guard class exercised |
|---|---|
| `js-string-registered/` | dead-code string-reference widening (a handler referenced only by a string literal, e.g. route-registration-by-name, must not be "dead") |
| `next-app-route/` | framework-entry exemption for orphan + dead-code (a new App-Router `route.ts` is runtime-referenced, not import-referenced) |
| `py-decorated-routes/` | decorator exemption for dead-code (a `@router.get(...)` handler is framework-registered) |
| `js-prose-jsdoc/` | commented-code-block prose + JSDoc guard (prose `//` lines and a `/** */` block are documentation, not commented-out code) |
| `js-sibling-helper/` | orphan sibling-import guard (a new helper file imported by a sibling is not an orphan) |

The FP rate is measured **per rule id** (a rule's warning+ finding count
across every sentinel after-state ÷ total source files scanned across the
whole sentinel set), never as a diluted aggregate across rules, and must stay
under 10% for every rule — the P5 budget (looser than `audit`/`real`'s 5% per
the ROADMAP, reflecting review's heuristic detectors). Info-severity findings
are excluded from the count, identical to the `real`/`audit` budget above.
