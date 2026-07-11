# testdata/corpus — the ground-truth corpus (docs/PLAN.md §9.1, docs/TESTING.md)

Two halves, both exercised by `crates/getdev-cli/tests/corpus.rs`:

- `seeded/` — synthetic "vibe-coded" apps with deliberately seeded fake
  packages/APIs/model-strings. Every seeded defect is cataloged in a
  companion `getdev-expected.json` — recall (100% of seeded fake packages
  caught) is measured against this catalog, per app.
- `sentinels/` — real, permissively-licensed OSS snapshots, vendored small.
  `getdev real` should stay quiet on them (the false-positive budget,
  docs/PLAN.md §9.2: aggregate FP rate < 5%).

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

Seeded defect types used across the ten apps (docs/PLAN.md §2.3's six
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

### The ten seeded apps

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
