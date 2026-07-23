# Precision reference corpus (PREC-01)

A curated, **secret-free**, synthetic real-world reference corpus. It reconstructs
each Seava dogfood false-positive *shape* (never copied Seava source, never a real
secret) plus representative clean apps, and is scored by the precision oracle
(`crates/getdev-cli/tests/precision_oracle.rs`) which runs `getdev check --json`
over every app and asserts overall **actionable precision ≥ 90 %** — the recorded
v0.2 exit criterion that turns "raise precision from <1 % to >90 %" into a CI gate.

## Synthetic-derivation + secret-free rule (D-14)

Every fixture is a **minimized, synthetic reconstruction of a shape**, derived from
the Seava FP taxonomy — NOT from Seava's proprietary source. **Zero real secret
values** appear anywhere: the one planted provider-format key
(`secret-negatives/src/secretConfig.ts`) uses an obviously-synthetic `FAKE` body,
so the `precision_corpus_is_secret_free` test can tell a synthetic recall anchor
from a real leaked credential (a provider-shaped value with no synthetic marker
fails the test).

## Layout

Each app directory carries:

- source files reconstructing an FP shape (or a clean app),
- **`getdev-precision.json`** — the catalog of `(id, file)` findings getdev is
  EXPECTED to *legitimately* produce (the "true" set; mostly empty — a few planted
  trues are the recall anchors),
- **`getdev-cache-seed.json`** — offline registry existence seed (npm/pypi → bool),
  so the run is hermetic (no network).

## Apps

| App | Exercises | Expected trues |
|-----|-----------|----------------|
| `aliased-ts/` | PREC-02 — TS/Vite `@/…` path aliases resolve, so aliased imports are Local (no phantom/nonexistent/typosquat/orphan). | none |
| `installed-surface/` | PREC-03 — a package whose types are declared ONLY via `exports["."].types` (with a decoy top-level `.d.ts` a pre-fix guess would have used). Real named imports enumerate the real surface. | none |
| `secret-negatives/` | PREC-04 — object-data slug, URL, enum slug, `*.test.ts` filename values do NOT fire; one synthetic planted provider key does. | `env/hardcoded-secret` |
| `sql-and-orm/` | PREC-05 — a genuine raw `${}` `.query()` interpolation fires (medium); a parameterized Drizzle `sql\`\`` tagged template does not. | `audit/sql-string-concat` |
| `duplicate-scaffolding/` | PREC-05 — repetitive helpers in `*.spec.ts` are exempt; a genuine introduced duplicate in `src/*.ts` fires. | `review/duplicate-helper` |
| `clean-node-app/` | a small realistic clean Node/TS app — no findings at all. | none |

## The precision metric

For every app the oracle runs `getdev check --offline --json`, takes every
**warning+** finding (info excluded, mirroring `corpus.rs::is_warning_plus`), and
partitions it into **true** (its `(id, file)` is catalogued) vs **false** (not
catalogued). Overall actionable precision = `true ÷ (true + false)`, recorded
per-rule and overall, asserted `≥ 0.90`. The recall floor stays
`corpus.rs::seeded_recall_is_100_percent` (unchanged); the oracle additionally
asserts every planted true is actually produced (recall cannot silently collapse
to trivially satisfy precision).
