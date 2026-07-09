# packaging/reserve — name-reservation placeholders

Minimal placeholder packages published to reserve the `getdev` name on public registries
before v0.1 (see docs/DISTRIBUTION.md § Name reservations). The real distribution replaces
the npm and crates.io placeholders via the cargo-dist release pipeline; the PyPI package is
a permanent defensive stub (getdev ships no Python package).

| Dir | Registry | Published | Status |
|---|---|---|---|
| `npm-getdev/` | npmjs.com `getdev` | 0.0.1 on 2026-07-09 | replaced by cargo-dist npm installer at v0.1 |
| `crate-getdev/` | crates.io `getdev` | 0.0.0 on 2026-07-09 | replaced by the real CLI crate at v0.1 |
| `pypi-getdev/` | pypi.org `getdev` | 0.0.1 (defensive) | permanent stub pointing users to the real install |
