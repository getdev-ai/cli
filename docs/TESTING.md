# TESTING.md — Test Strategy

How getdev is tested: the layered pyramid, the ground-truth corpus, the false-positive policy, coverage floors, and the commands that run each layer.

> **Source:** distilled from `getdev-development-plan.md` §8 and §9; this doc is normative for test layering, fixture requirements, coverage floors, and corpus/FP gates.

---

## Testing pyramid

From fastest/narrowest to slowest/broadest:

| Layer | What | How |
|---|---|---|
| 1. Unit | Rule matchers, parsers, individual functions | Plain `#[test]`, per crate |
| 2. Per-rule fixtures | Every shipped rule: **≥ 3 positive + ≥ 3 negative** fixture files, table-driven | Fixtures in `testdata/fixtures/`; each rule registered in tests — no exceptions (CLAUDE.md rule 3) |
| 3. Corpus integration | Full commands run against `testdata/corpus/` via `assert_cmd`; golden-file JSON output via `insta` snapshots | `cargo test -p getdev-cli --test corpus` |
| 4. Property tests | `proptest`: snap round-trip (snap → mutate randomly → back → tree byte-identical, 1000 iterations); mutate (output always reparses) | Part of `cargo test --workspace` |
| 5. Benchmarks | `criterion` suite gating the performance budgets in `docs/PLAN.md` §3.5 | `cargo bench -p getdev-core` |

## The corpus (ground truth)

`testdata/corpus/` = 20+ sample projects:

- **10 synthetic "vibe-coded" apps** (Node/Express, Next.js, FastAPI, Flask, Django) with **seeded, cataloged defects** (fake packages, secrets, missing auth, dead code…). Every seeded defect has an expected finding — recall is measured against this catalog.
- **10 real popular OSS repos** (permissive licenses, vendored snapshots) used as **false-positive sentinels**: getdev should stay quiet on healthy code.

Corpus recall targets per phase (see `docs/ROADMAP.md` exit criteria): `env` ≥ 95 % seeded secrets, `real` 100 % seeded fake packages, `review` ≥ 80 % seeded artifacts. Release gate requires 100 % seeded-defect recall for `real`/`env` (`docs/PLAN.md` §9.3).

## False-positive policy

- Every rule ships with a **measured FP rate on the sentinel set**. If FP > 5 %, the rule is demoted to `low`/`info` severity or `confidence: low` until improved.
- Heuristic rules must surface their reasoning in the finding's `detail` field.
- Suppressions require a recorded reason and are visible in `check -v`.

## Coverage floor

- **80 %** line coverage on library crates (`cargo-llvm-cov`).
- **100 %** of shipped rules fixture-covered (layer 2 above).

## Commands

```bash
cargo test --workspace                    # unit + fixture + property tests
cargo test -p getdev-core                 # one crate
cargo test -p getdev-cli --test corpus    # corpus integration (assert_cmd + insta)
cargo insta review                        # review/accept changed snapshots
cargo bench -p getdev-core                # criterion benches vs perf budgets
cargo clippy --workspace --all-targets -- -D warnings   # must pass clean
cargo fmt --check
```

## CI expectations

- **3-OS matrix:** ubuntu / macos / windows × x86_64 (aarch64 via release smoke tests). See `docs/CI.md`.
- `sccache` + dependency caching keep CI under 10 min.
- **Tests must be hermetic — no network.** Registry-dependent code paths are tested against cache/fixtures; `--offline` behavior is exercised explicitly. (Only `getdev-registry` and `cli::update` may ever touch the network at runtime, and never in tests.)
- Clippy denies warnings (`clippy::unwrap_used`/`expect_used` denied outside tests); `cargo-deny` audits licenses and advisories.
- Benchmarks gate the performance budgets — regressions beyond budget fail the release gate.

## Release gate

Every release additionally requires (see `docs/PLAN.md` §9.3): full matrix green, coverage floor met, benchmarks within budget, corpus recall/FP targets met, `docker build` success on all `ship` preset outputs, manual "first five minutes" smoke on all 3 OSes, signed artifacts + checksums + SBOM.
