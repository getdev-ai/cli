# Contributing to getdev

Thanks for helping make AI-generated code safer to ship. This guide covers everything from
a first rule contribution (zero Rust required) to core engine work.

## Ways to contribute

| I want to… | Where to start | Rust needed? |
|---|---|---|
| Add/improve a detection rule | `rules/*.yaml` + fixtures — see [Rule contributions](#rule-contributions) | **No** |
| Report a false positive | [False-positive issue template](.github/ISSUE_TEMPLATE/false_positive.md) | No |
| Report a bug | [Bug issue template](.github/ISSUE_TEMPLATE/bug_report.md) | No |
| Improve docs | Any `.md` file, `docs/` | No |
| Fix a bug / build a feature | `crates/` — check `good-first-issue` labels | Yes |
| Propose a new command or flag | Open a discussion first — command scopes are contractual (docs/PLAN.md §2.3) | — |

Please open an issue or discussion before large changes. Small, single-concern PRs merge fast;
big surprise PRs stall.

## Development setup

Prerequisites:

- **Rust** — the exact toolchain is pinned in `rust-toolchain.toml`; `rustup` picks it up
  automatically. No nightly needed.
- **git** ≥ 2.30 (used by `getdev snap`/`review` and their tests)
- A C compiler (Xcode CLT / `build-essential` / MSVC Build Tools) — tree-sitter grammars and
  bundled SQLite compile from C.

```bash
git clone https://github.com/getdev-ai/cli
cd getdev-cli
cargo check --workspace        # fast inner loop — use this while iterating
cargo build --workspace
cargo test --workspace
```

Full build documentation (compile-time tips, sccache, cross-compilation): [docs/BUILDING.md](docs/BUILDING.md).

## Before you push — the local gate

CI denies warnings, so run the same checks locally:

```bash
cargo fmt --all                                            # format
cargo clippy --workspace --all-targets -- -D warnings      # lint (must be clean)
cargo test --workspace                                     # unit + fixture tests
cargo insta review                                         # if snapshot tests changed
cargo test -p getdev-cli --test corpus                     # corpus integration tests
```

## Code standards (enforced by CI)

- **No `unwrap()`/`expect()` outside tests** — clippy-denied. Use `thiserror` typed errors in
  library crates, `anyhow` at the CLI boundary. No panics across crate boundaries.
- **`#![forbid(unsafe_code)]`** everywhere except `getdev-grammars` (the isolated FFI crate).
- **Files are parsed once** per invocation into `ScanContext`; analyzers are read-only
  visitors. Never re-parse inside an analyzer.
- **All mutations go through `core::mutate`** (atomic write → reparse-verify → rollback).
  Commands never mutate files without explicit `--write`/`--fix`.
- **Network code lives only in `getdev-registry`** (npm/PyPI) and `getdev-cli::update`
  (GitHub Releases). Nothing else may touch the network — this is the privacy promise.
- **No async runtime.** Blocking `reqwest` + `rayon`. This is settled (docs/DECISIONS.md);
  PRs introducing tokio will be declined.
- User-facing output goes through `core::report` renderers — never `println!` from analyzers.
- Error messages: lowercase start, actionable, name the file/flag involved.

## Rule contributions

Rules are declarative YAML — the designed easy first PR. A rule ships as:

1. `rules/<command>/<rule-id>.yaml` — pattern (tree-sitter query or regex), severity,
   confidence, message, remediation, refs. Format: docs/SPEC-RULES.md and the template in
   Appendix B of the development plan.
2. **≥ 3 positive and ≥ 3 negative fixtures** in `testdata/fixtures/` — no exceptions.
   Negative fixtures (code that must NOT fire) are what keep getdev's false-positive rate
   below the 5% policy threshold (docs/PLAN.md §9.2).
3. Registration in the fixture test table.

Rules that can't demonstrate a low FP rate on the sentinel corpus get `confidence: low` or
`severity: info` until improved — that's policy, not a judgment of your work.

## Testing pyramid

| Layer | Tool | What |
|---|---|---|
| Unit | `cargo test` | matchers, parsers, scoring |
| Fixtures | table-driven tests | every rule: ≥3 pos / ≥3 neg |
| Corpus | `assert_cmd` + `insta` golden files | full commands on `testdata/corpus/` |
| Property | `proptest` | snap round-trip; mutate output always reparses |
| Benchmarks | `criterion` (`cargo bench -p getdev-core`) | perf budgets are release-blocking |

Coverage floor: 80% on library crates (`cargo-llvm-cov`); 100% of shipped rules fixture-covered.

## Commits & pull requests

- **Conventional commits**: `feat(real): …`, `fix(env): …`, `docs: …`, `test(audit): …`.
  The changelog is generated from these (`git-cliff`), so they matter.
- **DCO sign-off required** on every commit: `git commit -s` adds the
  `Signed-off-by: Your Name <you@example.com>` trailer. This certifies you have the right to
  submit the code under Apache-2.0 (see [developercertificate.org](https://developercertificate.org)).
  **DCO, never a CLA** — a CLA would let us relicense your contributions; DCO makes that
  impossible. Your code stays Apache-2.0, period.
- One concern per PR. Include tests. Fill in the PR template.
- CI must be fully green (fmt, clippy, tests on all 3 OSes, cargo-deny) before review.

## Scope discipline

Command behavior and flags are specified in docs/SPEC-COMMANDS.md and the scopes in
docs/PLAN.md §2.3 are contractual for each release. Ideas beyond the spec are welcome —
as roadmap proposals (issues/discussions), not as unsolicited implementation PRs. Check
docs/DECISIONS.md before proposing a revisit of a settled decision (async runtime, git2,
telemetry, LLM-in-core).

## Governance & conduct

- BDFL model until v1.0, then a maintainer team; decisions happen in public issues.
- Be kind. We follow the [Contributor Covenant](CODE_OF_CONDUCT.md).
- Security vulnerabilities: **do not open an issue** — see [SECURITY.md](SECURITY.md).
