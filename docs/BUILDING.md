# Building getdev from source

This document covers local development builds, tests, lints, release-profile builds, and
cross-compilation. For contributing standards see [../CONTRIBUTING.md](../CONTRIBUTING.md);
for the release pipeline see [RELEASING.md](RELEASING.md).

## Prerequisites

| Requirement | Notes |
|---|---|
| Rust (stable) | Pinned in `rust-toolchain.toml` — `rustup` installs/selects it automatically. Never build releases with an unpinned toolchain. |
| C compiler | tree-sitter grammars and bundled SQLite (`rusqlite` `bundled` feature) compile C. macOS: `xcode-select --install` · Debian/Ubuntu: `apt install build-essential` · Windows: MSVC Build Tools |
| git ≥ 2.30 | `snap`/`review` shell out to the git binary; integration tests need it on PATH |

Notably **not** required: OpenSSL (we use `rustls`), Node/Python runtimes (only needed to run
the corpus fixtures' package installs in some integration tests), any system SQLite.

## Workspace layout

```
crates/getdev-cli        binary crate (bin name: getdev) — clap commands, self-update
crates/getdev-core       engine: scan, findings, rules, mutate, report, config
crates/getdev-registry   npm/PyPI clients + SQLite cache (the ONLY crate with HTTP)
crates/getdev-gitx       git plumbing via std::process::Command
crates/getdev-grammars   tree-sitter grammars (the ONLY crate with unsafe/FFI)
rules/                   embedded YAML rule packs + models.json
testdata/                corpus projects + per-rule fixtures
```

The crate split exists for compile-time hygiene: `getdev-grammars` isolates the slowest C
dependencies so they compile once and stay cached.

## Build & iterate

```bash
cargo check --workspace          # the inner loop — seconds after grammars are cached
cargo build --workspace          # debug binary at target/debug/getdev
cargo run -p getdev-cli -- check # run against CWD
```

First build compiles the tree-sitter grammars and bundled SQLite — expect several minutes.
Every build after that is fast; if it isn't, see [Keeping builds fast](#keeping-builds-fast).

## Test

```bash
cargo test --workspace                     # unit + fixture tests
cargo test -p getdev-core                  # one crate
cargo test -p getdev-cli --test corpus     # corpus integration (assert_cmd + insta golden files)
cargo insta review                         # review changed snapshot output
cargo bench -p getdev-core                 # criterion benches — perf budgets are release gates
```

Perf budgets the benches enforce (repo ≈ 500 files / 100k LOC): `check` warm < 3 s ·
`audit`/`review` < 2 s · `snap` < 1 s · memory < 500 MB on 1M LOC.

## Lint & hygiene (CI denies warnings)

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check          # licenses + RustSec advisories (cargo install cargo-deny)
cargo llvm-cov --workspace --lcov   # coverage; floor is 80% on library crates
```

Clippy is configured to deny `unwrap_used`/`expect_used` outside tests, and every crate
except `getdev-grammars` carries `#![forbid(unsafe_code)]`.

## Release-profile builds

```bash
cargo build --workspace --release
```

The workspace release profile is tuned for a small static binary:

```toml
[profile.release]
lto = true
strip = true
codegen-units = 1
```

Budget: **< 25 MB** binary (grammars dominate). The binary is fully static — rustls (no
OpenSSL), bundled SQLite, statically linked grammars — so it runs with zero system
dependencies.

## Cross-compilation

Release artifacts for all six targets are built by `cargo-dist` in CI (see
[RELEASING.md](RELEASING.md)) — you normally never cross-compile locally. Supported targets:

| Target | Tier |
|---|---|
| `aarch64-apple-darwin` / `x86_64-apple-darwin` | release |
| `x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu` | release |
| `x86_64-pc-windows-msvc` | release |
| `aarch64-pc-windows-msvc` | best-effort |

To sanity-check a cross-build locally (needs a cross C toolchain because of the grammar FFI —
`cargo install cross` and use Docker-backed builds is the least painful route):

```bash
cross build --release --target x86_64-unknown-linux-gnu
```

To test the full release pipeline locally without tagging:

```bash
cargo dist build        # builds artifacts for the host target
cargo dist plan         # shows what a real release would produce
```

## Keeping builds fast

- **Use `cargo check`** for iteration; only `build` when you need to run the binary.
- **`sccache`**: `cargo install sccache`, then `export RUSTC_WRAPPER=sccache`. CI uses it too.
- Don't `cargo clean` — you'll pay the grammar compile again. If a single crate misbehaves,
  `cargo clean -p <crate>`.
- Touching `getdev-grammars` or its dependencies invalidates the expensive layer; changes
  there should be rare and reviewed.

## Windows notes

- Build with MSVC (the pinned default), not GNU.
- Tests must pass with CRLF checkouts and `\` paths — CI runs the full suite on
  `windows-latest`; don't gate Windows-specific behavior on "works on my Mac".
- ANSI color handling goes through `anstream`; never write raw escape codes.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cc`/link errors on first build | Missing C toolchain — see prerequisites |
| Wrong rustc version errors | Let rustup manage it; check `rust-toolchain.toml` isn't overridden by `rustup override` |
| Corpus tests fail with "git not found" | Install git / add to PATH |
| Snapshot test failures after intentional output change | `cargo insta review` and accept |
| Slow rebuilds after `git pull` | Grammar crate bumped — one-time cost; sccache absorbs repeats |
