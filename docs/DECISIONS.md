# DECISIONS.md — Decision Log

Settled technical decisions in lightweight ADR form. Check here before proposing "why don't we just…" changes — if a decision is listed as settled, re-opening it requires a new entry, not a drive-by change.

> **Source:** distilled from the project master plan (internal) §3.2, §3.4, §6, §8, §11 (plus repo-setup decisions made during P0 scaffolding); this doc is normative for the technology and process choices below.

---

## 1. No async runtime — blocking `reqwest` + `rayon`

**Date:** 2026-07-08 · **Status:** settled

**Context:** getdev is a batch CLI; the only network traffic is package-registry lookups. Async Rust (tokio) is the language's steepest learning hill and adds complexity a batch tool never recoups.

**Decision:** Synchronous architecture throughout. HTTP via `reqwest` blocking feature; parallelism via `rayon` data parallelism (file-level, bounded by logical CPUs). Do not introduce tokio or any async runtime.

## 2. Git via `std::process::Command`, not `git2`/`gix`

**Date:** 2026-07-08 · **Status:** settled

**Context:** `snap`/`back` and `review` diff extraction need git plumbing. Library bindings (`git2`, `gix`) add heavy dependencies and API surface we don't need in v0.x.

**Decision:** `getdev-gitx` shells out to the git binary via `std::process::Command`, plumbing commands only, `refs/getdev/` namespace only. Resist `git2`/`gix` until needed; git-free object writing via `gix` is a v1.x hardening item. If git is absent: clear error + install pointer (v0.1 requires git).

## 3. Rules are YAML data, never code

**Date:** 2026-07-08 · **Status:** settled

**Context:** Community contribution is the growth lever; contributors should never need to write Rust. Hostile rule packs must not be able to execute code.

**Decision:** Detection rules are declarative YAML (`serde_yaml`, validated against JSON Schema), embedded via `include_dir!`, mergeable with user packs via `--rules`. New detection logic = a new matcher type in `core::rules` + spec update, never a hardcoded check. Rule packs are declarative-only — no code execution. See `docs/SPEC-RULES.md`.

## 4. Deterministic core — no LLM calls in v0.1–v0.3

**Date:** 2026-07-08 · **Status:** settled

**Context:** Trust and speed require reproducible results; v0.1 must need no API key.

**Decision:** No LLM calls anywhere in v0.1–v0.3. Same input → same output. The optional v0.4 semantic layer is off by default, BYO key or local endpoint, findings tagged `confidence: "llm"`, deterministic findings never depend on it (see `docs/ROADMAP.md`).

## 5. No telemetry, ever

**Date:** 2026-07-08 · **Status:** settled

**Context:** Local-first privacy is the core positioning ("nothing leaves your machine") and must be verifiable in source.

**Decision:** No telemetry, no analytics, no code upload. Network calls are exhaustively listed: npm registry, PyPI, GitHub Releases (self-update only). `--offline` disables all. All network code lives in `getdev-registry` and `getdev-cli::update` only.

## 6. Rust (stable toolchain) + tree-sitter

**Date:** 2026-07-08 · **Status:** settled

**Context:** Need runtime speed, low memory, memory safety across parsers handling hostile input, and multi-language parsing. The modern devtools wave (ruff, uv, biome) made Rust native to this category.

**Decision:** Rust 2021 edition, stable channel, pinned via `rust-toolchain.toml`. Parsing via tree-sitter (`tree-sitter-javascript`/`-typescript`/`-python`), statically linked through `getdev-grammars`. De-risked by the P0 day-1–2 spike (walker + tree-sitter + cross-compile) before further commitment.

## 7. Cache via `rusqlite` (bundled)

**Date:** 2026-07-08 · **Status:** settled

**Context:** Registry responses need a transactional, TTL-friendly local cache with zero system dependencies (single static binary promise).

**Decision:** `rusqlite` with the bundled feature — SQLite statically compiled in. Cache lives at `~/.getdev/cache/registry/` (TTL 7 days existence, 24 h metadata).

## 8. Workspace crate split; grammars isolated for compile time

**Date:** 2026-07-08 · **Status:** settled

**Context:** tree-sitter grammar crates dominate compile time; iteration speed dies if they rebuild in the inner loop. Clean dependency boundaries also enforce the network/unsafe rules.

**Decision:** Cargo workspace: `getdev-cli`, `getdev-core`, `getdev-registry`, `getdev-gitx`, `getdev-grammars`. Grammars live behind one crate boundary so they build once and stay cached; `cargo check` stays the inner loop; `sccache` in CI. See `docs/ARCHITECTURE.md` §3.2.

## 9. Release via `cargo-dist` + GitHub Actions

**Date:** 2026-07-08 · **Status:** settled

**Context:** Need cross-platform binaries (darwin/linux/windows × x86_64/aarch64), installers, checksums, signing without hand-rolled release toil.

**Decision:** `cargo-dist` (the GoReleaser equivalent for Rust) drives the release workflow; SBOM (Syft) + cosign signing added in the same workflow; install.sh generated by cargo-dist. See `docs/RELEASING.md` and `docs/DISTRIBUTION.md`.

## 10. Error handling: `thiserror` in libraries, `anyhow` at the CLI boundary

**Date:** 2026-07-08 · **Status:** settled

**Context:** Library crates need typed, matchable errors; the CLI edge needs ergonomic context.

**Decision:** `thiserror` for typed errors inside library crates, `anyhow` at the CLI boundary. No `unwrap`/`expect` outside tests (`clippy::unwrap_used`/`expect_used` denied). No panics across crate boundaries; analyzer panics on hostile input are release-blocking bugs.

## 11. `unsafe` forbidden outside `getdev-grammars`

**Date:** 2026-07-08 · **Status:** settled

**Context:** tree-sitter grammars require FFI; nothing else does.

**Decision:** `#![forbid(unsafe_code)]` workspace-wide except inside `getdev-grammars`, which isolates the FFI and is reviewed.

## 12. Apache-2.0 license + DCO, not CLA

**Date:** 2026-07-08 · **Status:** settled

**Context:** Patent grant enables frictionless corporate adoption; a CLA is friction for the community contribution funnel.

**Decision:** Apache-2.0. Developer Certificate of Origin sign-off (lighter than CLA, keeps relicensing honest). CLI stays 100 % free forever; optional paid *support*, never paid *features*.

## 13. Crate published as `getdev` from `crates/getdev-cli`

**Date:** 2026-07-09 · **Status:** settled

**Context:** Users install with `cargo install getdev` / `cargo binstall getdev`; internally the binary crate is named `getdev-cli` to match the workspace naming scheme.

**Decision:** The binary crate lives at `crates/getdev-cli` but is published to crates.io under the name `getdev`.

## 14. Scoop manifest maintained manually

**Date:** 2026-07-09 · **Status:** settled

**Context:** cargo-dist generates installers for install.sh/Homebrew/etc. but does not support Scoop manifest generation.

**Decision:** The Scoop manifest is maintained manually (see `packaging/` and `docs/DISTRIBUTION.md`), updated as part of the release checklist.

## 15. Repository lives at `getdev-ai/cli`; product name stays `getdev`

**Date:** 2026-07-09 · **Status:** settled

**Context:** The bare `getdev` GitHub name is held by an unrelated dormant account, and the getdev.ai website lives in its own private repo. Doubling the brand in the slug (`getdev-ai/getdev-cli`) reads poorly in links.

**Decision:** The CLI lives under the `getdev-ai` org (matching the domain, like `getsentry`/`astral-sh`) as `getdev-ai/cli` — the GitHub-CLI pattern (`cli/cli` → `gh`). Everything users *type* stays `getdev`: binary, Homebrew formula, npm package, crates.io crate, release artifacts. Formula/package names must match the command, so they never take the short repo form. Vacated slugs (`pzelenin/getdev-cli`) are never reused — reuse would destroy GitHub's redirects.

## 16. `getdev-mcp` graduates into the workspace, stays hand-rolled

**Date:** 2026-07-23 · **Status:** settled

**Context:** The MCP server (getdev as tools for AI agents) shipped as a standalone preview under `integrations/mcp/` with its own `[workspace]` — decoupled from the cargo-dist release pipeline, so users had to `cargo build` it from source. v0.2 (Phase 12, MCP-01) makes it a first-class release artifact.

**Decision:** Move it to `crates/getdev-mcp/` as a workspace member, shipped **prebuilt** via cargo-dist per-package config: `[package.metadata.dist] dist = true` (cargo-dist's documented override that forces the binary into the prebuilt release artifacts) while `publish = false` stays (**never** published to crates.io), and archive-only `installers = []` (no per-app npm/homebrew/shell/powershell installers — only the `getdev` CLI mints those). It inherits the workspace lints (`unsafe_code = "forbid"`, `unwrap_used`/`expect_used = "deny"`) via `[lints] workspace = true`. It stays a **blocking stdio JSON-RPC loop** with `serde`/`serde_json` only — **`rmcp`/tokio are NOT adopted** (they are hard-tokio-bound; adopting them would breach DEC-01's no-async-runtime rule). It makes no network calls of its own — every tool shells out to the installed `getdev` binary, which owns the (already egress-confined, DEC-05) network behavior.

**Consequence:** One more prebuilt archive rides in the **same** GitHub Release (no crates.io publish, no dedicated installer); `network_egress.rs` auto-covers `crates/getdev-mcp/src` (a new network symbol there fails CI) and `cargo deny check bans` gates the crate against any async/HTTP/LLM dependency. Phase 17 (MCP-02) bundles that archive into the Claude-Code plugin installer.
