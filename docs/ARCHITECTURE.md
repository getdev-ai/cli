# ARCHITECTURE.md — System Design

High-level design of the getdev workspace: crate boundaries, the shared-scan engine, mutation safety, language support, and technology choices.

> **Source:** distilled from `getdev-development-plan.md` §3 and §8; this doc is normative for crate responsibilities, the parse-once invariant, mutation safety invariants, and the network boundary. Plan cross-crate/engine changes against this doc first.

---

## 3.1 High-level design

```
┌─────────────────────────────────────────────────────────────┐
│  getdev-cli (clap v4, derive API)                           │
│  thin command definitions: flags → options struct → engine  │
└──────────────┬──────────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────────┐
│  getdev-core::engine                                        │
│  orchestrates: one ProjectScan shared by all analyzers      │
│                                                             │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐             │
│  │ analyzer:  │  │ analyzer:  │  │ analyzer:  │  ...        │
│  │ real       │  │ audit      │  │ review     │             │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘             │
│        └───────────────┴───────┬───────┘                    │
│                                ▼                            │
│                   Vec<Finding> (unified schema)             │
└──────────────┬──────────────────────────────────────────────┘
               │
   ┌───────────┼────────────────┬───────────────┐
   ▼           ▼                ▼               ▼
core::scan  getdev-registry getdev-gitx     core::report
tree-sitter npm+PyPI        snap plumbing   terminal/json/md
AST, file   client + cache  diff extraction renderers, score
walk, stack (rusqlite)
detection
```

## 3.2 Core crates & modules (Cargo workspace)

| Crate / module | Responsibility | Key decisions |
|---|---|---|
| `getdev-core::scan` | File walk (gitignore-aware via `ignore` crate), language detection, tree-sitter parsing, stack/framework detection, **ScanContext** (parsed ASTs cached per file, shared by all analyzers) | Parse each file **once** per invocation; analyzers are read-only visitors. Parallelism via `rayon` (bounded by logical CPUs) |
| `getdev-core::findings` | `Finding` struct (serde-derived), severity, rule registry, suppression (inline `// getdev-ignore rule-id` + config) | Schema is versioned — see `docs/SPEC-FINDINGS.md` |
| `getdev-registry` | npm/PyPI clients (`reqwest` **blocking** — no async runtime; a batch CLI gains nothing from tokio), `rusqlite` cache, top-10k popularity dataset, typosquat distance | Rate-limited, exponential backoff, hard 5 s/req timeout, hermetic in `--offline` |
| `getdev-gitx` | All git interaction: snaps (plumbing commands), diff extraction for `review` | Shells out to git via `std::process::Command` in v0.x (resist `git2`/`gix` until needed); namespaced refs only |
| `getdev-core::rules` | Load embedded + user rule packs (YAML via `serde_yaml`, validated against JSON Schema), compile patterns | Rules embedded via `include_dir!`; `--rules` merges user packs |
| `getdev-core::report` | Renderers: human terminal (grouped, colored via `anstream`/`owo-colors`, honors NO_COLOR), `--json`, markdown (`SHIP.md`, future); Ship Score computation | All renderers consume the same `Vec<Finding>` |
| `getdev-core::config` | `.getdev.toml` + global `~/.getdev/config.toml` + flags precedence (flags > project > global > defaults) | `serde` + `toml` |
| `getdev-core::mutate` | Shared safe-file-rewrite engine used by `env`/`ship`/`fix`: plan → atomic write (temp+rename) → verify reparse | Mutations always go through one audited path; auto-snap before any multi-file mutation |
| `getdev-cli::update` | Self-update (GitHub Releases, signature check), version pinning | `self_update` crate or hand-rolled |
| `getdev-grammars` | tree-sitter grammar crates re-exported behind one crate boundary | Isolates the slowest-compiling deps so they build once and stay cached; keeps the `cargo check` inner loop fast |

Dependency direction: `getdev-cli` depends on all others; `getdev-core` depends only on `getdev-grammars`; `getdev-grammars` is the only crate with FFI/`unsafe`.

## The ScanContext parse-once invariant

Files are parsed **once** per invocation into a `ScanContext` (parsed ASTs cached per file). All analyzers (`real`, `audit`, `review`, `env`-detect, …) are **read-only visitors** over that shared context. Never re-parse inside an analyzer. This is what makes `check` a single-pass aggregate that fits the performance budgets (`docs/PLAN.md` §3.5).

## Mutation safety invariants (enforced in `core::mutate`)

All file mutations (`env --write`, `ship --write`, future `fix`) go through the single audited `core::mutate` path:

1. **Plan** — compute the full change set before touching disk.
2. **Atomic write** — temp file + rename; never partial in-place writes.
3. **Reparse-verify** — post-write reparse must succeed, or **rollback**.
4. **Auto-snap** — a snapshot precedes any multi-file mutation (`snap.auto_snap_before_fix`).
5. **Dry-run fidelity** — `--dry-run` output must equal the actually applied diff.

Commands never mutate files without explicit `--write`/`--fix` (safe by default).

## 3.3 Language support matrix (v0.1)

| Capability | JS/TS | Python | Notes |
|---|---|---|---|
| Parsing (tree-sitter) | ✅ js, ts, tsx | ✅ | grammars embedded |
| Manifest/lockfile | package.json, package-lock, pnpm-lock, yarn.lock | requirements.txt, pyproject.toml, poetry.lock, uv.lock | |
| Registry | npm | PyPI | |
| API-surface introspection | exports + `.d.ts` in node_modules | AST of site-packages source | confidence-tiered |
| Frameworks (audit awareness) | Express, Next.js | FastAPI, Flask, Django | |

Go/Rust/Ruby project detection returns a clear "stack not yet supported for deep analysis" info finding rather than silent partial results. (Roadmap: Go analysis support in v0.5.)

## 3.4 Technology choices

| Decision | Choice | Rationale |
|---|---|---|
| Language | **Rust (2021 edition, stable toolchain)** | Runtime speed & low memory, memory safety across parsers handling hostile input, first-class tree-sitter ecosystem, fearless refactoring; the modern devtools wave (ruff, uv, biome) has made Rust native to this category |
| Concurrency model | Synchronous + `rayon` data parallelism | **No async runtime.** A batch CLI gains nothing from tokio; blocking HTTP + rayon file-level parallelism covers every need with a fraction of the complexity |
| CLI framework | `clap` v4 (derive API) | Subcommands, global flags, shell completions, help — industry standard |
| Parsing | `tree-sitter` + `tree-sitter-javascript`/`-typescript`/`-python`, statically linked via `getdev-grammars` | Native Rust bindings; one engine, many languages, incremental-parse future |
| File walking | `ignore` crate | ripgrep's gitignore-aware parallel walker — battle-tested, exactly the `scan` requirement |
| HTTP (registry) | `reqwest` (blocking feature) with `rustls` | No OpenSSL system dependency; fully static binaries |
| Cache | `rusqlite` (bundled feature) | SQLite statically compiled in, zero system deps, transactional, easy TTL |
| Config | `serde` + `toml` | Human-friendly; comment-preserving needs are minimal |
| Rules format | YAML (`serde_yaml`) with JSON-Schema validation (`jsonschema`) | Community PR-friendly; contributors never need to write Rust |
| Findings / JSON | `serde` + `serde_json` | Schema structs derive serialization |
| Terminal output | `anstream` + `owo-colors` | Correct Windows ANSI handling; honors `NO_COLOR` |
| Errors | `thiserror` (libraries) + `anyhow` (CLI boundary) | Standard split |
| Regex / entropy | `regex` crate + hand-rolled Shannon entropy | `regex` is famously fast; linear-time guarantees resist pathological patterns in scanned code |
| Release | **`cargo-dist`** + GitHub Actions | The GoReleaser equivalent for Rust: cross-platform CI matrix, installers, checksums generated for you; SBOM (Syft) + cosign signing added in the same workflow. Binaries for darwin/linux/windows × x86_64/aarch64 |
| Build hygiene | `sccache`, workspace-split grammars, `cargo check` inner loop | tree-sitter grammars dominate compile time; isolating them keeps iteration fast |
| Install | `install.sh` on getdev.ai (cargo-dist generated), Homebrew tap, Scoop, npm wrapper (`npx getdev`), `cargo install getdev`, `cargo binstall` | npm wrapper is critical: vibe coders live in npm |

## Error-handling conventions

- `thiserror` for typed errors inside library crates; `anyhow` (with context) at the CLI boundary only.
- No `unwrap()`/`expect()` outside tests — lint-enforced (`clippy::unwrap_used`, `clippy::expect_used` denied).
- No panics across crate boundaries; analyzer panics on hostile input are treated as release-blocking bugs.
- Error messages: lowercase start, actionable, name the file/flag involved (per CLAUDE.md style).
- User-facing output goes through `core::report` renderers — never `println!` from analyzers.

## Network boundary rule

Only **`getdev-registry`** and **`getdev-cli::update`** may touch the network. Permitted destinations, exhaustively:

1. npm registry API
2. PyPI JSON API
3. GitHub Releases (self-update only)

`getdev-core`, `getdev-gitx`, and `getdev-grammars` contain **no network code**. `--offline` disables all network traffic (registry falls back to cache; doctor skips the version check). No telemetry, no analytics, no code upload — ever. getdev never executes project code unless the user passes an explicit opt-in flag (`ship --run-build`).

## Threat model (summary)

Documented threats and mitigations (full doc: TBD — plan calls for a threat-model doc in `/docs`):
- Malicious repo inputs (parser bombs) → size/time limits per file.
- Cache poisoning → registry responses validated.
- Hostile rule packs → `--rules` packs are declarative-only, no code execution.
