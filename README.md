# getdev

> **Verify, secure, and ship AI-generated code. One binary, runs locally, nothing leaves your machine.**

[![CI](https://github.com/getdev-ai/cli/actions/workflows/ci.yml/badge.svg)](https://github.com/getdev-ai/cli/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/getdev.svg)](https://crates.io/crates/getdev)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **v0.1.0 — released.** The full toolbelt (`check`, `real`, `audit`, `review`, `env`,
> `snap`/`back`, `ship`, `init`, `update`) ships as one static binary for macOS, Linux, and
> Windows. Install below; see [docs/ROADMAP.md](docs/ROADMAP.md) for what's next and the
> v0.1.x polish backlog for known issues we're tracking.

This repo (`getdev-ai/cli`) is the CLI tool; [getdev.ai](https://getdev.ai) is the
project's home — landing, docs, and install scripts. The product, binary, and package
name everywhere you type it (Homebrew, npm, crates.io, releases) is plain **`getdev`**.

getdev is a free, open-source CLI toolbelt for AI-assisted ("vibe") development. AI coding
agents hallucinate packages, hardcode secrets, skip auth, and leave debris behind. getdev is
what you run *after* the agent:

| Command | What it does |
|---|---|
| `getdev check` | Run everything, get one **Ship Score 0–100** |
| `getdev real` | Verify that packages, APIs, and model strings actually exist (anti-slopsquatting) |
| `getdev audit` | Security scan tuned to AI-generated failure patterns |
| `getdev review` | Diff analysis: dead code, duplicate helpers, debug leftovers |
| `getdev env` | Extract hardcoded secrets to `.env` and rewrite references |
| `getdev snap` / `back` | One-command checkpoints and restore (git hidden underneath) |
| `getdev ship` | Pre-flight: Dockerfile generation, env validation, deploy checklist |

## The privacy promise

- **No telemetry. No analytics. No code upload. Ever.** There are zero LLM code
  paths and no API key is required — the core is deterministic (same input → same
  output).
- The only network destinations getdev can reach are the npm registry, PyPI, and
  GitHub Releases (self-update) — and this is **mechanically enforced, not just
  asserted**. Two CI gates fail the build on any regression: a `cargo-deny`
  `[bans]` rule if a second HTTP client, a second async runtime, or any LLM SDK
  enters the dependency tree, and a source-symbol egress test (`network_egress.rs`)
  if a network call appears outside the two sanctioned locations. `--offline`
  disables all network access.
- `getdev update` verifies a keyed-cosign signature over the release checksums
  against a public key embedded in the binary — no network trust root, no Rekor.
- getdev never executes your project's code unless you explicitly opt in
  (`ship --run-build`).
- Detected secret values are never printed — masked previews only (`sk-…f3a9`).

The full threat model — every promise above tied to a named, enforced mitigation
— is in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Install

The seven channels below all resolve to the same static binary. Frozen install URLs
(getdev.ai) — the scripts detect OS/arch and download the checksum-verified release.

```bash
# 1 · Install script — macOS / Linux
curl -fsSL https://getdev.ai/install.sh | sh

# 2 · Install script — Windows (PowerShell)
irm https://getdev.ai/install.ps1 | iex

# 3 · npm (no Rust toolchain — downloads the native binary)
npx getdev                 # or: npm install -g getdev

# 4 · Homebrew (macOS / Linux)
brew install getdev-ai/tap/getdev

# 5 · Scoop (Windows)
scoop bucket add getdev https://github.com/getdev-ai/scoop-bucket
scoop install getdev

# 6 · crates.io (Rust users)
cargo install getdev       # or: cargo binstall getdev  (prebuilt, no compile)

# 7 · GitHub Releases — download the static binary for your platform
#     https://github.com/getdev-ai/cli/releases
```

Already installed? `getdev update` self-updates from GitHub Releases (checksum + cosign
signature verified against a key embedded in the binary).

See [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md) for the full channel matrix and how each
channel is published.

## Quick start

```bash
cd my-vibe-app
getdev init --yes         # config + optional pre-commit hook + agent-context block
getdev check              # Ship Score + ranked findings
getdev env --write        # secrets → .env, references rewritten, .gitignore patched
getdev snap -m "before the big refactor"
getdev back               # restore in one second when the agent goes sideways
getdev ship --write       # Dockerfile + SHIP.md deploy checklist
```

CI usage: `getdev check --json --fail-on high`

## Building from source

```bash
git clone https://github.com/getdev-ai/cli
cd getdev-cli
cargo build --workspace --release
```

Full instructions (prerequisites, tests, lints, compile-time tips): [docs/BUILDING.md](docs/BUILDING.md).

## Documentation

- [docs/BUILDING.md](docs/BUILDING.md) — build from source, test, lint
- [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md) — install channels and how they're published
- [docs/RELEASING.md](docs/RELEASING.md) — release process, gates, signing, SBOM
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — threats and enforced mitigations (privacy, self-update)
- [docs/CI.md](docs/CI.md) — GitHub Actions setup
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute (rules need zero Rust!)
- [SECURITY.md](SECURITY.md) — vulnerability disclosure

## Contributing

The easiest first contribution is a detection rule — rules are YAML data, not Rust code.
See [CONTRIBUTING.md](CONTRIBUTING.md). We use DCO sign-off (`git commit -s`) and
conventional commits.

## License & sustainability

getdev is built and funded by [getdev.ai](https://getdev.ai) — the portfolio platform for
people who ship. The CLI is free, Apache-2.0, and needs no account.

**Can getdev stop being free?** Every released version is Apache-2.0 forever — you can
always fork the last commit. There is no CLA, so contributed code can't be relicensed even
if I wanted to (contributions are DCO sign-off only). The CLI works with no account and
talks to no getdev server. And the business doesn't need it to be paid: the paid product is
the platform; the CLI is not a trial and has no paid tier.
