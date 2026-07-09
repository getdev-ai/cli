# getdev

> **Verify, secure, and ship AI-generated code. One binary, runs locally, nothing leaves your machine.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **Status: pre-development (P0 — foundation).** The plan is written, the code is not.
> Install channels below describe the release target, not what works today.
> See [docs/](docs/) for the full development plan and release engineering docs.

This repo (`getdev-cli`) is the CLI tool. The [getdev.ai](https://getdev.ai) site — landing,
docs pages, and the tool listing — lives in the separate
[`pzelenin/getdev`](https://github.com/pzelenin/getdev) repo. The product, binary, and
package name everywhere (Homebrew, npm, crates.io, releases) is plain **`getdev`**.

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

- **No telemetry. No analytics. No code upload. Ever.**
- The only network calls getdev makes: the npm registry, PyPI, and GitHub Releases
  (self-update). Each is documented and verifiable in source. `--offline` disables all of them.
- getdev never executes your project's code unless you explicitly opt in (`ship --run-build`).
- Detected secret values are never printed — masked previews only (`sk-…f3a9`).

## Install (target channels for v0.1)

```bash
# macOS / Linux
curl -fsSL https://getdev.ai/install.sh | sh

# Homebrew
brew install pzelenin/tap/getdev

# npm (no Rust required — downloads the native binary)
npx getdev check          # or: npm install -g getdev

# Windows
powershell -c "irm https://getdev.ai/install.ps1 | iex"   # or: scoop install getdev

# Rust users
cargo install getdev      # or: cargo binstall getdev
```

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
git clone https://github.com/pzelenin/getdev-cli
cd getdev-cli
cargo build --workspace --release
```

Full instructions (prerequisites, tests, lints, compile-time tips): [docs/BUILDING.md](docs/BUILDING.md).

## Documentation

- [docs/BUILDING.md](docs/BUILDING.md) — build from source, test, lint
- [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md) — install channels and how they're published
- [docs/RELEASING.md](docs/RELEASING.md) — release process, gates, signing, SBOM
- [docs/CI.md](docs/CI.md) — GitHub Actions setup
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute (rules need zero Rust!)
- [SECURITY.md](SECURITY.md) — vulnerability disclosure

## Contributing

The easiest first contribution is a detection rule — rules are YAML data, not Rust code.
See [CONTRIBUTING.md](CONTRIBUTING.md). We use DCO sign-off (`git commit -s`) and
conventional commits.

## License & sustainability

Apache-2.0. The CLI is 100% free forever — no accounts, no paid features, and that's
stated policy, not a phase. Development is supported through [getdev.ai](https://getdev.ai)
— the companion platform for vibe-coding devs. Optional paid *support* may exist one day;
paid *features* never will.
