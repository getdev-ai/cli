# getdev docs index

## Build & release engineering

| Doc | Contents |
|---|---|
| [BUILDING.md](BUILDING.md) | Prerequisites, workspace layout, build/test/lint commands, release-profile builds, cross-compilation, compile-time hygiene |
| [CI.md](CI.md) | GitHub Actions workflows (ci.yml, release.yml), dependabot, repository hardening settings |
| [RELEASING.md](RELEASING.md) | Versioning, release gate, tag-to-channels pipeline, signing/SBOM/provenance, verification, hotfix & yank procedures |
| [DISTRIBUTION.md](DISTRIBUTION.md) | All install channels (install.sh, npm, Homebrew, Scoop, crates.io, binstall, self-update), name reservations, support matrix |

## Community / policy (repo root)

| Doc | Contents |
|---|---|
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Dev setup, code standards, rule contributions, DCO, commit conventions |
| [../SECURITY.md](../SECURITY.md) | Vulnerability disclosure (security@getdev.ai), scope, release integrity |
| [../CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 |
| [../LICENSE](../LICENSE) | Apache-2.0 |

## Product & engineering specs (normative)

Distilled from the master plan ([../getdev-development-plan.md](../getdev-development-plan.md));
where they conflict, these docs win — they are what CLAUDE.md holds the code to.

| Doc | Normative for |
|---|---|
| [PLAN.md](PLAN.md) | **§2.3 command scopes (contractual)**, global flags, exit codes, perf budgets, quality/release gates |
| [ROADMAP.md](ROADMAP.md) | phase sequence P0–P7, v0.2–v0.5 scope, v1.0 criteria, out-of-scope list |
| [DECISIONS.md](DECISIONS.md) | settled technical decisions (no-async, no-git2, rules-as-YAML, no-telemetry, …) — check before proposing a revisit |
| [ARCHITECTURE.md](ARCHITECTURE.md) | crate boundaries, parse-once ScanContext, mutation safety, network-boundary rule |
| [SPEC-COMMANDS.md](SPEC-COMMANDS.md) | per-command behavior, flags, mutation/network contracts, golden examples |
| [SPEC-FINDINGS.md](SPEC-FINDINGS.md) | findings JSON schema v1 (matches `core::findings` exactly) |
| [SPEC-CONFIG.md](SPEC-CONFIG.md) | `.getdev.toml` surface + precedence (matches `core::config` exactly) |
| [SPEC-RULES.md](SPEC-RULES.md) | rule YAML format, fixture requirements, FP policy tie-in |
| [TESTING.md](TESTING.md) | test pyramid, corpus, coverage floors, hermetic-CI rules |

Still to write: `THREAT-MODEL.md` (called for by the plan §10; lands with the P1 mutation
engine).
