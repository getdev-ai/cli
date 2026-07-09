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

## Product & engineering specs (planned — referenced by CLAUDE.md, not yet written)

These are the P0+ documents the development plan calls for; they will land here as the
corresponding work starts:

`PLAN.md` · `ROADMAP.md` · `ARCHITECTURE.md` · `DECISIONS.md` · `SPEC-COMMANDS.md` ·
`SPEC-FINDINGS.md` · `SPEC-RULES.md` · `SPEC-CONFIG.md` · `TESTING.md` · `THREAT-MODEL.md`

Until then, the source of truth is the master plan at
[../getdev-development-plan.md](../getdev-development-plan.md).
