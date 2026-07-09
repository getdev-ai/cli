# Security Policy

getdev audits other people's supply chains and secrets — its own security posture has to be
exemplary. This document covers how to report vulnerabilities in getdev, and what getdev does
to keep its own releases trustworthy.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

- Email: **security@getdev.ai**
- Or use GitHub private vulnerability reporting ("Report a vulnerability" under the repo's
  Security tab).

Include: getdev version (`getdev version`), OS/arch, reproduction steps or PoC, and impact
assessment if you have one. Reports in English or Russian are fine.

### What to expect

| Stage | Timeline |
|---|---|
| Acknowledgement | within 72 hours |
| Triage & severity assessment | within 7 days |
| Fix or mitigation for confirmed issues | targeted within 30 days; critical issues faster |
| Coordinated public disclosure | within **90 days** of report, or earlier by mutual agreement |

We follow a 90-day coordinated disclosure policy. If we can't fix within 90 days we'll
discuss disclosure timing with you rather than sit on it. Credit is given in release notes
and the credits section below unless you prefer anonymity. There is currently no bug bounty
(getdev is an unfunded open-source project), but reports are deeply appreciated and credited.

## Scope

In scope:

- Code execution, privilege escalation, or file writes outside the mutation engine's
  guarantees triggered by scanning a **malicious repository** (parser bombs, hostile ASTs,
  crafted manifests, symlink tricks)
- Secret values leaking into findings output, JSON reports, logs, or cache (the contract is
  masked previews only)
- Any undisclosed network call (the only permitted destinations are the npm registry, PyPI,
  and GitHub Releases for self-update)
- Cache poisoning via crafted registry responses
- Rule-pack loading executing code (rule packs are declarative-only by design)
- Self-update integrity bypass (checksum/signature verification flaws)
- Supply-chain issues in getdev's own release pipeline or dependencies

Out of scope:

- Vulnerabilities in the *scanned project* that getdev fails to detect (that's a detection
  gap — file a normal issue; missed detections are bugs, not vulnerabilities)
- Issues requiring a maliciously modified getdev binary (verify your download — see below)
- DoS from scanning pathologically large repos within documented limits

## Supported versions

Pre-1.0: only the **latest release** receives security fixes. From v1.0: the latest minor
release of the current major version.

## What getdev does on its side

- **No telemetry, no analytics, no code upload** — the privacy promise is verifiable in
  source: all network code is confined to `getdev-registry` and the updater.
- getdev never executes project code unless explicitly opted in (`ship --run-build`).
- Releases are built by GitHub Actions from tagged commits: artifacts ship with SHA-256
  checksums, **cosign signatures** (keyless, GitHub OIDC), an **SBOM** (Syft), and SLSA
  provenance. Verification instructions: [docs/RELEASING.md](docs/RELEASING.md#verifying-a-release).
- `install.sh` verifies checksums before installing and is only pointed at a new version
  after the release gate passes.
- Dependencies are pinned and audited in CI with `cargo-deny` (RustSec advisories) and
  Dependabot.
- Threat model (malicious repo inputs, cache poisoning, hostile rule packs): `docs/THREAT-MODEL.md`.

## Credits

Security researchers who have reported valid issues will be listed here.

*(none yet — be the first)*
