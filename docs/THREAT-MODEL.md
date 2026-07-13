# THREAT-MODEL.md — getdev

The full threat model for getdev. It expands the three-bullet "Threat model
(summary)" stub in [ARCHITECTURE.md](./ARCHITECTURE.md#threat-model-summary)
into a standalone launch document, so getdev's privacy and safety promises are
**verifiable against named, enforced mitigations** — not merely asserted.

> **Scope & framing.** getdev is a local, offline-by-nature CLI that inspects
> *untrusted* code: the whole point is to point it at an AI-generated repo you
> do not yet trust. So the primary adversary is **the scanned project itself**
> (hostile source, hostile config, hostile rule packs), followed by **the
> software supply chain** feeding getdev's own binary (self-update). getdev is
> **not** a network service, has no server component, stores no user accounts,
> and — by settled decision — sends no telemetry. Where a threat is mitigated,
> this doc cites the exact code / test / decision that enforces it, using
> [STRIDE](https://en.wikipedia.org/wiki/STRIDE_model) categories.
>
> Report a suspected vulnerability per [SECURITY.md](../SECURITY.md).

---

## Trust boundaries

```
   UNTRUSTED                          getdev process                 NETWORK (egress-limited)
 ┌───────────────┐   read-only    ┌────────────────────────┐   npm registry ─┐
 │ scanned repo  │ ─────────────► │ core::scan (parse-once) │                 │
 │  source files │                │ analyzers (visitors)    │   PyPI ─────────┤ ← ONLY these
 │ .getdev.toml  │                │ core::mutate (--write)  │                 │   three, ONLY
 │ --rules packs │                └───────────┬────────────┘   GitHub Releases┘   from two
 └───────────────┘                            │  writes                            crates
                                              ▼  (opt-in only)
                                    ┌────────────────────────┐
                                    │ user's working tree     │  ◄── auto-snap before multi-file
                                    └────────────────────────┘       mutation (undoable)
```

Four boundaries cross into getdev, each an entry for an attacker who controls
the thing on the untrusted side:

| # | Boundary | Attacker-controlled input | Primary risk |
|---|----------|---------------------------|--------------|
| B1 | scanned source → parser | arbitrary/hostile files (incl. FIFOs, `/proc`, huge files) | DoS (parser bomb), panic across crate boundary |
| B2 | project config / rule packs → engine | `.getdev.toml`, `--rules` YAML | code execution, resource exhaustion |
| B3 | registry responses → cache | npm/PyPI JSON | cache poisoning, false "package is real" verdict |
| B4 | release artifact → running binary | downloaded `SHA256SUMS` + binary (self-update) | remote code execution via a tampered/backdoored release |

And one boundary crosses **out** — the network egress boundary (B5), where the
promise is that *nothing* leaves the machine except the three sanctioned
package/release lookups.

---

## T1 — Hostile input (parser bombs, adversarial & special files)

**STRIDE: Denial of Service, (potential) Elevation via a parser panic.**
getdev parses attacker-authored source with tree-sitter. The threats are a
"zip-bomb"-style pathological file that blows up memory/CPU, a non-regular file
(a FIFO, device node, or `/proc` entry) that never returns or defeats a naive
`stat`-then-read, and a hostile input that panics an analyzer.

**Mitigations (enforced):**

- **Bounded reads that cap the read itself, not a pre-check.** Source is read
  through `core::scan::read_source_capped`, which caps the number of bytes
  actually consumed (`take(cap + 1)`), so a file that grows between `stat` and
  `read`, or a never-ending FIFO/device, cannot defeat the limit. The same
  hardened pattern guards the attacker-controllable `.getdev.toml`
  (`core::config`, which additionally **rejects non-regular files** — see
  `config.rs`'s `is_file()` gate and its `WR-02` cap-defeat hardening test).
- **Parse-once, read-only visitors.** Each file is parsed a single time into a
  `ScanContext`; analyzers are read-only visitors and never re-parse
  (ARCHITECTURE.md "parse-once invariant"). This bounds total parser work per
  invocation to O(files), not O(files × analyzers).
- **Memory safety + no panics across crate boundaries.** All parsing rides on
  tree-sitter behind `getdev-grammars` (the *only* crate permitted `unsafe`;
  everywhere else is `#![forbid(unsafe_code)]`, [DEC-11](./DECISIONS.md)). No
  `unwrap()`/`expect()` outside tests (clippy-denied), so hostile input yields
  a typed error, not a crash; an analyzer panic on hostile input is treated as
  a release-blocking bug.
- **Linear-time matching.** Detection uses the `regex` crate (linear-time
  guarantees) and hand-rolled entropy — no backtracking engine that a crafted
  string could drive to super-linear time.

---

## T2 — Hostile rule packs (`--rules`)

**STRIDE: Elevation of Privilege / Tampering.** Community rule packs are a
growth lever; a malicious pack must never be able to run code or otherwise
escape "match a pattern, emit a finding."

**Mitigations (enforced):**

- **Rules are data, never code** ([DEC-03](./DECISIONS.md)). A rule pack is
  YAML, validated against a JSON Schema (`core::rules`), compiled into
  tree-sitter queries / text patterns. There is no eval, no plugin `.so`, no
  shell-out — the richest thing a rule can do is describe an AST/text pattern.
  A hostile pack can at worst produce noisy or wrong *findings*; it can never
  execute.
- **Every rule is fixture-pinned.** Per CLAUDE.md hard rule 3, each shipped
  rule carries ≥3 positive + ≥3 negative fixtures, so a rule that silently
  changed behavior fails its tests.

---

## T3 — Cache poisoning (registry responses)

**STRIDE: Tampering / Spoofing.** getdev's `real` check asks npm/PyPI whether a
package exists and caches the answer in SQLite. A poisoned cache or a spoofed
"exists" response could make a hallucinated (and possibly typosquatted) package
read as real — defeating the tool's core purpose.

**Mitigations (enforced):**

- **Validated, typed responses.** Registry JSON is deserialized with strict
  `serde` structs in `getdev-registry`; malformed/oversized responses are
  rejected the same way hostile source is, never trusted blindly.
- **Bounded, offline-capable cache.** The `rusqlite` cache
  ([DEC-07](./DECISIONS.md)) is TTL'd; `doctor --fix` clears a corrupt cache
  rather than trusting it. `--offline` falls back to cache only and makes no
  network call at all, so an air-gapped run has a well-defined, attacker-free
  answer.
- **Typosquat distance is computed locally**, so a "looks real" name close to a
  popular package still surfaces regardless of a cache hit.

---

## T4 — Self-update supply chain (highest-value target)

**STRIDE: Tampering → Remote Code Execution.** `getdev update` fetches a release
from GitHub and swaps the running binary. This is the single highest-value
attack surface in the tool: a backdoored or tampered release, a signature
stripped in flight, a partial/interrupted write leaving a corrupt binary, or a
forced *downgrade* to a known-vulnerable version would all be RCE-class.

**Mitigations (enforced / locked for launch):**

- **Keyed-cosign signature, verified in-process** ([D-01], `update::signature`).
  Releases are signed CI-side by *keyed* cosign (`cosign sign-blob --key`) over
  the `SHA256SUMS` manifest; the client verifies with pure-Rust RustCrypto
  (`p256`/`ecdsa`/`signature`) against an **embedded** public key —
  `base64(DER ECDSA-P256)` over `sha256(manifest)`, mirrored exactly by
  `verify_detached`. No async `sigstore`, no `tokio` added: DEC-01 preserved
  literally. Because the key is embedded, verification is a pure local
  computation — it adds **no fourth network destination** and keeps `--offline`
  meaningful.
- **Fail-closed.** `UpdateError` is deliberately coarse (`SignatureMalformed`,
  `PublicKeyMalformed`, `SignatureMismatch`) so it never leaks forge-useful
  detail; 08-04's swap engine treats **any** `Err` as "abort, leave the running
  binary untouched." Tamper-vector coverage lives in the 08-01 test suite.
- **Checksum gate then verify-then-swap.** A SHA-256 checksum gate precedes the
  signature check; the binary is only swapped after both pass, and the swap is
  atomic (never a partial in-place overwrite), so an interrupted update cannot
  leave a half-written binary.
- **Downgrade refusal & offline no-op.** The updater refuses to move to an older
  version and is a no-op under `--offline`/`GETDEV_OFFLINE=1` (the version
  probe short-circuits *before* any client is built — see
  `update::latest_release_version`).

Release-side signing/SBOM details: [RELEASING.md](./RELEASING.md).

---

## T5 — Network / privacy boundary (the SC4 promise)

**STRIDE: Information Disclosure.** getdev's central promise is that your code
never leaves your machine: **no telemetry, no analytics, no code upload — ever**
([DEC-05](./DECISIONS.md)). The risk is a future change silently adding a
network destination (an analytics beacon, a second HTTP client, an LLM API
call) that erodes that promise unnoticed.

**Mitigations (enforced — two mechanically-different, CI-runnable proofs):**

- **Exhaustive egress allowlist.** The only permitted destinations are the npm
  registry, PyPI, and GitHub Releases (self-update), and the only crates
  permitted to touch the network are `getdev-registry` and `getdev-cli::update`
  (ARCHITECTURE.md "Network boundary rule", DEC-05). `getdev-core`,
  `getdev-gitx`, and `getdev-grammars` contain no network code.
- **Dependency-graph proof — `deny.toml`.** `cargo deny check bans` fails the
  build if a second async runtime (`async-std`/`smol`/…), a second HTTP client
  (`ureq`/`isahc`/`curl`/direct `hyper`/…), or any LLM/AI SDK
  (`async-openai`/`anthropic`/…) enters the tree. `tokio`/`hyper` are permitted
  **only** transitively under the sanctioned blocking `reqwest`
  (wrapper-scoped); a direct dependency on either fails the gate.
- **Source-symbol proof — `network_egress.rs`.** `cargo test --test
  network_egress` asserts that network symbols (`reqwest::`, `std::net::`,
  `TcpStream`, …) appear only in the two sanctioned locations, and that every
  host literal there is on the npm/PyPI/GitHub-Releases allowlist. The two
  proofs are complementary: a dependency can be present-but-uncalled (caught
  only by the symbol scan) and a symbol can be reached transitively without
  appearing in source (caught only by the dep-graph scan).
- **`--offline` disables all network traffic** — registry falls back to cache,
  `doctor` skips the version check, self-update is a no-op — so a run can be
  made provably networkless. No LLM calls anywhere in v0.1–v0.3
  ([DEC-04](./DECISIONS.md)); same input → same output.

Both proofs are wired as CI jobs (08-06), so this section is a build gate, not
a pledge.

---

## T6 — Mutation safety (`--write` / `--fix`)

**STRIDE: Tampering (with the user's own tree), Denial of Service.** Commands
that can modify files (`env --write`, `ship --write`, future `fix`) risk
corrupting the working tree — a bad rewrite that introduces a syntax error, a
partially-applied multi-file change, or a secret briefly written world-readable.

**Mitigations (enforced in `core::mutate`):**

- **Safe by default.** Nothing is written without an explicit `--write`/`--fix`;
  getdev never executes project code unless the user passes the opt-in
  `ship --run-build` (the single project-code exec point in the product).
- **Verify-first, in memory.** Every rewritten source must reparse cleanly
  **before any byte hits disk**; a rewrite that would introduce a syntax error
  aborts the whole plan with nothing written.
- **Atomic writes, owner-only.** Temp file (created `0600`, so a secret-bearing
  new file is never briefly world-readable) + rename — never a partial in-place
  write.
- **Rollback + auto-snap.** A failed mid-plan write restores already-written
  files; a snapshot precedes any multi-file mutation
  (`snap.auto_snap_before_fix`), so a write is always undoable. `--dry-run`
  output equals the applied diff.

---

## STRIDE register (summary)

| ID | Category | Boundary | Disposition | Enforcing mitigation |
|----|----------|----------|-------------|----------------------|
| T1 | DoS / Elevation | B1 | mitigate | `read_source_capped` (capped read), non-regular-file reject, `#![forbid(unsafe_code)]`, no-panic rule, linear-time `regex` |
| T2 | Elevation / Tampering | B2 | mitigate | rules-as-YAML + JSON-Schema, no code execution (DEC-03); ≥3+3 fixtures/rule |
| T3 | Tampering / Spoofing | B3 | mitigate | strict `serde` deserialization, TTL'd cache, `doctor --fix`, local typosquat, `--offline` |
| T4 | Tampering → RCE | B4 | mitigate | keyed-cosign p256 verify-in-process (D-01), fail-closed, checksum gate, verify-then-swap, downgrade refusal |
| T5 | Information Disclosure | B5 | mitigate | `deny.toml` bans + `network_egress.rs` scan + exhaustive host allowlist + `--offline` (DEC-04/05) |
| T6 | Tampering / DoS | write path | mitigate | `core::mutate`: verify-first, atomic `0600` write, rollback, auto-snap, safe-by-default |

---

## Non-goals & residual risk

- **getdev is not a sandbox.** It does not run the scanned project (unless you
  pass `ship --run-build`); it makes no guarantee about code you choose to
  execute yourself after getdev reports on it.
- **getdev is not a substitute for the registries' own integrity.** A package
  that genuinely exists on npm/PyPI but is itself malicious is out of scope for
  `real` (which answers "does this exist / is it a likely typo?"); `audit` and
  `review` address code-level risk, not upstream package trustworthiness.
- **Embedded release key management** (rotation, revocation) is a launch
  operational concern tracked in RELEASING.md; the placeholder key in
  `update::signature` is replaced with the real release key at launch (08-08).

---

## Cross-references

- [ARCHITECTURE.md](./ARCHITECTURE.md) — crate boundaries, parse-once invariant,
  mutation-safety invariants, network boundary rule (this doc's parent stub).
- [DECISIONS.md](./DECISIONS.md) — DEC-01 (no async), DEC-03 (rules-as-YAML),
  DEC-04 (no LLM), DEC-05 (no telemetry / egress allowlist), DEC-07 (cache),
  DEC-11 (`unsafe` forbidden outside grammars).
- [RELEASING.md](./RELEASING.md) — release signing, SBOM, cosign.
- [SECURITY.md](../SECURITY.md) — how to report a vulnerability.

> **Follow-up (out of this change's file set):** update ARCHITECTURE.md's
> "Threat model (summary)" stub to link here. Deferred to keep 08-03's file set
> disjoint from parallel Wave-1 plans; see 08-03-SUMMARY.md.
