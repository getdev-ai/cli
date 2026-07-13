# SPEC — Configuration

Configuration surface and precedence rules. **This document is normative**; the
implementation is `crates/getdev-core/src/config.rs` and the two must never drift.

Source: distilled from the project master plan (internal) §5.

## Precedence

**flags > project config > global config > built-in defaults** — resolved per invocation.

| Layer | Location | Status |
|---|---|---|
| flags | CLI arguments | wired per command as commands land |
| project | `./.getdev.toml` (or `--config <path>`) | ✅ implemented |
| global | `~/.getdev/config.toml` (color, cache location/TTL, update channel, default flags) | lands with the cache work (P2) |
| defaults | compiled in | ✅ implemented |

## Behavior rules

- A **missing** `.getdev.toml` is the default config — getdev works with zero setup.
- A **malformed** file, an **unknown key**, or an invalid value is a hard error → exit code
  **3**. A typo that silently disables a check is worse than a loud failure, so
  `deny_unknown_fields` applies at every level.
- Every section and every key is optional; defaults below apply per-key.
- The config file (`.getdev.toml`, the global config, or a `--config` target) is read through a
  **1 MiB size cap**, and the read is bounded at read time (not via a stat pre-check) so a file
  that grows mid-read cannot slurp past the cap. A file over the cap, or a **non-regular file**
  (FIFO/device/symlink to one), is rejected rather than read — `.getdev.toml` lives in the
  scanned, attacker-controllable repo, so an unbounded read would be a denial-of-service. A
  rejected config file is a hard error (exit code **3**), same as a malformed one.
- `[[suppress]]` entries **require** `reason` — suppression without an audit trail is
  rejected at parse time. Suppressions are surfaced in `check -v` so they don't rot silently.
- Inline suppression (in code): `// getdev-ignore <rule-id> -- <reason>` — reason required;
  a bare ignore emits an `info` finding.

## Full v0.1 surface (with defaults)

```toml
[project]
stack = "auto"                    # "auto" | "node" | "python"

[check]
fail_on = "high"                  # severity threshold for exit code 1
score_badge = false               # write .getdev/score.json for badges (v0.2)

[real]
offline = false
check_apis = true
typosquat_sensitivity = "normal"  # "strict" | "normal" | "off"

[audit]
severity_min = "low"

[review]
against = "HEAD"

[env]
include_urls = false
env_file = ".env"

[snap]
keep = 20                         # retention for `snap prune`
auto_snap_before_fix = true       # engine auto-snaps before any mutation

[ship]
target = "auto"                   # "auto" | "vercel" | "railway" | "fly" | "docker" | "vps"
run_build = false                 # ship never executes project code unless opted in

[update]                          # `getdev update` self-update policy (no per-command flags)
channel = "stable"                # "stable" (latest non-prerelease) | "prerelease"
# pin = "0.1.2"                   # pin to an exact version; omitted = track the channel
allow_downgrade = false           # refuse installing an older version (downgrade attack) unless true

[ignore]
rules = []                        # e.g. ["audit/debug-mode-enabled"]
paths = []                        # e.g. ["vendor/", "dist/", "migrations/"]

# false-positive suppression with audit trail (repeatable)
[[suppress]]
fingerprint = "sha256:abc…"
reason = "test fixture key, not a real secret"    # REQUIRED
```

## Reserved for v0.4 (documented now so the schema stays stable)

Not yet accepted by the parser; will be added — with `enabled = false` as the default —
when the semantic layer lands:

```toml
[llm]
enabled = false                   # semantic checks are always opt-in
provider = "anthropic"            # "anthropic" | "openai" | "custom"
base_url = ""                     # OpenAI-compatible endpoint → Ollama / LM Studio /
                                  # llama.cpp for a fully local semantic layer
model = ""                        # api key via GETDEV_LLM_API_KEY env only —
                                  # NEVER stored in config
```

## Exit codes (contract, docs/PLAN.md §2.2)

`0` clean / below threshold · `1` findings ≥ `--fail-on` · `2` execution error ·
`3` config error.
