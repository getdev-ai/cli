# getdev integrations — put getdev in your agent's loop

getdev is the **deterministic guardrail loop** for autonomous coding agents. This directory has
ready-to-use setup for the common agents so the agent verifies its own output on every iteration:

```
agent proposes a change
  → getdev snap            reversible checkpoint
  → apply
  → getdev check           one Ship Score + ranked, fixable findings
       high enough  → keep / commit
       findings     → hand back to the agent → it fixes → re-check
       broke it     → getdev back   one-second rollback, retry
```

Everything here is **local and deterministic** — no code leaves the machine, no LLM in getdev's core,
so the agent can call it as often as it likes without cost, latency, or nondeterminism.

> **Prerequisite:** install getdev (`curl -fsSL https://getdev.ai/install.sh | sh`, `npx getdev`,
> `brew install getdev-ai/tap/getdev`, …) and run `getdev init` once in the repo. `init` writes
> `.getdev.toml` and drops the canonical getdev block into any `CLAUDE.md` / `AGENTS.md` /
> `.cursorrules` it finds — so for most agents, `getdev init` *is* the integration.

---

## The one contract every integration uses

Two things make getdev loop-friendly, and every integration below is built on them:

1. **A single scored verdict.** `getdev check` prints a **Ship Score 0–100** plus ranked findings.
   `getdev check --json --fail-on <severity>` exits non-zero when anything at/above that severity
   remains — so an agent (or CI) can `until getdev check --fail-on high; do <fix>; done`.
2. **A transaction with rollback.** `getdev snap` is a one-command reversible checkpoint;
   `getdev back` restores byte-identically. An autonomous agent can experiment freely because every
   step is one command from undo.

---

## Claude Code

**Skill (recommended).** Copy the skill into your skills directory so Claude Code invokes getdev at
the right moments automatically:

```bash
cp -r integrations/claude-code/getdev ~/.claude/skills/     # user-wide
# or, per-project:
cp -r integrations/claude-code/getdev .claude/skills/
```

See [`claude-code/getdev/SKILL.md`](claude-code/getdev/SKILL.md). It teaches Claude to `snap` before
large changes, `check` after, feed findings back into its own edits, and `back` on a regression.

**Or just `getdev init`** — it writes the getdev block into `CLAUDE.md`, which Claude Code reads as
project instructions. The skill and the `CLAUDE.md` block compose; use either or both.

---

## Cursor / Windsurf

Add the canonical block to your rules file (`.cursorrules`, or a `.mdc` under `.cursor/rules/`).
`getdev init` writes it to `.cursorrules` automatically; to add it by hand, paste
[the block below](#the-canonical-agents-block).

---

## Cline / Roo / Continue / Aider / any `AGENTS.md`-aware agent

These read an `AGENTS.md` (or equivalent) at the repo root. `getdev init` seeds it; otherwise paste
[the canonical block](#the-canonical-agents-block) into your `AGENTS.md`.

For **Aider** specifically, you can also gate commits directly:

```bash
aider --test-cmd "getdev check --fail-on high" --auto-test
```

so every AI edit is followed by a getdev gate and Aider self-corrects on a non-zero exit.

---

## MCP server — any MCP-capable agent (native tools)

For the tightest integration, run **[`getdev-mcp`](mcp/)** — a Model Context Protocol server that
exposes getdev as native tools (`getdev_check`, `getdev_real`, `getdev_audit`, `getdev_review`,
`getdev_env_detect`, `getdev_snap`, `getdev_back`). The agent calls them directly instead of running
shell commands, and gets structured JSON back. It's a thin synchronous wrapper over the installed
`getdev` binary — same local, deterministic, network-confined behavior. Setup (build + `claude mcp
add` / `.mcp.json` / Cursor / Cline) is in [`mcp/README.md`](mcp/README.md).

## Generic harness / your own agent loop

If you drive an agent programmatically, wrap each risky step as a transaction:

```bash
getdev snap -m "before: <task>"
# ... let the agent apply its change ...
if getdev check --json --fail-on high > findings.json; then
  echo "clean — keep"
else
  # hand findings.json back to the agent to fix, then re-check;
  # or bail out and restore:
  getdev back
fi
```

`--json` gives you the full findings report (schema in
[`docs/SPEC-FINDINGS.md`](../docs/SPEC-FINDINGS.md)); the exit code gives you the gate.

---

## The canonical `AGENTS.md` block

This is the same guidance `getdev init` writes, expanded for an agent operating in a loop. Paste it
into `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, or any agent rules file:

```markdown
## getdev — verify your own output

This project uses **getdev**, a local, deterministic CLI, to verify AI-generated code. It runs
entirely on this machine — nothing is uploaded.

When you (the agent) change code:

1. **Before a large or risky change**, take a checkpoint: `getdev snap -m "before <task>"`.
2. **After changing code**, run `getdev check` and read the Ship Score + findings.
   - Fix every `critical`/`high` finding you introduced, then re-run `getdev check`.
   - `getdev real` flags packages/imports that do not exist — if you added one, you likely
     hallucinated it; remove or correct it.
   - `getdev audit` flags security anti-patterns (injection, wildcard CORS, hardcoded secrets…).
   - `getdev env --write` moves any hardcoded secret into `.env` and rewrites the references.
3. **If a change makes things worse or breaks the build**, roll back: `getdev back`.
4. **Don't consider the task done** until `getdev check --fail-on high` exits 0.

All getdev commands are safe to run repeatedly and never mutate files without an explicit
`--write`/`--fix` flag.
```

---

## Forward plan

First-class agentic features on the roadmap — `getdev fix` (auto-remediation), `--format=agent`
(LLM-shaped output), `getdev guard <cmd>` (snap → run → check → auto-back), and a
`getdev-mcp` server (getdev as MCP tools) — are tracked under the **Agentic / auto-mode workflow**
theme in [`docs/ROADMAP.md`](../docs/ROADMAP.md). Contributions welcome; see
[`CONTRIBUTING.md`](../CONTRIBUTING.md).
