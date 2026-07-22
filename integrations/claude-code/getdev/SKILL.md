---
name: getdev
description: >-
  Verify AI-generated code with getdev, the local, deterministic guardrail CLI.
  Use this whenever you are about to make, or have just made, non-trivial code
  changes in a project that has getdev available: take a reversible checkpoint
  before large edits, run an aggregate Ship-Score check afterward and fix what
  it finds, catch hallucinated packages, extract hardcoded secrets, and roll
  back cleanly when a change goes wrong. Triggers on: "verify this", "is this
  safe to ship", "check my changes", "did I hallucinate a package", after a
  large refactor or scaffolding step, or before committing agent-written code.
---

# getdev — verify your own output

getdev is a free, local, **deterministic** CLI that verifies AI-generated code. It runs entirely on
this machine — nothing is uploaded, there is no LLM in its core, and the same input always produces
the same output. That is exactly why you can call it on every iteration.

**First, confirm it's available:** run `getdev --version`. If it's missing, tell the user to install
it (`curl -fsSL https://getdev.ai/install.sh | sh`, `npx getdev`, or `brew install
getdev-ai/tap/getdev`) and stop — do not fabricate results.

## The loop

Work in this transaction shape whenever you change more than a line or two:

1. **Checkpoint before a large or risky change.**
   `getdev snap -m "before <short task description>"`
   This is a one-command reversible checkpoint (git under the hood, in a private ref namespace — it
   never touches the user's branches, index, or stash).

2. **Make your change.**

3. **Verify.** `getdev check`
   Read the **Ship Score (0–100)** and the ranked findings. For machine-readable output use
   `getdev check --json`.
   - Fix every `critical` and `high` finding **you introduced**, then re-run `getdev check`.
   - Do not consider the task complete until `getdev check --fail-on high` exits `0`.

4. **Roll back if you made things worse.** `getdev back`
   Restores the working tree to the last checkpoint, byte-identically, in about a second. Prefer this
   over trying to hand-unwind a bad change.

## The individual commands (run these when you want a focused answer)

- **`getdev real`** — verifies that imported packages, APIs, and model strings actually exist
  (anti-hallucination / anti-slopsquatting). If it flags a package you added, you almost certainly
  hallucinated it — remove or correct it; do not add a `# it exists` comment.
- **`getdev audit`** — security scan tuned to AI failure patterns: command/SQL injection from string
  building, wildcard CORS, debug mode on, missing auth, hardcoded secrets. Fix findings at the
  source; these are rules, not style nits.
- **`getdev env --write`** — moves hardcoded secrets into `.env`, rewrites the references to read
  from the environment, and patches `.gitignore`. Run this instead of leaving a key in source.
- **`getdev review`** — diff analysis for the debris agents leave: dead code, duplicate helpers,
  debug leftovers, orphaned files. Useful after a big scaffolding step.
- **`getdev ship`** — pre-flight before deploying: Dockerfile generation, env validation, a deploy
  checklist.

## Rules of engagement

- **Safe by default:** no getdev command mutates files without an explicit `--write` (or, later,
  `--fix`) flag. `check`, `real`, `audit`, `review` are read-only — run them freely.
- **Never print or commit a secret value.** getdev masks them (`sk-…f3a9`); you should too.
- **Trust the deterministic verdict over your own confidence.** If `getdev real` says a package does
  not exist, it does not exist, regardless of how plausible the name looks.
- **Report honestly.** If `getdev check` is not clean, say so with the findings; do not claim a task
  is done while `--fail-on high` is non-zero.

## One-shot gate (for CI or a scripted loop)

```bash
getdev check --json --fail-on high
```

Exits non-zero while any high-or-critical finding remains — the signal to keep fixing.
