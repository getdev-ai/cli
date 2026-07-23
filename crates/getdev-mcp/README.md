# getdev-mcp — getdev as MCP tools for AI agents

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes getdev to any
MCP-capable agent (Claude Code, Cursor, Cline, Windsurf, …) as native tools. The agent can then
verify its own output *inside its loop* — call `getdev_check` after an edit, `getdev_real` to catch
a hallucinated package, `getdev_snap`/`getdev_back` as a safety net — without you wiring shell
commands by hand.

It is a thin, **synchronous** wrapper (no async runtime) that shells out to the installed `getdev`
binary, so it inherits getdev's exact behavior and privacy guarantees: local, deterministic, and
network-confined to what `getdev` itself already allows.

## Tools

| Tool | Wraps | Mutates? |
|---|---|---|
| `getdev_check` | `getdev check --json` — aggregate Ship Score + findings | no |
| `getdev_real` | `getdev real --json` — hallucinated/typosquatted package detection | no |
| `getdev_audit` | `getdev audit --json` — AI-pattern security scan | no |
| `getdev_review` | `getdev review --json` (`--all` or `--against <ref>`) — agent-debris | no |
| `getdev_env_detect` | `getdev env --json` — secret detection (**detect-only, never `--write`**) | no |
| `getdev_snap` | `getdev snap` — reversible checkpoint | refs only |
| `getdev_back` | `getdev back --quiet` — restore to a snapshot (auto-snaps first) | working tree |

Every tool takes an optional `path` (defaults to the working directory); `getdev_check`/`getdev_real`
also take `offline`.

## Prerequisites

- **getdev** installed and on `PATH` (`curl -fsSL https://getdev.ai/install.sh | sh`, or see the
  [main README](../../README.md#install)). Override the binary location with `GETDEV_BIN`.

## Install

`getdev-mcp` ships **prebuilt** in each getdev release — no Rust toolchain, no `cargo build`.
Download the `getdev-mcp-<target>` archive from the
[latest GitHub Release](https://github.com/getdev-ai/cli/releases/latest), unpack it, and point
your agent at the `getdev-mcp` binary (see below).

To build from source instead (e.g. for local development), it is a normal workspace member:

```bash
cargo build --release -p getdev-mcp
# binary at ./target/release/getdev-mcp
```

## Wire it into your agent

**Claude Code** — add it as an MCP server:

```bash
claude mcp add getdev -- /absolute/path/to/getdev-mcp
```

or in `.mcp.json` (project) / your user MCP config:

```json
{
  "mcpServers": {
    "getdev": {
      "command": "/absolute/path/to/getdev-mcp",
      "env": { "GETDEV_BIN": "getdev" }
    }
  }
}
```

**Cursor** — `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "getdev": { "command": "/absolute/path/to/getdev-mcp" }
  }
}
```

**Cline / Windsurf / any MCP client** — point the client at the `getdev-mcp` command over stdio; the
config shape is the same `{ command, env }` pair.

## Verify it's working

The server speaks newline-delimited JSON-RPC 2.0 over stdio. A quick smoke test:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | ./target/release/getdev-mcp
```

You should see an `initialize` result and the 7-tool catalogue.

## Design notes / invariants

- **No async runtime** — a blocking read-line → dispatch → write-line loop (getdev's settled
  no-tokio decision, DEC-01). MCP stdio is line-delimited JSON-RPC, which needs no executor.
- **No network of its own** — it only spawns the `getdev` subprocess; all network behavior (and its
  egress confinement) belongs to `getdev`.
- **stdout is the protocol channel** — only JSON-RPC goes there; diagnostics go to stderr.
- **`env` is detect-only** — the MCP tool never passes `--write`, so an agent can *find* secrets but
  extraction stays an explicit human action.

This crate is a first-class workspace member shipped **prebuilt** in each getdev release
(DEC-16). Phase 17 (MCP-02) bundles it into the Claude-Code plugin installer and lists it on the
MCP registry.
