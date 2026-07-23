//! `getdev-mcp` — a Model Context Protocol (MCP) server that exposes the getdev
//! CLI as tools any MCP-capable agent (Claude Code, Cursor, Cline, Windsurf, …)
//! can call natively.
//!
//! ## Design (getdev's invariants, preserved)
//! - **No async runtime.** MCP's stdio transport is newline-delimited JSON-RPC
//!   2.0; this is a plain blocking read-line → dispatch → write-line loop. No
//!   tokio, no futures (CLAUDE.md / DEC-01).
//! - **No network of its own.** Every tool shells out to the installed `getdev`
//!   binary (resolved from `$GETDEV_BIN`, else `getdev` on `PATH`), which owns
//!   the already-egress-confined network behavior. This server only spawns a
//!   subprocess and relays its JSON.
//! - **stdout is the protocol channel** — only JSON-RPC messages go there; all
//!   diagnostics go to stderr.
//!
//! Tools mirror the CLI: `getdev_check` / `getdev_real` / `getdev_audit` /
//! `getdev_review` / `getdev_env_detect` (never `--write`), plus the safety-net
//! transaction `getdev_snap` / `getdev_back`.

use std::io::{self, BufRead, Write};
use std::process::Command;

use serde_json::{json, Value};

/// The MCP protocol revision this server speaks.
const PROTOCOL_VERSION: &str = "2024-11-05";

fn main() {
    let getdev_bin = std::env::var("GETDEV_BIN").unwrap_or_else(|_| "getdev".to_owned());
    eprintln!(
        "getdev-mcp {} — MCP stdio server (getdev binary: {getdev_bin})",
        env!("CARGO_PKG_VERSION")
    );

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(err) => {
                eprintln!("getdev-mcp: stdin read error: {err}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(err) => {
                // We can't know the id of an unparseable message (JSON-RPC §5.1).
                write_message(
                    &mut stdout,
                    &error(Value::Null, -32700, &format!("parse error: {err}")),
                );
                continue;
            }
        };
        if let Some(response) = handle(&getdev_bin, &request) {
            write_message(&mut stdout, &response);
        }
    }
}

/// Dispatch one JSON-RPC message. Returns `Some(response)` for a request and
/// `None` for a notification (no `id` → no reply, JSON-RPC §4.1).
fn handle(getdev_bin: &str, request: &Value) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let is_notification = id.is_none();

    match method {
        "initialize" => Some(result(id, initialize_result())),
        "ping" => Some(result(id, json!({}))),
        "tools/list" => Some(result(id, json!({ "tools": tools_list() }))),
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
            Some(result(id, call_tool(getdev_bin, &params)))
        }
        // `notifications/initialized` and any other notification: no reply.
        _ if is_notification => None,
        // An unknown *request* (has an id) gets a proper method-not-found error.
        other => Some(error(
            id.unwrap_or(Value::Null),
            -32601,
            &format!("method not found: {other}"),
        )),
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "getdev-mcp", "version": env!("CARGO_PKG_VERSION") }
    })
}

/// A reusable `{ path }` property fragment for tool input schemas.
fn path_property() -> Value {
    json!({
        "type": "string",
        "description": "Project directory to run in (defaults to the current working directory)."
    })
}

/// The tool catalogue advertised to the agent. Read-only verification tools
/// plus the `snap`/`back` safety-net transaction.
fn tools_list() -> Value {
    json!([
        {
            "name": "getdev_check",
            "description": "Run getdev's full aggregate verification (real + audit + env-detect + review) over the project and return one Ship Score (0-100) plus ranked, fixable findings as JSON. Read-only. Use this after making code changes; fix critical/high findings and re-run.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": path_property(),
                    "offline": { "type": "boolean", "description": "Disable all network access (skip registry existence checks)." }
                }
            }
        },
        {
            "name": "getdev_real",
            "description": "Verify that imported/declared packages, APIs, and model strings actually exist (anti-hallucination / anti-slopsquatting). If it flags a dependency you added, you likely hallucinated it. Read-only. Returns JSON.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": path_property(),
                    "offline": { "type": "boolean", "description": "Use only the local cache; do not query npm/PyPI." }
                }
            }
        },
        {
            "name": "getdev_audit",
            "description": "Security scan tuned to AI-generated failure patterns: command/SQL injection from string-building, wildcard CORS, debug mode enabled, missing auth, hardcoded secrets. Read-only. Returns JSON.",
            "inputSchema": {
                "type": "object",
                "properties": { "path": path_property() }
            }
        },
        {
            "name": "getdev_review",
            "description": "Diff analysis for agent debris: dead code, duplicate helpers, debug leftovers, TODOs, orphaned files. Read-only. Returns JSON. Without 'against' it reviews the whole tree (--all); with 'against' it reviews the diff vs that git ref.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": path_property(),
                    "against": { "type": "string", "description": "Git ref to diff against (e.g. HEAD, main). Omit to review the whole tree." }
                }
            }
        },
        {
            "name": "getdev_env_detect",
            "description": "Detect hardcoded secrets and report where they are (masked previews only — never the raw value). Detection ONLY: this never writes files. To actually extract them, the user runs `getdev env --write`. Returns JSON.",
            "inputSchema": {
                "type": "object",
                "properties": { "path": path_property() }
            }
        },
        {
            "name": "getdev_snap",
            "description": "Take a reversible checkpoint of the working tree before a risky change (git under the hood, in a private ref namespace — never touches the user's branches/index/stash). Pairs with getdev_back. Safe to call often.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": path_property(),
                    "message": { "type": "string", "description": "Optional label for the checkpoint." }
                }
            }
        },
        {
            "name": "getdev_back",
            "description": "Restore the working tree to the most recent snapshot (or a specific id), discarding changes made since. ALWAYS takes a pre-restore auto-snap first, so the restore is itself reversible. Use to roll back a change that made things worse.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": path_property(),
                    "id": { "type": "integer", "description": "Snapshot id to restore. Omit for the most recent snapshot." }
                }
            }
        }
    ])
}

/// Execute a tool call, returning an MCP `tools/call` result object
/// (`{ content: [...], isError? }`). A tool that fails is reported via
/// `isError: true` content, not a JSON-RPC error, per the MCP tool contract.
fn call_tool(getdev_bin: &str, params: &Value) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let argv = match build_argv(name, &args) {
        Ok(argv) => argv,
        Err(msg) => return tool_error(&msg),
    };
    match run_getdev(getdev_bin, &argv) {
        Ok(text) => json!({ "content": [{ "type": "text", "text": text }] }),
        Err(msg) => tool_error(&msg),
    }
}

/// Translate an MCP tool name + arguments into a `getdev` argv. Pure (no I/O),
/// so the mapping is unit-testable. Unknown tools are an error.
fn build_argv(name: &str, args: &Value) -> Result<Vec<String>, String> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or(".")
        .to_owned();
    let offline = args
        .get("offline")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let mut argv: Vec<String> = Vec::new();
    match name {
        "getdev_check" => {
            argv.push("check".into());
            if offline {
                argv.push("--offline".into());
            }
        }
        "getdev_real" => {
            argv.push("real".into());
            if offline {
                argv.push("--offline".into());
            }
        }
        "getdev_audit" => argv.push("audit".into()),
        "getdev_review" => {
            argv.push("review".into());
            match args.get("against").and_then(Value::as_str) {
                Some(reference) if !reference.is_empty() => {
                    argv.push("--against".into());
                    argv.push(reference.to_owned());
                }
                _ => argv.push("--all".into()),
            }
        }
        "getdev_env_detect" => argv.push("env".into()), // detect-only: never --write
        "getdev_snap" => {
            argv.push("snap".into());
            if let Some(message) = args.get("message").and_then(Value::as_str) {
                if !message.is_empty() {
                    argv.push("-m".into());
                    argv.push(message.to_owned());
                }
            }
        }
        "getdev_back" => {
            argv.push("back".into());
            argv.push("--quiet".into()); // non-interactive: auto-proceed
            if let Some(id) = args.get("id").and_then(Value::as_u64) {
                argv.push(id.to_string());
            }
        }
        other => return Err(format!("unknown tool: {other}")),
    }
    // Global flags every tool shares: machine-readable output, explicit path.
    argv.push("--json".into());
    argv.push("--path".into());
    argv.push(path);
    Ok(argv)
}

/// Run `getdev <argv>` as a blocking subprocess and return its stdout. On a
/// non-zero exit, `getdev`'s own stderr is surfaced as the error (findings that
/// merely trip `--fail-on` still return their JSON on stdout, so we keep stdout
/// when it is present even for a non-zero exit).
fn run_getdev(getdev_bin: &str, argv: &[String]) -> Result<String, String> {
    let output = Command::new(getdev_bin)
        .args(argv)
        .output()
        .map_err(|err| {
            format!("could not run '{getdev_bin}' (is getdev installed and on PATH? set $GETDEV_BIN to override): {err}")
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.success() || !stdout.trim().is_empty() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        Err(format!(
            "getdev exited with {} and no output. stderr: {}",
            output.status,
            stderr.trim()
        ))
    }
}

fn tool_error(message: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

/// Build a JSON-RPC success response. `id` is echoed verbatim (null for the
/// unusual case of a request that arrived without one).
fn result(id: Option<Value>, value: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "result": value })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Write one JSON-RPC message as a single line to stdout (the MCP stdio framing)
/// and flush so the client sees it immediately.
fn write_message(stdout: &mut io::Stdout, message: &Value) {
    if let Ok(line) = serde_json::to_string(message) {
        let _ = writeln!(stdout, "{line}");
        let _ = stdout.flush();
    }
}

#[cfg(test)]
mod tests {
    // The crate now inherits the workspace lints (`unwrap_used`/`expect_used =
    // "deny"`); tests are the sanctioned exception, matching every other crate's
    // test module.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn initialize_advertises_tools_capability_and_protocol() {
        let init = initialize_result();
        assert_eq!(init["protocolVersion"], PROTOCOL_VERSION);
        assert!(init["capabilities"]["tools"].is_object());
        assert_eq!(init["serverInfo"]["name"], "getdev-mcp");
    }

    #[test]
    fn every_advertised_tool_is_well_formed_and_maps_to_an_argv() {
        let tools = tools_list();
        let tools = tools.as_array().expect("tools is an array");
        assert!(tools.len() >= 7, "expected the full tool set");
        for tool in tools {
            let name = tool["name"].as_str().expect("tool has a name");
            assert!(
                tool["description"].as_str().is_some_and(|d| d.len() > 20),
                "{name} needs a real description"
            );
            assert_eq!(tool["inputSchema"]["type"], "object", "{name} schema");
            // Each advertised tool must translate to a real getdev argv.
            let argv = build_argv(name, &json!({ "path": "." })).expect("maps to argv");
            assert!(argv.contains(&"--json".to_owned()), "{name} passes --json");
            assert!(argv.contains(&"--path".to_owned()), "{name} passes --path");
        }
    }

    #[test]
    fn check_offline_flag_threads_through() {
        let argv = build_argv("getdev_check", &json!({ "offline": true })).unwrap();
        assert!(argv.contains(&"--offline".to_owned()));
        let argv = build_argv("getdev_check", &json!({})).unwrap();
        assert!(!argv.contains(&"--offline".to_owned()));
    }

    #[test]
    fn env_detect_never_writes() {
        let argv = build_argv("getdev_env_detect", &json!({})).unwrap();
        assert!(
            !argv.iter().any(|a| a == "--write"),
            "env tool must be detect-only: {argv:?}"
        );
    }

    #[test]
    fn review_defaults_to_all_but_honors_against() {
        let all = build_argv("getdev_review", &json!({})).unwrap();
        assert!(all.contains(&"--all".to_owned()));
        let against = build_argv("getdev_review", &json!({ "against": "HEAD" })).unwrap();
        assert!(against.contains(&"--against".to_owned()) && against.contains(&"HEAD".to_owned()));
        assert!(!against.contains(&"--all".to_owned()));
    }

    #[test]
    fn back_is_non_interactive_and_takes_optional_id() {
        let argv = build_argv("getdev_back", &json!({ "id": 3 })).unwrap();
        assert!(
            argv.contains(&"--quiet".to_owned()),
            "back must not block on a prompt"
        );
        assert!(argv.contains(&"3".to_owned()));
    }

    #[test]
    fn unknown_tool_is_an_error() {
        assert!(build_argv("getdev_nope", &json!({})).is_err());
    }

    #[test]
    fn notifications_get_no_reply_but_requests_do() {
        // A notification (no id) must not produce a response.
        let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(handle("getdev", &note).is_none());
        // A request (with id) for an unknown method gets a method-not-found error.
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "does/not/exist" });
        let resp = handle("getdev", &req).expect("request gets a reply");
        assert_eq!(resp["error"]["code"], -32601);
        assert_eq!(resp["id"], 1);
    }

    #[test]
    fn tools_list_request_returns_the_catalogue() {
        let req = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" });
        let resp = handle("getdev", &req).expect("reply");
        assert_eq!(resp["id"], 7);
        assert!(resp["result"]["tools"]
            .as_array()
            .is_some_and(|t| !t.is_empty()));
    }
}
