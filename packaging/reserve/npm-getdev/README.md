# getdev

> Verify, secure, and ship AI-generated code. One binary, runs locally, nothing leaves your machine.

**This is a placeholder release reserving the package name** while the CLI is in
development. From v0.1, `npm install -g getdev` / `npx getdev` will install the native
binary (macOS/Linux/Windows) — no Rust toolchain required.

- Site: https://getdev.ai
- Source (Apache-2.0): https://github.com/getdev-ai/cli

Planned commands: `check` (Ship Score), `real` (hallucinated package/API detection),
`audit` (AI-pattern security scan), `review` (agent-debris diff analysis), `env`
(secret extraction to .env), `snap`/`back` (checkpoints), `ship` (deploy pre-flight).
