# getdev

> Verify, secure, and ship AI-generated code. One binary, runs locally, nothing leaves your machine.

**getdev is not a Python package.** It's a native CLI (written in Rust); this PyPI package
exists only to reserve the name defensively — AI coding agents and their users frequently
guess `pip install <tool>`, and that name shouldn't be claimable by an attacker. (Package
hallucination is literally one of the failure modes getdev detects.)

Install the real tool:

```bash
curl -fsSL https://getdev.ai/install.sh | sh
# or: brew install pzelenin/tap/getdev · npx getdev · cargo install getdev
```

- Site: https://getdev.ai
- Source (Apache-2.0): https://github.com/pzelenin/getdev-cli
