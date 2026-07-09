<!-- Thanks for contributing! One concern per PR keeps reviews fast. -->

## What & why

<!-- What does this change, and what problem does it solve? Link the issue: Fixes #123 -->

## Type

- [ ] New/updated rule (YAML + fixtures — no Rust changes)
- [ ] Bug fix
- [ ] Feature (in-spec per docs/SPEC-COMMANDS.md — new scope needs a roadmap issue first)
- [ ] Docs
- [ ] CI / build / release engineering

## Checklist

- [ ] `cargo fmt` + `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo test --workspace` passes locally
- [ ] Commits follow conventional commits (`feat(real): …`) and are DCO signed (`git commit -s`)
- [ ] **If a rule:** ≥ 3 positive + ≥ 3 negative fixtures added and registered
- [ ] **If output changed:** `cargo insta review` done; findings still match docs/SPEC-FINDINGS.md
- [ ] **If it mutates files:** goes through `core::mutate`, gated behind `--write`/`--fix`
- [ ] No new network calls outside `getdev-registry` / updater (privacy promise)
