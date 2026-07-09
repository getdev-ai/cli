#![forbid(unsafe_code)]
//! getdev engine. Currently: the P0 scan walker (gitignore-aware file walk,
//! tree-sitter parsing, language detection). Findings, rules, mutate, report,
//! and config land in later P0/P1 work per docs/PLAN.md.

pub mod scan;
