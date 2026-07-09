#![forbid(unsafe_code)]
//! getdev engine: scan (walker + tree-sitter parsing), the unified findings
//! schema, project config, and report renderers. Rules, mutate, and the full
//! ScanContext land in later phases per docs/PLAN.md.

pub mod config;
pub mod findings;
pub mod report;
pub mod scan;
