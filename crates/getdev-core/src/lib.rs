#![forbid(unsafe_code)]
//! getdev engine: scan (walker + tree-sitter parsing), the unified findings
//! schema, project config, and report renderers. Rules, mutate, and the full
//! ScanContext land in later phases per docs/PLAN.md.

pub mod apisurface;
pub mod audit;
pub mod config;
pub mod deps;
pub mod env;
pub mod findings;
pub mod frameworks;
pub mod models;
pub mod mutate;
pub mod real;
pub mod report;
pub mod review;
pub mod rules;
pub mod scan;
pub mod secrets;
pub mod suppress;
