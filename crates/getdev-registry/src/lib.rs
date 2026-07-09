//! npm and PyPI registry clients with a local SQLite cache.
//!
//! This is the ONLY crate in the workspace permitted to make network calls
//! (blocking `reqwest` + `rustls`; permitted destinations: npm registry, PyPI).
//! Scaffold only — implemented in phase P2 (`getdev real`).
