//! JS/TS/TSX import & `require()` extraction (tree-sitter query) and the
//! embedded Node.js builtin-module dataset.
//!
//! Mirrors `scan::collect_string_assignments`'s parse-once, skip-not-fail
//! walker (docs/ARCHITECTURE.md invariant): grammar/query errors are
//! programming bugs and propagate; per-file read/parse trouble is expected
//! in the wild and is collected instead of aborting the walk. This is a
//! dedicated walk (not a reuse of `env`'s walk) since `real` extracts a
//! different query over the same files.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use getdev_grammars::tree_sitter::{Parser, Query, QueryCursor};
use ignore::WalkBuilder;
use serde::Deserialize;
use streaming_iterator::StreamingIterator;

use crate::scan::{Lang, ScanError};

use super::{relative_display, DepsError, RawImport};

const EMBEDDED_NODE_BUILTINS: &str = include_str!("../../../../rules/real/node-builtins.json");

#[derive(Debug, Deserialize)]
struct ModuleListFile {
    #[allow(dead_code)]
    version: u32,
    modules: Vec<String>,
}

/// The embedded Node.js builtin module list — both bare (`fs`) and
/// `node:`-prefixed (`node:fs`) forms are present in the dataset itself
/// (Pitfall 7), so no prefix-stripping logic is needed at match time.
pub fn node_builtins() -> Result<HashSet<String>, DepsError> {
    let file: ModuleListFile =
        serde_json::from_str(EMBEDDED_NODE_BUILTINS).map_err(|source| DepsError::Json {
            path: PathBuf::from("rules/real/node-builtins.json"),
            source,
        })?;
    Ok(file.modules.into_iter().collect())
}

/// Per-language import query, mirroring `scan.rs`'s `string_assignment_query`
/// shape. Only ever invoked for `JavaScript`/`TypeScript`/`Tsx` — the walker
/// filters by extension first, so the `Python` arm is never reached.
fn import_query(lang: Lang) -> &'static str {
    match lang {
        Lang::JavaScript => {
            "(import_statement source: (string) @source)\n\
             (call_expression\n\
                 function: (identifier) @fn (#eq? @fn \"require\")\n\
                 arguments: (arguments (string) @source))"
        }
        Lang::TypeScript | Lang::Tsx => {
            "(import_statement source: (string) @source)\n\
             (import_require_clause source: (string) @source)\n\
             (call_expression\n\
                 function: (identifier) @fn (#eq? @fn \"require\")\n\
                 arguments: (arguments (string) @source))"
        }
        Lang::Python => "",
    }
}

/// Walk `root` and collect every JS/TS/TSX `import`/`require` specifier.
/// Same skip semantics as [`crate::scan::collect_string_assignments`].
pub fn collect_imports(root: &Path) -> Result<(Vec<RawImport>, Vec<ScanError>), ScanError> {
    let mut results = Vec::new();
    let mut skipped = Vec::new();

    for entry in WalkBuilder::new(root).build().flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        let Some(lang) = Lang::from_path(path) else {
            continue;
        };
        if !matches!(lang, Lang::JavaScript | Lang::TypeScript | Lang::Tsx) {
            continue;
        }
        match imports_in_file(path, lang, root) {
            Ok(mut found) => results.append(&mut found),
            Err(err @ (ScanError::Grammar(_) | ScanError::Query(_))) => return Err(err),
            Err(err) => skipped.push(err),
        }
    }

    Ok((results, skipped))
}

fn imports_in_file(path: &Path, lang: Lang, root: &Path) -> Result<Vec<RawImport>, ScanError> {
    let source = std::fs::read_to_string(path).map_err(|source| ScanError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    let language = lang.language();
    let mut parser = Parser::new();
    parser.set_language(&language)?;
    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| ScanError::Parse {
            path: path.to_path_buf(),
        })?;

    let query = Query::new(&language, import_query(lang))?;
    let source_idx = query.capture_index_for_name("source");

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
    let mut results = Vec::new();

    while let Some(m) = matches.next() {
        for capture in m.captures {
            if Some(capture.index) != source_idx {
                continue;
            }
            let Ok(raw) = capture.node.utf8_text(source.as_bytes()) else {
                continue;
            };
            let Some(spec) = strip_js_string(raw) else {
                continue;
            };
            if spec.is_empty() {
                continue;
            }
            let is_relative = spec.starts_with('.') || spec.starts_with('/');
            let module = if is_relative {
                spec.clone()
            } else {
                bare_js_module(&spec)
            };
            let pos = capture.node.start_position();
            results.push(RawImport {
                module,
                is_relative,
                file: relative_display(path, root),
                line: u32::try_from(pos.row).unwrap_or(u32::MAX).saturating_add(1),
            });
        }
    }

    Ok(results)
}

fn strip_js_string(raw: &str) -> Option<String> {
    for quote in ['"', '\''] {
        if raw.len() >= 2 && raw.starts_with(quote) && raw.ends_with(quote) {
            return Some(raw[1..raw.len() - 1].to_owned());
        }
    }
    None
}

/// `lodash/fp` -> `lodash`; `@scope/name/sub` -> `@scope/name`.
fn bare_js_module(spec: &str) -> String {
    if let Some(rest) = spec.strip_prefix('@') {
        let mut parts = rest.splitn(2, '/');
        let scope = parts.next().unwrap_or("");
        let name = parts.next().and_then(|s| s.split('/').next());
        match name {
            Some(name) if !name.is_empty() => format!("@{scope}/{name}"),
            _ => format!("@{scope}"),
        }
    } else {
        spec.split('/').next().unwrap_or(spec).to_owned()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn embedded_node_builtins_load_and_contain_prefixed_forms() {
        let builtins = node_builtins().unwrap();
        assert!(builtins.contains("fs"));
        assert!(builtins.contains("node:fs"));
        assert!(builtins.contains("path"));
    }

    #[test]
    fn bare_js_module_strips_subpaths() {
        assert_eq!(bare_js_module("lodash/fp"), "lodash");
        assert_eq!(bare_js_module("lodash"), "lodash");
        assert_eq!(bare_js_module("@scope/name/sub/path"), "@scope/name");
        assert_eq!(bare_js_module("@scope/name"), "@scope/name");
    }

    #[test]
    fn collects_import_and_require_specifiers() {
        let dir = std::env::temp_dir().join(format!(
            "getdev-imports-js-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("a.js"),
            "import fs from \"node:fs\";\n\
             const path = require(\"path\");\n\
             import { helper } from \"./helper\";\n",
        )
        .unwrap();

        let (imports, skipped) = collect_imports(&dir).unwrap();
        assert!(skipped.is_empty());
        let specs: Vec<(&str, bool)> = imports
            .iter()
            .map(|i| (i.module.as_str(), i.is_relative))
            .collect();
        assert!(specs.contains(&("node:fs", false)));
        assert!(specs.contains(&("path", false)));
        assert!(specs.contains(&("./helper", true)));
    }
}
