//! Python `import`/`from ... import` extraction (tree-sitter query) and the
//! embedded Python stdlib module dataset.
//!
//! Same parse-once, skip-not-fail walker contract as
//! `deps::imports_js::collect_imports`.

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use getdev_grammars::tree_sitter::{Parser, Query, QueryCursor};
use serde::Deserialize;
use streaming_iterator::StreamingIterator;

use crate::scan::{project_walker, read_source_capped, Lang, ScanError};

use super::{relative_display, DepsError, RawImport};

const EMBEDDED_PYTHON_STDLIB: &str = include_str!("../../../../rules/real/python-stdlib.json");
const EMBEDDED_PY_IMPORT_ALIASES: &str =
    include_str!("../../../../rules/real/py-import-aliases.json");

#[derive(Debug, Deserialize)]
struct ModuleListFile {
    #[allow(dead_code)]
    version: u32,
    modules: Vec<String>,
}

pub fn python_stdlib() -> Result<HashSet<String>, DepsError> {
    let file: ModuleListFile =
        serde_json::from_str(EMBEDDED_PYTHON_STDLIB).map_err(|source| DepsError::Json {
            path: PathBuf::from("rules/real/python-stdlib.json"),
            source,
        })?;
    Ok(file.modules.into_iter().collect())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportAliasFile {
    #[allow(dead_code)]
    version: u32,
    #[allow(dead_code)]
    source: String,
    aliases: HashMap<String, Vec<String>>,
}

/// The embedded PyPI import-name -> distribution-name alias dataset (A5):
/// `import yaml` declares as `pyyaml`, `import PIL` declares as `pillow`,
/// etc. Values are lists — `psycopg2` accepts either the `psycopg2` or
/// `psycopg2-binary` distribution — never a single string, so callers never
/// need a separate multi-value special case.
pub fn python_import_aliases() -> Result<HashMap<String, Vec<String>>, DepsError> {
    let file: ImportAliasFile =
        serde_json::from_str(EMBEDDED_PY_IMPORT_ALIASES).map_err(|source| DepsError::Json {
            path: PathBuf::from("rules/real/py-import-aliases.json"),
            source,
        })?;
    Ok(file.aliases)
}

/// Per-language import query, mirroring `scan.rs`'s `string_assignment_query`
/// shape. Only ever invoked for `Python` — the walker filters by extension
/// first, so the JS/TS/TSX arm is never reached.
///
/// `relative_import` (`from . import x` / `from ..pkg import y`) is captured
/// separately from `dotted_name` (Pattern 5) since it is a distinct grammar
/// node — always local, never a registry lookup.
fn import_query(lang: Lang) -> &'static str {
    match lang {
        Lang::Python => {
            "(import_statement name: (dotted_name) @module)\n\
             (import_statement name: (aliased_import name: (dotted_name) @module))\n\
             (import_from_statement module_name: (dotted_name) @module)\n\
             (import_from_statement module_name: (relative_import) @relative)"
        }
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => "",
    }
}

/// Walk `root` and collect every Python `import`/`from` module reference.
/// Same skip semantics as [`crate::scan::collect_string_assignments`].
pub fn collect_imports(root: &Path) -> Result<(Vec<RawImport>, Vec<ScanError>), ScanError> {
    let mut results = Vec::new();
    let mut skipped = Vec::new();

    for entry in project_walker(root).build().flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        let Some(lang) = Lang::from_path(path) else {
            continue;
        };
        if lang != Lang::Python {
            continue;
        }
        match imports_in_file(path, root) {
            Ok(mut found) => results.append(&mut found),
            Err(err @ (ScanError::Grammar(_) | ScanError::Query(_))) => return Err(err),
            Err(err) => skipped.push(err),
        }
    }

    Ok((results, skipped))
}

fn imports_in_file(path: &Path, root: &Path) -> Result<Vec<RawImport>, ScanError> {
    let source = read_source_capped(path)?;

    let language = Lang::Python.language();
    let mut parser = Parser::new();
    parser.set_language(&language)?;
    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| ScanError::Parse {
            path: path.to_path_buf(),
        })?;

    let query = Query::new(&language, import_query(Lang::Python))?;
    let module_idx = query.capture_index_for_name("module");
    let relative_idx = query.capture_index_for_name("relative");

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
    let mut results = Vec::new();

    while let Some(m) = matches.next() {
        for capture in m.captures {
            let Ok(raw) = capture.node.utf8_text(source.as_bytes()) else {
                continue;
            };
            let pos = capture.node.start_position();
            let line = u32::try_from(pos.row).unwrap_or(u32::MAX).saturating_add(1);
            let file = relative_display(path, root);

            if Some(capture.index) == module_idx {
                let module = bare_py_module(raw);
                if module.is_empty() {
                    continue;
                }
                results.push(RawImport {
                    module,
                    is_relative: false,
                    file,
                    line,
                });
            } else if Some(capture.index) == relative_idx {
                results.push(RawImport {
                    module: raw.to_owned(),
                    is_relative: true,
                    file,
                    line,
                });
            }
        }
    }

    Ok(results)
}

/// `os.path` -> `os`.
fn bare_py_module(spec: &str) -> String {
    spec.split('.').next().unwrap_or(spec).to_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn embedded_python_import_aliases_load() {
        let aliases = python_import_aliases().unwrap();
        assert_eq!(
            aliases.get("yaml").map(Vec::as_slice),
            Some(["pyyaml".to_owned()].as_slice())
        );
        assert_eq!(
            aliases.get("PIL").map(Vec::as_slice),
            Some(["pillow".to_owned()].as_slice())
        );
        let psycopg2 = aliases.get("psycopg2").unwrap();
        assert!(psycopg2.contains(&"psycopg2".to_owned()));
        assert!(psycopg2.contains(&"psycopg2-binary".to_owned()));
    }

    #[test]
    fn embedded_python_stdlib_loads() {
        let stdlib = python_stdlib().unwrap();
        assert!(stdlib.contains("os"));
        assert!(stdlib.contains("json"));
        assert!(stdlib.contains("typing"));
    }

    #[test]
    fn bare_py_module_strips_dotted_suffix() {
        assert_eq!(bare_py_module("os.path"), "os");
        assert_eq!(bare_py_module("os"), "os");
    }

    #[test]
    fn collects_absolute_and_relative_imports() {
        let dir = std::env::temp_dir().join(format!(
            "getdev-imports-py-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("a.py"),
            "import os\n\
             import os.path as osp\n\
             from json import loads\n\
             from . import helpers\n\
             from ..pkg import thing\n",
        )
        .unwrap();

        let (imports, skipped) = collect_imports(&dir).unwrap();
        assert!(skipped.is_empty());

        let absolute: Vec<&str> = imports
            .iter()
            .filter(|i| !i.is_relative)
            .map(|i| i.module.as_str())
            .collect();
        assert!(absolute.contains(&"os"));
        assert!(absolute.contains(&"json"));

        let relative_count = imports.iter().filter(|i| i.is_relative).count();
        assert_eq!(relative_count, 2);
    }
}
