//! File walking + tree-sitter parsing.
//!
//! P0 spike scope: walk a directory (gitignore-aware), parse JS/TS/TSX/Python,
//! and run one query per file (function definitions). The full `ScanContext`
//! (parse-once, analyzers as read-only visitors) grows out of this module.

use std::fmt;
use std::path::{Path, PathBuf};

use getdev_grammars::tree_sitter::{Language, Parser, Query, QueryCursor};
use ignore::WalkBuilder;
use streaming_iterator::StreamingIterator;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lang {
    JavaScript,
    TypeScript,
    Tsx,
    Python,
}

impl Lang {
    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()? {
            "js" | "jsx" | "mjs" | "cjs" => Some(Self::JavaScript),
            "ts" | "mts" | "cts" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            "py" => Some(Self::Python),
            _ => None,
        }
    }

    fn language(self) -> Language {
        match self {
            Self::JavaScript => getdev_grammars::javascript(),
            Self::TypeScript => getdev_grammars::typescript(),
            Self::Tsx => getdev_grammars::tsx(),
            Self::Python => getdev_grammars::python(),
        }
    }

    /// The P0 spike query: every kind of function definition.
    fn function_query(self) -> &'static str {
        match self {
            Self::JavaScript | Self::TypeScript | Self::Tsx => {
                "(function_declaration) @fn\n\
                 (function_expression) @fn\n\
                 (arrow_function) @fn\n\
                 (method_definition) @fn"
            }
            Self::Python => "(function_definition) @fn",
        }
    }
}

impl fmt::Display for Lang {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
            Self::Python => "python",
        };
        f.write_str(name)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("grammar rejected by tree-sitter runtime (version mismatch): {0}")]
    Grammar(#[from] getdev_grammars::tree_sitter::LanguageError),
    #[error("invalid tree-sitter query: {0}")]
    Query(#[from] getdev_grammars::tree_sitter::QueryError),
    #[error("parser returned no tree for {path}")]
    Parse { path: PathBuf },
}

/// Per-file result of the spike scan.
#[derive(Debug)]
pub struct FileScan {
    pub path: PathBuf,
    pub lang: Lang,
    pub functions: usize,
    /// tree-sitter recovered from syntax errors somewhere in the file
    pub has_syntax_errors: bool,
}

/// Walk `root` (honoring .gitignore) and parse every supported source file,
/// counting function definitions via one tree-sitter query per language.
///
/// Unreadable files are skipped and reported in the second return value
/// rather than failing the whole scan — a hostile or half-broken repo must
/// never abort getdev.
pub fn scan_path(root: &Path) -> Result<(Vec<FileScan>, Vec<ScanError>), ScanError> {
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
        match scan_file(path, lang) {
            Ok(scan) => results.push(scan),
            // grammar/query errors are programming bugs — fail loudly;
            // per-file read/parse trouble is expected in the wild — skip
            Err(err @ (ScanError::Grammar(_) | ScanError::Query(_))) => return Err(err),
            Err(err) => skipped.push(err),
        }
    }

    Ok((results, skipped))
}

fn scan_file(path: &Path, lang: Lang) -> Result<FileScan, ScanError> {
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

    let query = Query::new(&language, lang.function_query())?;
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
    let mut functions = 0;
    while matches.next().is_some() {
        functions += 1;
    }

    Ok(FileScan {
        path: path.to_path_buf(),
        lang,
        functions,
        has_syntax_errors: tree.root_node().has_error(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn detects_language_from_extension() {
        assert_eq!(Lang::from_path(Path::new("a/b.py")), Some(Lang::Python));
        assert_eq!(Lang::from_path(Path::new("x.mjs")), Some(Lang::JavaScript));
        assert_eq!(Lang::from_path(Path::new("x.tsx")), Some(Lang::Tsx));
        assert_eq!(Lang::from_path(Path::new("x.rs")), None);
        assert_eq!(Lang::from_path(Path::new("Makefile")), None);
    }

    #[test]
    fn counts_functions_per_language() {
        let dir = tempdir();
        std::fs::write(
            dir.join("a.py"),
            "def one():\n    pass\n\ndef two():\n    pass\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("b.js"),
            "function one() {}\nconst two = () => {};\n",
        )
        .unwrap();

        let (scans, skipped) = scan_path(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(scans.len(), 2);
        let total: usize = scans.iter().map(|s| s.functions).sum();
        assert_eq!(total, 4);
    }

    #[test]
    fn broken_syntax_is_flagged_not_fatal() {
        let dir = tempdir();
        std::fs::write(dir.join("broken.py"), "def oops(:\n").unwrap();

        let (scans, _) = scan_path(&dir).unwrap();
        assert_eq!(scans.len(), 1);
        assert!(scans[0].has_syntax_errors);
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-scan-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
