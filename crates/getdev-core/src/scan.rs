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

    pub fn language(self) -> Language {
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

    /// Query for `identifier = "string literal"` shapes — the raw material
    /// for secret detection (`env`, later `audit`). Template strings and
    /// f-strings are deliberately excluded: interpolated values are not
    /// literal secrets.
    fn string_assignment_query(self) -> &'static str {
        match self {
            Self::JavaScript | Self::TypeScript | Self::Tsx => {
                "(variable_declarator name: (identifier) @name value: (string) @value)\n\
                 (assignment_expression left: (identifier) @name right: (string) @value)\n\
                 (pair key: (property_identifier) @name value: (string) @value)"
            }
            Self::Python => "(assignment left: (identifier) @name right: (string) @value)",
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

/// A string literal assigned to a named identifier or object key.
#[derive(Debug, Clone)]
pub struct StringAssignment {
    pub path: PathBuf,
    pub lang: Lang,
    /// the identifier / property name the literal is assigned to
    pub name: String,
    /// literal contents with quotes (and Python string prefixes) stripped
    pub value: String,
    /// 1-based position of the literal
    pub line: u32,
    pub column: u32,
    /// byte span of the whole literal node (incl. quotes) — used by the
    /// rewrite engine to replace the literal with an env accessor
    pub value_span: (usize, usize),
}

/// Walk `root` and collect every `name = "literal"` shape in supported
/// languages. Same skip semantics as [`scan_path`].
pub fn collect_string_assignments(
    root: &Path,
) -> Result<(Vec<StringAssignment>, Vec<ScanError>), ScanError> {
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
        match assignments_in_file(path, lang) {
            Ok(mut found) => results.append(&mut found),
            Err(err @ (ScanError::Grammar(_) | ScanError::Query(_))) => return Err(err),
            Err(err) => skipped.push(err),
        }
    }

    Ok((results, skipped))
}

fn assignments_in_file(path: &Path, lang: Lang) -> Result<Vec<StringAssignment>, ScanError> {
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

    let query = Query::new(&language, lang.string_assignment_query())?;
    let name_idx = query.capture_index_for_name("name");
    let value_idx = query.capture_index_for_name("value");

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
    let mut results = Vec::new();

    while let Some(m) = matches.next() {
        let mut name = None;
        let mut value_node = None;
        for capture in m.captures {
            if Some(capture.index) == name_idx {
                name = capture.node.utf8_text(source.as_bytes()).ok();
            } else if Some(capture.index) == value_idx {
                value_node = Some(capture.node);
            }
        }
        let (Some(name), Some(node)) = (name, value_node) else {
            continue;
        };
        let Ok(raw) = node.utf8_text(source.as_bytes()) else {
            continue;
        };
        let Some(value) = strip_string_delimiters(raw, lang) else {
            continue; // interpolated / prefixed strings are not literals
        };
        if value.is_empty() {
            continue;
        }
        let pos = node.start_position();
        results.push(StringAssignment {
            path: path.to_path_buf(),
            lang,
            name: name.to_owned(),
            value,
            line: u32::try_from(pos.row).unwrap_or(u32::MAX).saturating_add(1),
            column: u32::try_from(pos.column)
                .unwrap_or(u32::MAX)
                .saturating_add(1),
            value_span: (node.start_byte(), node.end_byte()),
        });
    }

    Ok(results)
}

/// Strip quotes (and Python prefixes) from a string literal's source text.
/// Returns None for strings we must not treat as plain literals (f-strings,
/// byte strings, raw prefixes with interpolation semantics).
fn strip_string_delimiters(raw: &str, lang: Lang) -> Option<String> {
    let mut s = raw;
    if lang == Lang::Python {
        // reject f/b prefixes (interpolation / bytes); allow r/u
        let prefix_len = s.chars().take_while(|c| c.is_ascii_alphabetic()).count();
        let prefix = s[..prefix_len].to_lowercase();
        if prefix.contains('f') || prefix.contains('b') {
            return None;
        }
        s = &s[prefix_len..];
    }
    for quote in ["\"\"\"", "'''", "\"", "'"] {
        if s.len() >= quote.len() * 2 && s.starts_with(quote) && s.ends_with(quote) {
            return Some(s[quote.len()..s.len() - quote.len()].to_owned());
        }
    }
    None
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
