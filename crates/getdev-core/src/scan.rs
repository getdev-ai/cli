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
    /// for secret detection (`env`, later `audit`) and the model-string
    /// matcher (`real`, A12). Template strings and f-strings are
    /// deliberately excluded: interpolated values are not literal secrets.
    ///
    /// Two extra shapes beyond a plain assignment (A12, 03-REVIEW.md):
    /// object-literal keys given as a STRING (`{"model": "x"}`, not just
    /// the bare-identifier `{model: "x"}` already covered by `pair key:
    /// (property_identifier)`), and Python `keyword_argument`s
    /// (`client.messages.create(model="...")`) — the canonical
    /// Anthropic/OpenAI SDK call shape, previously invisible to this query
    /// because it only matched top-level `name = value` assignments.
    fn string_assignment_query(self) -> &'static str {
        match self {
            Self::JavaScript | Self::TypeScript | Self::Tsx => {
                "(variable_declarator name: (identifier) @name value: (string) @value)\n\
                 (assignment_expression left: (identifier) @name right: (string) @value)\n\
                 (pair key: (property_identifier) @name value: (string) @value)\n\
                 (pair key: (string) @name value: (string) @value)"
            }
            Self::Python => {
                "(assignment left: (identifier) @name right: (string) @value)\n\
                 (keyword_argument name: (identifier) @name value: (string) @value)"
            }
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
    /// F7 — files above [`MAX_SCAN_FILE_BYTES`] are never read into memory.
    #[error("skipped {path}: exceeds {MAX_SCAN_FILE_BYTES} byte scan cap")]
    TooLarge { path: PathBuf },
    /// Generic non-fatal skip, used by callers outside this module (e.g.
    /// `deps::build_graph`, A10) that need to fold a recoverable error
    /// (malformed manifest, etc.) into the same skip-reporting channel as
    /// scan errors, without inventing a second reporting type end-to-end.
    #[error("skipped {path}: {reason}")]
    Skipped { path: PathBuf, reason: String },
}

/// F7 — hard cap on the size of a single file this crate will read into
/// memory for parsing. A multi-GB minified bundle or vendored binary must
/// never be slurped whole just because it happens to carry a supported
/// extension.
pub const MAX_SCAN_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Directory names excluded from every project walk (A7): installed/vendored
/// dependency trees and VCS/build metadata a static analyzer must never
/// treat as first-party project source. Applied via `filter_entry` so
/// `ignore` never even descends into them, belt-and-braces alongside
/// `.gitignore` handling (which is skipped entirely on non-git trees without
/// this).
const EXCLUDED_DIR_NAMES: &[&str] = &[
    "node_modules",
    ".venv",
    "venv",
    "env",
    "site-packages",
    "__pycache__",
    ".git",
    "dist",
    "build",
    "target",
];

/// The single walker constructor every project-source walk in this crate
/// must build on (A7): `.gitignore` is honored even outside a git repo
/// (`require_git(false)`), the user's global `~/.gitignore` never leaks into
/// results (`git_global(false)`), and the excluded directories above are
/// hard-pruned regardless of `.gitignore` state. `hidden(true)` (skip
/// dotfiles/dot-directories) is kept at its `ignore` crate default — a
/// deliberate, documented decision, not an oversight (03-REVIEW.md A7).
pub fn project_walker(root: &Path) -> WalkBuilder {
    let mut builder = WalkBuilder::new(root);
    builder
        .require_git(false)
        .git_global(false)
        .filter_entry(is_not_excluded_dir);
    builder
}

/// `WalkBuilder::filter_entry` predicate backing [`project_walker`]. Only
/// ever prunes directories by exact name match; files are never filtered
/// here (extension filtering happens at each call site).
fn is_not_excluded_dir(entry: &ignore::DirEntry) -> bool {
    if entry.file_type().is_some_and(|t| t.is_dir()) {
        if let Some(name) = entry.file_name().to_str() {
            return !EXCLUDED_DIR_NAMES.contains(&name);
        }
    }
    true
}

/// Read a source file's contents, enforcing the [`MAX_SCAN_FILE_BYTES`] cap
/// (F7) before ever allocating a buffer for it. Every parse-eligible read in
/// this crate goes through this function rather than a bare
/// `std::fs::read_to_string`.
pub fn read_source_capped(path: &Path) -> Result<String, ScanError> {
    let metadata = std::fs::metadata(path).map_err(|source| ScanError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > MAX_SCAN_FILE_BYTES {
        return Err(ScanError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    std::fs::read_to_string(path).map_err(|source| ScanError::Read {
        path: path.to_path_buf(),
        source,
    })
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

    for entry in project_walker(root).build().flatten() {
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

    for entry in project_walker(root).build().flatten() {
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
    let source = read_source_capped(path)?;

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
        let mut name_node = None;
        let mut value_node = None;
        for capture in m.captures {
            if Some(capture.index) == name_idx {
                name_node = Some(capture.node);
            } else if Some(capture.index) == value_idx {
                value_node = Some(capture.node);
            }
        }
        let (Some(name_node), Some(node)) = (name_node, value_node) else {
            continue;
        };
        let Ok(raw_name) = name_node.utf8_text(source.as_bytes()) else {
            continue;
        };
        // A12: a `@name` capture is either a bare identifier/property name
        // (`model`) or, for the string-keyed object-pair shape
        // (`{"model": "x"}`), a quoted string node — strip its delimiters
        // the same way the value literal is stripped.
        let name = if name_node.kind() == "string" {
            let Some(stripped) = strip_string_delimiters(raw_name, lang) else {
                continue;
            };
            stripped
        } else {
            raw_name.to_owned()
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
            name,
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
    let source = read_source_capped(path)?;

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

    /// A7 regression: a bare `WalkBuilder` only honors `.gitignore` inside a
    /// git repository, so on a fresh clone/tempdir with no `.git` a
    /// `node_modules` tree was walked and parsed in full. This tempdir is
    /// deliberately never `git init`-ed.
    #[test]
    fn project_walker_excludes_node_modules_outside_a_git_repo() {
        let dir = tempdir();
        std::fs::create_dir_all(dir.join("node_modules/some-pkg")).unwrap();
        std::fs::write(
            dir.join("node_modules/some-pkg/index.js"),
            "function vendored() {}\n",
        )
        .unwrap();
        std::fs::write(dir.join("app.js"), "function first_party() {}\n").unwrap();

        let (scans, skipped) = scan_path(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(
            scans.len(),
            1,
            "node_modules must be pruned even without a .git directory present"
        );
        assert_eq!(scans[0].path, dir.join("app.js"));
    }

    /// A7 belt-and-braces: the same exclusion set covers Python's venv/
    /// site-packages/__pycache__ trees, and applies uniformly whether or not
    /// `.gitignore` would already have caught them.
    #[test]
    fn project_walker_excludes_python_vendor_dirs() {
        let dir = tempdir();
        for vendor in [".venv", "venv", "env", "site-packages", "__pycache__"] {
            std::fs::create_dir_all(dir.join(vendor)).unwrap();
            std::fs::write(dir.join(vendor).join("vendored.py"), "def x(): pass\n").unwrap();
        }
        std::fs::write(dir.join("app.py"), "def first_party(): pass\n").unwrap();

        let (scans, skipped) = scan_path(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].path, dir.join("app.py"));
    }

    /// F7: a file over the scan cap is skipped with a reason, never read
    /// into memory.
    #[test]
    fn oversized_file_is_skipped_not_read() {
        let dir = tempdir();
        // one byte over the cap
        let oversized = "x".repeat(usize::try_from(MAX_SCAN_FILE_BYTES).unwrap() + 1);
        std::fs::write(dir.join("huge.js"), format!("// {oversized}\n")).unwrap();
        std::fs::write(dir.join("small.js"), "function ok() {}\n").unwrap();

        let (scans, skipped) = scan_path(&dir).unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].path, dir.join("small.js"));
        assert_eq!(skipped.len(), 1);
        assert!(matches!(skipped[0], ScanError::TooLarge { .. }));
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
