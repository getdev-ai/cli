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

impl ScanError {
    /// The file this error is about, when there is one (`Grammar`/`Query`
    /// are crate-wide, not per-file). F4 audit fix: lets callers surface a
    /// `{ path, reason }` pair in `--json` skip-lists instead of only a
    /// pre-formatted display string.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Read { path, .. } | Self::Parse { path } | Self::TooLarge { path } => Some(path),
            Self::Skipped { path, .. } => Some(path),
            Self::Grammar(_) | Self::Query(_) => None,
        }
    }
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
///
/// W5 (05-REVIEW.md): this list is now restricted to UNAMBIGUOUS
/// artifact/vendor names only. Previously it also pruned the bare names
/// `env`, `venv`, `build`, and `dist` at any depth — a silent
/// false-negative for a security scanner, since a legitimate first-party
/// source dir such as `src/env/config.ts` was skipped whole and any
/// hardcoded secret in it shipped while getdev reported "clean". Those four
/// names are handled differently now:
///   * `env`/`venv` — a real Python virtualenv is detected STRUCTURALLY by
///     its `pyvenv.cfg` marker (see [`is_not_excluded_dir`]), so it is
///     pruned whatever it is named, without pruning same-named source dirs.
///   * `build`/`dist` — no longer pruned by bare name at all. Scanning
///     bundled/generated output is desirable for a security scanner: it is
///     exactly where `audit/api-key-in-client-bundle` finds a provider key
///     that was inlined into the shipped client bundle. The trade-off is
///     that a finding may surface both in source and in its build output;
///     that duplication is accepted to avoid the false-negative of a secret
///     that only appears in the built artifact.
const EXCLUDED_DIR_NAMES: &[&str] = &[
    "node_modules",
    ".venv",
    "site-packages",
    "__pycache__",
    ".git",
    "target",
];

/// Marker file that unambiguously identifies the root of a Python virtual
/// environment (PEP 405). Its mere presence in a directory means that
/// directory is a venv regardless of what it is named (`env`, `venv`,
/// `.env`, or anything custom), so it is pruned structurally rather than by
/// name (W5).
const VENV_MARKER: &str = "pyvenv.cfg";

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

/// `WalkBuilder::filter_entry` predicate backing [`project_walker`]. Prunes
/// directories either by exact name match against [`EXCLUDED_DIR_NAMES`] or
/// structurally when they are a Python virtualenv (they contain a
/// [`VENV_MARKER`]); files are never filtered here (extension filtering
/// happens at each call site).
///
/// W5: the bias is deliberately toward NOT pruning. Anything not clearly a
/// vendor/artifact tree is walked, because for a security scanner a silently
/// skipped first-party source file is the worst outcome. The `pyvenv.cfg`
/// stat below never errors into a prune: `Path::is_file` returns `false` on
/// any I/O error, so an unreadable directory is scanned, not skipped.
fn is_not_excluded_dir(entry: &ignore::DirEntry) -> bool {
    if entry.file_type().is_some_and(|t| t.is_dir()) {
        if let Some(name) = entry.file_name().to_str() {
            if EXCLUDED_DIR_NAMES.contains(&name) {
                return false;
            }
        }
        // Structural virtualenv detection (W5): a `pyvenv.cfg` marker at the
        // directory root means this is a Python venv whatever its name, so
        // prune it — this replaces the old bare-name pruning of `env`/`venv`
        // that also swallowed legitimate `src/env/...` source.
        if entry.path().join(VENV_MARKER).is_file() {
            return false;
        }
    }
    true
}

/// Read a source file's contents, enforcing the [`MAX_SCAN_FILE_BYTES`] cap
/// (F7) before ever allocating a buffer for it. Every parse-eligible read in
/// this crate goes through this function rather than a bare
/// `std::fs::read_to_string`.
pub fn read_source_capped(path: &Path) -> Result<String, ScanError> {
    use std::io::Read;
    let metadata = std::fs::metadata(path).map_err(|source| ScanError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    // Refuse anything that isn't a regular file. A FIFO / device / a symlink to
    // one reports a bogus small `len()`, so a metadata-only cap can be defeated:
    // `read_to_string` would then read unbounded (OOM) or block forever (hang).
    if !metadata.is_file() {
        return Err(ScanError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    // Bound the READ ITSELF (`take`), not just the metadata pre-check: a file
    // that grows after the stat must not slurp past the cap. Read cap+1 so an
    // exactly-at-cap file is accepted and one byte over is rejected.
    let mut buf = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| {
            f.take(MAX_SCAN_FILE_BYTES.saturating_add(1))
                .read_to_end(&mut buf)
        })
        .map_err(|source| ScanError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if buf.len() as u64 > MAX_SCAN_FILE_BYTES {
        return Err(ScanError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    String::from_utf8(buf).map_err(|err| ScanError::Read {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, err.utf8_error()),
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

/// The single source-file walk every collector in this crate builds on
/// (IN-05): apply [`project_walker`], keep only regular files with a
/// supported extension, and invoke `visit(path, lang)` for each. Extracting
/// it means the prune/skip semantics (which dirs are excluded, which entries
/// count as files) can never drift between `scan_path` and
/// `collect_string_assignments`. `visit` may return `Err(E)` to abort the
/// whole walk early (used to fail loudly on grammar/query bugs); a normal
/// per-file skip is handled inside `visit` and returns `Ok(())`.
fn for_each_source_file<E>(
    root: &Path,
    mut visit: impl FnMut(&Path, Lang) -> Result<(), E>,
) -> Result<(), E> {
    for entry in project_walker(root).build().flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        let Some(lang) = Lang::from_path(path) else {
            continue;
        };
        visit(path, lang)?;
    }
    Ok(())
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

    for_each_source_file(root, |path, lang| {
        match scan_file(path, lang) {
            Ok(scan) => results.push(scan),
            // grammar/query errors are programming bugs — fail loudly;
            // per-file read/parse trouble is expected in the wild — skip
            Err(err @ (ScanError::Grammar(_) | ScanError::Query(_))) => return Err(err),
            Err(err) => skipped.push(err),
        }
        Ok(())
    })?;

    Ok((results, skipped))
}

/// A string literal assigned to a named identifier or object key.
///
/// `value` stays `pub` (an API break here would ripple through every caller
/// that reads matched literals — models.rs, env.rs — for no correctness
/// gain), but `Debug` is hand-rolled to redact it (C6/03-REVIEW.md): this
/// type flows every string literal in a scanned project through it,
/// including ones that later turn out to be secrets, before `env::classify`
/// has had a chance to judge them. A derived `Debug`/`dbg!` would print the
/// raw literal.
#[derive(Clone)]
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

impl fmt::Debug for StringAssignment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StringAssignment")
            .field("path", &self.path)
            .field("lang", &self.lang)
            .field("name", &self.name)
            .field("value", &"«redacted»")
            .field("line", &self.line)
            .field("column", &self.column)
            .field("value_span", &self.value_span)
            .finish()
    }
}

/// Walk `root` and collect every `name = "literal"` shape in supported
/// languages. Same skip semantics as [`scan_path`].
pub fn collect_string_assignments(
    root: &Path,
) -> Result<(Vec<StringAssignment>, Vec<ScanError>), ScanError> {
    let mut results = Vec::new();
    let mut skipped = Vec::new();

    for_each_source_file(root, |path, lang| {
        match assignments_in_file(path, lang) {
            Ok(mut found) => results.append(&mut found),
            Err(err @ (ScanError::Grammar(_) | ScanError::Query(_))) => return Err(err),
            Err(err) => skipped.push(err),
        }
        Ok(())
    })?;

    Ok((results, skipped))
}

/// Project-relative display path with forward slashes — the same convention
/// as `audit`/`env`/`apisurface`'s own `relative_display`. Copied locally
/// rather than imported because each of those is crate-private to its own
/// module; keeping the one-liner here avoids widening any of their scopes.
fn relative_display(path: &Path, root: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.to_string_lossy().replace('\\', "/")
}

/// A single project source file, walked and parsed EXACTLY ONCE by
/// [`ScanContext::build`], caching everything a downstream read-only analyzer
/// needs to run a tree-sitter query without a second parse (CLAUDE.md rule 5):
/// its project-relative path, absolute path, language, source text, and parsed
/// `Tree`.
///
/// `source` may contain secrets (this type flows every scanned file, including
/// ones `env::classify` later flags), so `Debug` is hand-rolled to redact it —
/// a derived `Debug` would print the raw file contents (CLAUDE.md rule 4,
/// mirrors [`StringAssignment`]'s redaction).
pub struct ScannedFile {
    /// project-relative display path (forward slashes), same convention as
    /// `audit::relative_display`
    pub rel: PathBuf,
    /// absolute on-disk path, as yielded by the walker
    pub abs: PathBuf,
    pub lang: Lang,
    /// full file contents (already size-capped by [`read_source_capped`])
    pub source: String,
    /// the one-and-only parse of this file for this invocation
    pub tree: getdev_grammars::tree_sitter::Tree,
}

impl fmt::Debug for ScannedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScannedFile")
            .field("rel", &self.rel)
            .field("abs", &self.abs)
            .field("lang", &self.lang)
            .field("source", &"«redacted»")
            .field("tree", &self.tree)
            .finish()
    }
}

/// A parse-once shared context: walks the project tree EXACTLY ONCE (via the
/// same [`project_walker`] every analyzer uses today) and parses every
/// eligible JS/TS/TSX/Python source file EXACTLY ONCE, caching the result in
/// [`ScannedFile`]s. This is the single walk/parse code path the `check`
/// analyzers consume as read-only visitors — the difference between one shared
/// scan pass and the 4-5× redundant walk+parse a naive aggregate would incur
/// (Phase 7 Success Criterion 1; docs/PLAN.md "Full ScanContext sharing").
///
/// Skip-not-fail: an unreadable/oversized/unparseable single file is collected
/// into [`Self::skipped`] with the SAME [`ScanError`] variant the standalone
/// collectors produce — it never aborts the build. Only a fatal engine
/// condition (grammar/query mismatch — a programming bug) returns `Err`, byte
/// for byte the same policy as [`scan_path`]/[`collect_string_assignments`].
#[derive(Debug)]
pub struct ScanContext {
    pub root: PathBuf,
    pub files: Vec<ScannedFile>,
    pub skipped: Vec<ScanError>,
}

impl ScanContext {
    /// Walk `root` once and parse every eligible source file once. See the
    /// type docs for the skip-vs-fail contract.
    ///
    /// # Errors
    /// Returns a [`ScanError::Grammar`]/[`ScanError::Query`] only for a fatal
    /// engine condition (grammar version mismatch / malformed built-in query);
    /// a per-file read/parse failure is folded into [`Self::skipped`] instead.
    pub fn build(root: &Path) -> Result<Self, ScanError> {
        let mut files = Vec::new();
        let mut skipped = Vec::new();

        // Same walker, same eligibility gate, same read/parse idiom as
        // `scan_path`/`audit::run` — absorbed here ONCE so no analyzer repeats
        // it and the file set can never silently drift between them (Pitfall 1).
        for_each_source_file(root, |path, lang| {
            match parse_source_file(path, lang) {
                Ok((source, tree)) => files.push(ScannedFile {
                    rel: PathBuf::from(relative_display(path, root)),
                    abs: path.to_path_buf(),
                    lang,
                    source,
                    tree,
                }),
                // grammar/query errors are programming bugs — fail loudly;
                // per-file read/parse trouble is expected in the wild — skip.
                Err(err @ (ScanError::Grammar(_) | ScanError::Query(_))) => return Err(err),
                Err(err) => skipped.push(err),
            }
            Ok(())
        })?;

        Ok(Self {
            root: root.to_path_buf(),
            files,
            skipped,
        })
    }
}

/// Read + parse one eligible source file into `(source, Tree)`, using the same
/// capped reader and per-language parser setup as [`scan_file`] /
/// [`assignments_in_file`] / `audit::process_lang_file`. Every fallible step
/// maps to the existing [`ScanError`] variant so the caller can fold it into a
/// skip list unchanged.
fn parse_source_file(
    path: &Path,
    lang: Lang,
) -> Result<(String, getdev_grammars::tree_sitter::Tree), ScanError> {
    let source = read_source_capped(path)?;
    let language = lang.language();
    let mut parser = Parser::new();
    parser.set_language(&language)?;
    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| ScanError::Parse {
            path: path.to_path_buf(),
        })?;
    Ok((source, tree))
}

/// Compile-time proof that `tree_sitter::Tree` is `Send`. `check` runs its
/// analyzers sequentially over one `&ScanContext` (no threading is introduced
/// this phase), but any future cross-thread reuse of a cached `Tree` depends on
/// this property — so it is pinned at build time here, before it can ever be
/// relied on. If the grammar crate's `Tree` were ever not `Send`, the whole
/// crate fails to compile rather than miscompiling a later parallel consumer.
const fn assert_send<T: Send>() {}
const _: () = assert_send::<getdev_grammars::tree_sitter::Tree>();

/// Parse `path` and extract its string assignments. This is a convenience
/// wrapper that owns its own `Parser::parse` — do NOT call it on a hot path
/// where the same file has already been parsed (e.g. alongside
/// [`scan_file`]), or that file would be parsed twice per invocation,
/// violating the parse-once invariant (CLAUDE.md rule 5). A caller that
/// already holds a `Tree` must reuse [`string_assignments_from_tree`]
/// instead; the parse-once seam is regression-pinned by
/// `tree_reuse_matches_fresh_parse` (IN-06).
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

    string_assignments_from_tree(&tree, &source, lang, path)
}

/// The extraction half of [`assignments_in_file`], split out so a caller
/// that has ALREADY parsed a file (e.g. `core::audit`'s own per-file
/// AST-matcher loop, 04-02) can reuse this against its own `Tree` instead of
/// parsing the file a second time for secret detection — CLAUDE.md rule 5 /
/// 04-RESEARCH.md Pitfall 7: a file is parsed once per invocation, never
/// once per analysis purpose.
pub(crate) fn string_assignments_from_tree(
    tree: &getdev_grammars::tree_sitter::Tree,
    source: &str,
    lang: Lang,
    path: &Path,
) -> Result<Vec<StringAssignment>, ScanError> {
    let query = Query::new(&lang.language(), lang.string_assignment_query())?;
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

/// Collect every `name = "literal"` shape across a [`ScanContext`] WITHOUT a
/// second walk or a second parse: for each already-parsed [`ScannedFile`] it
/// reruns the string-assignment query against the cached `Tree` via
/// [`string_assignments_from_tree`]. This is the single-pass replacement for
/// [`collect_string_assignments`]'s walk that `check`'s env-detect + real
/// model matcher consume (wired in 07-04); the standalone
/// `collect_string_assignments(root)` stays for the standalone `env`/`real`
/// commands.
///
/// Returns a plain `Vec` (no `Result`): the only fallible step in
/// [`string_assignments_from_tree`] is building the fixed built-in query, a
/// programming bug already proven impossible for every supported language by
/// the in-crate query tests — a per-file query failure here is folded away
/// rather than aborting collection over an otherwise-valid context.
pub fn string_assignments_from_context(ctx: &ScanContext) -> Vec<StringAssignment> {
    let mut results = Vec::new();
    for file in &ctx.files {
        if let Ok(mut found) =
            string_assignments_from_tree(&file.tree, &file.source, file.lang, &file.abs)
        {
            results.append(&mut found);
        }
    }
    results
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

    /// C6 regression: `{:?}` on a `StringAssignment` must never print the
    /// raw `value` field, even though it stays `pub` for API stability.
    #[test]
    fn string_assignment_debug_redacts_value() {
        let assignment = StringAssignment {
            path: PathBuf::from("a.js"),
            lang: Lang::JavaScript,
            name: "stripeKey".to_owned(),
            value: "sk_live_FAKEFAKEFAKE1234".to_owned(),
            line: 1,
            column: 1,
            value_span: (0, 10),
        };
        let debug_output = format!("{assignment:?}");
        assert!(!debug_output.contains("sk_live_FAKEFAKEFAKE1234"));
        assert!(debug_output.contains("«redacted»"));
    }

    /// IN-06 regression: the parse-once seam. A caller that has ALREADY
    /// parsed a file must be able to extract string assignments from that one
    /// `Tree` via `string_assignments_from_tree`, with a result identical to
    /// the parsing wrapper `assignments_in_file` — proving a single cached
    /// parse is sufficient and no consumer needs a second parse of the same
    /// file (CLAUDE.md rule 5).
    #[test]
    fn tree_reuse_matches_fresh_parse() {
        let dir = unique_tempdir("parse_once");
        let src = "const apiKey = \"sk_live_abc\";\nfunction f() {}\n";
        let path = dir.join("t.js");
        std::fs::write(&path, src).unwrap();

        // reuse an externally-parsed tree — no re-read, no re-parse
        let mut parser = Parser::new();
        parser.set_language(&Lang::JavaScript.language()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let reused = string_assignments_from_tree(&tree, src, Lang::JavaScript, &path).unwrap();

        // the parsing wrapper (its own parse) must agree exactly
        let fresh = assignments_in_file(&path, Lang::JavaScript).unwrap();

        assert_eq!(reused.len(), 1, "one string assignment expected");
        assert_eq!(reused.len(), fresh.len());
        assert_eq!(reused[0].name, "apiKey");
        assert_eq!(reused[0].name, fresh[0].name);
        assert_eq!(reused[0].value, fresh[0].value);
        assert_eq!(reused[0].value_span, fresh[0].value_span);
    }

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

    /// A7 belt-and-braces: the unambiguous vendor/artifact trees
    /// (`.venv`/`site-packages`/`__pycache__`) are pruned by name at any
    /// depth, whether or not `.gitignore` would already have caught them.
    #[test]
    fn project_walker_excludes_python_vendor_dirs() {
        let dir = unique_tempdir("vendor_dirs");
        for vendor in [".venv", "site-packages", "__pycache__"] {
            std::fs::create_dir_all(dir.join(vendor)).unwrap();
            std::fs::write(dir.join(vendor).join("vendored.py"), "def x(): pass\n").unwrap();
        }
        std::fs::write(dir.join("app.py"), "def first_party(): pass\n").unwrap();

        let (scans, skipped) = scan_path(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].path, dir.join("app.py"));
    }

    /// W5 regression: a legitimate first-party source directory that merely
    /// happens to be named `env` (e.g. `src/env/config.ts`) must NOT be
    /// pruned. The old bare-name pruning of `env`/`venv` silently skipped
    /// real source, so a hardcoded secret in it shipped while getdev reported
    /// a clean scan — the worst outcome for a security scanner.
    #[test]
    fn project_walker_scans_first_party_env_dir() {
        let dir = unique_tempdir("w5_first_party_env");
        std::fs::create_dir_all(dir.join("src/env")).unwrap();
        std::fs::write(
            dir.join("src/env/leak.ts"),
            "const KEY = \"sk_live_leak\";\nfunction f() {}\n",
        )
        .unwrap();

        let (scans, skipped) = scan_path(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(
            scans.len(),
            1,
            "a first-party `env` source dir must be scanned, not pruned"
        );
        assert_eq!(scans[0].path, dir.join("src/env/leak.ts"));
    }

    /// W5: a real Python virtualenv is detected STRUCTURALLY by its
    /// `pyvenv.cfg` marker, so it is still pruned whatever it is named —
    /// `venv`, `env`, or anything custom — even though those bare names are
    /// no longer on the exclusion list.
    #[test]
    fn project_walker_prunes_structural_virtualenv() {
        let dir = unique_tempdir("w5_structural_venv");
        for venv_name in ["venv", "env", "my_custom_venv"] {
            let venv = dir.join(venv_name);
            std::fs::create_dir_all(venv.join("lib")).unwrap();
            std::fs::write(venv.join("pyvenv.cfg"), "home = /usr/bin\n").unwrap();
            std::fs::write(venv.join("lib/vendored.py"), "def x(): pass\n").unwrap();
        }
        std::fs::write(dir.join("app.py"), "def first_party(): pass\n").unwrap();

        let (scans, skipped) = scan_path(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(
            scans.len(),
            1,
            "dirs carrying a pyvenv.cfg marker must be pruned as virtualenvs"
        );
        assert_eq!(scans[0].path, dir.join("app.py"));
    }

    /// W5: `build`/`dist` are no longer pruned by bare name — scanning
    /// bundled/generated output is desirable (that is exactly what
    /// `audit/api-key-in-client-bundle` targets: a provider key inlined into
    /// the shipped client bundle).
    #[test]
    fn project_walker_scans_build_and_dist_output() {
        let dir = unique_tempdir("w5_build_dist");
        for out in ["build", "dist"] {
            std::fs::create_dir_all(dir.join(out)).unwrap();
            std::fs::write(dir.join(out).join("bundle.js"), "function b() {}\n").unwrap();
        }
        std::fs::write(dir.join("app.js"), "function a() {}\n").unwrap();

        let (scans, skipped) = scan_path(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(
            scans.len(),
            3,
            "build/ and dist/ output must be scanned, not pruned by name"
        );
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

    /// F7 hardening (commit-review: cap-defeat via non-regular file): a
    /// metadata-only size check is defeated by a FIFO/device — it reports a
    /// bogus small `len()` yet reads unbounded. `read_source_capped` must
    /// refuse a non-regular file rather than slurp it.
    #[test]
    #[cfg(unix)]
    fn non_regular_file_is_refused() {
        let err = read_source_capped(Path::new("/dev/null")).unwrap_err();
        assert!(matches!(err, ScanError::TooLarge { .. }));
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

    /// A per-test-name unique, freshly-cleared tempdir — needed by the W5
    /// tests, several of which assert an exact scan count and so must not
    /// inherit leftover files from a sibling test that reused the same
    /// thread-keyed [`tempdir`].
    fn unique_tempdir(name: &str) -> PathBuf {
        let dir = tempdir().join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
