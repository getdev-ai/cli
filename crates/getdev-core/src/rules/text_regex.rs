//! The non-AST "text-regex" matcher: a whole-file regex evaluated over
//! capped file bytes, no tree-sitter grammar involved (04-RESEARCH.md
//! Architecture Pattern 4). Backs matcher entries shaped `{file_glob,
//! text_pattern}` — for config files with no supported tree-sitter grammar
//! (e.g. Firebase's `.rules` DSL / `database.rules.json`).

use std::path::Path;

use globset::{Glob, GlobMatcher};
use regex::Regex;

use super::RuleLoadError;

/// A compiled `{file_glob, text_pattern}` matcher: `file_glob` selects
/// which files this matcher even looks at, `pattern` is the whole-file
/// regex run over that file's raw bytes.
#[derive(Debug)]
pub struct CompiledTextMatcher {
    file_glob: GlobMatcher,
    pattern: Regex,
}

impl CompiledTextMatcher {
    /// Compile a `{file_glob, text_pattern}` matcher entry. A malformed
    /// glob is `RuleLoadError::BadGlob`; a malformed regex is
    /// `RuleLoadError::BadRegex` — both typed, never a panic.
    pub fn compile(
        rule_id: &str,
        origin: &str,
        file_glob: &str,
        text_pattern: &str,
    ) -> Result<Self, RuleLoadError> {
        let glob = Glob::new(file_glob)
            .map_err(|source| RuleLoadError::BadGlob {
                origin: origin.to_owned(),
                rule_id: rule_id.to_owned(),
                source,
            })?
            .compile_matcher();
        let pattern = Regex::new(text_pattern).map_err(|source| RuleLoadError::BadRegex {
            origin: origin.to_owned(),
            rule_id: rule_id.to_owned(),
            source,
        })?;
        Ok(Self {
            file_glob: glob,
            pattern,
        })
    }

    /// `true` if `path` matches this matcher's `file_glob` AND `bytes`
    /// (decoded as UTF-8) matches `text_pattern`. `bytes` MUST already have
    /// been read via `scan::read_source_capped` — this matcher type does
    /// not bypass the 5 MiB per-file DoS cap (F7) just because it skips
    /// parsing. Non-UTF8 content never matches and never panics.
    #[must_use]
    pub fn is_match(&self, path: &Path, bytes: &[u8]) -> bool {
        if !self.file_glob.is_match(path) {
            return false;
        }
        std::str::from_utf8(bytes)
            .map(|text| self.pattern.is_match(text))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn matches_only_globbed_files_with_pattern_present() {
        let matcher = CompiledTextMatcher::compile(
            "audit/firebase-open-rules",
            "test",
            "**/*.rules",
            r"allow\s+read.*if\s+true",
        )
        .unwrap();
        assert!(matcher.is_match(
            Path::new("firestore.rules"),
            b"service cloud.firestore { match /{doc=**} { allow read: if true; } }"
        ));
        // right content, wrong path (glob doesn't match)
        assert!(!matcher.is_match(Path::new("firestore.txt"), b"allow read: if true;"));
        // right path, content doesn't match the pattern
        assert!(!matcher.is_match(Path::new("firestore.rules"), b"allow read: if isAuthed();"));
    }

    /// Task 2 behavior: an invalid regex is `BadRegex`.
    #[test]
    fn invalid_regex_is_bad_regex() {
        let err = CompiledTextMatcher::compile("audit/x", "test", "*.rules", "[").unwrap_err();
        assert!(matches!(err, RuleLoadError::BadRegex { .. }));
    }

    /// Task 2 behavior: an invalid glob is `BadGlob`.
    #[test]
    fn invalid_glob_is_bad_glob() {
        let err = CompiledTextMatcher::compile("audit/x", "test", "[", "x").unwrap_err();
        assert!(matches!(err, RuleLoadError::BadGlob { .. }));
    }

    /// Task 2 behavior: non-UTF8 file bytes never panic, just never match.
    #[test]
    fn non_utf8_bytes_never_panic_never_match() {
        let matcher = CompiledTextMatcher::compile("audit/x", "test", "*.rules", "true").unwrap();
        let invalid_utf8 = [0xFF, 0xFE, 0xFD];
        assert!(!matcher.is_match(Path::new("a.rules"), &invalid_utf8));
    }
}
