//! TS/Vite path-alias resolution (PREC-02) — the single highest-leverage
//! Seava false-positive fix.
//!
//! Resolves TypeScript `tsconfig.json` `compilerOptions.paths`/`baseUrl` and
//! Vite `resolve.alias` string entries BEFORE import classification, so an
//! aliased local import (`@/components/Foo`, `@shared/schema`) is recognized as
//! a project-local module rather than a hallucinated npm package. One
//! [`AliasResolver`] is built from the project root and consumed by BOTH the
//! `deps::classify` seam (the `real/*` checks) and the `review::orphan`
//! referenced-graph.
//!
//! ## Pure static parsing — never execution (REQ-privacy / DEC-04)
//! `tsconfig.json` is read as JSONC (a light comment/trailing-comma strip, then
//! serde_json). `vite.config.*` is parsed with the vendored JS/TS tree-sitter
//! grammar and only trivially-readable string `key: "value"` alias entries are
//! captured — a dynamically-computed alias (`path.resolve(__dirname, …)`) is
//! simply not captured, NEVER executed.
//!
//! ## Path-traversal safety (T-13-02b, mirrors `orphan::resolve_js` T-06-12)
//! A resolved alias target that escapes the project root (a leading `..` past
//! the top) is discarded — never classified Local, never touched on disk.
//!
//! ## Skip-not-fail (T-13-02a)
//! A missing/malformed tsconfig or vite config yields zero aliases, never a
//! hard error; every fallible read/parse degrades to "no aliases here".

use std::path::{Component, Path, PathBuf};

use getdev_grammars::tree_sitter::{Parser, Query, QueryCursor};
use streaming_iterator::StreamingIterator;

use crate::scan::{project_walker, read_source_capped, Lang};

use super::MANIFEST_DISCOVERY_DEPTH;

/// One alias mapping: a key that must prefix (or exactly equal) an import
/// specifier, and the project-relative target base directory/directories the
/// remainder is appended to.
#[derive(Debug, Clone)]
struct AliasEntry {
    /// The alias key with any trailing `/*` removed (`@/*` -> `@`, `@shared`
    /// -> `@shared`).
    key: String,
    /// Whether the match is a prefix/wildcard match (`@/*`, or a Vite prefix
    /// alias) rather than an exact-key match.
    wildcard: bool,
    /// project-relative target base dir(s) (forward slashes), each already
    /// root-scoped and guaranteed not to escape the project root.
    targets: Vec<String>,
}

/// Resolves import specifiers to their aliased project-local target base(s).
/// Built once from the project root and consumed read-only.
#[derive(Debug, Default)]
pub(crate) struct AliasResolver {
    /// The project root, absolutized + lexically normalized at build time so
    /// path math is prefix-strippable even when the caller passed a relative
    /// root (`.`, the `real`/`check` CLI default).
    root: PathBuf,
    entries: Vec<AliasEntry>,
    /// project-relative `baseUrl` base dir (forward slashes), for bare
    /// non-alias specifiers under a `baseUrl`-only tsconfig (D-04d).
    base_urls: Vec<String>,
}

impl AliasResolver {
    /// Build the resolver for `root`: discover + parse every `tsconfig*.json`
    /// and `vite.config.*` under `root` (bounded depth, `node_modules`/dot-dir
    /// exclusions), deterministically. Every fallible step is skip-not-fail.
    pub(crate) fn build(root: &Path) -> Self {
        let abs_root = absolutize(root);
        let mut entries = Vec::new();
        let mut base_urls = Vec::new();

        for tsconfig in discover_config_files(&abs_root, is_tsconfig_name) {
            parse_tsconfig(&abs_root, &tsconfig, &mut entries, &mut base_urls);
        }
        for vite in discover_config_files(&abs_root, is_vite_config_name) {
            parse_vite_config(&abs_root, &vite, &mut entries);
        }

        // Deterministic order regardless of walk order.
        entries.sort_by(|a, b| {
            b.key
                .len()
                .cmp(&a.key.len())
                .then_with(|| a.key.cmp(&b.key))
                .then_with(|| a.targets.cmp(&b.targets))
        });
        entries
            .dedup_by(|a, b| a.key == b.key && a.wildcard == b.wildcard && a.targets == b.targets);
        base_urls.sort();
        base_urls.dedup();

        Self {
            root: abs_root,
            entries,
            base_urls,
        }
    }

    /// Whether `specifier` matches any declared alias or `baseUrl` base and
    /// resolves to a plausible project-local target. A specifier that matches
    /// no alias (a genuine bare npm import) returns `false` — recall preserved.
    pub(crate) fn resolves(&self, specifier: &str) -> bool {
        !self.referenced_bases(specifier).is_empty()
    }

    /// Every project-relative target base `specifier` resolves to (empty when
    /// it matches no alias / `baseUrl`, or every candidate escapes the root).
    /// Longest-key-first: the first matching alias entry wins, mirroring
    /// TypeScript's most-specific-path semantics.
    pub(crate) fn referenced_bases(&self, specifier: &str) -> Vec<String> {
        let root = self.root.as_path();
        for entry in &self.entries {
            if let Some(remainder) = match_key(entry, specifier) {
                let mut bases = Vec::new();
                for target in &entry.targets {
                    if let Some(base) = join_and_scope(root, target, remainder) {
                        bases.push(base);
                    }
                }
                if !bases.is_empty() {
                    return bases;
                }
            }
        }
        // baseUrl bare-specifier resolution (D-04d): a bare `components/Foo`
        // under `baseUrl: "./src"`. Only bare, non-relative, non-scoped-alias
        // specifiers reach here; the alias entries above already had first
        // refusal.
        if !specifier.starts_with('.') {
            let mut bases = Vec::new();
            for base_url in &self.base_urls {
                if let Some(base) = join_and_scope(root, base_url, specifier) {
                    // Only treat as a baseUrl-local module if it plausibly
                    // targets a project file/dir — a bare npm import
                    // (`react`) must NOT be swallowed here.
                    if probe_local_target(root, &base) {
                        bases.push(base);
                    }
                }
            }
            return bases;
        }
        Vec::new()
    }
}

/// Absolutize `root` against the current working directory when relative
/// (WITHOUT `std::fs::canonicalize` — no symlink resolution, no existence
/// requirement), then lexically normalize, so `strip_prefix(root)` is reliable
/// even for a `.` root (the `real`/`check` CLI default).
fn absolutize(root: &Path) -> PathBuf {
    let joined = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| root.to_path_buf(), |cwd| cwd.join(root))
    };
    lexical_normalize(&joined)
}

/// Match `specifier` against one alias entry, returning the wildcard remainder
/// (`""` for an exact / bare-prefix match) when it matches, else `None`.
fn match_key<'a>(entry: &AliasEntry, specifier: &'a str) -> Option<&'a str> {
    if entry.wildcard {
        if specifier == entry.key {
            return Some("");
        }
        let with_sep = format!("{}/", entry.key);
        specifier.strip_prefix(&with_sep)
    } else if specifier == entry.key {
        Some("")
    } else {
        None
    }
}

/// Join a target base + wildcard remainder against `root`, lexically normalize,
/// and return the project-relative base (forward slashes). Returns `None` if
/// the result escapes the project root (T-13-02b).
fn join_and_scope(root: &Path, target: &str, remainder: &str) -> Option<String> {
    let mut rel = target.to_owned();
    if !remainder.is_empty() {
        if !rel.is_empty() && !rel.ends_with('/') {
            rel.push('/');
        }
        rel.push_str(remainder);
    }
    let joined = root.join(&rel);
    let normalized = lexical_normalize(&joined);
    let stripped = normalized.strip_prefix(root).ok()?;
    let display = stripped.to_string_lossy().replace('\\', "/");
    Some(display.trim_end_matches('/').to_owned())
}

/// Lexically resolve `.`/`..` components WITHOUT touching disk (so an escaping
/// target is caught before any filesystem access). Symlinks are not resolved —
/// this is a purely textual normalization.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// JS/TS module-resolution suffixes probed to decide whether a resolved base
/// plausibly targets a real project file/dir.
const PROBE_FILE_SUFFIXES: &[&str] = &[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".d.ts"];
const PROBE_INDEX_SUFFIXES: &[&str] = &[
    "/index.ts",
    "/index.tsx",
    "/index.js",
    "/index.jsx",
    "/index.mjs",
    "/index.cjs",
];

/// Whether a project-relative base plausibly targets a real project file or
/// directory (used only for the `baseUrl` bare-specifier path, where a false
/// Local would swallow a genuine bare npm import).
fn probe_local_target(root: &Path, base: &str) -> bool {
    let abs = root.join(base);
    if abs.is_dir() {
        return true;
    }
    for suffix in PROBE_FILE_SUFFIXES {
        if root.join(format!("{base}{suffix}")).is_file() {
            return true;
        }
    }
    for suffix in PROBE_INDEX_SUFFIXES {
        if root.join(format!("{base}{suffix}")).is_file() {
            return true;
        }
    }
    abs.is_file()
}

fn is_tsconfig_name(name: &str) -> bool {
    name == "tsconfig.json" || (name.starts_with("tsconfig.") && name.ends_with(".json"))
}

fn is_vite_config_name(name: &str) -> bool {
    matches!(
        name,
        "vite.config.ts"
            | "vite.config.js"
            | "vite.config.mjs"
            | "vite.config.cjs"
            | "vite.config.mts"
            | "vite.config.cts"
    )
}

/// Discover config files matching `pred` under `root`, bounded to
/// [`MANIFEST_DISCOVERY_DEPTH`] and reusing [`project_walker`]'s
/// `node_modules`/dot-dir exclusions. Deterministically sorted.
fn discover_config_files(root: &Path, pred: fn(&str) -> bool) -> Vec<PathBuf> {
    let mut builder = project_walker(root);
    builder.max_depth(Some(MANIFEST_DISCOVERY_DEPTH));
    let mut found: Vec<PathBuf> = builder
        .build()
        .flatten()
        .filter(|entry| entry.file_type().is_some_and(|t| t.is_file()))
        .filter(|entry| entry.file_name().to_str().is_some_and(pred))
        .map(ignore::DirEntry::into_path)
        .collect();
    found.sort();
    found
}

// ---------------------------------------------------------------------
// tsconfig.json (JSONC)
// ---------------------------------------------------------------------

fn parse_tsconfig(
    root: &Path,
    tsconfig: &Path,
    entries: &mut Vec<AliasEntry>,
    base_urls: &mut Vec<String>,
) {
    let Ok(raw) = std::fs::read_to_string(tsconfig) else {
        return;
    };
    let stripped = strip_jsonc(&raw);
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&stripped) else {
        return;
    };
    let Some(compiler_options) = value.get("compilerOptions") else {
        return;
    };
    let config_dir = tsconfig.parent().unwrap_or(root);

    // The base `paths` are resolved against: `baseUrl` when present, else the
    // tsconfig directory (TS >= 4.1 allows `paths` with no `baseUrl`).
    let base_url_field = compiler_options
        .get("baseUrl")
        .and_then(serde_json::Value::as_str);
    let paths_base_dir = match base_url_field {
        Some(base_url) => config_dir.join(base_url),
        None => config_dir.to_path_buf(),
    };

    // baseUrl itself, for bare-specifier resolution.
    if let Some(base_url) = base_url_field {
        let abs = lexical_normalize(&config_dir.join(base_url));
        if let Ok(stripped) = abs.strip_prefix(root) {
            base_urls.push(stripped.to_string_lossy().replace('\\', "/"));
        }
    }

    let Some(paths) = compiler_options.get("paths").and_then(|p| p.as_object()) else {
        return;
    };
    for (key, targets) in paths {
        let Some(target_list) = targets.as_array() else {
            continue;
        };
        let wildcard = key.ends_with("/*") || key.ends_with('*');
        let clean_key = key.trim_end_matches('*').trim_end_matches('/').to_owned();
        let mut target_bases = Vec::new();
        for target in target_list {
            let Some(target_str) = target.as_str() else {
                continue;
            };
            let clean_target = target_str.trim_end_matches('*').trim_end_matches('/');
            let abs = lexical_normalize(&paths_base_dir.join(clean_target));
            if let Ok(stripped) = abs.strip_prefix(root) {
                target_bases.push(stripped.to_string_lossy().replace('\\', "/"));
            }
        }
        if !clean_key.is_empty() && !target_bases.is_empty() {
            entries.push(AliasEntry {
                key: clean_key,
                wildcard,
                targets: target_bases,
            });
        }
    }
}

/// Strip `//` line comments, `/* */` block comments, and trailing commas from a
/// JSONC document, respecting string literals (so a `//` inside a string
/// survives). No new dependency (D-01) — a light in-house pre-strip.
fn strip_jsonc(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            out.push(b as char);
            if b == b'\\' && i + 1 < bytes.len() {
                // preserve the escaped char verbatim
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => {
                in_string = true;
                out.push('"');
                i += 1;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                // line comment — skip to end of line
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                // block comment — skip to closing */
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            _ => {
                // Non-ASCII bytes are pushed as-is via char reconstruction: the
                // scanner only special-cases ASCII structural bytes, so it is
                // safe to copy the raw byte through for multi-byte UTF-8.
                out.push(b as char);
                i += 1;
            }
        }
    }
    strip_trailing_commas(&out)
}

/// Remove trailing commas before `}`/`]` (respecting strings). Runs after
/// comment stripping so a comma before a comment-then-brace is also handled.
fn strip_trailing_commas(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            out.push(b);
            if b == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1]);
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            out.push(b);
            i += 1;
            continue;
        }
        if b == b',' {
            // look ahead past whitespace for a closing bracket
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b'}' || bytes[j] == b']') {
                // drop the comma, keep the whitespace
                i += 1;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_owned())
}

// ---------------------------------------------------------------------
// vite.config.* (tree-sitter, string entries only)
// ---------------------------------------------------------------------

/// Query for `key: (object)` pairs — candidate `alias` objects. Key text is
/// checked in Rust (property_identifier or quoted string).
const ALIAS_OBJECT_QUERY: &str = "\
    (pair key: (property_identifier) @key value: (object) @obj)\n\
    (pair key: (string) @key value: (object) @obj)";

fn parse_vite_config(root: &Path, vite: &Path, entries: &mut Vec<AliasEntry>) {
    let Some(lang) = Lang::from_path(vite) else {
        return;
    };
    if !matches!(lang, Lang::JavaScript | Lang::TypeScript) {
        return;
    }
    let Ok(source) = read_source_capped(vite) else {
        return;
    };
    let language = lang.language();
    let mut parser = Parser::new();
    if parser.set_language(&language).is_err() {
        return;
    }
    let Some(tree) = parser.parse(&source, None) else {
        return;
    };
    let Ok(query) = Query::new(&language, ALIAS_OBJECT_QUERY) else {
        return;
    };
    let bytes = source.as_bytes();
    let key_idx = query.capture_index_for_name("key");
    let obj_idx = query.capture_index_for_name("obj");

    let config_dir = vite.parent().unwrap_or(root);
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), bytes);
    while let Some(m) = matches.next() {
        let mut key_text = None;
        let mut obj_node = None;
        for capture in m.captures {
            if Some(capture.index) == key_idx {
                key_text = capture.node.utf8_text(bytes).ok().map(strip_key);
            } else if Some(capture.index) == obj_idx {
                obj_node = Some(capture.node);
            }
        }
        let (Some(key_text), Some(obj_node)) = (key_text, obj_node) else {
            continue;
        };
        if key_text != "alias" {
            continue;
        }
        // Walk the alias object's `pair` children, capturing string:string
        // entries only (a computed value node is skipped — never executed).
        let mut child_cursor = obj_node.walk();
        for pair in obj_node.named_children(&mut child_cursor) {
            if pair.kind() != "pair" {
                continue;
            }
            let Some(key_node) = pair.child_by_field_name("key") else {
                continue;
            };
            let Some(value_node) = pair.child_by_field_name("value") else {
                continue;
            };
            if value_node.kind() != "string" {
                continue; // computed/dynamic — not captured, never executed
            }
            let Ok(raw_key) = key_node.utf8_text(bytes) else {
                continue;
            };
            let Ok(raw_value) = value_node.utf8_text(bytes) else {
                continue;
            };
            let alias_key = strip_key(raw_key);
            let Some(target) = strip_js_string(raw_value) else {
                continue;
            };
            if alias_key.is_empty() || target.is_empty() {
                continue;
            }
            let wildcard = alias_key.ends_with('*') || alias_key.ends_with("/*");
            let clean_key = alias_key
                .trim_end_matches('*')
                .trim_end_matches('/')
                .to_owned();
            let clean_target = target.trim_end_matches('*').trim_end_matches('/');
            let abs = lexical_normalize(&config_dir.join(clean_target));
            let Ok(stripped) = abs.strip_prefix(root) else {
                continue;
            };
            if clean_key.is_empty() {
                continue;
            }
            entries.push(AliasEntry {
                // Vite aliases are prefix matches, so a non-`*` key still
                // matches `<key>/<rest>`.
                key: clean_key,
                wildcard: true.max(wildcard),
                targets: vec![stripped.to_string_lossy().replace('\\', "/")],
            });
        }
    }
}

/// Strip quotes from a `property_identifier` (returned as-is) or a `string` key
/// node's source text.
fn strip_key(raw: &str) -> String {
    strip_js_string(raw).unwrap_or_else(|| raw.to_owned())
}

fn strip_js_string(raw: &str) -> Option<String> {
    for quote in ['"', '\'', '`'] {
        if raw.len() >= 2 && raw.starts_with(quote) && raw.ends_with(quote) {
            return Some(raw[1..raw.len() - 1].to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-aliases-test-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn tsconfig_paths_resolve() {
        let dir = tempdir("tsconfig-paths");
        std::fs::write(
            dir.join("tsconfig.json"),
            r#"{ "compilerOptions": { "paths": { "@/*": ["./src/*"] } } }"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src/components")).unwrap();
        std::fs::write(
            dir.join("src/components/Foo.tsx"),
            "export const Foo = 1;\n",
        )
        .unwrap();

        let resolver = AliasResolver::build(&dir);
        let bases = resolver.referenced_bases("@/components/Foo");
        assert!(
            bases.contains(&"src/components/Foo".to_owned()),
            "got {bases:?}"
        );
        assert!(resolver.resolves("@/components/Foo"));
    }

    #[test]
    fn baseurl_resolve() {
        let dir = tempdir("baseurl");
        std::fs::write(
            dir.join("tsconfig.json"),
            r#"{ "compilerOptions": { "baseUrl": "./src" } }"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src/components")).unwrap();
        std::fs::write(dir.join("src/components/Foo.ts"), "export const Foo = 1;\n").unwrap();

        let resolver = AliasResolver::build(&dir);
        assert!(
            resolver.resolves("components/Foo"),
            "baseUrl bare specifier should resolve Local"
        );
        // a genuine bare npm import under baseUrl must NOT be swallowed
        assert!(!resolver.resolves("react"));
    }

    #[test]
    fn vite_alias_resolve() {
        let dir = tempdir("vite-alias");
        std::fs::create_dir_all(dir.join("app")).unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/schema.ts"), "export const schema = 1;\n").unwrap();
        std::fs::write(
            dir.join("app/vite.config.ts"),
            "export default { resolve: { alias: { \"@shared\": \"../src\" } } };\n",
        )
        .unwrap();

        let resolver = AliasResolver::build(&dir);
        let bases = resolver.referenced_bases("@shared/schema");
        assert!(bases.contains(&"src/schema".to_owned()), "got {bases:?}");
    }

    #[test]
    fn jsonc_tolerance() {
        let dir = tempdir("jsonc");
        std::fs::write(
            dir.join("tsconfig.json"),
            "{\n\
             // leading comment\n\
             \"compilerOptions\": {\n\
               /* block */ \"paths\": { \"@/*\": [\"./src/*\"], },\n\
             },\n\
             }\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/x.ts"), "export const x = 1;\n").unwrap();

        let resolver = AliasResolver::build(&dir);
        assert!(
            resolver.resolves("@/x"),
            "JSONC comments + trailing comma must still parse"
        );
    }

    #[test]
    fn root_escape_discarded() {
        let dir = tempdir("root-escape");
        std::fs::write(
            dir.join("tsconfig.json"),
            r#"{ "compilerOptions": { "paths": { "@/*": ["../../*"] } } }"#,
        )
        .unwrap();

        let resolver = AliasResolver::build(&dir);
        assert!(
            resolver.referenced_bases("@/x").is_empty(),
            "an alias target escaping the project root must be discarded (T-13-02b)"
        );
        assert!(!resolver.resolves("@/x"));
    }

    #[test]
    fn missing_config_is_noop() {
        let dir = tempdir("missing-config");
        std::fs::write(dir.join("app.ts"), "export const x = 1;\n").unwrap();

        let resolver = AliasResolver::build(&dir);
        assert!(resolver.referenced_bases("@/anything").is_empty());
        assert!(!resolver.resolves("@/anything"));
    }

    #[test]
    fn non_alias_bare_pkg_still_unresolved() {
        let dir = tempdir("bare-pkg");
        std::fs::write(
            dir.join("tsconfig.json"),
            r#"{ "compilerOptions": { "paths": { "@/*": ["./src/*"] } } }"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();

        let resolver = AliasResolver::build(&dir);
        // a genuine undeclared bare npm import matches no alias → unresolved,
        // so classify() will still reach Phantom (recall preserved).
        assert!(!resolver.resolves("totally-fake-pkg"));
        assert!(!resolver.resolves("react"));
    }

    #[test]
    fn malformed_tsconfig_is_noop() {
        let dir = tempdir("malformed");
        std::fs::write(dir.join("tsconfig.json"), "{ this is not json at all ").unwrap();

        let resolver = AliasResolver::build(&dir);
        assert!(!resolver.resolves("@/x"), "malformed config → no aliases");
    }

    #[test]
    fn strip_jsonc_preserves_urls_in_strings() {
        // a `//` inside a string value must survive the comment strip
        let stripped = strip_jsonc(r#"{ "url": "https://example.com", }"#);
        assert!(stripped.contains("https://example.com"));
        let value: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(value["url"], "https://example.com");
    }
}
