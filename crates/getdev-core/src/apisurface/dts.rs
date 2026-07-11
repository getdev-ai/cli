//! `node_modules/<pkg>` TypeScript `.d.ts`/`package.json` exports surface
//! enumeration, and JS/TS/TSX member-usage extraction from project source.
//!
//! Surface enumeration only — never full type resolution (no `tsc`, no
//! code execution; 03-RESEARCH.md "Don't Hand-Roll"). Grammar node shapes
//! below were hand-verified this session against the vendored
//! `tree-sitter-typescript` grammar (`declaration`/`source`/`value` fields
//! on `export_statement`; `export_clause`/`namespace_export` as unnamed
//! children; `.d.ts` function exports parse as `function_signature`, not
//! `function_declaration`; ambient module names live on a `module` child
//! of `ambient_declaration`).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use getdev_grammars::tree_sitter::{Node, Parser, Query, QueryCursor};
use serde::Deserialize;
use streaming_iterator::StreamingIterator;

use crate::scan::{Lang, ScanError};

use super::{relative_display, ApiSurface, SurfaceError, SurfaceTier, UsageSite};

#[derive(Debug, Default, Deserialize)]
struct PackageJsonTypes {
    types: Option<String>,
    typings: Option<String>,
}

/// Every `export_statement`/`ambient_declaration` in a file, in one query —
/// per-shape dispatch happens in Rust (the shapes vary too much for a flat
/// capture set: declaration exports, named re-exports, namespace
/// re-exports, bare `export * from`, and ambient module wildcards all need
/// different field/child inspection). Note this matches export_statement
/// nodes at *any* depth, including inside an `ambient_declaration`'s
/// `statement_block` body — which is exactly what lets a non-wildcard
/// `declare module "pkg" { export function f(): void; }` self-declaration
/// contribute its exports without any extra recursion.
const DTS_QUERY: &str = "(export_statement) @export\n(ambient_declaration) @ambient";

struct ParsedDts {
    names: BTreeSet<String>,
    star_reexports: Vec<String>,
    has_wildcard_ambient: bool,
    has_export_assign: bool,
}

/// Enumerate the exported surface of an installed `node_modules/<pkg>`
/// directory from its `.d.ts` type declarations. Never executes code —
/// pure tree-sitter parsing of files already on disk (REQ-privacy).
pub fn enumerate_js(pkg_dir: &Path) -> Result<ApiSurface, SurfaceError> {
    let Some(entry) = locate_types_entry(pkg_dir) else {
        return Ok(unreadable());
    };

    let parsed = match parse_dts_file(&entry) {
        Ok(parsed) => parsed,
        Err(
            ScanError::Read { .. }
            | ScanError::Parse { .. }
            | ScanError::TooLarge { .. }
            | ScanError::Skipped { .. },
        ) => return Ok(unreadable()),
        Err(err @ (ScanError::Grammar(_) | ScanError::Query(_))) => return Err(err.into()),
    };

    let mut exported = parsed.names;
    let mut tier = if parsed.has_wildcard_ambient || parsed.has_export_assign {
        SurfaceTier::Dynamic
    } else {
        SurfaceTier::Resolved
    };

    // Resolve exactly one level of bare `export * from './x'` (Pitfall 6).
    // Named re-exports (`export { a, b } from './y'`) need no cross-file
    // work at all — the names are already in the export_clause itself.
    for spec in &parsed.star_reexports {
        match resolve_dts_target(&entry, spec) {
            Some(target) => match parse_dts_file(&target) {
                Ok(target_parsed) => {
                    exported.extend(target_parsed.names);
                    // A second level of nesting we deliberately don't
                    // follow — a chain that goes deeper than one level is
                    // conservatively unresolved, never silently dropped.
                    if target_parsed.has_wildcard_ambient
                        || target_parsed.has_export_assign
                        || !target_parsed.star_reexports.is_empty()
                    {
                        tier = SurfaceTier::Dynamic;
                    }
                }
                Err(
                    ScanError::Read { .. }
                    | ScanError::Parse { .. }
                    | ScanError::TooLarge { .. }
                    | ScanError::Skipped { .. },
                ) => {
                    tier = SurfaceTier::Dynamic;
                }
                Err(err @ (ScanError::Grammar(_) | ScanError::Query(_))) => {
                    return Err(err.into());
                }
            },
            None => tier = SurfaceTier::Dynamic, // external/unresolvable target
        }
    }

    Ok(ApiSurface { exported, tier })
}

fn unreadable() -> ApiSurface {
    ApiSurface {
        exported: BTreeSet::new(),
        tier: SurfaceTier::Unreadable,
    }
}

/// Locate the package's type declaration entry point: `package.json`'s
/// `types`/`typings` field, else `index.d.ts`, else the first top-level
/// `.d.ts` file found (deterministic — sorted by name).
fn locate_types_entry(pkg_dir: &Path) -> Option<PathBuf> {
    if let Ok(text) = std::fs::read_to_string(pkg_dir.join("package.json")) {
        if let Ok(pkg) = serde_json::from_str::<PackageJsonTypes>(&text) {
            if let Some(types_field) = pkg.types.or(pkg.typings) {
                let candidate = normalize_dts_path(pkg_dir, &types_field);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }

    let index = pkg_dir.join("index.d.ts");
    if index.is_file() {
        return Some(index);
    }

    let mut found: Vec<PathBuf> = std::fs::read_dir(pkg_dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| is_dts_file(path))
        .collect();
    found.sort();
    found.into_iter().next()
}

fn is_dts_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".d.ts"))
}

fn normalize_dts_path(pkg_dir: &Path, types_field: &str) -> PathBuf {
    let joined = pkg_dir.join(types_field);
    if joined.extension().is_some() {
        joined
    } else {
        PathBuf::from(format!("{}.d.ts", joined.display()))
    }
}

fn parse_dts_file(path: &Path) -> Result<ParsedDts, ScanError> {
    let source = crate::scan::read_source_capped(path)?;

    let language = Lang::TypeScript.language();
    let mut parser = Parser::new();
    parser.set_language(&language)?;
    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| ScanError::Parse {
            path: path.to_path_buf(),
        })?;

    let query = Query::new(&language, DTS_QUERY)?;
    let export_idx = query.capture_index_for_name("export");
    let ambient_idx = query.capture_index_for_name("ambient");

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
    let bytes = source.as_bytes();

    let mut names = BTreeSet::new();
    let mut star_reexports = Vec::new();
    let mut has_wildcard_ambient = false;
    let mut has_export_assign = false;

    while let Some(m) = matches.next() {
        for capture in m.captures {
            if Some(capture.index) == export_idx {
                inspect_export_statement(
                    capture.node,
                    bytes,
                    &mut names,
                    &mut star_reexports,
                    &mut has_export_assign,
                );
            } else if Some(capture.index) == ambient_idx
                && ambient_declares_wildcard_module(capture.node, bytes)
            {
                has_wildcard_ambient = true;
            }
        }
    }

    Ok(ParsedDts {
        names,
        star_reexports,
        has_wildcard_ambient,
        has_export_assign,
    })
}

fn inspect_export_statement(
    node: Node,
    bytes: &[u8],
    names: &mut BTreeSet<String>,
    star_reexports: &mut Vec<String>,
    has_export_assign: &mut bool,
) {
    if let Some(decl) = node.child_by_field_name("declaration") {
        collect_declaration_names(decl, bytes, names);
        return;
    }

    let mut cursor = node.walk();
    let mut matched_clause = false;
    for child in node.children(&mut cursor) {
        match child.kind() {
            "export_clause" => {
                matched_clause = true;
                collect_export_clause_names(child, bytes, names);
            }
            "namespace_export" => {
                matched_clause = true;
                if let Some(id) = child.named_child(0) {
                    if let Ok(text) = id.utf8_text(bytes) {
                        names.insert(text.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    if matched_clause {
        return;
    }

    if let Some(source) = node.child_by_field_name("source") {
        // bare `export * from './x'` — no clause, no namespace_export.
        if let Ok(raw) = source.utf8_text(bytes) {
            if let Some(spec) = strip_ts_string(raw) {
                star_reexports.push(spec);
            }
        }
        return;
    }

    // `export = expr;` (bare identifier/expression child, no named field in
    // this grammar version) or `export default <non-declaration-expr>;`
    // (uses the `value` field) — either way, a value we cannot statically
    // enumerate members of.
    if node.named_child_count() > 0 {
        *has_export_assign = true;
    }
}

fn collect_declaration_names(decl: Node, bytes: &[u8], names: &mut BTreeSet<String>) {
    match decl.kind() {
        "interface_declaration"
        | "class_declaration"
        | "type_alias_declaration"
        | "enum_declaration"
        | "function_declaration"
        | "function_signature" => {
            if let Some(name_node) = decl.child_by_field_name("name") {
                if let Ok(text) = name_node.utf8_text(bytes) {
                    names.insert(text.to_owned());
                }
            }
        }
        "variable_declaration" | "lexical_declaration" => {
            let mut cursor = decl.walk();
            for child in decl.named_children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        if let Ok(text) = name_node.utf8_text(bytes) {
                            names.insert(text.to_owned());
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn collect_export_clause_names(clause: Node, bytes: &[u8], names: &mut BTreeSet<String>) {
    let mut cursor = clause.walk();
    for spec in clause.named_children(&mut cursor) {
        if spec.kind() != "export_specifier" {
            continue;
        }
        let target = spec
            .child_by_field_name("alias")
            .or_else(|| spec.child_by_field_name("name"));
        if let Some(target) = target {
            if let Ok(text) = target.utf8_text(bytes) {
                names.insert(strip_ts_string(text).unwrap_or_else(|| text.to_owned()));
            }
        }
    }
}

fn ambient_declares_wildcard_module(node: Node, bytes: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "module" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        if name_node.kind() != "string" {
            continue;
        }
        if let Ok(raw) = name_node.utf8_text(bytes) {
            if let Some(spec) = strip_ts_string(raw) {
                if spec.contains('*') {
                    return true;
                }
            }
        }
    }
    false
}

/// Resolve one level of a relative `export * from` target to a `.d.ts`
/// file path. Non-relative specifiers (re-exporting from a *different*
/// npm package) are deliberately never followed — that would require
/// resolving an arbitrary sibling package, out of scope here — and are
/// therefore unresolvable (`None`).
fn resolve_dts_target(current_file: &Path, spec: &str) -> Option<PathBuf> {
    if !spec.starts_with('.') {
        return None;
    }
    let base = current_file.parent()?;
    let joined = base.join(spec);
    if spec.ends_with(".d.ts") {
        return Some(joined).filter(|p| p.is_file());
    }
    let with_suffix = PathBuf::from(format!("{}.d.ts", joined.display()));
    if with_suffix.is_file() {
        return Some(with_suffix);
    }
    let index = joined.join("index.d.ts");
    if index.is_file() {
        return Some(index);
    }
    None
}

fn strip_ts_string(raw: &str) -> Option<String> {
    for quote in ['"', '\''] {
        if raw.len() >= 2 && raw.starts_with(quote) && raw.ends_with(quote) {
            return Some(raw[1..raw.len() - 1].to_owned());
        }
    }
    None
}

/// `lodash/fp` -> `lodash`; `@scope/name/sub` -> `@scope/name`. Duplicated
/// from `deps::imports_js`'s private helper of the same shape — that
/// module is crate-private and this plan's file scope does not touch
/// `deps/mod.rs`.
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

// ---------------------------------------------------------------------
// Member-usage extraction (JS/TS/TSX) — shared, used by mod.rs::check.
// ---------------------------------------------------------------------

/// Import bindings + named-import usages in one pass: default imports
/// (`import Foo from 'pkg'`) and namespace imports (`import * as Foo from
/// 'pkg'`) bind a local identifier to the module object (tracked via
/// `@binding`, resolved against subsequent `member_expression`s below);
/// named imports (`import { a, b as c } from 'pkg'`) and TS
/// `import x = require('pkg')` / CommonJS `const x = require('pkg')` are
/// captured too.
///
/// `import_require_clause` is a TypeScript-only grammar node — it does not
/// exist in the plain JavaScript grammar, so a query referencing it
/// unconditionally fails with `QueryError: Invalid node type
/// import_require_clause` the moment `usages_in_file` runs against a `.js`
/// file (every plain Node/Express project). Branch by language, mirroring
/// `imports_js.rs`'s `import_query` pattern, so the JS variant omits the
/// TS-only clause entirely.
const IMPORT_BINDING_QUERY_JS: &str = "\
    (import_statement (import_clause (identifier) @binding) source: (string) @src)\n\
    (import_statement (import_clause (namespace_import (identifier) @binding)) source: (string) @src)\n\
    (import_statement (import_clause (named_imports (import_specifier name: (identifier) @named_name alias: (identifier)? @named_alias))) source: (string) @src)\n\
    (variable_declarator name: (identifier) @binding value: (call_expression function: (identifier) @fn (#eq? @fn \"require\") arguments: (arguments (string) @src)))";

const IMPORT_BINDING_QUERY_TS: &str = "\
    (import_statement (import_clause (identifier) @binding) source: (string) @src)\n\
    (import_statement (import_clause (namespace_import (identifier) @binding)) source: (string) @src)\n\
    (import_statement (import_clause (named_imports (import_specifier name: (identifier) @named_name alias: (identifier)? @named_alias))) source: (string) @src)\n\
    (import_require_clause (identifier) @binding source: (string) @src)\n\
    (variable_declarator name: (identifier) @binding value: (call_expression function: (identifier) @fn (#eq? @fn \"require\") arguments: (arguments (string) @src)))";

fn import_binding_query(lang: Lang) -> &'static str {
    match lang {
        Lang::JavaScript => IMPORT_BINDING_QUERY_JS,
        Lang::TypeScript | Lang::Tsx => IMPORT_BINDING_QUERY_TS,
        Lang::Python => "",
    }
}

const MEMBER_EXPRESSION_QUERY: &str =
    "(member_expression object: (identifier) @obj property: (property_identifier) @prop)";

/// Walk `root`'s project source (never `node_modules`) and collect every
/// `pkg.member` / named-import usage site. Same skip-not-fail contract as
/// [`crate::scan::collect_string_assignments`].
pub(crate) fn collect_js_usages(
    root: &Path,
) -> Result<(Vec<UsageSite>, Vec<ScanError>), ScanError> {
    let mut results = Vec::new();
    let mut skipped = Vec::new();

    for entry in crate::scan::project_walker(root).build().flatten() {
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
        match usages_in_file(path, lang, root) {
            Ok(mut found) => results.append(&mut found),
            Err(err @ (ScanError::Grammar(_) | ScanError::Query(_))) => return Err(err),
            Err(err) => skipped.push(err),
        }
    }

    Ok((results, skipped))
}

fn usages_in_file(path: &Path, lang: Lang, root: &Path) -> Result<Vec<UsageSite>, ScanError> {
    let source = crate::scan::read_source_capped(path)?;

    let language = lang.language();
    let mut parser = Parser::new();
    parser.set_language(&language)?;
    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| ScanError::Parse {
            path: path.to_path_buf(),
        })?;
    let bytes = source.as_bytes();
    let file_display = relative_display(path, root);

    let mut results = Vec::new();
    let mut bindings: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    let binding_query = Query::new(&language, import_binding_query(lang))?;
    let src_idx = binding_query.capture_index_for_name("src");
    let binding_idx = binding_query.capture_index_for_name("binding");
    let named_name_idx = binding_query.capture_index_for_name("named_name");

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&binding_query, tree.root_node(), bytes);
    while let Some(m) = matches.next() {
        let mut src = None;
        let mut binding = None;
        let mut named_name = None;
        let mut named_line = 0u32;
        for capture in m.captures {
            if Some(capture.index) == src_idx {
                src = capture.node.utf8_text(bytes).ok().and_then(strip_ts_string);
            } else if Some(capture.index) == named_name_idx {
                named_name = capture.node.utf8_text(bytes).ok().map(str::to_owned);
                let pos = capture.node.start_position();
                named_line = u32::try_from(pos.row).unwrap_or(u32::MAX).saturating_add(1);
            } else if Some(capture.index) == binding_idx {
                binding = capture.node.utf8_text(bytes).ok().map(str::to_owned);
            }
        }
        let Some(src) = src else { continue };
        let package = bare_js_module(&src);
        if let Some(member) = named_name {
            results.push(UsageSite {
                package,
                member,
                file: file_display.clone(),
                line: named_line,
            });
        } else if let Some(binding) = binding {
            bindings.insert(binding, package);
        }
    }

    let member_query = Query::new(&language, MEMBER_EXPRESSION_QUERY)?;
    let obj_idx = member_query.capture_index_for_name("obj");
    let prop_idx = member_query.capture_index_for_name("prop");

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&member_query, tree.root_node(), bytes);
    while let Some(m) = matches.next() {
        let mut obj = None;
        let mut prop = None;
        let mut line = 0u32;
        for capture in m.captures {
            if Some(capture.index) == obj_idx {
                obj = capture.node.utf8_text(bytes).ok().map(str::to_owned);
            } else if Some(capture.index) == prop_idx {
                prop = capture.node.utf8_text(bytes).ok().map(str::to_owned);
                let pos = capture.node.start_position();
                line = u32::try_from(pos.row).unwrap_or(u32::MAX).saturating_add(1);
            }
        }
        let (Some(obj), Some(prop)) = (obj, prop) else {
            continue;
        };
        if let Some(package) = bindings.get(&obj) {
            results.push(UsageSite {
                package: package.clone(),
                member: prop,
                file: file_display.clone(),
                line,
            });
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-dts-test-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn resolved_surface_from_types_field() {
        let dir = tempdir("resolved");
        std::fs::write(dir.join("package.json"), r#"{"types":"index.d.ts"}"#).unwrap();
        std::fs::write(
            dir.join("index.d.ts"),
            "export function realFn(): void;\n\
             export const realConst: number;\n\
             export interface Baz {}\n",
        )
        .unwrap();

        let surface = enumerate_js(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Resolved);
        assert!(surface.exported.contains("realFn"));
        assert!(surface.exported.contains("realConst"));
        assert!(surface.exported.contains("Baz"));
        assert!(!surface.exported.contains("fakeFn"));
    }

    #[test]
    fn barrel_star_reexport_resolves_one_level() {
        let dir = tempdir("barrel");
        std::fs::write(dir.join("package.json"), r#"{"types":"index.d.ts"}"#).unwrap();
        std::fs::write(dir.join("index.d.ts"), "export * from './core';\n").unwrap();
        std::fs::write(dir.join("core.d.ts"), "export function coreFn(): void;\n").unwrap();

        let surface = enumerate_js(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Resolved);
        assert!(surface.exported.contains("coreFn"));
    }

    #[test]
    fn named_reexport_needs_no_target_file() {
        let dir = tempdir("named-reexport");
        std::fs::write(dir.join("package.json"), r#"{"types":"index.d.ts"}"#).unwrap();
        std::fs::write(
            dir.join("index.d.ts"),
            "export { a, b as c } from './missing-file';\n",
        )
        .unwrap();

        let surface = enumerate_js(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Resolved);
        assert!(surface.exported.contains("a"));
        assert!(surface.exported.contains("c"));
        assert!(!surface.exported.contains("b")); // "b" was renamed to "c"
    }

    #[test]
    fn ambient_wildcard_module_is_dynamic() {
        let dir = tempdir("wildcard");
        std::fs::write(dir.join("package.json"), r#"{"types":"index.d.ts"}"#).unwrap();
        std::fs::write(
            dir.join("index.d.ts"),
            "declare module \"wildcard-pkg/*\" {\n  const x: any;\n  export = x;\n}\n",
        )
        .unwrap();

        let surface = enumerate_js(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Dynamic);
    }

    #[test]
    fn no_dts_at_all_is_unreadable_not_empty_resolved() {
        let dir = tempdir("untyped");
        std::fs::write(dir.join("package.json"), r#"{"main":"index.js"}"#).unwrap();
        std::fs::write(dir.join("index.js"), "module.exports = {};\n").unwrap();

        let surface = enumerate_js(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Unreadable);
        assert!(surface.exported.is_empty());
    }

    #[test]
    fn unresolvable_star_target_downgrades_to_dynamic() {
        let dir = tempdir("unresolvable-star");
        std::fs::write(dir.join("package.json"), r#"{"types":"index.d.ts"}"#).unwrap();
        std::fs::write(dir.join("index.d.ts"), "export * from 'external-pkg';\n").unwrap();

        let surface = enumerate_js(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Dynamic);
    }

    #[test]
    fn export_assignment_downgrades_to_dynamic() {
        let dir = tempdir("export-assign");
        std::fs::write(dir.join("package.json"), r#"{"types":"index.d.ts"}"#).unwrap();
        std::fs::write(dir.join("index.d.ts"), "export = SomeThing;\n").unwrap();

        let surface = enumerate_js(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Dynamic);
    }

    #[test]
    fn collects_named_default_namespace_and_require_usages() {
        let dir = tempdir("usages");
        std::fs::write(
            dir.join("a.ts"),
            "import fooPkg from 'foo-pkg';\n\
             import * as barPkg from 'bar-pkg';\n\
             import { helper } from 'baz-pkg';\n\
             const quxPkg = require('qux-pkg');\n\
             fooPkg.doThing();\n\
             barPkg.doOther();\n\
             quxPkg.legacyCall();\n",
        )
        .unwrap();

        let (usages, skipped) = collect_js_usages(&dir).unwrap();
        assert!(skipped.is_empty());
        let pairs: Vec<(&str, &str)> = usages
            .iter()
            .map(|u| (u.package.as_str(), u.member.as_str()))
            .collect();
        assert!(pairs.contains(&("foo-pkg", "doThing")));
        assert!(pairs.contains(&("bar-pkg", "doOther")));
        assert!(pairs.contains(&("baz-pkg", "helper")));
        assert!(pairs.contains(&("qux-pkg", "legacyCall")));
    }
}
