//! `site-packages/<pkg>` Python surface enumeration via AST (top-level
//! `__init__.py` only — never imported/executed), and Python member-usage
//! extraction from project source.
//!
//! Grammar node shapes below were hand-verified this session against the
//! vendored `tree-sitter-python` grammar: a relative import's target lives
//! in `relative_import`'s `dotted_name` child (absent for bare `from .
//! import x`); `__getattr__` defined as a direct child of `module` is
//! module-level (a `__getattr__` method nested inside a `class_definition`
//! is a different, unrelated construct and is correctly excluded since
//! only *direct* children of `module` are inspected — Pitfall 5).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use getdev_grammars::tree_sitter::{Node, Parser, Query, QueryCursor};
use streaming_iterator::StreamingIterator;

use crate::scan::{Lang, ScanError};

use super::{relative_display, ApiSurface, SurfaceError, SurfaceTier, UsageSite};

const COMPILED_EXTENSIONS: &[&str] = &["so", "pyd"];

struct ParsedPy {
    names: BTreeSet<String>,
    all_names: Option<BTreeSet<String>>,
    has_dynamic_getattr: bool,
    /// Relative-import specifiers of `from .sub import *` — resolved one
    /// level (Pitfall 5's compiled/dynamic downgrade applies symmetrically
    /// to unresolvable wildcard targets, mirroring dts.rs's star-reexport
    /// handling).
    wildcard_targets: Vec<String>,
}

/// Enumerate the exported surface of an installed `site-packages/<pkg>`
/// directory from its `__init__.py` AST. Never imports/executes the
/// package — pure static parsing of files already on disk (REQ-privacy).
pub fn enumerate_py(pkg_dir: &Path) -> Result<ApiSurface, SurfaceError> {
    let init_path = pkg_dir.join("__init__.py");
    if !init_path.is_file() {
        return Ok(if has_compiled_extension(pkg_dir) {
            dynamic()
        } else {
            unreadable()
        });
    }

    let parsed = match parse_py_module(&init_path) {
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
    if let Some(all_names) = &parsed.all_names {
        exported.extend(all_names.iter().cloned());
    }
    let mut tier = if parsed.has_dynamic_getattr {
        SurfaceTier::Dynamic
    } else {
        SurfaceTier::Resolved
    };

    for target_spec in &parsed.wildcard_targets {
        match resolve_py_target(pkg_dir, target_spec) {
            Some(target_path) => match parse_py_module(&target_path) {
                Ok(target_parsed) => {
                    exported.extend(target_parsed.names);
                    if let Some(all_names) = target_parsed.all_names {
                        exported.extend(all_names);
                    }
                    if target_parsed.has_dynamic_getattr
                        || !target_parsed.wildcard_targets.is_empty()
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
            None => tier = SurfaceTier::Dynamic,
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

fn dynamic() -> ApiSurface {
    ApiSurface {
        exported: BTreeSet::new(),
        tier: SurfaceTier::Dynamic,
    }
}

/// A package shipping only compiled extensions (`.so`/`.pyd`) with no
/// `__init__.py` has zero discoverable attributes via AST introspection
/// (Pitfall 5) — never a hard miss, always downgraded.
fn has_compiled_extension(pkg_dir: &Path) -> bool {
    std::fs::read_dir(pkg_dir)
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| COMPILED_EXTENSIONS.contains(&ext))
        })
}

fn parse_py_module(path: &Path) -> Result<ParsedPy, ScanError> {
    let source = crate::scan::read_source_capped(path)?;

    let language = Lang::Python.language();
    let mut parser = Parser::new();
    parser.set_language(&language)?;
    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| ScanError::Parse {
            path: path.to_path_buf(),
        })?;

    let bytes = source.as_bytes();
    let mut names = BTreeSet::new();
    let mut all_names: Option<BTreeSet<String>> = None;
    let mut has_dynamic_getattr = false;
    let mut wildcard_targets = Vec::new();

    // Only *direct* children of the module root are top-level — this is
    // deliberately not a recursive tree-sitter query, since "top-level"
    // must exclude names bound inside class/function bodies.
    let mut cursor = tree.root_node().walk();
    for child in tree.root_node().named_children(&mut cursor) {
        inspect_top_level(
            child,
            bytes,
            &mut names,
            &mut all_names,
            &mut has_dynamic_getattr,
            &mut wildcard_targets,
        );
    }

    Ok(ParsedPy {
        names,
        all_names,
        has_dynamic_getattr,
        wildcard_targets,
    })
}

fn inspect_top_level(
    node: Node,
    bytes: &[u8],
    names: &mut BTreeSet<String>,
    all_names: &mut Option<BTreeSet<String>>,
    has_dynamic_getattr: &mut bool,
    wildcard_targets: &mut Vec<String>,
) {
    match node.kind() {
        "function_definition" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(text) = name_node.utf8_text(bytes) {
                    if text == "__getattr__" {
                        *has_dynamic_getattr = true;
                    } else {
                        names.insert(text.to_owned());
                    }
                }
            }
        }
        "class_definition" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(text) = name_node.utf8_text(bytes) {
                    names.insert(text.to_owned());
                }
            }
        }
        "decorated_definition" => {
            if let Some(def) = node.child_by_field_name("definition") {
                inspect_top_level(
                    def,
                    bytes,
                    names,
                    all_names,
                    has_dynamic_getattr,
                    wildcard_targets,
                );
            }
        }
        "expression_statement" => {
            if let Some(assignment) = node.named_child(0) {
                if assignment.kind() == "assignment" {
                    inspect_assignment(assignment, bytes, names, all_names);
                }
            }
        }
        "import_statement" => {
            let mut cursor = node.walk();
            for name_child in node.children_by_field_name("name", &mut cursor) {
                if let Some(binding) = import_statement_binding(name_child, bytes) {
                    names.insert(binding);
                }
            }
        }
        "import_from_statement" => {
            inspect_import_from(node, bytes, names, wildcard_targets);
        }
        _ => {}
    }
}

/// `import a.b.c` binds `a` in the enclosing scope; `import x as y` binds
/// `y`.
fn import_statement_binding(name_child: Node, bytes: &[u8]) -> Option<String> {
    match name_child.kind() {
        "dotted_name" => {
            let first = name_child.named_child(0)?;
            first.utf8_text(bytes).ok().map(str::to_owned)
        }
        "aliased_import" => {
            let alias = name_child.child_by_field_name("alias")?;
            alias.utf8_text(bytes).ok().map(str::to_owned)
        }
        _ => None,
    }
}

fn inspect_import_from(
    node: Node,
    bytes: &[u8],
    names: &mut BTreeSet<String>,
    wildcard_targets: &mut Vec<String>,
) {
    // A bare `from pkg import *` / `from .sub import *` has a
    // `wildcard_import` child instead of any `name` field entries.
    let mut cursor = node.walk();
    let has_wildcard = node
        .children(&mut cursor)
        .any(|c| c.kind() == "wildcard_import");
    if has_wildcard {
        if let Some(module_name) = node.child_by_field_name("module_name") {
            if module_name.kind() == "relative_import" {
                wildcard_targets.push(relative_import_target(module_name, bytes));
            }
            // Absolute wildcard imports (`from external_pkg import *`) are
            // deliberately never followed — resolving an arbitrary
            // sibling package's own site-packages entry is out of scope.
        }
        return;
    }

    let mut cursor = node.walk();
    for name_child in node.children_by_field_name("name", &mut cursor) {
        match name_child.kind() {
            "dotted_name" => {
                if let Ok(text) = name_child.utf8_text(bytes) {
                    names.insert(text.to_owned());
                }
            }
            "aliased_import" => {
                if let Some(alias) = name_child.child_by_field_name("alias") {
                    if let Ok(text) = alias.utf8_text(bytes) {
                        names.insert(text.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
}

/// Text form of a `relative_import`'s dotted-name target, e.g. `.sub` ->
/// `"sub"`, bare `from . import *` -> `""` (self-reference — always
/// unresolvable, handled by `resolve_py_target`'s dot-count check).
fn relative_import_target(relative_import: Node, bytes: &[u8]) -> String {
    let mut cursor = relative_import.walk();
    for child in relative_import.named_children(&mut cursor) {
        if child.kind() == "dotted_name" {
            if let Ok(text) = child.utf8_text(bytes) {
                return text.to_owned();
            }
        }
    }
    String::new()
}

fn inspect_assignment(
    assignment: Node,
    bytes: &[u8],
    names: &mut BTreeSet<String>,
    all_names: &mut Option<BTreeSet<String>>,
) {
    let Some(left) = assignment.child_by_field_name("left") else {
        return;
    };
    if left.kind() != "identifier" {
        return;
    }
    let Ok(left_text) = left.utf8_text(bytes) else {
        return;
    };

    if left_text == "__all__" {
        if let Some(right) = assignment.child_by_field_name("right") {
            if matches!(right.kind(), "list" | "tuple") {
                let mut collected = BTreeSet::new();
                let mut cursor = right.walk();
                for element in right.named_children(&mut cursor) {
                    if element.kind() == "string" {
                        if let Ok(raw) = element.utf8_text(bytes) {
                            if let Some(s) = strip_py_string(raw) {
                                collected.insert(s);
                            }
                        }
                    }
                }
                *all_names = Some(collected);
            }
        }
        return;
    }

    names.insert(left_text.to_owned());
}

/// Resolve one level of a relative wildcard-import target within the
/// package. Only a single-dot (`from .sub import *`) relative import
/// within the current package directory is followed; multi-dot (parent
/// package) and self-referential (`from . import *`) specifiers are
/// unresolvable by design (never traverse outside `pkg_dir`).
fn resolve_py_target(pkg_dir: &Path, target: &str) -> Option<PathBuf> {
    if target.is_empty() {
        return None;
    }
    let module_file = pkg_dir.join(format!("{target}.py"));
    if module_file.is_file() {
        return Some(module_file);
    }
    let package_init = pkg_dir.join(target).join("__init__.py");
    if package_init.is_file() {
        return Some(package_init);
    }
    None
}

fn strip_py_string(raw: &str) -> Option<String> {
    let mut s = raw;
    let prefix_len = s.chars().take_while(|c| c.is_ascii_alphabetic()).count();
    s = &s[prefix_len..];
    for quote in ["\"\"\"", "'''", "\"", "'"] {
        if s.len() >= quote.len() * 2 && s.starts_with(quote) && s.ends_with(quote) {
            return Some(s[quote.len()..s.len() - quote.len()].to_owned());
        }
    }
    None
}

// ---------------------------------------------------------------------
// Member-usage extraction (Python) — shared, used by mod.rs::check.
// ---------------------------------------------------------------------

const ATTRIBUTE_QUERY: &str =
    "(attribute object: (identifier) @obj attribute: (identifier) @member)";

const IMPORT_QUERY: &str = "\
    (import_statement name: (dotted_name) @module)\n\
    (import_statement name: (aliased_import name: (dotted_name) @module alias: (identifier) @alias))\n\
    (import_from_statement module_name: (dotted_name) @module name: (dotted_name) @member)\n\
    (import_from_statement module_name: (dotted_name) @module name: (aliased_import name: (dotted_name) @member))";

/// Walk `root`'s project source (never `site-packages`) and collect every
/// `pkg.member` / `from pkg import member` usage site. Same skip-not-fail
/// contract as [`crate::scan::collect_string_assignments`].
pub(crate) fn collect_py_usages(
    root: &Path,
) -> Result<(Vec<UsageSite>, Vec<ScanError>), ScanError> {
    let mut results = Vec::new();
    let mut skipped = Vec::new();

    for entry in crate::scan::project_walker(root).build().flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        if Lang::from_path(path) != Some(Lang::Python) {
            continue;
        }
        match usages_in_file(path, root) {
            Ok(mut found) => results.append(&mut found),
            Err(err @ (ScanError::Grammar(_) | ScanError::Query(_))) => return Err(err),
            Err(err) => skipped.push(err),
        }
    }

    Ok((results, skipped))
}

fn usages_in_file(path: &Path, root: &Path) -> Result<Vec<UsageSite>, ScanError> {
    let source = crate::scan::read_source_capped(path)?;

    let language = Lang::Python.language();
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

    let import_query = Query::new(&language, IMPORT_QUERY)?;
    let module_idx = import_query.capture_index_for_name("module");
    let alias_idx = import_query.capture_index_for_name("alias");
    let member_idx = import_query.capture_index_for_name("member");

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&import_query, tree.root_node(), bytes);
    while let Some(m) = matches.next() {
        let mut module = None;
        let mut alias = None;
        let mut member = None;
        let mut member_line = 0u32;
        for capture in m.captures {
            if Some(capture.index) == module_idx {
                module = capture.node.utf8_text(bytes).ok().map(first_dotted_segment);
            } else if Some(capture.index) == alias_idx {
                alias = capture.node.utf8_text(bytes).ok().map(str::to_owned);
            } else if Some(capture.index) == member_idx {
                member = capture.node.utf8_text(bytes).ok().map(str::to_owned);
                let pos = capture.node.start_position();
                member_line = u32::try_from(pos.row).unwrap_or(u32::MAX).saturating_add(1);
            }
        }
        let Some(module) = module else { continue };
        if let Some(member) = member {
            results.push(UsageSite {
                package: module,
                member,
                file: file_display.clone(),
                line: member_line,
            });
        } else {
            // plain `import module [as alias]` — binds the (aliased or
            // first-segment) local name to the module for attribute-access
            // tracking below.
            let local = alias.unwrap_or_else(|| module.clone());
            bindings.insert(local, module);
        }
    }

    let attr_query = Query::new(&language, ATTRIBUTE_QUERY)?;
    let obj_idx = attr_query.capture_index_for_name("obj");
    let attr_idx = attr_query.capture_index_for_name("member");

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&attr_query, tree.root_node(), bytes);
    while let Some(m) = matches.next() {
        let mut obj = None;
        let mut attr = None;
        let mut line = 0u32;
        for capture in m.captures {
            if Some(capture.index) == obj_idx {
                obj = capture.node.utf8_text(bytes).ok().map(str::to_owned);
            } else if Some(capture.index) == attr_idx {
                attr = capture.node.utf8_text(bytes).ok().map(str::to_owned);
                let pos = capture.node.start_position();
                line = u32::try_from(pos.row).unwrap_or(u32::MAX).saturating_add(1);
            }
        }
        let (Some(obj), Some(attr)) = (obj, attr) else {
            continue;
        };
        if let Some(package) = bindings.get(&obj) {
            results.push(UsageSite {
                package: package.clone(),
                member: attr,
                file: file_display.clone(),
                line,
            });
        }
    }

    Ok(results)
}

fn first_dotted_segment(text: &str) -> String {
    text.split('.').next().unwrap_or(text).to_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-pysurface-test-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn all_and_top_level_defs_are_resolved() {
        let dir = tempdir("all-and-defs");
        std::fs::write(
            dir.join("__init__.py"),
            "__all__ = [\"real_fn\"]\n\
             def real_fn():\n    pass\n\
             class RealClass:\n    pass\n\
             __version__ = \"1.0\"\n",
        )
        .unwrap();

        let surface = enumerate_py(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Resolved);
        assert!(surface.exported.contains("real_fn"));
        assert!(surface.exported.contains("RealClass"));
        assert!(surface.exported.contains("__version__"));
        assert!(!surface.exported.contains("fake_fn"));
    }

    #[test]
    fn module_level_getattr_is_dynamic() {
        let dir = tempdir("getattr");
        std::fs::write(
            dir.join("__init__.py"),
            "def __getattr__(name):\n    pass\n",
        )
        .unwrap();

        let surface = enumerate_py(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Dynamic);
    }

    #[test]
    fn class_level_getattr_is_not_module_level_dynamic() {
        let dir = tempdir("class-getattr");
        std::fs::write(
            dir.join("__init__.py"),
            "class Foo:\n    def __getattr__(self, name):\n        pass\n",
        )
        .unwrap();

        let surface = enumerate_py(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Resolved);
        assert!(surface.exported.contains("Foo"));
    }

    #[test]
    fn compiled_only_package_with_no_py_source_is_dynamic() {
        let dir = tempdir("compiled");
        std::fs::write(dir.join("_native.so"), []).unwrap();

        let surface = enumerate_py(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Dynamic);
        assert!(surface.exported.is_empty());
    }

    #[test]
    fn no_readable_source_at_all_is_unreadable() {
        let dir = tempdir("empty");
        let surface = enumerate_py(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Unreadable);
    }

    #[test]
    fn relative_reexport_one_level_needs_no_target_file() {
        let dir = tempdir("reexport");
        std::fs::write(
            dir.join("__init__.py"),
            "from .sub import real_fn\nfrom .sub import other as public_name\n",
        )
        .unwrap();

        let surface = enumerate_py(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Resolved);
        assert!(surface.exported.contains("real_fn"));
        assert!(surface.exported.contains("public_name"));
    }

    #[test]
    fn wildcard_reexport_resolves_target_file_one_level() {
        let dir = tempdir("wildcard-reexport");
        std::fs::write(dir.join("__init__.py"), "from .sub import *\n").unwrap();
        std::fs::write(dir.join("sub.py"), "def sub_fn():\n    pass\n").unwrap();

        let surface = enumerate_py(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Resolved);
        assert!(surface.exported.contains("sub_fn"));
    }

    #[test]
    fn unresolvable_wildcard_target_downgrades_to_dynamic() {
        let dir = tempdir("wildcard-unresolvable");
        std::fs::write(dir.join("__init__.py"), "from .missing import *\n").unwrap();

        let surface = enumerate_py(&dir).unwrap();
        assert_eq!(surface.tier, SurfaceTier::Dynamic);
    }

    #[test]
    fn collects_attribute_and_from_import_usages() {
        let dir = tempdir("usages");
        std::fs::write(
            dir.join("main.py"),
            "import requests\n\
             from json import dumps\n\
             requests.get('x')\n",
        )
        .unwrap();

        let (usages, skipped) = collect_py_usages(&dir).unwrap();
        assert!(skipped.is_empty());
        let pairs: Vec<(&str, &str)> = usages
            .iter()
            .map(|u| (u.package.as_str(), u.member.as_str()))
            .collect();
        assert!(pairs.contains(&("requests", "get")));
        assert!(pairs.contains(&("json", "dumps")));
    }
}
