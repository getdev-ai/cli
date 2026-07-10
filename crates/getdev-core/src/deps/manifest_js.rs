//! JS/TS manifest + lockfile parsers → declared npm package names.
//!
//! Every dialect present under `root` is unioned together: `package.json`'s
//! four dependency groups are the ALWAYS-present baseline (Pitfall 8 — an
//! unrecognized or absent lockfile must never silently yield an empty set),
//! and whichever lockfile is present contributes additional names on top.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Map, Value};

use super::DepsError;

/// Parse every JS/TS manifest/lockfile dialect present under `root` and
/// return the union of declared npm package names.
pub fn declared_npm(root: &Path) -> Result<BTreeSet<String>, DepsError> {
    let mut names = BTreeSet::new();

    if let Some(pkg) = read_json(&root.join("package.json"))? {
        names.extend(package_json_deps(&pkg));
    }

    if let Some(lock) = read_json(&root.join("package-lock.json"))? {
        names.extend(package_lock_deps(&lock));
    }

    if let Some(text) = read_optional(&root.join("pnpm-lock.yaml"))? {
        names.extend(pnpm_lock_deps(&text, &root.join("pnpm-lock.yaml"))?);
    }

    if let Some(text) = read_optional(&root.join("yarn.lock"))? {
        names.extend(yarn_lock_deps(&text, &root.join("yarn.lock"))?);
    }

    Ok(names)
}

fn read_optional(path: &Path) -> Result<Option<String>, DepsError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(DepsError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn read_json(path: &Path) -> Result<Option<Value>, DepsError> {
    let Some(text) = read_optional(path)? else {
        return Ok(None);
    };
    let value: Value = serde_json::from_str(&text).map_err(|source| DepsError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(Some(value))
}

/// `dependencies`/`devDependencies`/`optionalDependencies`/`peerDependencies`
/// — names only, version ranges are irrelevant to declaration.
fn package_json_deps(pkg: &Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for group in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(obj) = pkg.get(group).and_then(Value::as_object) {
            names.extend(obj.keys().cloned());
        }
    }
    names
}

/// Branches on `lockfileVersion`: v2/v3 walk the flat `packages` map, v1 (or
/// a missing version field, seen on very old lockfiles) walks the nested
/// `dependencies` tree. An unrecognized future version contributes nothing
/// — the caller already unioned in `package.json`'s direct deps, so this
/// never produces a silently empty graph (Pitfall 8).
fn package_lock_deps(lock: &Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    match lock.get("lockfileVersion").and_then(Value::as_u64) {
        Some(2) | Some(3) => {
            if let Some(packages) = lock.get("packages").and_then(Value::as_object) {
                for key in packages.keys() {
                    if let Some(name) = package_name_from_install_path(key) {
                        names.insert(name);
                    }
                }
            }
        }
        Some(1) | None => {
            if let Some(deps) = lock.get("dependencies").and_then(Value::as_object) {
                collect_v1_dependencies(deps, &mut names);
            }
        }
        Some(_) => {}
    }
    names
}

fn collect_v1_dependencies(deps: &Map<String, Value>, out: &mut BTreeSet<String>) {
    for (name, meta) in deps {
        out.insert(name.clone());
        if let Some(nested) = meta.get("dependencies").and_then(Value::as_object) {
            collect_v1_dependencies(nested, out);
        }
    }
}

/// `"node_modules/@babel/core"` -> `Some("@babel/core")`;
/// `"node_modules/foo/node_modules/bar"` -> `Some("bar")`;
/// `""` (the root project's own entry) -> `None`.
fn package_name_from_install_path(key: &str) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    key.rsplit_once("node_modules/")
        .map(|(_, name)| name.to_owned())
}

fn pnpm_lock_deps(text: &str, path: &Path) -> Result<BTreeSet<String>, DepsError> {
    let doc: serde_yaml::Value = serde_yaml::from_str(text).map_err(|source| DepsError::Yaml {
        path: path.to_path_buf(),
        source,
    })?;
    let mut names = BTreeSet::new();

    // pnpm-lock v6+ (`importers.<path>.{dependencies,devDependencies,...}`)
    if let Some(importers) = doc.get("importers").and_then(serde_yaml::Value::as_mapping) {
        for (_, importer) in importers {
            collect_pnpm_dep_group_names(importer, &mut names);
        }
    }
    // pnpm-lock v5 (top-level `dependencies`/`devDependencies`, no importers)
    collect_pnpm_dep_group_names(&doc, &mut names);

    // `packages` map: keys like "/lodash@4.17.21" or "/@scope/pkg@1.0.0" or
    // "eslint@8.0.0(typescript@5.0.0)" — strip leading slash + trailing
    // version/peer suffix.
    if let Some(packages) = doc.get("packages").and_then(serde_yaml::Value::as_mapping) {
        for key in packages.keys() {
            if let Some(raw) = key.as_str() {
                if let Some(name) = pnpm_package_name(raw) {
                    names.insert(name);
                }
            }
        }
    }

    Ok(names)
}

fn collect_pnpm_dep_group_names(node: &serde_yaml::Value, out: &mut BTreeSet<String>) {
    for group in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(map) = node.get(group).and_then(serde_yaml::Value::as_mapping) {
            for key in map.keys() {
                if let Some(name) = key.as_str() {
                    out.insert(name.to_owned());
                }
            }
        }
    }
}

fn pnpm_package_name(raw: &str) -> Option<String> {
    let raw = raw.strip_prefix('/').unwrap_or(raw);
    if let Some(rest) = raw.strip_prefix('@') {
        let at = rest.find('@')?;
        Some(format!("@{}", &rest[..at]))
    } else {
        let at = raw.find('@')?;
        if at == 0 {
            None
        } else {
            Some(raw[..at].to_owned())
        }
    }
}

fn yarn_lock_deps(text: &str, path: &Path) -> Result<BTreeSet<String>, DepsError> {
    let lockfile = yarn_lock_parser::parse_str(text).map_err(|source| DepsError::YarnLock {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(lockfile
        .entries
        .iter()
        .map(|entry| entry.name.to_owned())
        .collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-manifest-js-test-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn package_json_unions_all_four_groups() {
        let dir = tempdir("package-json");
        std::fs::write(
            dir.join("package.json"),
            r#"{
                "dependencies": {"lodash": "^4.17.21", "@scope/pkg": "^1.0.0"},
                "devDependencies": {"eslint": "^8.0.0"},
                "optionalDependencies": {"fsevents": "^2.3.0"},
                "peerDependencies": {"react": "^18.0.0"}
            }"#,
        )
        .unwrap();

        let names = declared_npm(&dir).unwrap();
        assert_eq!(
            names,
            BTreeSet::from([
                "@scope/pkg".to_owned(),
                "eslint".to_owned(),
                "fsevents".to_owned(),
                "lodash".to_owned(),
                "react".to_owned(),
            ])
        );
    }

    #[test]
    fn unrecognized_lockfile_version_falls_back_to_package_json() {
        let dir = tempdir("unknown-version");
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"left-pad": "^1.3.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{"lockfileVersion": 99, "packages": {"node_modules/should-be-ignored": {}}}"#,
        )
        .unwrap();

        let names = declared_npm(&dir).unwrap();
        assert!(!names.is_empty(), "Pitfall 8: must not silently empty out");
        assert_eq!(names, BTreeSet::from(["left-pad".to_owned()]));
    }

    #[test]
    fn lockfile_v1_walks_nested_dependencies_and_scoped_names_survive() {
        let dir = tempdir("v1");
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"left-pad": "^1.3.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
                "lockfileVersion": 1,
                "dependencies": {
                    "left-pad": {"version": "1.3.0"},
                    "@scope/chalk": {
                        "version": "4.1.2",
                        "dependencies": {"ansi-styles": {"version": "4.3.0"}}
                    }
                }
            }"#,
        )
        .unwrap();

        let names = declared_npm(&dir).unwrap();
        assert!(!names.is_empty());
        assert_eq!(
            names,
            BTreeSet::from([
                "left-pad".to_owned(),
                "@scope/chalk".to_owned(),
                "ansi-styles".to_owned(),
            ])
        );
    }

    #[test]
    fn lockfile_v3_flat_packages_map_and_scoped_names_survive() {
        let dir = tempdir("v3");
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"lodash": "^4.17.21"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "fixture", "dependencies": {"lodash": "^4.17.21"}},
                    "node_modules/lodash": {"version": "4.17.21"},
                    "node_modules/@babel/core": {"version": "7.24.0"},
                    "node_modules/@babel/core/node_modules/semver": {"version": "6.3.1"}
                }
            }"#,
        )
        .unwrap();

        let names = declared_npm(&dir).unwrap();
        assert!(!names.is_empty());
        assert_eq!(
            names,
            BTreeSet::from([
                "lodash".to_owned(),
                "@babel/core".to_owned(),
                "semver".to_owned(),
            ])
        );
    }

    #[test]
    fn pnpm_lock_importers_and_packages() {
        let dir = tempdir("pnpm");
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"fastify": "^4.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("pnpm-lock.yaml"),
            "lockfileVersion: '6.0'\n\
             importers:\n\
             \x20\x20.:\n\
             \x20\x20\x20\x20dependencies:\n\
             \x20\x20\x20\x20\x20\x20fastify:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20specifier: ^4.0.0\n\
             \x20\x20\x20\x20\x20\x20\x20\x20version: 4.26.2\n\
             packages:\n\
             \x20\x20/fastify@4.26.2:\n\
             \x20\x20\x20\x20resolution: {integrity: sha512-fake==}\n\
             \x20\x20/@fastify/error@3.4.1:\n\
             \x20\x20\x20\x20resolution: {integrity: sha512-fake==}\n",
        )
        .unwrap();

        let names = declared_npm(&dir).unwrap();
        assert_eq!(
            names,
            BTreeSet::from(["fastify".to_owned(), "@fastify/error".to_owned()])
        );
    }

    #[test]
    fn yarn_lock_entries() {
        let dir = tempdir("yarn");
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"is-odd": "^3.0.1"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("yarn.lock"),
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
             # yarn lockfile v1\n\
             \n\
             \n\
             is-number@^6.0.0:\n\
             \x20\x20version \"6.0.0\"\n\
             \x20\x20resolved \"https://registry.yarnpkg.com/is-number/-/is-number-6.0.0.tgz#fake\"\n\
             \x20\x20integrity sha512-fake==\n\
             \n\
             is-odd@^3.0.1:\n\
             \x20\x20version \"3.0.1\"\n\
             \x20\x20resolved \"https://registry.yarnpkg.com/is-odd/-/is-odd-3.0.1.tgz#fake\"\n\
             \x20\x20integrity sha512-fake==\n\
             \x20\x20dependencies:\n\
             \x20\x20\x20\x20is-number \"^6.0.0\"\n",
        )
        .unwrap();

        let names = declared_npm(&dir).unwrap();
        assert_eq!(
            names,
            BTreeSet::from(["is-odd".to_owned(), "is-number".to_owned()])
        );
    }

    #[test]
    fn absent_project_yields_empty_set_not_an_error() {
        let dir = tempdir("empty");
        let names = declared_npm(&dir).unwrap();
        assert!(names.is_empty());
    }
}
