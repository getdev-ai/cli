//! JS/TS manifest + lockfile parsers → declared npm package names.
//!
//! Every dialect present under `root` is unioned together: `package.json`'s
//! four dependency groups are the ALWAYS-present baseline (Pitfall 8 — an
//! unrecognized or absent lockfile must never silently yield an empty set),
//! and whichever lockfile is present contributes additional names on top.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Map, Value};

use super::{discover_manifests, record_or_fail, DeclaredNamesResult, DepsError};

/// Parse every JS/TS manifest/lockfile dialect present anywhere under `root`
/// (bounded-depth recursive discovery — A4) and return the union of
/// declared npm package names, plus the subset of those names declared
/// directly in `package.json` (F5: `direct` — everything else came from a
/// lockfile and is a transitive dependency the project never asked for by
/// name). A manifest that fails to *parse* is folded into the returned skip
/// list rather than aborting the whole graph build (A10) — see
/// [`super::record_or_fail`].
pub fn declared_npm(root: &Path) -> DeclaredNamesResult {
    let mut names = BTreeSet::new();
    let mut direct = BTreeSet::new();
    let mut skipped = Vec::new();

    for path in discover_manifests(root, "package.json") {
        match read_json(&path) {
            Ok(Some(pkg)) => {
                let found = package_json_deps(&pkg);
                direct.extend(found.iter().cloned());
                names.extend(found);
            }
            Ok(None) => {}
            Err(err) => record_or_fail(err, &path, &mut skipped)?,
        }
    }

    for path in discover_manifests(root, "package-lock.json") {
        match read_json(&path) {
            Ok(Some(lock)) => names.extend(package_lock_deps(&lock)),
            Ok(None) => {}
            Err(err) => record_or_fail(err, &path, &mut skipped)?,
        }
    }

    for path in discover_manifests(root, "pnpm-lock.yaml") {
        match read_optional(&path) {
            Ok(Some(text)) => match pnpm_lock_deps(&text, &path) {
                Ok(found) => names.extend(found),
                Err(err) => record_or_fail(err, &path, &mut skipped)?,
            },
            Ok(None) => {}
            Err(err) => record_or_fail(err, &path, &mut skipped)?,
        }
    }

    for path in discover_manifests(root, "yarn.lock") {
        match read_optional(&path) {
            Ok(Some(text)) => match yarn_lock_deps(&text, &path) {
                Ok(found) => names.extend(found),
                Err(err) => record_or_fail(err, &path, &mut skipped)?,
            },
            Ok(None) => {}
            Err(err) => record_or_fail(err, &path, &mut skipped)?,
        }
    }

    Ok((names, direct, skipped))
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
/// — the public-registry package name of every entry whose specifier
/// actually targets npmjs.org. C4: an entry whose specifier points somewhere
/// else (`workspace:`/`file:`/`link:`/`portal:`/git/github/tarball-url) is
/// dropped — 404-checking a monorepo sibling or private/local source against
/// the public registry is a guaranteed false "package does not exist"
/// positive. An `npm:` alias is checked under its aliased TARGET, not the
/// key. Mirrors the VCS/local-path filtering `requirements.txt` already does
/// (`manifest_py::requirement_line_name`).
fn package_json_deps(pkg: &Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for group in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(obj) = pkg.get(group).and_then(Value::as_object) {
            for (key, specifier) in obj {
                if let Some(name) = registry_name_for_dep(key, specifier) {
                    names.insert(name);
                }
            }
        }
    }
    names
}

/// The public-registry package name to existence-check for one
/// `package.json` dependency entry — `(key, specifier)` — or `None` when the
/// specifier resolves OUTSIDE the public npm registry and must never be
/// 404-checked against npmjs.org (C4: a workspace/monorepo sibling, local
/// path, git/github source, tarball URL, or portal is not a "nonexistent
/// package").
///
/// `npm:` aliases (`"foo": "npm:real-pkg@1.2.3"`) resolve to their ALIASED
/// TARGET (`real-pkg`): the registry package is the alias target, not the
/// dependency key — checking `foo` would both miss the real target and
/// spuriously check a name that is not a dependency.
fn registry_name_for_dep(key: &str, specifier: &Value) -> Option<String> {
    let spec = specifier.as_str().unwrap_or("").trim();
    if let Some(alias) = spec.strip_prefix("npm:") {
        return npm_alias_target(alias);
    }
    if is_non_registry_specifier(spec) {
        return None;
    }
    Some(key.to_owned())
}

/// Extract the aliased registry package name from an `npm:` alias body
/// (everything after `npm:`): `real-pkg@1.2.3` -> `real-pkg`,
/// `@scope/pkg@1.2.3` -> `@scope/pkg`, a bare `real-pkg` -> `real-pkg`. The
/// version suffix is the `@` AFTER the scope for a scoped target (the first
/// `@` is the scope marker). Uses `split_once` throughout — never byte-index
/// slicing — so it cannot panic on a non-char-boundary.
fn npm_alias_target(alias: &str) -> Option<String> {
    let alias = alias.trim();
    let name = match alias.strip_prefix('@') {
        // Scoped `@scope/name@version`: reattach the scope, drop version.
        Some(scoped) => {
            let base = scoped.split_once('@').map_or(scoped, |(name, _)| name);
            format!("@{base}")
        }
        // Unscoped `name@version`: keep the part before the version `@`.
        None => alias
            .split_once('@')
            .map_or(alias, |(name, _)| name)
            .to_owned(),
    };
    let name = name.trim();
    if name.is_empty() || name == "@" {
        None
    } else {
        Some(name.to_owned())
    }
}

/// True when a package.json / pnpm version specifier points somewhere OTHER
/// than the public npm registry — a workspace/monorepo sibling, a local
/// path, a git/github/gitlab/bitbucket source, a tarball URL, or a yarn
/// portal — none of which must ever be existence-checked (404-ed) against
/// npmjs.org (C4).
///
/// `npm:` ALIASES are NOT handled here (they DO target the registry, under a
/// different name) — callers resolve those via [`npm_alias_target`] BEFORE
/// calling this, which is also why the bare-`/` github-shorthand heuristic
/// below is safe (the one registry specifier form that contains `/` is an
/// `npm:` alias, already stripped away).
fn is_non_registry_specifier(spec: &str) -> bool {
    const NON_REGISTRY_PREFIXES: &[&str] = &[
        "workspace:",
        "file:",
        "link:",
        "portal:",
        "git+",
        "git:",
        "git@",
        "github:",
        "gist:",
        "bitbucket:",
        "gitlab:",
        "http://",
        "https://",
    ];
    if NON_REGISTRY_PREFIXES
        .iter()
        .any(|prefix| spec.starts_with(prefix))
    {
        return true;
    }
    // Bare `owner/repo[#ref]` GitHub shorthand npm/pnpm accept as a
    // specifier (`"dep": "expressjs/express"`). A semver range never
    // contains `/`; a scoped-package NAME (`@scope/pkg`) does, but that only
    // ever appears as a dependency KEY, never as a version specifier. So a
    // `/` here is a github slug, not a registry range.
    spec.contains('/')
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
            for (key, value) in map {
                let Some(name) = key.as_str() else { continue };
                // C4: honor the specifier so a workspace/file/link/git/url
                // dep is never 404-checked against npmjs.org, and an `npm:`
                // alias resolves to its aliased target — same rules as
                // `package.json`, applied to pnpm monorepos' importer entries.
                let specifier = pnpm_dep_specifier(value).trim();
                if let Some(alias) = specifier.strip_prefix("npm:") {
                    if let Some(target) = npm_alias_target(alias) {
                        out.insert(target);
                    }
                    continue;
                }
                if is_non_registry_specifier(specifier) {
                    continue;
                }
                out.insert(name.to_owned());
            }
        }
    }
}

/// The version specifier of one pnpm importer/dependency entry: the
/// `specifier` field of a pnpm-lock v6 importer mapping (`{specifier,
/// version}`), or the bare version string of a v5/top-level entry. Any other
/// shape yields an empty specifier — treated as a plain registry dep (fail
/// open: keep the name rather than silently drop a real dependency).
fn pnpm_dep_specifier(value: &serde_yaml::Value) -> &str {
    if let Some(spec) = value.as_str() {
        return spec;
    }
    value
        .get("specifier")
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or("")
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
        // C4: drop an entry whose EVERY descriptor range resolves outside
        // the public registry (yarn-berry `workspace:`/`file:`/`link:`/
        // `portal:`/git deps) — those must never be 404-checked against
        // npmjs.org. An entry with no parsed descriptors is kept (fail open:
        // a redundant existence check beats dropping a real dependency).
        .filter(|entry| {
            entry.descriptors.is_empty()
                || !entry
                    .descriptors
                    .iter()
                    .all(|(_, range)| is_non_registry_specifier(range.trim()))
        })
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

        let (names, _direct, skipped) = declared_npm(&dir).unwrap();
        assert!(skipped.is_empty());
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

        let (names, _direct, skipped) = declared_npm(&dir).unwrap();
        assert!(skipped.is_empty());
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

        let (names, _direct, skipped) = declared_npm(&dir).unwrap();
        assert!(skipped.is_empty());
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

        let (names, _direct, skipped) = declared_npm(&dir).unwrap();
        assert!(skipped.is_empty());
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
    fn direct_set_is_manifest_only_lockfile_transitives_are_excluded() {
        // F5: `direct` must contain only what package.json itself declares
        // ("lodash") — the lockfile-only transitives ("@babel/core",
        // "semver") show up in `names` (still checked for existence) but
        // NOT in `direct` (exempt from typosquat scoring).
        let dir = tempdir("direct-vs-transitive");
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

        let (names, direct, skipped) = declared_npm(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(
            names,
            BTreeSet::from([
                "lodash".to_owned(),
                "@babel/core".to_owned(),
                "semver".to_owned(),
            ])
        );
        assert_eq!(direct, BTreeSet::from(["lodash".to_owned()]));
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

        let (names, _direct, skipped) = declared_npm(&dir).unwrap();
        assert!(skipped.is_empty());
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

        let (names, _direct, skipped) = declared_npm(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(
            names,
            BTreeSet::from(["is-odd".to_owned(), "is-number".to_owned()])
        );
    }

    #[test]
    fn absent_project_yields_empty_set_not_an_error() {
        let dir = tempdir("empty");
        let (names, _direct, skipped) = declared_npm(&dir).unwrap();
        assert!(skipped.is_empty());
        assert!(names.is_empty());
    }

    #[test]
    fn package_json_skips_non_registry_specifiers() {
        // C4: a workspace/file/link/git/github/url/portal dep must NEVER be
        // existence-checked against npmjs.org — a monorepo sibling or private
        // source is not a "nonexistent package". Only the plain registry dep
        // ("lodash") survives, in `names` AND `direct`.
        let dir = tempdir("non-registry-specifiers");
        std::fs::write(
            dir.join("package.json"),
            r#"{
                "dependencies": {
                    "lodash": "^4.17.21",
                    "@myorg/utils": "workspace:*",
                    "local-lib": "file:../local-lib",
                    "linked": "link:../linked",
                    "from-git": "git+https://github.com/o/r.git",
                    "from-git-ssh": "git@github.com:o/r.git",
                    "from-github": "github:owner/repo",
                    "shorthand": "owner/repo#semver:^1.0.0",
                    "tarball": "https://example.com/pkg.tgz",
                    "portaled": "portal:../portaled"
                }
            }"#,
        )
        .unwrap();

        let (names, direct, skipped) = declared_npm(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(names, BTreeSet::from(["lodash".to_owned()]));
        assert_eq!(direct, BTreeSet::from(["lodash".to_owned()]));
    }

    #[test]
    fn package_json_npm_alias_resolves_to_aliased_target() {
        // C4: `"foo": "npm:real-pkg@1.2.3"` targets the registry package
        // `real-pkg`, NOT the key `foo`. Existence is checked under the
        // aliased target; the key itself is neither checked nor declared.
        let dir = tempdir("npm-alias");
        std::fs::write(
            dir.join("package.json"),
            r#"{
                "dependencies": {
                    "foo": "npm:real-pkg@1.2.3",
                    "bar": "npm:@scope/aliased@^2.0.0",
                    "baz": "npm:no-version"
                }
            }"#,
        )
        .unwrap();

        let (names, direct, skipped) = declared_npm(&dir).unwrap();
        assert!(skipped.is_empty());
        let expected = BTreeSet::from([
            "real-pkg".to_owned(),
            "@scope/aliased".to_owned(),
            "no-version".to_owned(),
        ]);
        assert_eq!(names, expected);
        assert_eq!(direct, expected);
        assert!(!names.contains("foo"));
        assert!(!names.contains("bar"));
        assert!(!names.contains("baz"));
    }

    #[test]
    fn pnpm_importers_skip_workspace_and_resolve_alias() {
        // C4 for pnpm monorepos: an importer dep with a `workspace:`
        // specifier is never registry-checked, and an `npm:` alias resolves
        // to its target — even though package.json (always parsed) may also
        // list the same workspace dep.
        let dir = tempdir("pnpm-workspace");
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"fastify": "^4.0.0", "@myorg/utils": "workspace:*"}}"#,
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
             \x20\x20\x20\x20\x20\x20'@myorg/utils':\n\
             \x20\x20\x20\x20\x20\x20\x20\x20specifier: 'workspace:*'\n\
             \x20\x20\x20\x20\x20\x20\x20\x20version: link:../utils\n\
             \x20\x20\x20\x20\x20\x20aliased:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20specifier: 'npm:real-pkg@^1.0.0'\n\
             \x20\x20\x20\x20\x20\x20\x20\x20version: real-pkg@1.0.0\n",
        )
        .unwrap();

        let (names, _direct, skipped) = declared_npm(&dir).unwrap();
        assert!(skipped.is_empty());
        assert!(
            !names.contains("@myorg/utils"),
            "workspace dep must not be registry-checked (from package.json OR importers)"
        );
        assert!(names.contains("fastify"));
        assert!(names.contains("real-pkg"));
        assert!(!names.contains("aliased"));
    }
}
