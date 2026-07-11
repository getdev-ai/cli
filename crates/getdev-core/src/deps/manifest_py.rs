//! Python manifest + lockfile parsers → declared PyPI package names, PEP 503
//! normalized (Pitfall 3 — `Django`/`django`/`DJANGO` must collapse to one
//! entry, or downstream registry lookups triple their work for nothing).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::{discover_manifests, record_or_fail, DeclaredNamesResult, DepsError};

/// Depth cap on `-r`/`--requirement` include resolution (F8): deep enough
/// for a realistic split (`requirements.txt` -> `base.txt` -> `common.txt`)
/// without letting a pathological or cyclic chain of includes recurse
/// unboundedly. Combined with the visited-path cycle guard in
/// [`resolve_requirement_include`].
const MAX_REQUIREMENTS_INCLUDE_DEPTH: usize = 3;

/// Parse every Python manifest/lockfile dialect present anywhere under
/// `root` (bounded-depth recursive discovery — A4) and return the union of
/// declared PyPI package names (PEP 503 normalized), plus the subset of
/// those names declared directly in `requirements.txt`/`pyproject.toml`
/// (F5: `direct` — `poetry.lock`/`uv.lock`-only names are transitive
/// dependencies the project never asked for by name). A manifest that fails
/// to *parse* is folded into the returned skip list rather than aborting
/// the whole graph build (A10) — see [`super::record_or_fail`].
pub fn declared_pypi(root: &Path) -> DeclaredNamesResult {
    let mut raw = Vec::new();
    let mut direct_raw = Vec::new();
    let mut skipped = Vec::new();

    for path in discover_manifests(root, "requirements.txt") {
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let mut visited = HashSet::new();
                visited.insert(canonical_or_self(&path));
                let found = requirements_txt_deps(
                    &text,
                    &path,
                    &mut visited,
                    MAX_REQUIREMENTS_INCLUDE_DEPTH,
                );
                direct_raw.extend(found.iter().cloned());
                raw.extend(found);
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(DepsError::Read { path, source }),
        }
    }

    for path in discover_manifests(root, "pyproject.toml") {
        match read_optional(&path) {
            Ok(Some(text)) => match pyproject_deps(&text, &path) {
                Ok(found) => {
                    direct_raw.extend(found.iter().cloned());
                    raw.extend(found);
                }
                Err(err) => record_or_fail(err, &path, &mut skipped)?,
            },
            Ok(None) => {}
            Err(err) => record_or_fail(err, &path, &mut skipped)?,
        }
    }

    for path in discover_manifests(root, "poetry.lock") {
        match read_optional(&path) {
            Ok(Some(text)) => match toml_lock_package_names(&text, &path) {
                Ok(found) => raw.extend(found),
                Err(err) => record_or_fail(err, &path, &mut skipped)?,
            },
            Ok(None) => {}
            Err(err) => record_or_fail(err, &path, &mut skipped)?,
        }
    }

    for path in discover_manifests(root, "uv.lock") {
        match read_optional(&path) {
            Ok(Some(text)) => match toml_lock_package_names(&text, &path) {
                Ok(found) => raw.extend(found),
                Err(err) => record_or_fail(err, &path, &mut skipped)?,
            },
            Ok(None) => {}
            Err(err) => record_or_fail(err, &path, &mut skipped)?,
        }
    }

    Ok((
        raw.iter().map(|name| normalize_pep503(name)).collect(),
        direct_raw
            .iter()
            .map(|name| normalize_pep503(name))
            .collect(),
        skipped,
    ))
}

fn canonical_or_self(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
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

/// PEP 503 name normalization: lowercase; runs of `-`, `_`, `.` collapse to
/// a single `-`. Must happen at the dependency-graph construction boundary
/// (once), not scattered at each downstream call site.
pub fn normalize_pep503(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_was_sep = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !last_was_sep {
                out.push('-');
                last_was_sep = true;
            }
        } else {
            out.push(c.to_ascii_lowercase());
            last_was_sep = false;
        }
    }
    out
}

/// Minimal `requirements.txt` line parser: v0.1 only needs the package
/// **name** (existence/typosquat checks), not full PEP 508 extras/markers —
/// see 03-RESEARCH.md Alternatives. Skips comments, blank lines, unknown
/// option lines silently (F8), and VCS/URL/local-path requirements; `-r`/
/// `--requirement` lines are resolved and recursively parsed (F8, depth-
/// capped and cycle-safe via `visited`).
fn requirements_txt_deps(
    text: &str,
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    depth: usize,
) -> Vec<String> {
    let mut names = Vec::new();
    for raw in text.lines() {
        if let Some(target) = requirement_include_target(raw) {
            if depth > 0 {
                names.extend(resolve_requirement_include(&target, path, visited, depth));
            }
            continue;
        }
        if let Some(name) = requirement_line_name(raw) {
            names.push(name);
        }
    }
    names
}

/// `-r other.txt` / `--requirement other.txt` (optionally `-r=other.txt`) ->
/// `Some("other.txt")`. Any other `-`-prefixed option line (`-e`, `-c`,
/// `--index-url`, ...) is not a recursive include and returns `None` —
/// callers fall through to [`requirement_line_name`], which drops it
/// silently (F8's "unknown option lines skipped silently"). The suffix
/// after `-r`/`--requirement` must start with whitespace or `=`, so this
/// never misfires on an (invalid, but theoretically possible) line like
/// `-refactor-lib`.
fn requirement_include_target(raw: &str) -> Option<String> {
    let line = raw.split('#').next().unwrap_or("").trim();
    let rest = line
        .strip_prefix("--requirement")
        .or_else(|| line.strip_prefix("-r"))?;
    if rest.is_empty() || !(rest.starts_with('=') || rest.starts_with(char::is_whitespace)) {
        return None;
    }
    let target = rest.trim_start_matches('=').trim();
    if target.is_empty() {
        None
    } else {
        Some(target.to_owned())
    }
}

/// Resolve an `-r`/`--requirement` include relative to the file it was
/// found in (never relative to `root` — a nested `backend/requirements.txt`
/// including `./base.txt` means `backend/base.txt`, not `base.txt`) and
/// recursively extract its declared names. An unreadable include (missing
/// file, permission error) is skipped silently rather than failing the
/// whole manifest — a name-existence check must not die on one broken
/// include line. `visited` guards against include cycles.
fn resolve_requirement_include(
    target: &str,
    from_path: &Path,
    visited: &mut HashSet<PathBuf>,
    depth: usize,
) -> Vec<String> {
    let base = from_path.parent().unwrap_or_else(|| Path::new("."));
    let included = base.join(target);
    let canonical = canonical_or_self(&included);
    if !visited.insert(canonical) {
        return Vec::new(); // cycle guard — already visited
    }
    let Ok(included_text) = std::fs::read_to_string(&included) else {
        return Vec::new();
    };
    requirements_txt_deps(&included_text, &included, visited, depth - 1)
}

fn requirement_line_name(raw: &str) -> Option<String> {
    let line = raw.split('#').next().unwrap_or("").trim();
    if line.is_empty() || line.starts_with('-') {
        return None;
    }
    if line.starts_with("git+") || line.starts_with("http://") || line.starts_with("https://") {
        return None;
    }
    // F8: a bare `.` (or `-e .`, already caught by the `-` prefix check
    // above) is a local-project self-reference, not a package name — it
    // must yield NO declared name, never the bogus literal `.` (or `-`).
    if line == "." || line == ".." || line.starts_with("./") || line.starts_with("../") {
        return None;
    }
    let end = line
        .find(|c: char| "[=<>!~;".contains(c) || c.is_whitespace())
        .unwrap_or(line.len());
    let name = line[..end].trim();
    if name.is_empty() || name == "." {
        None
    } else {
        Some(name.to_owned())
    }
}

/// `pyproject-toml` models PEP 621's `[project.dependencies]` but not
/// arbitrary `[tool.*]` tables, so Poetry's `[tool.poetry.dependencies]` is
/// walked separately via the raw TOML document.
/// A11: beyond `[project.dependencies]`/`[tool.poetry.dependencies]`, also
/// unions in PEP 621 `[project.optional-dependencies]` (every extras
/// group), PEP 735 `[dependency-groups]`, `[tool.poetry.group.*.dependencies]`,
/// and `[tool.poetry.dev-dependencies]` — a project that only imports a
/// package via `pytest`/`ruff`-style dev/optional groups previously had no
/// declared entry for it at all, guaranteed `real/phantom-import` FPs.
fn pyproject_deps(text: &str, path: &Path) -> Result<Vec<String>, DepsError> {
    let parsed =
        pyproject_toml::PyProjectToml::new(text).map_err(|source| DepsError::PyProjectToml {
            path: path.to_path_buf(),
            message: source.to_string(),
        })?;

    let mut names = Vec::new();
    if let Some(deps) = parsed
        .project
        .as_ref()
        .and_then(|p| p.dependencies.as_ref())
    {
        names.extend(deps.iter().map(|req| req.name.to_string()));
    }

    // PEP 621 optional-dependencies + PEP 735 dependency-groups, resolved
    // (handles `include-group`/self-referential extras). If resolution
    // fails (e.g. a self-referential extra without `project.name`, or an
    // unresolvable `include-group`), still recover the plain string entries
    // directly rather than losing the whole section — a manifest quirk in
    // one group must not blank out every other declared name.
    match parsed.resolve() {
        Ok(resolved) => {
            for reqs in resolved.optional_dependencies.values() {
                names.extend(reqs.iter().map(|req| req.name.to_string()));
            }
            for reqs in resolved.dependency_groups.values() {
                names.extend(reqs.iter().map(|req| req.name.to_string()));
            }
        }
        Err(_) => {
            if let Some(opt_deps) = parsed
                .project
                .as_ref()
                .and_then(|p| p.optional_dependencies.as_ref())
            {
                for reqs in opt_deps.values() {
                    names.extend(reqs.iter().map(|req| req.name.to_string()));
                }
            }
            if let Some(groups) = parsed.dependency_groups.as_ref() {
                for specifiers in groups.values() {
                    for spec in specifiers {
                        if let pyproject_toml::DependencyGroupSpecifier::String(req) = spec {
                            names.push(req.name.to_string());
                        }
                    }
                }
            }
        }
    }

    let raw: toml::Value = toml::from_str(text).map_err(|source| DepsError::Toml {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    if let Some(poetry) = raw.get("tool").and_then(|t| t.get("poetry")) {
        if let Some(poetry_deps) = poetry.get("dependencies").and_then(toml::Value::as_table) {
            names.extend(
                poetry_deps
                    .keys()
                    .filter(|name| name.as_str() != "python")
                    .cloned(),
            );
        }
        if let Some(dev_deps) = poetry
            .get("dev-dependencies")
            .and_then(toml::Value::as_table)
        {
            names.extend(
                dev_deps
                    .keys()
                    .filter(|name| name.as_str() != "python")
                    .cloned(),
            );
        }
        if let Some(groups) = poetry.get("group").and_then(toml::Value::as_table) {
            for group in groups.values() {
                if let Some(deps) = group.get("dependencies").and_then(toml::Value::as_table) {
                    names.extend(
                        deps.keys()
                            .filter(|name| name.as_str() != "python")
                            .cloned(),
                    );
                }
            }
        }
    }

    Ok(names)
}

/// `poetry.lock` / `uv.lock`: both TOML, both an array of `[[package]]`
/// tables with a `name` field.
fn toml_lock_package_names(text: &str, path: &Path) -> Result<Vec<String>, DepsError> {
    let raw: toml::Value = toml::from_str(text).map_err(|source| DepsError::Toml {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    let Some(packages) = raw.get("package").and_then(toml::Value::as_array) else {
        return Ok(Vec::new());
    };
    Ok(packages
        .iter()
        .filter_map(|pkg| pkg.get("name").and_then(toml::Value::as_str))
        .map(str::to_owned)
        .collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::BTreeSet;

    use super::*;

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-manifest-py-test-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn normalizes_pep503() {
        assert_eq!(normalize_pep503("Django"), "django");
        assert_eq!(normalize_pep503("django"), "django");
        assert_eq!(normalize_pep503("DJANGO"), "django");
        assert_eq!(normalize_pep503("typing_extensions"), "typing-extensions");
        assert_eq!(normalize_pep503("typing-extensions"), "typing-extensions");
        assert_eq!(normalize_pep503("a..b__c"), "a-b-c");
    }

    #[test]
    fn requirements_txt_skips_options_and_vcs_and_comments() {
        let dir = tempdir("requirements");
        std::fs::write(
            dir.join("requirements.txt"),
            "# core deps\n\
             Flask==2.3.0\n\
             -r base.txt\n\
             -e ./local-pkg\n\
             git+https://github.com/psf/requests.git@main#egg=requests\n\
             requests>=2.0,<3.0  # pin\n",
        )
        .unwrap();

        let (names, _direct, skipped) = declared_pypi(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(
            names,
            BTreeSet::from(["flask".to_owned(), "requests".to_owned()])
        );
    }

    #[test]
    fn pyproject_pep621_dependencies() {
        let dir = tempdir("pep621");
        std::fs::write(
            dir.join("pyproject.toml"),
            "[project]\n\
             name = \"fixture\"\n\
             version = \"0.1.0\"\n\
             dependencies = [\n\
             \x20\x20\"requests>=2.31.0\",\n\
             \x20\x20\"typing_extensions>=4.0\",\n\
             ]\n",
        )
        .unwrap();

        let (names, _direct, skipped) = declared_pypi(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(
            names,
            BTreeSet::from(["requests".to_owned(), "typing-extensions".to_owned()])
        );
    }

    #[test]
    fn pyproject_poetry_dependencies_excludes_python_pin() {
        let dir = tempdir("poetry");
        std::fs::write(
            dir.join("pyproject.toml"),
            "[tool.poetry]\n\
             name = \"fixture\"\n\
             version = \"0.1.0\"\n\
             \n\
             [tool.poetry.dependencies]\n\
             python = \"^3.11\"\n\
             Django = \"^4.2\"\n",
        )
        .unwrap();

        let (names, _direct, skipped) = declared_pypi(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(names, BTreeSet::from(["django".to_owned()]));
    }

    #[test]
    fn mixed_case_across_manifests_collapses_to_one_entry() {
        let dir = tempdir("normalize-collision");
        std::fs::write(dir.join("requirements.txt"), "Flask==2.3.0\n").unwrap();
        std::fs::write(
            dir.join("pyproject.toml"),
            "[tool.poetry.dependencies]\n\
             python = \"^3.11\"\n\
             flask = \"^2.3.0\"\n",
        )
        .unwrap();

        let (names, _direct, skipped) = declared_pypi(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(names, BTreeSet::from(["flask".to_owned()]));
    }

    #[test]
    fn poetry_lock_and_uv_lock_package_tables() {
        let dir = tempdir("lock");
        std::fs::write(
            dir.join("poetry.lock"),
            "[[package]]\n\
             name = \"certifi\"\n\
             version = \"2024.2.2\"\n\
             \n\
             [[package]]\n\
             name = \"charset-normalizer\"\n\
             version = \"3.3.2\"\n",
        )
        .unwrap();

        let (names, _direct, skipped) = declared_pypi(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(
            names,
            BTreeSet::from(["certifi".to_owned(), "charset-normalizer".to_owned()])
        );
    }

    #[test]
    fn direct_set_is_manifest_only_lock_only_transitives_are_excluded() {
        // F5: `direct` must contain only what requirements.txt/pyproject.toml
        // itself declares ("requests") — poetry.lock-only transitives
        // ("certifi", "charset-normalizer") show up in `names` (still
        // checked for existence) but NOT in `direct` (exempt from
        // typosquat scoring).
        let dir = tempdir("direct-vs-transitive");
        std::fs::write(dir.join("requirements.txt"), "requests==2.31.0\n").unwrap();
        std::fs::write(
            dir.join("poetry.lock"),
            "[[package]]\n\
             name = \"certifi\"\n\
             version = \"2024.2.2\"\n\
             \n\
             [[package]]\n\
             name = \"charset-normalizer\"\n\
             version = \"3.3.2\"\n",
        )
        .unwrap();

        let (names, direct, skipped) = declared_pypi(&dir).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(
            names,
            BTreeSet::from([
                "requests".to_owned(),
                "certifi".to_owned(),
                "charset-normalizer".to_owned(),
            ])
        );
        assert_eq!(direct, BTreeSet::from(["requests".to_owned()]));
    }

    #[test]
    fn absent_project_yields_empty_set_not_an_error() {
        let dir = tempdir("empty");
        let (names, _direct, skipped) = declared_pypi(&dir).unwrap();
        assert!(skipped.is_empty());
        assert!(names.is_empty());
    }
}
