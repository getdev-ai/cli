//! Python manifest + lockfile parsers → declared PyPI package names, PEP 503
//! normalized (Pitfall 3 — `Django`/`django`/`DJANGO` must collapse to one
//! entry, or downstream registry lookups triple their work for nothing).

use std::collections::BTreeSet;
use std::path::Path;

use super::DepsError;

/// Parse every Python manifest/lockfile dialect present under `root` and
/// return the union of declared PyPI package names, PEP 503 normalized.
pub fn declared_pypi(root: &Path) -> Result<BTreeSet<String>, DepsError> {
    let mut raw = Vec::new();

    if let Some(text) = read_optional(&root.join("requirements.txt"))? {
        raw.extend(requirements_txt_deps(&text));
    }

    if let Some(text) = read_optional(&root.join("pyproject.toml"))? {
        raw.extend(pyproject_deps(&text, &root.join("pyproject.toml"))?);
    }

    if let Some(text) = read_optional(&root.join("poetry.lock"))? {
        raw.extend(toml_lock_package_names(&text, &root.join("poetry.lock"))?);
    }

    if let Some(text) = read_optional(&root.join("uv.lock"))? {
        raw.extend(toml_lock_package_names(&text, &root.join("uv.lock"))?);
    }

    Ok(raw.iter().map(|name| normalize_pep503(name)).collect())
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
/// see 03-RESEARCH.md Alternatives. Skips comments, blank lines, option
/// lines (`-r`, `-e`, ...), and VCS/URL requirements.
fn requirements_txt_deps(text: &str) -> Vec<String> {
    text.lines().filter_map(requirement_line_name).collect()
}

fn requirement_line_name(raw: &str) -> Option<String> {
    let line = raw.split('#').next().unwrap_or("").trim();
    if line.is_empty() || line.starts_with('-') {
        return None;
    }
    if line.starts_with("git+") || line.starts_with("http://") || line.starts_with("https://") {
        return None;
    }
    let end = line
        .find(|c: char| "[=<>!~;".contains(c) || c.is_whitespace())
        .unwrap_or(line.len());
    let name = line[..end].trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

/// `pyproject-toml` models PEP 621's `[project.dependencies]` but not
/// arbitrary `[tool.*]` tables, so Poetry's `[tool.poetry.dependencies]` is
/// walked separately via the raw TOML document.
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

    let raw: toml::Value = toml::from_str(text).map_err(|source| DepsError::Toml {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    if let Some(poetry_deps) = raw
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(toml::Value::as_table)
    {
        names.extend(
            poetry_deps
                .keys()
                .filter(|name| name.as_str() != "python")
                .cloned(),
        );
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

        let names = declared_pypi(&dir).unwrap();
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

        let names = declared_pypi(&dir).unwrap();
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

        let names = declared_pypi(&dir).unwrap();
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

        let names = declared_pypi(&dir).unwrap();
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

        let names = declared_pypi(&dir).unwrap();
        assert_eq!(
            names,
            BTreeSet::from(["certifi".to_owned(), "charset-normalizer".to_owned()])
        );
    }

    #[test]
    fn absent_project_yields_empty_set_not_an_error() {
        let dir = tempdir("empty");
        let names = declared_pypi(&dir).unwrap();
        assert!(names.is_empty());
    }
}
