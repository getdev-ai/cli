//! Framework detection (Express / Next.js API routes / FastAPI / Flask) —
//! pure static analysis of the existing dependency graph plus Next.js's
//! path-based routing convention. No code execution, no network
//! (04-RESEARCH.md Pattern 5). Detection is project-level metadata:
//! `core::audit` gates a rule's `frameworks:` selector against the boolean
//! set here, never a hardcoded `if is_express` branch (CLAUDE.md rule 7).

use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::deps::{relative_display, DependencyGraph, Ecosystem};
use crate::rules::Framework;
use crate::scan::project_walker;

/// Which of the four v0.1 frameworks this project statically declares.
/// `nextjs_api` additionally requires at least one file matching Next.js's
/// API-route path convention (`pages/api/**`, `app/api/**/route.*`) — a
/// bare `next` dependency alone is not enough (a Next.js app with only
/// pages, no API routes, has nothing for API-route-scoped rules to check;
/// 04-RESEARCH.md Pattern 5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DetectedFrameworks {
    pub express: bool,
    pub nextjs_api: bool,
    pub fastapi: bool,
    pub flask: bool,
}

impl DetectedFrameworks {
    /// Whether `framework` is present in this project — the single
    /// sanctioned way a rule's `frameworks:` selector gates against project
    /// state; `core::audit` must never hardcode a per-framework branch
    /// (CLAUDE.md rule 7).
    #[must_use]
    pub fn contains(&self, framework: Framework) -> bool {
        match framework {
            Framework::Express => self.express,
            Framework::Nextjs => self.nextjs_api,
            Framework::Fastapi => self.fastapi,
            Framework::Flask => self.flask,
        }
    }
}

/// Detect Express/Next.js-API/FastAPI/Flask presence for one project.
/// Express/FastAPI/Flask are pure declared-dependency membership checks —
/// deliberately NO source-level identifier scan (Pitfall 3: a
/// coincidentally-named local `express` identifier in a project with no
/// `express` npm dependency must never register as Express; the only way to
/// avoid that false positive structurally is to never look at source
/// content for this signal at all). Next.js additionally requires a
/// path-convention API-route file to exist under `root`.
#[must_use]
pub fn detect(graph: &DependencyGraph, root: &Path) -> DetectedFrameworks {
    let npm = graph.declared.get(&Ecosystem::Npm);
    let pypi = graph.declared.get(&Ecosystem::Pypi);

    let express = npm.is_some_and(|deps| deps.contains("express"));
    let next_declared = npm.is_some_and(|deps| deps.contains("next"));
    let fastapi = pypi.is_some_and(|deps| deps.contains("fastapi"));
    let flask = pypi.is_some_and(|deps| deps.contains("flask"));

    DetectedFrameworks {
        express,
        nextjs_api: next_declared && has_nextjs_api_route(root),
        fastapi,
        flask,
    }
}

/// Next.js Pages Router (`pages/api/**`) and App Router
/// (`app/api/**/route.*`) API-route conventions — purely path-based, no
/// grammar can see this (04-RESEARCH.md Pattern 5 detection-signals table).
const NEXTJS_API_ROUTE_GLOBS: &[&str] = &[
    "pages/api/**",
    "app/api/**/route.js",
    "app/api/**/route.ts",
    "app/api/**/route.jsx",
    "app/api/**/route.tsx",
    "app/api/**/route.mjs",
    "app/api/**/route.cjs",
];

fn nextjs_api_route_matcher() -> Option<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in NEXTJS_API_ROUTE_GLOBS {
        builder.add(Glob::new(pattern).ok()?);
    }
    builder.build().ok()
}

/// Purely path-convention based (no file content is ever read, no parsing)
/// — Next.js's App/Pages router API-route detection is a filesystem-layout
/// fact, not an AST fact.
fn has_nextjs_api_route(root: &Path) -> bool {
    let Some(matcher) = nextjs_api_route_matcher() else {
        return false;
    };
    project_walker(root).build().flatten().any(|entry| {
        entry.file_type().is_some_and(|t| t.is_file())
            && matcher.is_match(relative_display(entry.path(), root))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    fn graph_with(npm: &[&str], pypi: &[&str]) -> DependencyGraph {
        let mut declared: BTreeMap<Ecosystem, BTreeSet<String>> = BTreeMap::new();
        declared.insert(
            Ecosystem::Npm,
            npm.iter().map(|s| (*s).to_owned()).collect(),
        );
        declared.insert(
            Ecosystem::Pypi,
            pypi.iter().map(|s| (*s).to_owned()).collect(),
        );
        DependencyGraph {
            declared,
            ..DependencyGraph::default()
        }
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-frameworks-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn express_detected_from_declared_dependency() {
        let graph = graph_with(&["express"], &[]);
        let dir = tempdir();
        assert!(detect(&graph, &dir).express);
    }

    #[test]
    fn express_not_detected_without_the_dependency() {
        let graph = graph_with(&[], &[]);
        let dir = tempdir();
        assert!(!detect(&graph, &dir).express);
    }

    /// Pitfall 3: a project with no `express` npm dependency, but source
    /// containing the bare identifier `express`, must never register as
    /// Express — detection here never inspects file content at all.
    #[test]
    fn coincidental_identifier_never_triggers_express() {
        let graph = graph_with(&[], &[]);
        let dir = tempdir();
        std::fs::write(
            dir.join("app.js"),
            "const express = require('unrelated-lib');\nexpress();\n",
        )
        .unwrap();
        assert!(!detect(&graph, &dir).express);
    }

    #[test]
    fn fastapi_and_flask_detected_independently_from_pypi_declared() {
        let fastapi_graph = graph_with(&[], &["fastapi"]);
        let flask_graph = graph_with(&[], &["flask"]);
        let dir = tempdir();
        assert!(detect(&fastapi_graph, &dir).fastapi);
        assert!(!detect(&fastapi_graph, &dir).flask);
        assert!(detect(&flask_graph, &dir).flask);
        assert!(!detect(&flask_graph, &dir).fastapi);
    }

    #[test]
    fn nextjs_api_true_only_with_next_dependency_and_an_api_route_file() {
        let graph = graph_with(&["next"], &[]);
        let dir = tempdir();
        std::fs::create_dir_all(dir.join("pages/api")).unwrap();
        std::fs::write(
            dir.join("pages/api/hello.ts"),
            "export default function handler() {}\n",
        )
        .unwrap();
        assert!(detect(&graph, &dir).nextjs_api);
    }

    #[test]
    fn nextjs_api_false_when_next_declared_but_no_api_route_present() {
        let graph = graph_with(&["next"], &[]);
        let dir = tempdir();
        std::fs::write(
            dir.join("pages_index.tsx"),
            "export default function Home() { return null; }\n",
        )
        .unwrap();
        assert!(!detect(&graph, &dir).nextjs_api);
    }

    #[test]
    fn nextjs_api_false_without_next_dependency_even_with_an_api_route_file() {
        let graph = graph_with(&[], &[]);
        let dir = tempdir();
        std::fs::create_dir_all(dir.join("pages/api")).unwrap();
        std::fs::write(
            dir.join("pages/api/hello.ts"),
            "export default function handler() {}\n",
        )
        .unwrap();
        assert!(!detect(&graph, &dir).nextjs_api);
    }

    #[test]
    fn app_router_route_convention_also_detected() {
        let graph = graph_with(&["next"], &[]);
        let dir = tempdir();
        std::fs::create_dir_all(dir.join("app/api/hello")).unwrap();
        std::fs::write(
            dir.join("app/api/hello/route.ts"),
            "export async function GET() {}\n",
        )
        .unwrap();
        assert!(detect(&graph, &dir).nextjs_api);
    }

    #[test]
    fn contains_maps_each_framework_correctly() {
        let detected = DetectedFrameworks {
            express: true,
            nextjs_api: false,
            fastapi: true,
            flask: false,
        };
        assert!(detected.contains(Framework::Express));
        assert!(!detected.contains(Framework::Nextjs));
        assert!(detected.contains(Framework::Fastapi));
        assert!(!detected.contains(Framework::Flask));
    }
}
