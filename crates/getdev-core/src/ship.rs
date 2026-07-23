//! `core::ship` — the pure-logic engine behind `getdev ship`: mutually-
//! exclusive stack-preset detection, per-preset Dockerfile / `.dockerignore`
//! / `SHIP.md` string templating, and three programmatic pre-flight
//! validators (`ship/missing-env-declaration`, `ship/hardcoded-port`,
//! `ship/blocking-findings`).
//!
//! Scope (07-05): pure detection + templating + validation over a shared
//! parse-once [`crate::scan::ScanContext`]. The CLI surface, `--write`
//! mutation (through [`crate::mutate`]), and `--run-build` execution land in
//! 07-06/07-07 — none of them live here. No network, no code execution
//! (REQ-privacy / CLAUDE.md: `getdev-core` has NO network code).
//!
//! ## Why a NEW resolver, not `frameworks::DetectedFrameworks`
//! `frameworks::detect` answers a *boolean bag* question ("which of
//! Express/Next.js-API/FastAPI/Flask are present", possibly several at once)
//! purely to gate `audit`/`review` rule selectors, and has NO Django variant
//! (07-RESEARCH.md Pattern 3). `ship` needs a *single* Dockerfile preset, so
//! [`detect_stack`] is a mutually-exclusive resolver layered ON TOP of
//! `frameworks::detect` (reused verbatim — not forked) plus the one missing
//! Django membership check (`pypi` contains `django`).
//!
//! ## Why programmatic detectors, not `rules/ship/*.yaml`
//! `ship`'s checks cross-reference and aggregate (env references vs
//! `.env.example`; audit criticals) rather than matching a single syntactic
//! pattern — the exact CLAUDE.md rule-7 exception `core::review` already
//! established for hand-written Rust detectors under a `<cmd>/*` id prefix.
//! No `rules/ship/` YAML directory exists. Templating is plain `format!` /
//! const strings — no template-engine crate (07-RESEARCH.md Standard Stack:
//! a templating-engine dependency would be over-engineering for a fixed
//! handful of presets).

use std::collections::BTreeSet;
use std::path::Path;

use getdev_grammars::tree_sitter::Query;

use crate::deps::{DependencyGraph, Ecosystem};
use crate::findings::{Confidence, Finding, Severity};
use crate::frameworks;
use crate::scan::{Lang, ScanContext, ScannedFile};

/// The single Dockerfile preset that applies to one project — mutually
/// exclusive, unlike the boolean [`frameworks::DetectedFrameworks`] bag.
/// Resolved by [`detect_stack`] with a documented precedence (07-RESEARCH.md
/// A5 / Open Q4): `NodeNextjs` > `Fastapi` > `Flask` > `Django` > `Node` >
/// `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShipStack {
    /// A Next.js app that declares `next` AND has an API-route file (the
    /// `frameworks::detect` `nextjs_api` signal).
    NodeNextjs,
    /// Any other Node project (a `package.json` is present).
    Node,
    /// A Python project declaring `fastapi`.
    Fastapi,
    /// A Python project declaring `flask`.
    Flask,
    /// A Python project declaring `django` — the preset
    /// [`frameworks::DetectedFrameworks`] cannot express today.
    Django,
    /// No recognized stack — nothing to generate a Dockerfile for.
    Unknown,
}

impl ShipStack {
    /// Stable lowercase identifier for banners / `SHIP.md` headings.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NodeNextjs => "node/next.js",
            Self::Node => "node",
            Self::Fastapi => "fastapi",
            Self::Flask => "flask",
            Self::Django => "django",
            Self::Unknown => "unknown",
        }
    }

    /// The `project.stack` identifier list for a findings report
    /// (docs/SPEC-FINDINGS.md: `string[]`, e.g. `["node", "nextjs"]`) — the
    /// language root plus any detected framework, most-general first. `Unknown`
    /// is the empty list ("undetected"). Coarser than [`as_str`](Self::as_str)'s
    /// single banner label on purpose: consumers filter on the individual
    /// identifiers.
    #[must_use]
    pub fn identifiers(self) -> &'static [&'static str] {
        match self {
            Self::NodeNextjs => &["node", "nextjs"],
            Self::Node => &["node"],
            Self::Fastapi => &["python", "fastapi"],
            Self::Flask => &["python", "flask"],
            Self::Django => &["python", "django"],
            Self::Unknown => &[],
        }
    }
}

/// The deployment target a `SHIP.md` checklist is tailored for. Mirrors the
/// spec's `--target vercel|railway|fly|docker|vps` (docs/SPEC-COMMANDS.md
/// `getdev ship`); `Docker` is the default when none is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShipTarget {
    Vercel,
    Railway,
    Fly,
    #[default]
    Docker,
    Vps,
}

impl ShipTarget {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vercel => "vercel",
            Self::Railway => "railway",
            Self::Fly => "fly",
            Self::Docker => "docker",
            Self::Vps => "vps",
        }
    }
}

impl std::str::FromStr for ShipTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "vercel" => Ok(Self::Vercel),
            "railway" => Ok(Self::Railway),
            "fly" => Ok(Self::Fly),
            "docker" => Ok(Self::Docker),
            "vps" => Ok(Self::Vps),
            other => Err(format!(
                "unknown ship target '{other}' (expected vercel|railway|fly|docker|vps)"
            )),
        }
    }
}

/// Resolve the single Dockerfile preset for `root` from its declared
/// dependency graph. Reuses [`frameworks::detect`] verbatim for the
/// Express/Next.js/FastAPI/Flask signals (no parallel detector — the shared
/// false-positive discipline of "declared-dependency membership only, no
/// source-content scan" comes with it) and adds the one membership check
/// `DetectedFrameworks` lacks: Django (`pypi` contains `django`, already
/// PEP 503-collapsed by [`crate::deps`]).
///
/// Precedence (07-RESEARCH.md A5, documented decision): a Next.js app wins
/// over everything; among Python frameworks FastAPI > Flask > Django; a bare
/// `package.json` with no framework is plain `Node`; nothing recognized is
/// `Unknown`.
#[must_use]
pub fn detect_stack(graph: &DependencyGraph, root: &Path) -> ShipStack {
    let detected = frameworks::detect(graph, root);
    let pypi = graph.declared.get(&Ecosystem::Pypi);
    let npm = graph.declared.get(&Ecosystem::Npm);
    let django = pypi.is_some_and(|deps| deps.contains("django"));
    let has_node_manifest =
        npm.is_some_and(|deps| !deps.is_empty()) || root.join("package.json").is_file();

    if detected.nextjs_api {
        ShipStack::NodeNextjs
    } else if detected.fastapi {
        ShipStack::Fastapi
    } else if detected.flask {
        ShipStack::Flask
    } else if django {
        ShipStack::Django
    } else if has_node_manifest {
        ShipStack::Node
    } else {
        ShipStack::Unknown
    }
}

// ---------------------------------------------------------------------------
// Templating — plain const strings + `format!`, no template-engine crate.
// ---------------------------------------------------------------------------

/// Node/Next.js standalone-output multi-stage Dockerfile (07-RESEARCH.md
/// Code Examples). Requires `output: "standalone"` in the user's Next config
/// — `SHIP.md`'s checklist flags this as a manual verification step.
const DOCKERFILE_NEXTJS: &str = r#"# syntax=docker/dockerfile:1
# Multi-stage Next.js build (requires `output: "standalone"` in next.config).
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./
RUN if [ -f pnpm-lock.yaml ]; then corepack enable && pnpm install --frozen-lockfile; \
    elif [ -f yarn.lock ]; then yarn install --frozen-lockfile; \
    else npm ci; fi

FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -g 1001 -S nodejs && adduser -S nextjs -u 1001
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
USER nextjs
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:${PORT}/ || exit 1
CMD ["node", "server.js"]
"#;

/// Plain Node multi-stage Dockerfile — a generic `node server.js` runtime
/// (no `.next/standalone` copy, which only exists for a Next.js build).
const DOCKERFILE_NODE: &str = r#"# syntax=docker/dockerfile:1
# Multi-stage Node.js build.
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./
RUN if [ -f pnpm-lock.yaml ]; then corepack enable && pnpm install --frozen-lockfile; \
    elif [ -f yarn.lock ]; then yarn install --frozen-lockfile; \
    else npm ci; fi

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -g 1001 -S nodejs && adduser -S appuser -u 1001
COPY --from=deps /app/node_modules ./node_modules
COPY --chown=appuser:nodejs . .
USER appuser
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:${PORT}/ || exit 1
CMD ["node", "server.js"]
"#;

/// FastAPI multi-stage Dockerfile (07-RESEARCH.md Code Examples): a
/// `pip install --user` builder stage copied into a slim runtime stage.
const DOCKERFILE_FASTAPI: &str = r#"# syntax=docker/dockerfile:1
# Multi-stage FastAPI build.
FROM python:3.13-slim AS builder
WORKDIR /app
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM python:3.13-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/root/.local/bin:$PATH
RUN useradd --create-home appuser
COPY --from=builder /root/.local /root/.local
COPY . .
USER appuser
ENV PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://localhost:{os.environ[\"PORT\"]}/health')" || exit 1
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
"#;

/// Flask multi-stage Dockerfile — the same slim python builder/runtime shape
/// as FastAPI, served by gunicorn.
const DOCKERFILE_FLASK: &str = r#"# syntax=docker/dockerfile:1
# Multi-stage Flask build.
FROM python:3.13-slim AS builder
WORKDIR /app
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM python:3.13-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/root/.local/bin:$PATH
RUN useradd --create-home appuser
COPY --from=builder /root/.local /root/.local
COPY . .
USER appuser
ENV PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://localhost:{os.environ[\"PORT\"]}/')" || exit 1
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} app:app"]
"#;

/// Django multi-stage Dockerfile (07-RESEARCH.md Code Examples). DELIBERATELY
/// omits `collectstatic` at build time (Pitfall 2): a working `docker build`
/// must not depend on the user's `settings.py` requiring `SECRET_KEY` /
/// `DATABASE_URL` / etc. at import time — `collectstatic` is deferred to
/// container start / documented in `SHIP.md` instead.
const DOCKERFILE_DJANGO: &str = r#"# syntax=docker/dockerfile:1
# Multi-stage Django build. Intentionally does NOT run any management command
# at build time — defer static-file gathering to container start so
# `docker build` never depends on the user's runtime settings
# (SECRET_KEY / DATABASE_URL / ...).
FROM python:3.13-slim AS builder
WORKDIR /app
ENV PIP_NO_CACHE_DIR=1
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM python:3.13-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/root/.local/bin:$PATH
RUN useradd --create-home appuser
COPY --from=builder /root/.local /root/.local
COPY . .
USER appuser
ENV PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://localhost:{os.environ[\"PORT\"]}/')" || exit 1
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} myproject.wsgi:application"]
"#;

/// The multi-stage Dockerfile for `stack`, or `None` for [`ShipStack::Unknown`]
/// (nothing to generate — `SHIP.md`'s checklist carries the "unrecognized
/// stack" note instead). Every returned template is multi-stage (>= 2 `FROM`)
/// and carries a `HEALTHCHECK`; the Django template never runs `collectstatic`
/// at build time.
#[must_use]
pub fn render_dockerfile(stack: ShipStack) -> Option<String> {
    let body = match stack {
        ShipStack::NodeNextjs => DOCKERFILE_NEXTJS,
        ShipStack::Node => DOCKERFILE_NODE,
        ShipStack::Fastapi => DOCKERFILE_FASTAPI,
        ShipStack::Flask => DOCKERFILE_FLASK,
        ShipStack::Django => DOCKERFILE_DJANGO,
        ShipStack::Unknown => return None,
    };
    Some(body.to_owned())
}

/// Stack-agnostic base `.dockerignore` entries (07-RESEARCH.md Code Examples)
/// — never ship `.git`, secrets, vendored deps, or build output into the
/// image build context.
const DOCKERIGNORE_BASE: &[&str] = &[
    ".git",
    ".gitignore",
    ".getdev.toml",
    ".env",
    ".env.example",
    "node_modules",
    "__pycache__",
    "*.pyc",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    "SHIP.md",
    "Dockerfile",
];

/// Per-stack additions layered on top of [`DOCKERIGNORE_BASE`].
fn dockerignore_extras(stack: ShipStack) -> &'static [&'static str] {
    match stack {
        ShipStack::NodeNextjs | ShipStack::Node => &["npm-debug.log*", "coverage", ".turbo"],
        ShipStack::Fastapi | ShipStack::Flask | ShipStack::Django => {
            &["*.egg-info", ".pytest_cache", ".mypy_cache", "*.sqlite3"]
        }
        ShipStack::Unknown => &[],
    }
}

/// The shared base `.dockerignore` plus `stack`'s additions, newline-joined
/// with a trailing newline — deterministic for a given `stack`.
#[must_use]
pub fn render_dockerignore(stack: ShipStack) -> String {
    let mut lines: Vec<&str> = DOCKERIGNORE_BASE.to_vec();
    lines.extend_from_slice(dockerignore_extras(stack));
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// The per-target deployment steps for a `SHIP.md` checklist.
fn target_steps(target: ShipTarget, stack: ShipStack) -> Vec<&'static str> {
    let mut steps = match target {
        ShipTarget::Vercel => vec![
            "Install the Vercel CLI (`npm i -g vercel`) and run `vercel` to link the project.",
            "Set every production environment variable in the Vercel dashboard (Project → Settings → Environment Variables).",
            "Run `vercel --prod` to deploy.",
        ],
        ShipTarget::Railway => vec![
            "Create a Railway project and link it (`railway init` / `railway link`).",
            "Add environment variables with `railway variables set KEY=value`.",
            "Deploy with `railway up` (Railway builds from the generated Dockerfile).",
        ],
        ShipTarget::Fly => vec![
            "Run `fly launch` to generate a fly.toml (it will detect the Dockerfile).",
            "Set secrets with `fly secrets set KEY=value` — never commit them.",
            "Deploy with `fly deploy`.",
        ],
        ShipTarget::Docker => vec![
            "Build the image: `docker build -t my-app .`.",
            "Run it, passing runtime env vars: `docker run -p 3000:3000 --env-file .env my-app`.",
            "Confirm the container's HEALTHCHECK reports healthy (`docker ps`).",
        ],
        ShipTarget::Vps => vec![
            "Install Docker (or a runtime) on the VPS and copy the repository across.",
            "Provide production environment variables via an `.env` file kept OFF version control.",
            "Build and run the image behind a reverse proxy (nginx / Caddy) terminating TLS.",
        ],
    };
    if stack == ShipStack::NodeNextjs {
        steps.push("Verify `output: \"standalone\"` is set in your Next.js config — the generated Dockerfile depends on it.");
    }
    if stack == ShipStack::Django {
        steps.push("Run `python manage.py collectstatic --noinput` at container start (deferred out of the build for portability).");
    }
    steps
}

/// Render the per-target `SHIP.md` markdown checklist for `stack`, embedding a
/// summary of the pre-flight `findings` (the three validators' output). Pure
/// string templating — deterministic for a given `(stack, target, findings)`.
#[must_use]
pub fn render_ship_md(stack: ShipStack, target: ShipTarget, findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Ship checklist — {}\n\n", stack.as_str()));
    out.push_str(&format!("Target: **{}**\n\n", target.as_str()));

    out.push_str("## Generated files\n\n");
    if render_dockerfile(stack).is_some() {
        out.push_str("- `Dockerfile` — multi-stage build with a `HEALTHCHECK`\n");
        out.push_str("- `.dockerignore`\n\n");
    } else {
        out.push_str(
            "- No Dockerfile generated: the project stack was not recognized. Add a manifest \
             (`package.json` / `requirements.txt`) so getdev can detect the stack.\n\n",
        );
    }

    out.push_str("## Pre-flight validation\n\n");
    if findings.is_empty() {
        out.push_str("No outstanding ship findings — the pre-flight checks passed.\n\n");
    } else {
        out.push_str(&format!(
            "{} finding(s) to resolve before shipping:\n\n",
            findings.len()
        ));
        for finding in findings {
            out.push_str(&format!(
                "- **{}** ({}): {}\n",
                finding.id, finding.severity, finding.message
            ));
        }
        out.push('\n');
    }

    out.push_str(&format!("## {} deployment steps\n\n", target.as_str()));
    for step in target_steps(target, stack) {
        out.push_str(&format!("- [ ] {step}\n"));
    }
    out
}

// ---------------------------------------------------------------------------
// Validators — programmatic `ship/*` detectors over a shared &ScanContext.
// ---------------------------------------------------------------------------

/// Strip one layer of matching string delimiters (`"..."`, `'...'`, triples)
/// — `None` if `raw` is not a plain quoted string.
fn strip_quotes(raw: &str) -> Option<String> {
    for quote in ["\"\"\"", "'''", "\"", "'"] {
        if raw.len() >= quote.len() * 2 && raw.starts_with(quote) && raw.ends_with(quote) {
            return Some(raw[quote.len()..raw.len() - quote.len()].to_owned());
        }
    }
    None
}

/// The env-var REFERENCE query per language — the READ side (distinct from
/// `env.rs`'s WRITE-side rewrite): JS/TS `process.env.X` / `process.env["X"]`,
/// Python `os.environ["X"]` / `os.environ.get("X")` / `os.getenv("X")`. Each
/// referenced var name is captured as `@finding` (a bare identifier for the JS
/// member form, a quoted string node otherwise). Predicates pin the object
/// shape so an unrelated `foo.env.BAR` never fires.
fn env_ref_query(lang: Lang) -> &'static str {
    match lang {
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => {
            "(member_expression\n\
             \x20 object: (member_expression\n\
             \x20   object: (identifier) @_p\n\
             \x20   property: (property_identifier) @_e)\n\
             \x20 property: (property_identifier) @finding\n\
             \x20 (#eq? @_p \"process\")\n\
             \x20 (#eq? @_e \"env\"))\n\
             (subscript_expression\n\
             \x20 object: (member_expression\n\
             \x20   object: (identifier) @_p\n\
             \x20   property: (property_identifier) @_e)\n\
             \x20 index: (string) @finding\n\
             \x20 (#eq? @_p \"process\")\n\
             \x20 (#eq? @_e \"env\"))"
        }
        Lang::Python => {
            "(subscript\n\
             \x20 value: (attribute\n\
             \x20   object: (identifier) @_o\n\
             \x20   attribute: (identifier) @_a)\n\
             \x20 subscript: (string) @finding\n\
             \x20 (#eq? @_o \"os\")\n\
             \x20 (#eq? @_a \"environ\"))\n\
             (call\n\
             \x20 function: (attribute\n\
             \x20   object: (identifier) @_o\n\
             \x20   attribute: (identifier) @_f)\n\
             \x20 arguments: (argument_list . (string) @finding)\n\
             \x20 (#eq? @_o \"os\")\n\
             \x20 (#eq? @_f \"getenv\"))\n\
             (call\n\
             \x20 function: (attribute\n\
             \x20   object: (attribute\n\
             \x20     object: (identifier) @_o\n\
             \x20     attribute: (identifier) @_env)\n\
             \x20   attribute: (identifier) @_g)\n\
             \x20 arguments: (argument_list . (string) @finding)\n\
             \x20 (#eq? @_o \"os\")\n\
             \x20 (#eq? @_env \"environ\")\n\
             \x20 (#eq? @_g \"get\"))"
        }
    }
}

/// One env-var reference site: the referenced name and its 1-based position.
struct EnvRef {
    name: String,
    line: u32,
    column: u32,
}

/// Extract every env-var reference in one already-parsed file (no re-parse —
/// CLAUDE.md rule 5 / DoS mitigation T-07-12: runs over the same capped,
/// cached source/tree as every other analyzer). A per-file query build
/// failure (a programming bug already impossible for the fixed built-in
/// queries) is folded away rather than aborting.
fn env_refs_in_file(file: &ScannedFile) -> Vec<EnvRef> {
    let Ok(query) = Query::new(&file.lang.language(), env_ref_query(file.lang)) else {
        return Vec::new();
    };
    let source = file.source.as_bytes();
    let mut refs = Vec::new();
    for node in crate::audit::run_ast_matcher(&query, file.tree.root_node(), source) {
        let Ok(text) = node.utf8_text(source) else {
            continue;
        };
        let name = if node.kind() == "string" {
            match strip_quotes(text) {
                Some(name) => name,
                None => continue,
            }
        } else {
            text.to_owned()
        };
        if name.is_empty() {
            continue;
        }
        let pos = node.start_position();
        refs.push(EnvRef {
            name,
            line: u32::try_from(pos.row).unwrap_or(u32::MAX).saturating_add(1),
            column: u32::try_from(pos.column)
                .unwrap_or(u32::MAX)
                .saturating_add(1),
        });
    }
    refs
}

/// Parse the `KEY=` names declared in `root/.env.example` (plain text, not a
/// tree-sitter source file). A missing/unreadable file yields the empty set —
/// then every env reference is "undeclared" (the intended signal). `export `
/// prefixes and inline `# comments` / blank lines are handled.
fn declared_env_keys(root: &Path) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let Ok(contents) = std::fs::read_to_string(root.join(".env.example")) else {
        return keys;
    };
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((key, _)) = line.split_once('=') {
            let key = key.trim();
            if !key.is_empty() {
                keys.insert(key.to_owned());
            }
        }
    }
    keys
}

/// `ship/missing-env-declaration` (medium): every env var referenced in code
/// but absent from `.env.example`. Reports the var NAME + reference location,
/// never a value (T-07-14). Runs over the shared `ctx` — no new read path.
#[must_use]
pub fn missing_env_declaration(ctx: &ScanContext, root: &Path) -> Vec<Finding> {
    let declared = declared_env_keys(root);
    let mut findings = Vec::new();
    for file in &ctx.files {
        let rel = file.rel.to_string_lossy().replace('\\', "/");
        for env_ref in env_refs_in_file(file) {
            if declared.contains(&env_ref.name) {
                continue;
            }
            findings.push(Finding {
                id: "ship/missing-env-declaration".to_owned(),
                command: "ship".to_owned(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                file: rel.clone(),
                line: Some(env_ref.line),
                column: Some(env_ref.column),
                end_line: Some(env_ref.line),
                message: format!(
                    "environment variable `{}` is referenced in code but not declared in .env.example",
                    env_ref.name
                ),
                detail: Some(
                    "add it to .env.example so deployments know it is required (missing declarations are a common cause of runtime crashes on first deploy)"
                        .to_owned(),
                ),
                suggestion: Some(format!("{}=", env_ref.name)),
                remediation: Some(format!(
                    "declare `{}=` in .env.example (no value — it documents the requirement)",
                    env_ref.name
                )),
                fixable: false,
                refs: Vec::new(),
                seed: crate::fingerprint::FingerprintSeed::default(),
                fingerprint: None,
            });
        }
    }
    sort_findings(&mut findings);
    findings
}

/// The hardcoded-port query per language: a numeric port constant in a bind
/// call — JS `<x>.listen(<number>)`, Python `<x>.run(..., port=<integer>)`.
/// The number node is captured as `@finding`. A port read from
/// `process.env.PORT` / `os.environ["PORT"]` is not a numeric constant and
/// never matches.
fn hardcoded_port_query(lang: Lang) -> &'static str {
    match lang {
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => {
            "(call_expression\n\
             \x20 function: (member_expression\n\
             \x20   property: (property_identifier) @_m)\n\
             \x20 arguments: (arguments . (number) @finding)\n\
             \x20 (#eq? @_m \"listen\"))"
        }
        Lang::Python => {
            "(call\n\
             \x20 function: (attribute\n\
             \x20   attribute: (identifier) @_r)\n\
             \x20 arguments: (argument_list\n\
             \x20   (keyword_argument\n\
             \x20     name: (identifier) @_k\n\
             \x20     value: (integer) @finding))\n\
             \x20 (#eq? @_r \"run\")\n\
             \x20 (#eq? @_k \"port\"))"
        }
    }
}

/// `ship/hardcoded-port` (low): a numeric port constant passed to a server
/// bind call instead of being sourced from the `PORT` env var. Runs over the
/// shared `ctx` — no new read path.
#[must_use]
pub fn hardcoded_port(ctx: &ScanContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in &ctx.files {
        let Ok(query) = Query::new(&file.lang.language(), hardcoded_port_query(file.lang)) else {
            continue;
        };
        let rel = file.rel.to_string_lossy().replace('\\', "/");
        let source = file.source.as_bytes();
        for node in crate::audit::run_ast_matcher(&query, file.tree.root_node(), source) {
            let pos = node.start_position();
            let line = u32::try_from(pos.row).unwrap_or(u32::MAX).saturating_add(1);
            let column = u32::try_from(pos.column)
                .unwrap_or(u32::MAX)
                .saturating_add(1);
            findings.push(Finding {
                id: "ship/hardcoded-port".to_owned(),
                command: "ship".to_owned(),
                severity: Severity::Low,
                confidence: Confidence::Medium,
                file: rel.clone(),
                line: Some(line),
                column: Some(column),
                end_line: Some(line),
                message:
                    "server port is hardcoded; bind to the PORT environment variable so the host can assign it"
                        .to_owned(),
                detail: Some(
                    "platforms like Railway/Fly/Render inject a PORT env var the app must bind to — a hardcoded port fails health checks there"
                        .to_owned(),
                ),
                suggestion: None,
                remediation: Some(
                    "read the port from the environment (e.g. `process.env.PORT` / `os.environ[\"PORT\"]`)"
                        .to_owned(),
                ),
                fixable: false,
                refs: Vec::new(),
                seed: crate::fingerprint::FingerprintSeed::default(),
                fingerprint: None,
            });
        }
    }
    sort_findings(&mut findings);
    findings
}

/// `ship/blocking-findings` (critical): the outstanding `audit` criticals that
/// must be resolved before shipping. NOT a new detector — it reuses
/// [`crate::audit::run`] (the 07-02 `&ScanContext` signature) filtered to
/// [`Severity::Critical`], so audit's severity logic is the single source of
/// truth (no re-implemented severity code). Each surviving audit critical is
/// re-emitted as a `ship/blocking-findings` context finding (the underlying
/// audit finding is already masked, so no raw secret can leak — T-07-14).
///
/// Any engine-level failure (embedded pack / graph build / audit run)
/// degrades to an empty result rather than panicking — ship must never abort
/// the run over an engine hiccup (CLAUDE.md rule 1).
#[must_use]
pub fn blocking_findings(ctx: &ScanContext, root: &Path) -> Vec<Finding> {
    let Ok(pack) = crate::rules::load_embedded() else {
        return Vec::new();
    };
    let Ok((graph, _skipped)) = crate::deps::build_graph_with_context(ctx, root) else {
        return Vec::new();
    };
    let detected = frameworks::detect(&graph, root);
    let opts = crate::audit::AuditOptions {
        severity_min: Severity::Critical,
    };
    let Ok((audit_findings, _skipped)) = crate::audit::run(ctx, &pack, &detected, &opts) else {
        return Vec::new();
    };

    let mut findings: Vec<Finding> = audit_findings
        .into_iter()
        .filter(|f| f.severity == Severity::Critical)
        .map(|f| Finding {
            id: "ship/blocking-findings".to_owned(),
            command: "ship".to_owned(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            file: f.file,
            line: f.line,
            column: f.column,
            end_line: f.end_line,
            message: format!("blocking audit critical ({}): {}", f.id, f.message),
            detail: Some(
                "resolve outstanding audit criticals before shipping (run `getdev audit` for the full report)"
                    .to_owned(),
            ),
            suggestion: None,
            remediation: f.remediation,
            fixable: false,
            refs: f.refs,
            seed: crate::fingerprint::FingerprintSeed::default(),
            fingerprint: None,
        })
        .collect();
    sort_findings(&mut findings);
    findings
}

/// Stable total order for a detector's findings (file, line, column, id,
/// message) — the deterministic-core principle, independent of walk order.
fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.message.cmp(&b.message))
    });
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::deps::build_graph;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-ship-unit-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

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

    #[test]
    fn detect_django_from_pypi_graph() {
        let dir = tempdir("django");
        assert_eq!(
            detect_stack(&graph_with(&[], &["django"]), &dir),
            ShipStack::Django
        );
    }

    #[test]
    fn detect_nextjs_requires_next_dep_and_api_route() {
        let dir = tempdir("nextjs");
        std::fs::create_dir_all(dir.join("pages/api")).unwrap();
        std::fs::write(
            dir.join("pages/api/hello.ts"),
            "export default function handler() {}\n",
        )
        .unwrap();
        assert_eq!(
            detect_stack(&graph_with(&["next"], &[]), &dir),
            ShipStack::NodeNextjs
        );
    }

    #[test]
    fn detect_unknown_for_empty_graph() {
        let dir = tempdir("empty");
        assert_eq!(
            detect_stack(&DependencyGraph::default(), &dir),
            ShipStack::Unknown
        );
    }

    #[test]
    fn detect_precedence_fastapi_wins_over_django_and_node() {
        let dir = tempdir("precedence");
        std::fs::write(dir.join("package.json"), "{}\n").unwrap();
        // Both fastapi and django declared: fastapi wins per precedence.
        assert_eq!(
            detect_stack(&graph_with(&[], &["fastapi", "django"]), &dir),
            ShipStack::Fastapi
        );
    }

    #[test]
    fn detect_plain_node_from_package_json() {
        let dir = tempdir("plain-node");
        std::fs::write(dir.join("package.json"), "{\"name\":\"x\"}\n").unwrap();
        assert_eq!(
            detect_stack(&DependencyGraph::default(), &dir),
            ShipStack::Node
        );
    }

    #[test]
    fn every_preset_dockerfile_is_multistage_with_healthcheck() {
        for stack in [
            ShipStack::NodeNextjs,
            ShipStack::Node,
            ShipStack::Fastapi,
            ShipStack::Flask,
            ShipStack::Django,
        ] {
            let dockerfile = render_dockerfile(stack).unwrap();
            assert!(
                dockerfile.matches("FROM ").count() >= 2,
                "{stack:?} must be multi-stage"
            );
            assert!(
                dockerfile.contains("HEALTHCHECK"),
                "{stack:?} must have a HEALTHCHECK"
            );
        }
        assert!(render_dockerfile(ShipStack::Unknown).is_none());
    }

    #[test]
    fn django_dockerfile_never_runs_collectstatic_at_build_time() {
        let dockerfile = render_dockerfile(ShipStack::Django).unwrap();
        assert!(!dockerfile.to_lowercase().contains("collectstatic"));
    }

    #[test]
    fn dockerignore_contains_base_and_stack_extras() {
        let out = render_dockerignore(ShipStack::Django);
        assert!(out.contains(".env"));
        assert!(out.contains("__pycache__"));
        assert!(out.contains(".pytest_cache"));
    }

    #[test]
    fn ship_md_embeds_findings_and_target_steps() {
        let dir = tempdir("shipmd");
        std::fs::write(dir.join("requirements.txt"), "django\n").unwrap();
        let ctx = ScanContext::build(&dir).unwrap();
        let findings = missing_env_declaration(&ctx, &dir);
        let md = render_ship_md(ShipStack::Django, ShipTarget::Fly, &findings);
        assert!(md.contains("Ship checklist"));
        assert!(md.contains("fly deploy"));
        assert!(md.contains("collectstatic")); // Django deferred-step note
    }

    #[test]
    fn missing_env_fires_for_undeclared_and_silent_for_declared() {
        let dir = tempdir("missing-env");
        std::fs::write(
            dir.join("app.js"),
            "const a = process.env.UNDECLARED_ONE;\n",
        )
        .unwrap();
        let ctx = ScanContext::build(&dir).unwrap();
        let hits = missing_env_declaration(&ctx, &dir);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "ship/missing-env-declaration");
        assert!(hits[0].message.contains("UNDECLARED_ONE"));

        std::fs::write(dir.join(".env.example"), "UNDECLARED_ONE=\n").unwrap();
        let ctx = ScanContext::build(&dir).unwrap();
        assert!(missing_env_declaration(&ctx, &dir).is_empty());
    }

    #[test]
    fn hardcoded_port_fires_on_constant_and_silent_on_env() {
        let dir = tempdir("port");
        std::fs::write(dir.join("server.js"), "app.listen(3000);\n").unwrap();
        let ctx = ScanContext::build(&dir).unwrap();
        let hits = hardcoded_port(&ctx);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "ship/hardcoded-port");

        std::fs::write(dir.join("server.js"), "app.listen(process.env.PORT);\n").unwrap();
        let ctx = ScanContext::build(&dir).unwrap();
        assert!(hardcoded_port(&ctx).is_empty());
    }

    #[test]
    fn blocking_findings_surfaces_audit_criticals_only() {
        // A clean project: no audit criticals -> no blocking findings.
        let dir = tempdir("blocking-clean");
        std::fs::write(dir.join("app.js"), "function ok() { return 1; }\n").unwrap();
        let ctx = ScanContext::build(&dir).unwrap();
        // Sanity: the graph builds for this project.
        let _ = build_graph(&dir).unwrap();
        assert!(blocking_findings(&ctx, &dir).is_empty());
    }
}
