//! `.getdev.toml` project configuration + `~/.getdev/config.toml` global
//! configuration.
//!
//! Normative spec: docs/SPEC-CONFIG.md. Precedence is
//! **flags > project config > global config > built-in defaults**, resolved
//! per invocation by [`Config::resolve`]. Unknown keys are hard errors at
//! every layer — a typo that silently disables a check is worse than a loud
//! failure (exit code 3).

use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::findings::Severity;

pub const PROJECT_CONFIG_FILE: &str = ".getdev.toml";
/// File name under the global config directory (`~/.getdev/`).
pub const GLOBAL_CONFIG_FILE: &str = "config.toml";
/// Directory name under `$HOME`/`%USERPROFILE%` that holds the global
/// config (and, separately, the registry cache — see
/// `getdev_registry::cache::cache_dir`).
const GLOBAL_CONFIG_DIR_NAME: &str = ".getdev";

/// Hard cap on the size of a config file this crate will read into memory
/// (WR-02). `.getdev.toml` is a **project-local, attacker-controllable**
/// file — it lives in the untrusted repo getdev is pointed at — so, exactly
/// like the scan cap [`crate::scan::MAX_SCAN_FILE_BYTES`] (F7), config reads
/// are size-checked BEFORE any buffer is allocated. A multi-GB `.getdev.toml`
/// (or a `--config`/symlink target) must never be slurped whole into memory,
/// which would OOM/kill the process on a constrained CI runner. 1 MiB is far
/// beyond any legitimate TOML config.
pub const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid config in {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    /// WR-02 — a config file above [`MAX_CONFIG_FILE_BYTES`] is never read
    /// into memory (unbounded-read DoS on a hostile repo).
    #[error("config {path} exceeds {MAX_CONFIG_FILE_BYTES} byte limit")]
    TooLarge { path: PathBuf },
}

/// Read a config file, enforcing [`MAX_CONFIG_FILE_BYTES`] via a metadata
/// pre-check BEFORE ever allocating a buffer for it (WR-02) — the same
/// pattern as [`crate::scan::read_source_capped`]. A missing file yields
/// `Ok(None)` (the caller substitutes defaults); an oversize file is a hard
/// [`ConfigError::TooLarge`]. Every config read in this module goes through
/// here rather than a bare `std::fs::read_to_string`.
fn read_config_capped(path: &Path) -> Result<Option<String>, ConfigError> {
    use std::io::Read;
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    // Refuse anything that isn't a regular file: a FIFO/device (or symlink to
    // one) reports a bogus small `len()`, defeating a metadata-only cap and
    // letting the read run unbounded (OOM) or block forever (hang). `.getdev.toml`
    // lives in the attacker-controllable scanned repo, so this must be robust.
    if !metadata.is_file() {
        return Err(ConfigError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    // Bound the READ ITSELF (`take`), not just the metadata pre-check: a file
    // that grows after the stat must not slurp past the cap. Read cap+1 so an
    // exactly-at-cap file is accepted and one byte over is rejected.
    let mut buf = Vec::new();
    match std::fs::File::open(path).and_then(|f| {
        f.take(MAX_CONFIG_FILE_BYTES.saturating_add(1))
            .read_to_end(&mut buf)
    }) {
        Ok(_) => {}
        // a file that vanished between the stat and the open is a race, not a
        // present-but-unreadable error — treat it as absent, same as above
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            })
        }
    }
    if buf.len() as u64 > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    match String::from_utf8(buf) {
        Ok(text) => Ok(Some(text)),
        Err(err) => Err(ConfigError::Read {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, err.utf8_error()),
        }),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub project: ProjectConfig,
    pub check: CheckConfig,
    pub real: RealConfig,
    pub audit: AuditConfig,
    pub review: ReviewConfig,
    pub env: EnvConfig,
    pub snap: SnapConfig,
    pub ship: ShipConfig,
    pub ignore: IgnoreConfig,
    #[serde(rename = "suppress")]
    pub suppressions: Vec<Suppression>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProjectConfig {
    /// "auto" | "node" | "python"
    pub stack: String,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            stack: "auto".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CheckConfig {
    pub fail_on: Severity,
    /// write .getdev/score.json for badges (v0.2)
    pub score_badge: bool,
}

impl Default for CheckConfig {
    fn default() -> Self {
        Self {
            fail_on: Severity::High,
            score_badge: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RealConfig {
    pub offline: bool,
    pub check_apis: bool,
    /// "strict" | "normal" | "off"
    pub typosquat_sensitivity: String,
}

impl Default for RealConfig {
    fn default() -> Self {
        Self {
            offline: false,
            check_apis: true,
            typosquat_sensitivity: "normal".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditConfig {
    pub severity_min: Severity,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            severity_min: Severity::Low,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ReviewConfig {
    pub against: String,
}

impl Default for ReviewConfig {
    fn default() -> Self {
        Self {
            against: "HEAD".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EnvConfig {
    pub include_urls: bool,
    pub env_file: String,
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            include_urls: false,
            env_file: ".env".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SnapConfig {
    pub keep: u32,
    pub auto_snap_before_fix: bool,
}

impl Default for SnapConfig {
    fn default() -> Self {
        Self {
            keep: 20,
            auto_snap_before_fix: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ShipConfig {
    /// "auto" | "vercel" | "railway" | "fly" | "docker" | "vps"
    pub target: String,
    pub run_build: bool,
}

impl Default for ShipConfig {
    fn default() -> Self {
        Self {
            target: "auto".into(),
            run_build: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct IgnoreConfig {
    /// rule IDs, e.g. ["audit/debug-mode-enabled"]
    pub rules: Vec<String>,
    /// path prefixes, e.g. ["vendor/", "dist/"]
    pub paths: Vec<String>,
}

/// False-positive suppression with an audit trail — `reason` is mandatory.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suppression {
    pub fingerprint: String,
    pub reason: String,
}

/// Presence-tracking mirror of [`Config`] used only during [`Config::merge`]
/// (B1 audit fix): every leaf is `Option<T>` so "this key was absent from
/// the file" is distinguishable from "present and happens to equal the
/// compiled-in default". The old value-based `pick()` conflated the two,
/// producing a precedence inversion: a project config that pinned
/// `fail_on = "high"` (the default) could never override a global
/// `fail_on = "low"`, because `"high" == default` looked identical to
/// "project didn't mention `fail_on`". Never exposed outside this module —
/// [`Config`] (concrete types) is what the rest of the codebase consumes.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawConfig {
    project: RawProjectConfig,
    check: RawCheckConfig,
    real: RawRealConfig,
    audit: RawAuditConfig,
    review: RawReviewConfig,
    env: RawEnvConfig,
    snap: RawSnapConfig,
    ship: RawShipConfig,
    ignore: RawIgnoreConfig,
    #[serde(rename = "suppress")]
    suppressions: Option<Vec<Suppression>>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawProjectConfig {
    stack: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawCheckConfig {
    fail_on: Option<Severity>,
    score_badge: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawRealConfig {
    offline: Option<bool>,
    check_apis: Option<bool>,
    typosquat_sensitivity: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawAuditConfig {
    severity_min: Option<Severity>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawReviewConfig {
    against: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawEnvConfig {
    include_urls: Option<bool>,
    env_file: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawSnapConfig {
    keep: Option<u32>,
    auto_snap_before_fix: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawShipConfig {
    target: Option<String>,
    run_build: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawIgnoreConfig {
    rules: Option<Vec<String>>,
    paths: Option<Vec<String>>,
}

impl RawConfig {
    fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })
    }

    fn load(dir: &Path) -> Result<Self, ConfigError> {
        let path = dir.join(PROJECT_CONFIG_FILE);
        match read_config_capped(&path)? {
            Some(text) => Self::parse(&text, &path),
            None => Ok(Self::default()),
        }
    }

    fn load_global_at(dir: &Path) -> Result<Self, ConfigError> {
        let path = dir.join(GLOBAL_CONFIG_FILE);
        match read_config_capped(&path)? {
            Some(text) => Self::parse(&text, &path),
            None => Ok(Self::default()),
        }
    }

    fn load_global() -> Result<Self, ConfigError> {
        Self::load_global_at(&global_config_dir())
    }
}

impl Config {
    /// Load `.getdev.toml` from `dir`; a missing file is the default config,
    /// a malformed or unknown-key file is a hard error (CLI exit code 3).
    pub fn load(dir: &Path) -> Result<Self, ConfigError> {
        let path = dir.join(PROJECT_CONFIG_FILE);
        match read_config_capped(&path)? {
            Some(text) => Self::parse(&text, &path),
            None => Ok(Self::default()),
        }
    }

    pub fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })
    }

    /// Load `~/.getdev/config.toml` (`GETDEV_CONFIG_HOME` overrides the
    /// directory — the hermetic-test seam, same shape as
    /// `getdev_registry::cache::cache_dir`'s `GETDEV_CACHE_DIR`). A missing
    /// file is the default config; a malformed one is a hard error exactly
    /// like the project layer (exit code 3).
    pub fn load_global() -> Result<Self, ConfigError> {
        Self::load_global_at(&global_config_dir())
    }

    /// Hermetic-test entry point for the global layer: load
    /// `dir/config.toml` directly, bypassing env-var resolution. Mirrors
    /// `getdev_registry::Cache::open_at`'s override-by-parameter pattern —
    /// tests must never mutate process-wide env vars (see that crate's test
    /// module for the rationale).
    pub fn load_global_at(dir: &Path) -> Result<Self, ConfigError> {
        let path = dir.join(GLOBAL_CONFIG_FILE);
        match read_config_capped(&path)? {
            Some(text) => Self::parse(&text, &path),
            None => Ok(Self::default()),
        }
    }

    /// Presence-based field-level precedence merge (B1 audit fix): a
    /// `project` value that was explicitly present in the file wins,
    /// regardless of whether it equals the built-in default; otherwise an
    /// explicitly-present `global` value wins; otherwise the default
    /// applies. `docs/SPEC-CONFIG.md`: **flags > project > global >
    /// defaults** — this implements the project/global/defaults half of
    /// that chain (flags are applied by the CLI layer on top of the
    /// `Config` this returns).
    fn merge(project: RawConfig, global: RawConfig) -> Config {
        let default = Config::default();
        Config {
            project: ProjectConfig {
                stack: resolve_field(
                    project.project.stack,
                    global.project.stack,
                    default.project.stack,
                ),
            },
            check: CheckConfig {
                fail_on: resolve_field(
                    project.check.fail_on,
                    global.check.fail_on,
                    default.check.fail_on,
                ),
                score_badge: resolve_field(
                    project.check.score_badge,
                    global.check.score_badge,
                    default.check.score_badge,
                ),
            },
            real: RealConfig {
                offline: resolve_field(
                    project.real.offline,
                    global.real.offline,
                    default.real.offline,
                ),
                check_apis: resolve_field(
                    project.real.check_apis,
                    global.real.check_apis,
                    default.real.check_apis,
                ),
                typosquat_sensitivity: resolve_field(
                    project.real.typosquat_sensitivity,
                    global.real.typosquat_sensitivity,
                    default.real.typosquat_sensitivity,
                ),
            },
            audit: AuditConfig {
                severity_min: resolve_field(
                    project.audit.severity_min,
                    global.audit.severity_min,
                    default.audit.severity_min,
                ),
            },
            review: ReviewConfig {
                against: resolve_field(
                    project.review.against,
                    global.review.against,
                    default.review.against,
                ),
            },
            env: EnvConfig {
                include_urls: resolve_field(
                    project.env.include_urls,
                    global.env.include_urls,
                    default.env.include_urls,
                ),
                env_file: resolve_field(
                    project.env.env_file,
                    global.env.env_file,
                    default.env.env_file,
                ),
            },
            snap: SnapConfig {
                keep: resolve_field(project.snap.keep, global.snap.keep, default.snap.keep),
                auto_snap_before_fix: resolve_field(
                    project.snap.auto_snap_before_fix,
                    global.snap.auto_snap_before_fix,
                    default.snap.auto_snap_before_fix,
                ),
            },
            ship: ShipConfig {
                target: resolve_field(project.ship.target, global.ship.target, default.ship.target),
                run_build: resolve_field(
                    project.ship.run_build,
                    global.ship.run_build,
                    default.ship.run_build,
                ),
            },
            ignore: IgnoreConfig {
                rules: resolve_field(
                    project.ignore.rules,
                    global.ignore.rules,
                    default.ignore.rules,
                ),
                paths: resolve_field(
                    project.ignore.paths,
                    global.ignore.paths,
                    default.ignore.paths,
                ),
            },
            suppressions: resolve_field(
                project.suppressions,
                global.suppressions,
                default.suppressions,
            ),
        }
    }

    /// Resolve the full precedence chain for one invocation: load the
    /// project config (from `cli_config` if the `--config` flag was given,
    /// else `dir/.getdev.toml`), load the global config, and merge them.
    /// Flags themselves are applied by the caller on top of the result.
    pub fn resolve(cli_config: Option<&Path>, dir: &Path) -> Result<Self, ConfigError> {
        let project = match cli_config {
            Some(path) => {
                // an explicitly-passed `--config <path>` that is missing must
                // fail loudly (a typo in the flag is a user error, not a
                // silent fall-back to defaults) — but it is still size-capped
                // (WR-02) before being read.
                let text = read_config_capped(path)?.ok_or_else(|| ConfigError::Read {
                    path: path.to_path_buf(),
                    source: std::io::Error::from(std::io::ErrorKind::NotFound),
                })?;
                RawConfig::parse(&text, path)?
            }
            None => RawConfig::load(dir)?,
        };
        let global = RawConfig::load_global()?;
        Ok(Self::merge(project, global))
    }
}

/// Resolves the global config directory: `GETDEV_CONFIG_HOME` first (the
/// hermetic-test override — tests must never touch the real `~/.getdev`),
/// else `~/.getdev` (`%USERPROFILE%` on Windows).
pub fn global_config_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("GETDEV_CONFIG_HOME") {
        return PathBuf::from(dir);
    }
    let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let home = std::env::var_os(home_var)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(GLOBAL_CONFIG_DIR_NAME)
}

/// The single source of truth for offline mode across every command:
/// true if the `--offline` flag was passed, OR `GETDEV_OFFLINE` is set
/// (any value), OR `[real].offline = true` in the resolved config.
#[must_use]
pub fn offline_resolved(flag: bool, cfg: &Config) -> bool {
    flag || std::env::var_os("GETDEV_OFFLINE").is_some() || cfg.real.offline
}

/// `project` wins if the key was explicitly present in the project file
/// (`Some`, regardless of value); otherwise `global` wins under the same
/// rule; otherwise `default` applies. This is the presence-based
/// field-level precedence primitive `Config::merge` applies to every key
/// (B1 audit fix — replaces the old value-based `pick()`).
fn resolve_field<T>(project: Option<T>, global: Option<T>, default: T) -> T {
    project.or(global).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const FULL_EXAMPLE: &str = r#"
[project]
stack = "auto"

[check]
fail_on = "high"
score_badge = false

[real]
offline = false
check_apis = true
typosquat_sensitivity = "normal"

[audit]
severity_min = "low"

[review]
against = "HEAD"

[env]
include_urls = false
env_file = ".env"

[snap]
keep = 20
auto_snap_before_fix = true

[ship]
target = "auto"
run_build = false

[ignore]
rules = ["audit/debug-mode-enabled"]
paths = ["vendor/", "dist/"]

[[suppress]]
fingerprint = "sha256:abc"
reason = "test fixture key, not a real secret"
"#;

    #[test]
    fn full_example_from_spec_parses() {
        let config = Config::parse(FULL_EXAMPLE, Path::new(".getdev.toml")).unwrap();
        assert_eq!(config.check.fail_on, Severity::High);
        assert_eq!(config.snap.keep, 20);
        assert_eq!(config.ignore.rules, vec!["audit/debug-mode-enabled"]);
        assert_eq!(config.suppressions.len(), 1);
        assert_eq!(
            config.suppressions[0].reason,
            "test fixture key, not a real secret"
        );
    }

    #[test]
    fn empty_and_missing_sections_get_defaults() {
        let config = Config::parse("", Path::new(".getdev.toml")).unwrap();
        assert_eq!(config, Config::default());
        assert_eq!(config.check.fail_on, Severity::High);
        assert_eq!(config.audit.severity_min, Severity::Low);
        assert_eq!(config.env.env_file, ".env");
        assert!(!config.ship.run_build);
    }

    #[test]
    fn unknown_keys_are_hard_errors() {
        let err =
            Config::parse("[check]\nfail_onn = \"high\"\n", Path::new(".getdev.toml")).unwrap_err();
        assert!(err.to_string().contains(".getdev.toml"));
    }

    #[test]
    fn suppression_without_reason_is_rejected() {
        let text = "[[suppress]]\nfingerprint = \"sha256:abc\"\n";
        assert!(Config::parse(text, Path::new(".getdev.toml")).is_err());
    }

    #[test]
    fn invalid_severity_is_rejected() {
        let text = "[check]\nfail_on = \"severe\"\n";
        assert!(Config::parse(text, Path::new(".getdev.toml")).is_err());
    }

    #[test]
    fn missing_file_is_default() {
        let dir = std::env::temp_dir().join(format!("getdev-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = Config::load(&dir).unwrap();
        assert_eq!(config, Config::default());
    }

    /// WR-02 regression: `.getdev.toml` is attacker-controllable (it lives in
    /// the scanned repo). A file over [`MAX_CONFIG_FILE_BYTES`] must be
    /// rejected via a metadata pre-check — never slurped whole into memory
    /// (unbounded-read OOM DoS). We write one byte over the cap and assert the
    /// typed `TooLarge` error rather than an allocation.
    #[test]
    fn oversized_project_config_is_rejected_not_read() {
        let dir = tmp_dir("oversized");
        let oversized =
            "# ".to_owned() + &"x".repeat(usize::try_from(MAX_CONFIG_FILE_BYTES).unwrap() + 1);
        std::fs::write(dir.join(PROJECT_CONFIG_FILE), oversized).unwrap();
        let err = Config::load(&dir).unwrap_err();
        assert!(matches!(err, ConfigError::TooLarge { .. }));
        assert!(err.to_string().contains("byte limit"));
    }

    /// WR-02 hardening (commit-review: cap-defeat via non-regular file): a
    /// metadata-only size check is defeated by a FIFO/device — it reports
    /// `len()==0` yet reads unbounded. `/dev/null` (a char device) must be
    /// refused, not treated as a valid empty config.
    #[test]
    #[cfg(unix)]
    fn non_regular_config_file_is_refused() {
        let err = read_config_capped(std::path::Path::new("/dev/null")).unwrap_err();
        assert!(matches!(err, ConfigError::TooLarge { .. }));
    }

    /// WR-02: the same cap guards the global config and the `--config`
    /// target, not just the project file.
    #[test]
    fn oversized_global_and_explicit_config_are_rejected() {
        let dir = tmp_dir("oversized-global");
        let oversized = "x".repeat(usize::try_from(MAX_CONFIG_FILE_BYTES).unwrap() + 1);
        std::fs::write(dir.join(GLOBAL_CONFIG_FILE), &oversized).unwrap();
        assert!(matches!(
            Config::load_global_at(&dir).unwrap_err(),
            ConfigError::TooLarge { .. }
        ));

        let explicit = dir.join("explicit.toml");
        std::fs::write(&explicit, &oversized).unwrap();
        assert!(matches!(
            Config::resolve(Some(&explicit), &dir).unwrap_err(),
            ConfigError::TooLarge { .. }
        ));
    }

    fn tmp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "getdev-cfg-global-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_global_config_is_default() {
        let dir = tmp_dir("missing");
        let config = Config::load_global_at(&dir).unwrap();
        assert_eq!(config, Config::default());
    }

    #[test]
    fn malformed_global_config_is_a_hard_parse_error() {
        let dir = tmp_dir("malformed");
        std::fs::write(
            dir.join(GLOBAL_CONFIG_FILE),
            "[check]\nfail_onn = \"low\"\n",
        )
        .unwrap();
        let err = Config::load_global_at(&dir).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn global_only_value_is_used_when_project_unset() {
        let dir = tmp_dir("global-only");
        std::fs::write(dir.join(GLOBAL_CONFIG_FILE), "[check]\nfail_on = \"low\"\n").unwrap();
        let global = RawConfig::load_global_at(&dir).unwrap();
        let merged = Config::merge(RawConfig::default(), global);
        assert_eq!(merged.check.fail_on, Severity::Low);
    }

    #[test]
    fn project_value_overrides_the_same_key_set_in_global() {
        let dir = tmp_dir("project-overrides");
        std::fs::write(dir.join(GLOBAL_CONFIG_FILE), "[check]\nfail_on = \"low\"\n").unwrap();
        let global = RawConfig::load_global_at(&dir).unwrap();
        let project = RawConfig::parse(
            "[check]\nfail_on = \"critical\"\n",
            Path::new(".getdev.toml"),
        )
        .unwrap();
        let merged = Config::merge(project, global);
        assert_eq!(merged.check.fail_on, Severity::Critical);
    }

    #[test]
    fn merge_falls_back_to_default_when_neither_layer_sets_a_key() {
        let merged = Config::merge(RawConfig::default(), RawConfig::default());
        assert_eq!(merged, Config::default());
    }

    /// B1 regression: presence-based precedence. Global sets `fail_on =
    /// "low"`; project explicitly sets `fail_on = "high"` — which happens to
    /// equal the compiled-in default. The old value-based `pick()` treated
    /// "equals the default" as "wasn't set", so project's explicit "high"
    /// would have lost to global's "low". Presence-based merge must resolve
    /// to the project's explicit value.
    #[test]
    fn project_value_equal_to_default_still_overrides_global_via_presence() {
        let dir = tmp_dir("presence-precedence");
        std::fs::write(dir.join(GLOBAL_CONFIG_FILE), "[check]\nfail_on = \"low\"\n").unwrap();
        let global = RawConfig::load_global_at(&dir).unwrap();
        let project =
            RawConfig::parse("[check]\nfail_on = \"high\"\n", Path::new(".getdev.toml")).unwrap();
        let merged = Config::merge(project, global);
        assert_eq!(merged.check.fail_on, Severity::High);
    }

    #[test]
    fn offline_resolved_true_when_flag_set() {
        assert!(offline_resolved(true, &Config::default()));
    }

    #[test]
    fn offline_resolved_true_when_config_real_offline_set() {
        let mut cfg = Config::default();
        cfg.real.offline = true;
        assert!(offline_resolved(false, &cfg));
    }

    // The `GETDEV_OFFLINE` env-var branch of `offline_resolved` is a single
    // `var_os` read (see the function above), exercised the same way
    // `getdev_registry::client::resolve_offline`'s env branch is: not
    // re-verified here via `std::env::set_var`, which this crate's
    // `unsafe_code = "forbid"` lint plus the workspace's env-var-mutation
    // convention (see `getdev-registry/src/cache.rs` tests) both steer away
    // from in a parallel-test binary. This next test instead pins down that
    // *absent* the env var, an unset flag and unset config both resolve to
    // `false` — the behavior CI relies on for every other hermetic test.
    #[test]
    fn offline_resolved_false_when_nothing_is_set_and_env_var_absent() {
        if std::env::var_os("GETDEV_OFFLINE").is_none() {
            assert!(!offline_resolved(false, &Config::default()));
        }
    }
}
