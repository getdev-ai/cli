//! `.getdev.toml` project configuration.
//!
//! Normative spec: docs/SPEC-CONFIG.md. Precedence is
//! **flags > project config > global config > built-in defaults**; this
//! module owns the project-config layer (global `~/.getdev/config.toml`
//! lands with the cache work in P2). Unknown keys are hard errors — a typo
//! that silently disables a check is worse than a loud failure (exit code 3).

use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::findings::Severity;

pub const PROJECT_CONFIG_FILE: &str = ".getdev.toml";

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

impl Config {
    /// Load `.getdev.toml` from `dir`; a missing file is the default config,
    /// a malformed or unknown-key file is a hard error (CLI exit code 3).
    pub fn load(dir: &Path) -> Result<Self, ConfigError> {
        let path = dir.join(PROJECT_CONFIG_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(source) => return Err(ConfigError::Read { path, source }),
        };
        Self::parse(&text, &path)
    }

    pub fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

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
}
