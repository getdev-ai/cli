//! The unified findings schema — the single internal currency for every
//! analyzer, renderer, and future integration.
//!
//! Normative spec: docs/SPEC-FINDINGS.md. The JSON produced by serializing
//! [`FindingsReport`] IS the `--json` output; renderers in [`crate::report`]
//! consume the same structs. Never print secret values into any field —
//! masked previews only (`sk-…f3a9`).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Version of the findings JSON schema, independent of the tool version.
pub const SCHEMA_VERSION: &str = "1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL_DESC: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "info" => Ok(Self::Info),
            other => Err(format!(
                "unknown severity '{other}' (expected critical|high|medium|low|info)"
            )),
        }
    }
}

/// How sure the rule is, independent of how bad the problem would be.
/// Heuristic rules can be high-severity/low-confidence and are visually
/// distinguished by renderers. (v0.4 adds a distinct `llm` tier.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        };
        f.write_str(s)
    }
}

/// One finding. Field semantics are normative in docs/SPEC-FINDINGS.md.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Rule ID, `<command>/<rule-name>` (e.g. `real/nonexistent-package`)
    pub id: String,
    /// Command that produced it: real|audit|review|env|ship
    pub command: String,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Project-relative path
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    /// One-line human summary. Never contains secret values.
    pub message: String,
    /// Longer explanation; heuristic rules MUST surface their reasoning here
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// "Did you mean…" style hint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    /// How to fix it
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// True if a getdev command can fix this automatically
    pub fixable: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<String>,
    /// Stable hash of (rule, file, normalized context) — baselines, v0.2
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// Per-severity counts plus how many findings are auto-fixable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub fixable: usize,
}

impl Summary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self::default();
        for finding in findings {
            match finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
            summary.fixable += usize::from(finding.fixable);
        }
        summary
    }

    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }

    /// Count of findings at or above `severity`.
    pub fn at_or_above(&self, severity: Severity) -> usize {
        let mut count = 0;
        for s in Severity::ALL_DESC {
            if s < severity {
                break;
            }
            count += match s {
                Severity::Critical => self.critical,
                Severity::High => self.high,
                Severity::Medium => self.medium,
                Severity::Low => self.low,
                Severity::Info => self.info,
            };
        }
        count
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    /// Path the scan ran against, as given by the user
    pub path: String,
    /// Detected stack identifiers, e.g. ["node", "nextjs"]
    pub stack: Vec<String>,
}

/// The top-level report envelope — serializing this IS the `--json` output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsReport {
    pub schema_version: String,
    pub tool_version: String,
    /// RFC 3339 UTC timestamp
    pub generated_at: String,
    pub project: ProjectInfo,
    /// Ship Score 0–100; present only for `check`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

impl FindingsReport {
    /// Build a report; computes the summary and sorts findings by severity
    /// (worst first), then file, then line — the stable presentation order
    /// shared by all renderers.
    pub fn new(tool_version: &str, project: ProjectInfo, mut findings: Vec<Finding>) -> Self {
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.line.cmp(&b.line))
        });
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            tool_version: tool_version.to_owned(),
            generated_at: humantime::format_rfc3339_seconds(std::time::SystemTime::now())
                .to_string(),
            project,
            score: None,
            summary: Summary::from_findings(&findings),
            findings,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn finding(severity: Severity, fixable: bool) -> Finding {
        Finding {
            id: "audit/hardcoded-secret".into(),
            command: "audit".into(),
            severity,
            confidence: Confidence::High,
            file: "src/payments.ts".into(),
            line: Some(12),
            column: Some(7),
            end_line: Some(12),
            message: "Stripe live secret key assigned to 'stripeKey' (sk_live_…9f2a)".into(),
            detail: None,
            suggestion: None,
            remediation: Some("run: getdev env --write".into()),
            fixable,
            refs: vec!["https://getdev.ai/rules/audit/hardcoded-secret".into()],
            fingerprint: None,
        }
    }

    #[test]
    fn severity_orders_and_parses() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Info < Severity::Low);
        assert_eq!("high".parse::<Severity>().unwrap(), Severity::High);
        assert!("bogus".parse::<Severity>().is_err());
    }

    #[test]
    fn summary_counts_and_threshold() {
        let findings = vec![
            finding(Severity::Critical, false),
            finding(Severity::High, true),
            finding(Severity::High, false),
            finding(Severity::Low, true),
        ];
        let summary = Summary::from_findings(&findings);
        assert_eq!(summary.total(), 4);
        assert_eq!(summary.fixable, 2);
        assert_eq!(summary.at_or_above(Severity::High), 3);
        assert_eq!(summary.at_or_above(Severity::Info), 4);
    }

    #[test]
    fn report_sorts_worst_first_and_serializes_schema() {
        let report = FindingsReport::new(
            "0.1.0-dev",
            ProjectInfo {
                path: ".".into(),
                stack: vec!["node".into()],
            },
            vec![
                finding(Severity::Low, false),
                finding(Severity::Critical, false),
            ],
        );
        assert_eq!(report.findings[0].severity, Severity::Critical);

        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(json["schema_version"], "1");
        assert_eq!(json["summary"]["critical"], 1);
        assert_eq!(json["findings"][0]["severity"], "critical");
        // score is absent unless set (check-only)
        assert!(json.get("score").is_none());
        // round-trips
        let back: FindingsReport = serde_json::from_value(json).unwrap();
        assert_eq!(back.findings.len(), 2);
    }
}
