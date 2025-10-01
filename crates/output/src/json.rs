use detectors::types::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// JSON output formatter for SolidityDefend findings
#[derive(Debug)]
pub struct JsonFormatter {
    include_metadata: bool,
    include_statistics: bool,
    pretty_print: bool,
}

impl JsonFormatter {
    /// Create a new JSON formatter with default settings
    pub fn new() -> Self {
        Self {
            include_metadata: true,
            include_statistics: true,
            pretty_print: true,
        }
    }

    /// Configure whether to include metadata in output
    pub fn with_metadata(mut self, include: bool) -> Self {
        self.include_metadata = include;
        self
    }

    /// Configure whether to include statistics in output
    pub fn with_statistics(mut self, include: bool) -> Self {
        self.include_statistics = include;
        self
    }

    /// Configure whether to pretty print the JSON
    pub fn with_pretty_print(mut self, pretty: bool) -> Self {
        self.pretty_print = pretty;
        self
    }

    /// Format findings as JSON string
    pub fn format(&self, findings: &[Finding]) -> Result<String, JsonError> {
        let output = self.create_output(findings)?;

        if self.pretty_print {
            serde_json::to_string_pretty(&output)
                .map_err(JsonError::SerializationError)
        } else {
            serde_json::to_string(&output)
                .map_err(JsonError::SerializationError)
        }
    }

    /// Create the JSON output structure
    fn create_output(&self, findings: &[Finding]) -> Result<JsonOutput, JsonError> {
        let mut output = JsonOutput {
            version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            findings: findings.iter().map(|f| self.convert_finding(f)).collect(),
            metadata: None,
            statistics: None,
        };

        if self.include_metadata {
            output.metadata = Some(self.create_metadata());
        }

        if self.include_statistics {
            output.statistics = Some(self.create_statistics(findings));
        }

        Ok(output)
    }

    /// Convert a Finding to JsonFinding
    fn convert_finding(&self, finding: &Finding) -> JsonFinding {
        JsonFinding {
            detector_id: finding.detector_id.to_string(),
            message: finding.message.clone(),
            severity: JsonSeverity::from(&finding.severity),
            location: JsonLocation {
                line: finding.primary_location.line as usize,
                column: finding.primary_location.column as usize,
                length: finding.primary_location.length as usize,
            },
            cwe: finding.cwe_ids.first().map(|c| format!("CWE-{}", c)),
            fix_suggestion: finding.fix_suggestion.as_ref().map(|description| JsonFixSuggestion {
                description: description.clone(),
                replacements: vec![], // TODO: Extract actual replacements from fix suggestion
            }),
            related_findings: Vec::new(), // TODO: Implement if needed
            code_snippet: None, // TODO: Add code snippet extraction
        }
    }

    /// Create metadata section
    fn create_metadata(&self) -> JsonMetadata {
        JsonMetadata {
            tool_name: "SolidityDefend".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_type: "static_analysis".to_string(),
            language: "solidity".to_string(),
            rules_version: "1.0.0".to_string(),
        }
    }

    /// Create statistics section
    fn create_statistics(&self, findings: &[Finding]) -> JsonStatistics {
        let mut severity_counts = HashMap::new();
        severity_counts.insert("critical".to_string(), 0);
        severity_counts.insert("high".to_string(), 0);
        severity_counts.insert("medium".to_string(), 0);
        severity_counts.insert("low".to_string(), 0);
        severity_counts.insert("info".to_string(), 0);

        for finding in findings {
            let severity_key = match finding.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            *severity_counts.get_mut(severity_key).unwrap() += 1;
        }

        JsonStatistics {
            total_findings: findings.len(),
            severity_counts,
            unique_detectors: findings.iter()
                .map(|f| f.detector_id.to_string())
                .collect::<std::collections::HashSet<_>>()
                .len(),
        }
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self::new()
    }
}

/// Main JSON output structure
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonOutput {
    pub version: String,
    pub timestamp: DateTime<Utc>,
    pub findings: Vec<JsonFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<JsonMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statistics: Option<JsonStatistics>,
}

/// JSON representation of a finding
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonFinding {
    pub detector_id: String,
    pub message: String,
    pub severity: JsonSeverity,
    pub location: JsonLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_suggestion: Option<JsonFixSuggestion>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub related_findings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_snippet: Option<JsonCodeSnippet>,
}

/// JSON severity representation
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JsonSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<&Severity> for JsonSeverity {
    fn from(severity: &Severity) -> Self {
        match severity {
            Severity::Critical => JsonSeverity::Critical,
            Severity::High => JsonSeverity::High,
            Severity::Medium => JsonSeverity::Medium,
            Severity::Low => JsonSeverity::Low,
            Severity::Info => JsonSeverity::Info,
        }
    }
}

/// Location information in JSON format
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonLocation {
    pub line: usize,
    pub column: usize,
    pub length: usize,
}

/// Fix suggestion in JSON format
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonFixSuggestion {
    pub description: String,
    pub replacements: Vec<JsonReplacement>,
}

/// Text replacement in JSON format
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonReplacement {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub new_text: String,
}

/// Code snippet in JSON format
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonCodeSnippet {
    pub start_line: usize,
    pub end_line: usize,
    pub lines: Vec<JsonCodeLine>,
}

/// Individual line of code
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonCodeLine {
    pub line_number: usize,
    pub content: String,
    pub is_highlighted: bool,
}

/// Metadata about the scan
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonMetadata {
    pub tool_name: String,
    pub tool_version: String,
    pub scan_type: String,
    pub language: String,
    pub rules_version: String,
}

/// Statistics about the findings
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonStatistics {
    pub total_findings: usize,
    pub severity_counts: HashMap<String, usize>,
    pub unique_detectors: usize,
}

/// Baseline comparison result in JSON format
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonBaselineComparison {
    pub baseline_timestamp: DateTime<Utc>,
    pub current_timestamp: DateTime<Utc>,
    pub new_findings: Vec<JsonFinding>,
    pub resolved_findings: Vec<JsonFinding>,
    pub unchanged_findings: Vec<JsonFinding>,
    pub summary: JsonBaselineSummary,
}

/// Summary of baseline comparison
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonBaselineSummary {
    pub new_count: usize,
    pub resolved_count: usize,
    pub unchanged_count: usize,
    pub net_change: i32, // positive = more issues, negative = fewer issues
}

/// CI/CD specific JSON output
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonCiOutput {
    #[serde(flatten)]
    pub base: JsonOutput,
    pub ci_metadata: JsonCiMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_comparison: Option<JsonBaselineComparison>,
}

/// CI/CD specific metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonCiMetadata {
    pub exit_code: i32,
    pub exit_reason: String,
    pub threshold_violations: Vec<JsonThresholdViolation>,
    pub scan_duration_ms: u64,
    pub files_analyzed: usize,
}

/// Threshold violation information
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonThresholdViolation {
    pub threshold_type: String,
    pub threshold_value: String,
    pub actual_value: String,
    pub description: String,
}

/// Errors that can occur during JSON formatting
#[derive(Debug, thiserror::Error)]
pub enum JsonError {
    #[error("Failed to serialize JSON: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Invalid finding data: {0}")]
    InvalidData(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Builder for creating custom JSON output configurations
pub struct JsonOutputBuilder {
    formatter: JsonFormatter,
    include_baseline: bool,
    include_ci_metadata: bool,
}

impl JsonOutputBuilder {
    pub fn new() -> Self {
        Self {
            formatter: JsonFormatter::new(),
            include_baseline: false,
            include_ci_metadata: false,
        }
    }

    pub fn with_metadata(mut self, include: bool) -> Self {
        self.formatter = self.formatter.with_metadata(include);
        self
    }

    pub fn with_statistics(mut self, include: bool) -> Self {
        self.formatter = self.formatter.with_statistics(include);
        self
    }

    pub fn with_pretty_print(mut self, pretty: bool) -> Self {
        self.formatter = self.formatter.with_pretty_print(pretty);
        self
    }

    pub fn with_baseline_comparison(mut self, include: bool) -> Self {
        self.include_baseline = include;
        self
    }

    pub fn with_ci_metadata(mut self, include: bool) -> Self {
        self.include_ci_metadata = include;
        self
    }

    pub fn build(self) -> JsonFormatter {
        self.formatter
    }
}

impl Default for JsonOutputBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use detectors::types::{DetectorId, FixSuggestion, TextReplacement};

    fn create_test_finding() -> Finding {
        Finding {
            detector_id: DetectorId::new("test-detector"),
            message: "Test vulnerability detected".to_string(),
            severity: Severity::High,
            line: 42,
            column: 10,
            length: 15,
            cwe: Some(123),
            fix_suggestion: Some(FixSuggestion {
                description: "Add access control".to_string(),
                replacements: vec![TextReplacement {
                    start_line: 42,
                    start_column: 10,
                    end_line: 42,
                    end_column: 25,
                    new_text: "require(msg.sender == owner); ".to_string(),
                }],
            }),
        }
    }

    #[test]
    fn test_json_formatter_basic() {
        let formatter = JsonFormatter::new();
        let findings = vec![create_test_finding()];

        let result = formatter.format(&findings).unwrap();

        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed["findings"].is_array());
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_json_formatter_no_metadata() {
        let formatter = JsonFormatter::new().with_metadata(false);
        let findings = vec![create_test_finding()];

        let result = formatter.format(&findings).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert!(parsed["metadata"].is_null());
    }

    #[test]
    fn test_json_formatter_statistics() {
        let formatter = JsonFormatter::new();
        let findings = vec![
            create_test_finding(),
            Finding {
                detector_id: DetectorId::new("another-detector"),
                message: "Another issue".to_string(),
                severity: Severity::Critical,
                line: 1,
                column: 1,
                length: 5,
                cwe: None,
                fix_suggestion: None,
            },
        ];

        let result = formatter.format(&findings).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        let stats = &parsed["statistics"];
        assert_eq!(stats["total_findings"], 2);
        assert_eq!(stats["severity_counts"]["high"], 1);
        assert_eq!(stats["severity_counts"]["critical"], 1);
        assert_eq!(stats["unique_detectors"], 2);
    }

    #[test]
    fn test_json_formatter_compact() {
        let formatter = JsonFormatter::new().with_pretty_print(false);
        let findings = vec![create_test_finding()];

        let result = formatter.format(&findings).unwrap();

        // Compact JSON should not contain unnecessary whitespace
        assert!(!result.contains("  "));
        assert!(!result.contains("\n"));
    }

    #[test]
    fn test_json_severity_conversion() {
        assert!(matches!(JsonSeverity::from(&Severity::Critical), JsonSeverity::Critical));
        assert!(matches!(JsonSeverity::from(&Severity::High), JsonSeverity::High));
        assert!(matches!(JsonSeverity::from(&Severity::Medium), JsonSeverity::Medium));
        assert!(matches!(JsonSeverity::from(&Severity::Low), JsonSeverity::Low));
        assert!(matches!(JsonSeverity::from(&Severity::Info), JsonSeverity::Info));
    }

    #[test]
    fn test_json_output_builder() {
        let formatter = JsonOutputBuilder::new()
            .with_metadata(false)
            .with_statistics(true)
            .with_pretty_print(false)
            .build();

        let findings = vec![create_test_finding()];
        let result = formatter.format(&findings).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert!(parsed["metadata"].is_null());
        assert!(parsed["statistics"].is_object());
        assert!(!result.contains("\n"));
    }

    #[test]
    fn test_empty_findings() {
        let formatter = JsonFormatter::new();
        let findings = vec![];

        let result = formatter.format(&findings).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["statistics"]["total_findings"], 0);
    }
}