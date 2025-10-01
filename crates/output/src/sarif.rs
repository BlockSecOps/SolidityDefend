use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use detectors::types::{Finding, AnalysisContext, Severity};

/// SARIF 2.1.0 compliant output formatter
#[derive(Debug)]
pub struct SarifFormatter {
    /// Tool information
    tool_info: ToolInfo,
}

/// Complete SARIF report structure
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

/// SARIF run containing results from a single analysis
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
    pub taxonomies: Option<Vec<SarifTaxonomy>>,
    #[serde(rename = "baselineGuid", skip_serializing_if = "Option::is_none")]
    pub baseline_guid: Option<String>,
}

/// Tool information in SARIF format
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

/// Driver information (the main analysis tool)
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

/// Rule definition in SARIF
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    pub help: SarifMessage,
    pub properties: SarifRuleProperties,
}

/// Rule properties including security information
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRuleProperties {
    #[serde(rename = "security-severity")]
    pub security_severity: String,
    pub tags: Vec<String>,
}

/// SARIF result representing a finding
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    pub level: String,
    #[serde(rename = "baselineState", skip_serializing_if = "Option::is_none")]
    pub baseline_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixes: Option<Vec<SarifFix>>,
    #[serde(rename = "codeFlows", skip_serializing_if = "Option::is_none")]
    pub code_flows: Option<Vec<SarifCodeFlow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taxa: Option<Vec<SarifTaxonReference>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Message structure in SARIF
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

/// Location information in SARIF
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,
}

/// Physical location in source code
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

/// Artifact (file) location
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

/// Region in source code
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: u32,
    #[serde(rename = "startColumn")]
    pub start_column: u32,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
}

/// Fix suggestion in SARIF format
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifFix {
    pub description: SarifMessage,
    #[serde(rename = "artifactChanges")]
    pub artifact_changes: Vec<SarifArtifactChange>,
}

/// Artifact change for fixes
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactChange {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub replacements: Vec<SarifReplacement>,
}

/// Text replacement in SARIF
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifReplacement {
    #[serde(rename = "deletedRegion")]
    pub deleted_region: SarifRegion,
    #[serde(rename = "insertedContent")]
    pub inserted_content: SarifMessage,
}

/// Code flow for showing execution paths
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifCodeFlow {
    #[serde(rename = "threadFlows")]
    pub thread_flows: Vec<SarifThreadFlow>,
}

/// Thread flow showing a sequence of locations
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifThreadFlow {
    pub locations: Vec<SarifThreadFlowLocation>,
}

/// Location in a thread flow
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifThreadFlowLocation {
    pub location: SarifLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
}

/// Taxonomy reference (e.g., CWE)
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTaxonomy {
    pub name: String,
    pub organization: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    pub taxa: Vec<SarifTaxon>,
}

/// Individual taxon (e.g., specific CWE)
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTaxon {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
}

/// Reference to a taxon
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTaxonReference {
    pub id: String,
    #[serde(rename = "toolComponent")]
    pub tool_component: SarifToolComponentReference,
}

/// Tool component reference
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifToolComponentReference {
    pub name: String,
}

/// Tool information
#[derive(Debug, Clone)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub information_uri: String,
}

/// Minimal context for simplified formatting
#[derive(Debug)]
struct MinimalContext {
    pub file_path: String,
}

impl SarifFormatter {
    /// Create a new SARIF formatter
    pub fn new() -> Result<Self> {
        Ok(Self {
            tool_info: ToolInfo {
                name: "SolidityDefend".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                information_uri: "https://github.com/soliditydefend/soliditydefend".to_string(),
            },
        })
    }

    /// Format findings as SARIF report without context (simplified)
    pub fn format_simple(&self, findings: &[Finding]) -> Result<String> {
        // Create a minimal context for SARIF output
        let minimal_ctx = MinimalContext {
            file_path: "unknown".to_string(),
        };

        let rules = self.extract_rules_from_findings(findings);
        let results = self.convert_findings_to_results_simple(findings, &minimal_ctx)?;

        let run = SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: self.tool_info.name.clone(),
                    version: self.tool_info.version.clone(),
                    information_uri: self.tool_info.information_uri.clone(),
                    rules,
                },
            },
            results,
            taxonomies: Some(self.create_taxonomies()),
            baseline_guid: None,
        };

        let report = SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![run],
        };

        serde_json::to_string_pretty(&report).map_err(|e| e.into())
    }

    /// Format findings as SARIF report
    pub fn format_findings(&self, findings: &[Finding], ctx: &AnalysisContext<'_>) -> Result<SarifReport> {
        let rules = self.extract_rules_from_findings(findings);
        let results = self.convert_findings_to_results(findings, ctx)?;

        let run = SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: self.tool_info.name.clone(),
                    version: self.tool_info.version.clone(),
                    information_uri: self.tool_info.information_uri.clone(),
                    rules,
                },
            },
            results,
            taxonomies: Some(self.create_taxonomies()),
            baseline_guid: None,
        };

        Ok(SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![run],
        })
    }

    /// Format findings with fix suggestions
    pub fn format_findings_with_fixes(&self, findings: &[Finding], ctx: &AnalysisContext<'_>) -> Result<SarifReport> {
        let mut report = self.format_findings(findings, ctx)?;

        // Add fix suggestions to results
        for (result, finding) in report.runs[0].results.iter_mut().zip(findings.iter()) {
            if let Some(fix_suggestion) = &finding.fix_suggestion {
                let fix = SarifFix {
                    description: SarifMessage {
                        text: fix_suggestion.clone(),
                    },
                    artifact_changes: vec![SarifArtifactChange {
                        artifact_location: SarifArtifactLocation {
                            uri: ctx.file_path.clone(),
                        },
                        replacements: vec![SarifReplacement {
                            deleted_region: SarifRegion {
                                start_line: finding.primary_location.line,
                                start_column: finding.primary_location.column,
                                end_line: Some(finding.primary_location.line),
                                end_column: Some(finding.primary_location.column + finding.primary_location.length),
                            },
                            inserted_content: SarifMessage {
                                text: "/* TODO: Apply fix */".to_string(),
                            },
                        }],
                    }],
                };
                result.fixes = Some(vec![fix]);
            }
        }

        Ok(report)
    }

    /// Format findings with code flows
    pub fn format_findings_with_flows(&self, findings: &[Finding], ctx: &AnalysisContext<'_>) -> Result<SarifReport> {
        let mut report = self.format_findings(findings, ctx)?;

        // Add code flows for complex vulnerabilities
        for (result, finding) in report.runs[0].results.iter_mut().zip(findings.iter()) {
            if self.should_include_code_flow(&finding.detector_id.0.as_str()) {
                let code_flow = self.create_code_flow_for_finding(finding, ctx);
                result.code_flows = Some(vec![code_flow]);
            }
        }

        Ok(report)
    }

    /// Format with baseline comparison
    pub fn format_with_baseline(
        &self,
        current_findings: &[Finding],
        baseline_findings: &[Finding],
        ctx: &AnalysisContext<'_>,
    ) -> Result<SarifReport> {
        let mut report = self.format_findings(current_findings, ctx)?;

        // Set baseline GUID
        report.runs[0].baseline_guid = Some("baseline-001".to_string());

        // Compare with baseline and set baseline state
        for (result, current_finding) in report.runs[0].results.iter_mut().zip(current_findings.iter()) {
            let baseline_state = if baseline_findings.iter().any(|bf| self.findings_match(bf, current_finding)) {
                "unchanged"
            } else {
                "new"
            };
            result.baseline_state = Some(baseline_state.to_string());
        }

        Ok(report)
    }

    /// Convert to JSON string
    pub fn to_json(&self, report: &SarifReport) -> Result<String> {
        Ok(serde_json::to_string_pretty(report)?)
    }

    /// Extract unique rules from findings
    fn extract_rules_from_findings(&self, findings: &[Finding]) -> Vec<SarifRule> {
        let mut rules_map = HashMap::new();

        for finding in findings {
            let rule_id = finding.detector_id.0.as_str();
            if !rules_map.contains_key(rule_id) {
                let rule = SarifRule {
                    id: rule_id.to_string(),
                    name: self.format_rule_name(rule_id),
                    short_description: SarifMessage {
                        text: finding.message.clone(),
                    },
                    full_description: SarifMessage {
                        text: format!("{}\n\n{}", finding.message,
                            finding.fix_suggestion.as_deref().unwrap_or("Consider reviewing this issue.")),
                    },
                    help: SarifMessage {
                        text: self.get_help_text_for_rule(rule_id),
                    },
                    properties: SarifRuleProperties {
                        security_severity: self.severity_to_string(&finding.severity),
                        tags: self.get_tags_for_rule(rule_id),
                    },
                };
                rules_map.insert(rule_id.to_string(), rule);
            }
        }

        rules_map.into_values().collect()
    }

    /// Convert findings to SARIF results (simplified version)
    fn convert_findings_to_results_simple(&self, findings: &[Finding], ctx: &MinimalContext) -> Result<Vec<SarifResult>> {
        findings.iter().map(|finding| {
            Ok(SarifResult {
                rule_id: finding.detector_id.0.as_str().to_string(),
                message: SarifMessage {
                    text: finding.message.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: ctx.file_path.clone(),
                        },
                        region: SarifRegion {
                            start_line: finding.primary_location.line,
                            start_column: finding.primary_location.column,
                            end_line: None,
                            end_column: None,
                        },
                    },
                    message: None,
                }],
                level: self.severity_to_level(&finding.severity),
                baseline_state: None,
                fixes: None,
                code_flows: None,
                tags: None,
                taxa: None,
            })
        }).collect()
    }

    /// Convert findings to SARIF results
    fn convert_findings_to_results(&self, findings: &[Finding], ctx: &AnalysisContext<'_>) -> Result<Vec<SarifResult>> {
        findings.iter().map(|finding| {
            Ok(SarifResult {
                rule_id: finding.detector_id.0.as_str().to_string(),
                message: SarifMessage {
                    text: finding.message.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: ctx.file_path.clone(),
                        },
                        region: SarifRegion {
                            start_line: finding.primary_location.line,
                            start_column: finding.primary_location.column,
                            end_line: None,
                            end_column: None,
                        },
                    },
                    message: None,
                }],
                level: self.severity_to_level(&finding.severity),
                baseline_state: None,
                fixes: None,
                code_flows: None,
                taxa: finding.cwe_ids.first().map(|cwe| vec![SarifTaxonReference {
                    id: format!("CWE-{}", cwe),
                    tool_component: SarifToolComponentReference {
                        name: "CWE".to_string(),
                    },
                }]),
                tags: Some(vec!["security".to_string()]),
            })
        }).collect()
    }

    /// Create standard taxonomies (CWE, etc.)
    fn create_taxonomies(&self) -> Vec<SarifTaxonomy> {
        vec![
            SarifTaxonomy {
                name: "CWE".to_string(),
                organization: "MITRE".to_string(),
                short_description: SarifMessage {
                    text: "Common Weakness Enumeration".to_string(),
                },
                taxa: vec![
                    SarifTaxon {
                        id: "CWE-476".to_string(),
                        name: "NULL Pointer Dereference".to_string(),
                        short_description: SarifMessage {
                            text: "A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL.".to_string(),
                        },
                    },
                    SarifTaxon {
                        id: "CWE-362".to_string(),
                        name: "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')".to_string(),
                        short_description: SarifMessage {
                            text: "The program contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource.".to_string(),
                        },
                    },
                    SarifTaxon {
                        id: "CWE-269".to_string(),
                        name: "Improper Privilege Management".to_string(),
                        short_description: SarifMessage {
                            text: "The software does not properly assign, modify, track, or check privileges for an actor.".to_string(),
                        },
                    },
                ],
            },
        ]
    }

    /// Check if a finding should include code flow
    fn should_include_code_flow(&self, detector_id: &str) -> bool {
        matches!(detector_id, "reentrancy" | "state-machine-error" | "call-graph-complexity")
    }

    /// Create code flow for a finding
    fn create_code_flow_for_finding(&self, finding: &Finding, ctx: &AnalysisContext<'_>) -> SarifCodeFlow {
        // Simplified code flow - in a real implementation, this would trace execution paths
        SarifCodeFlow {
            thread_flows: vec![SarifThreadFlow {
                locations: vec![
                    SarifThreadFlowLocation {
                        location: SarifLocation {
                            physical_location: SarifPhysicalLocation {
                                artifact_location: SarifArtifactLocation {
                                    uri: ctx.file_path.clone(),
                                },
                                region: SarifRegion {
                                    start_line: finding.primary_location.line,
                                    start_column: finding.primary_location.column,
                                    end_line: None,
                                    end_column: None,
                                },
                            },
                            message: Some(SarifMessage {
                                text: "Vulnerability entry point".to_string(),
                            }),
                        },
                        kinds: Some(vec!["vulnerability".to_string()]),
                    },
                ],
            }],
        }
    }

    /// Check if two findings are the same (for baseline comparison)
    fn findings_match(&self, f1: &Finding, f2: &Finding) -> bool {
        f1.detector_id == f2.detector_id &&
        f1.primary_location.line == f2.primary_location.line &&
        f1.primary_location.column == f2.primary_location.column &&
        f1.message == f2.message
    }

    /// Convert severity to SARIF level
    fn severity_to_level(&self, severity: &Severity) -> String {
        match severity {
            Severity::Critical | Severity::High => "error".to_string(),
            Severity::Medium => "warning".to_string(),
            Severity::Low => "note".to_string(),
            Severity::Info => "note".to_string(),
        }
    }

    /// Convert severity to security severity string
    fn severity_to_string(&self, severity: &Severity) -> String {
        match severity {
            Severity::Critical => "9.0".to_string(),
            Severity::High => "7.0".to_string(),
            Severity::Medium => "5.0".to_string(),
            Severity::Low => "3.0".to_string(),
            Severity::Info => "1.0".to_string(),
        }
    }

    /// Format rule name from detector ID
    fn format_rule_name(&self, rule_id: &str) -> String {
        rule_id.split('-')
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Get help text for a rule
    fn get_help_text_for_rule(&self, rule_id: &str) -> String {
        match rule_id {
            "reentrancy" => "Reentrancy vulnerabilities occur when external calls can call back into the contract before the first invocation is complete. Use the checks-effects-interactions pattern to prevent this.".to_string(),
            "missing-access-control" => "Functions missing access control can be called by anyone. Add appropriate modifiers or require statements to restrict access.".to_string(),
            "missing-zero-address-check" => "Address parameters should be validated to ensure they are not the zero address (0x0) to prevent accidental loss of funds.".to_string(),
            "integer-overflow" => "Integer overflows can cause unexpected behavior. Use SafeMath library or Solidity ^0.8.0 for automatic overflow protection.".to_string(),
            "division-before-multiplication" => "Performing division before multiplication can cause precision loss. Reorder operations to multiply first, then divide.".to_string(),
            _ => "Review this security issue and implement appropriate safeguards.".to_string(),
        }
    }

    /// Get tags for a rule
    fn get_tags_for_rule(&self, rule_id: &str) -> Vec<String> {
        let mut tags = vec!["security".to_string()];

        match rule_id {
            "reentrancy" => tags.push("reentrancy".to_string()),
            "missing-access-control" => tags.push("access-control".to_string()),
            "missing-zero-address-check" => tags.push("validation".to_string()),
            "integer-overflow" => tags.push("arithmetic".to_string()),
            "division-before-multiplication" => tags.push("precision".to_string()),
            _ => {},
        }

        tags
    }
}

impl Default for SarifFormatter {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
