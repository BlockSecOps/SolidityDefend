//! Project security summary generation
//!
//! Provides high-level security overview for project analysis results.

use detectors::types::{Finding, Severity};
use std::collections::HashMap;

/// Project security summary for executive reporting
#[derive(Debug, Clone)]
pub struct ProjectSummary {
    /// Total contracts analyzed
    pub contracts_analyzed: usize,
    /// Number of source contracts
    pub source_contracts: usize,
    /// Number of dependency contracts
    pub dependency_contracts: usize,
    /// Total findings
    pub total_findings: usize,
    /// Critical severity findings count
    pub critical_count: usize,
    /// High severity findings count
    pub high_count: usize,
    /// Medium severity findings count
    pub medium_count: usize,
    /// Low severity findings count
    pub low_count: usize,
    /// Info severity findings count
    pub info_count: usize,
    /// Cross-contract findings count
    pub cross_contract_findings: usize,
    /// Files with critical issues
    pub files_with_critical: Vec<String>,
    /// Protocol risk score (0.0 - 10.0)
    pub risk_score: f32,
    /// Analysis duration in seconds
    pub analysis_duration_secs: f64,
    /// Source findings (categorized)
    pub source_finding_count: usize,
    /// Dependency findings (categorized)
    pub dependency_finding_count: usize,
}

impl ProjectSummary {
    /// Create a new project summary from findings
    pub fn from_findings(
        findings: &[Finding],
        source_findings: &[Finding],
        dep_findings: &[Finding],
        source_contracts: usize,
        dependency_contracts: usize,
        cross_contract_findings: usize,
        analysis_duration_secs: f64,
    ) -> Self {
        let mut severity_counts: HashMap<Severity, usize> = HashMap::new();
        let mut files_with_critical: Vec<String> = Vec::new();

        for finding in findings {
            *severity_counts.entry(finding.severity).or_insert(0) += 1;

            if finding.severity == Severity::Critical {
                let file = finding.primary_location.file.clone();
                if !files_with_critical.contains(&file) {
                    files_with_critical.push(file);
                }
            }
        }

        let critical_count = *severity_counts.get(&Severity::Critical).unwrap_or(&0);
        let high_count = *severity_counts.get(&Severity::High).unwrap_or(&0);
        let medium_count = *severity_counts.get(&Severity::Medium).unwrap_or(&0);
        let low_count = *severity_counts.get(&Severity::Low).unwrap_or(&0);
        let info_count = *severity_counts.get(&Severity::Info).unwrap_or(&0);

        // Calculate risk score
        let risk_score = Self::calculate_risk_score(
            critical_count,
            high_count,
            medium_count,
            low_count,
        );

        Self {
            contracts_analyzed: source_contracts + dependency_contracts,
            source_contracts,
            dependency_contracts,
            total_findings: findings.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            cross_contract_findings,
            files_with_critical,
            risk_score,
            analysis_duration_secs,
            source_finding_count: source_findings.len(),
            dependency_finding_count: dep_findings.len(),
        }
    }

    /// Calculate a risk score from 0.0 to 10.0
    fn calculate_risk_score(
        critical: usize,
        high: usize,
        medium: usize,
        low: usize,
    ) -> f32 {
        let score = (critical as f32 * 5.0)
            + (high as f32 * 3.0)
            + (medium as f32 * 1.5)
            + (low as f32 * 0.5);
        score.min(10.0)
    }

    /// Get the risk level as a string
    pub fn risk_level(&self) -> &'static str {
        match self.risk_score {
            s if s == 0.0 => "Excellent",
            s if s < 3.0 => "Low Risk",
            s if s < 6.0 => "Medium Risk",
            _ => "High Risk",
        }
    }

    /// Render the summary as a formatted string
    pub fn render(&self) -> String {
        let mut output = String::new();

        output.push_str("\n=== Project Security Summary ===\n");
        output.push_str(&format!(
            "Contracts Analyzed: {} ({} source, {} dependencies)\n",
            self.contracts_analyzed, self.source_contracts, self.dependency_contracts
        ));

        output.push_str("\nFindings Overview:\n");
        if self.critical_count > 0 {
            output.push_str(&format!("  Critical: {} (IMMEDIATE ACTION REQUIRED)\n", self.critical_count));
        }
        if self.high_count > 0 {
            output.push_str(&format!("  High:     {} (should be addressed)\n", self.high_count));
        }
        if self.medium_count > 0 {
            output.push_str(&format!("  Medium:   {}\n", self.medium_count));
        }
        if self.low_count > 0 {
            output.push_str(&format!("  Low:      {}\n", self.low_count));
        }
        if self.info_count > 0 {
            output.push_str(&format!("  Info:     {}\n", self.info_count));
        }

        if self.cross_contract_findings > 0 {
            output.push_str(&format!("\n  Cross-Contract Issues: {}\n", self.cross_contract_findings));
        }

        if !self.files_with_critical.is_empty() {
            output.push_str("\nFiles with Critical Issues:\n");
            for file in &self.files_with_critical {
                output.push_str(&format!("  - {}\n", file));
            }
        }

        output.push_str(&format!(
            "\nProtocol Risk Score: {:.1}/10 ({})\n",
            self.risk_score, self.risk_level()
        ));

        output.push_str(&format!(
            "\nAnalysis completed in {:.2}s\n",
            self.analysis_duration_secs
        ));

        output
    }

    /// Render as JSON-compatible structure
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "contracts_analyzed": self.contracts_analyzed,
            "source_contracts": self.source_contracts,
            "dependency_contracts": self.dependency_contracts,
            "findings": {
                "total": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
                "cross_contract": self.cross_contract_findings,
                "source": self.source_finding_count,
                "dependency": self.dependency_finding_count
            },
            "files_with_critical": self.files_with_critical,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level(),
            "analysis_duration_secs": self.analysis_duration_secs
        })
    }
}

/// Categorized findings for source vs dependency separation
#[derive(Debug, Clone)]
pub struct CategorizedFindings {
    /// Findings in source contracts
    pub source_findings: Vec<Finding>,
    /// Findings in dependency contracts
    pub dependency_findings: Vec<Finding>,
}

impl CategorizedFindings {
    /// Categorize findings based on whether they're in dependency paths
    pub fn from_findings(findings: Vec<Finding>, dep_paths: &[std::path::PathBuf]) -> Self {
        let (dep, src): (Vec<_>, Vec<_>) = findings.into_iter().partition(|f| {
            dep_paths.iter().any(|p| {
                f.primary_location.file.contains(&p.to_string_lossy().to_string())
                    || p.to_string_lossy().contains(&f.primary_location.file)
            })
        });

        Self {
            source_findings: src,
            dependency_findings: dep,
        }
    }

    /// Get total finding count
    pub fn total(&self) -> usize {
        self.source_findings.len() + self.dependency_findings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use detectors::types::{Confidence, DetectorId, SourceLocation};

    fn create_test_finding(severity: Severity, file: &str) -> Finding {
        Finding::new(
            DetectorId::new("test-detector"),
            severity,
            Confidence::High,
            "Test finding".to_string(),
            SourceLocation::new(file.to_string(), 1, 1, 10),
        )
    }

    #[test]
    fn test_summary_from_findings() {
        let findings = vec![
            create_test_finding(Severity::Critical, "src/Vault.sol"),
            create_test_finding(Severity::High, "src/Token.sol"),
            create_test_finding(Severity::Medium, "src/Utils.sol"),
        ];

        let summary = ProjectSummary::from_findings(
            &findings,
            &findings,
            &[],
            3,
            0,
            0,
            1.5,
        );

        assert_eq!(summary.total_findings, 3);
        assert_eq!(summary.critical_count, 1);
        assert_eq!(summary.high_count, 1);
        assert_eq!(summary.medium_count, 1);
        assert_eq!(summary.files_with_critical.len(), 1);
        assert!(summary.risk_score > 0.0);
    }

    #[test]
    fn test_risk_score_calculation() {
        // No findings = 0 risk
        let score = ProjectSummary::calculate_risk_score(0, 0, 0, 0);
        assert_eq!(score, 0.0);

        // Max risk is capped at 10
        let score = ProjectSummary::calculate_risk_score(10, 10, 10, 10);
        assert_eq!(score, 10.0);
    }

    #[test]
    fn test_risk_levels() {
        let mut summary = ProjectSummary::from_findings(&[], &[], &[], 0, 0, 0, 0.0);

        summary.risk_score = 0.0;
        assert_eq!(summary.risk_level(), "Excellent");

        summary.risk_score = 2.0;
        assert_eq!(summary.risk_level(), "Low Risk");

        summary.risk_score = 5.0;
        assert_eq!(summary.risk_level(), "Medium Risk");

        summary.risk_score = 8.0;
        assert_eq!(summary.risk_level(), "High Risk");
    }
}
