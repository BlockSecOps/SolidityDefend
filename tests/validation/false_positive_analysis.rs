use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub detector: String,
    pub severity: Severity,
    pub file_path: String,
    pub line_number: usize,
    pub description: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruth {
    pub file_path: String,
    pub true_positives: Vec<TruePositive>,
    pub known_false_positives: Vec<KnownFalsePositive>,
    pub annotations: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TruePositive {
    pub detector: String,
    pub line_number: usize,
    pub vulnerability_type: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownFalsePositive {
    pub detector: String,
    pub line_number: usize,
    pub reason: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveAnalysis {
    pub total_findings: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_positive_rate: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub detector_analysis: HashMap<String, DetectorAnalysis>,
    pub severity_analysis: HashMap<Severity, SeverityAnalysis>,
    pub false_positive_patterns: Vec<FalsePositivePattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorAnalysis {
    pub detector_name: String,
    pub total_findings: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub precision: f64,
    pub recall: f64,
    pub common_false_positive_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityAnalysis {
    pub severity: Severity,
    pub total_findings: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_positive_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositivePattern {
    pub pattern_id: String,
    pub description: String,
    pub affected_detectors: Vec<String>,
    pub frequency: usize,
    pub example_code: String,
    pub mitigation_strategy: String,
}

pub struct FalsePositiveAnalyzer {
    ground_truth: HashMap<String, GroundTruth>,
    findings: Vec<Finding>,
    tolerance_threshold: f64,
}

impl FalsePositiveAnalyzer {
    pub fn new(tolerance_threshold: f64) -> Self {
        Self {
            ground_truth: HashMap::new(),
            findings: Vec::new(),
            tolerance_threshold,
        }
    }

    pub fn load_ground_truth(&mut self, ground_truth_file: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(ground_truth_file)?;
        let ground_truth_data: Vec<GroundTruth> = serde_json::from_str(&content)?;

        for gt in ground_truth_data {
            self.ground_truth.insert(gt.file_path.clone(), gt);
        }

        println!("Loaded ground truth for {} files", self.ground_truth.len());
        Ok(())
    }

    pub fn load_findings(&mut self, findings_file: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(findings_file)?;
        self.findings = serde_json::from_str(&content)?;
        println!("Loaded {} findings for analysis", self.findings.len());
        Ok(())
    }

    pub fn analyze(&self) -> FalsePositiveAnalysis {
        let mut true_positives = 0;
        let mut false_positives = 0;
        let mut detector_stats: HashMap<String, (usize, usize, usize)> = HashMap::new();
        let mut severity_stats: HashMap<Severity, (usize, usize, usize)> = HashMap::new();
        let mut false_positive_reasons: HashMap<String, Vec<String>> = HashMap::new();

        for finding in &self.findings {
            let is_true_positive = self.is_true_positive(finding);

            if is_true_positive {
                true_positives += 1;
            } else {
                false_positives += 1;
                self.record_false_positive_reason(finding, &mut false_positive_reasons);
            }

            // Update detector statistics
            let detector_entry = detector_stats.entry(finding.detector.clone()).or_insert((0, 0, 0));
            detector_entry.0 += 1; // total
            if is_true_positive {
                detector_entry.1 += 1; // tp
            } else {
                detector_entry.2 += 1; // fp
            }

            // Update severity statistics
            let severity_entry = severity_stats.entry(finding.severity.clone()).or_insert((0, 0, 0));
            severity_entry.0 += 1; // total
            if is_true_positive {
                severity_entry.1 += 1; // tp
            } else {
                severity_entry.2 += 1; // fp
            }
        }

        let total_findings = self.findings.len();
        let false_positive_rate = if total_findings > 0 {
            false_positives as f64 / total_findings as f64
        } else {
            0.0
        };

        let precision = if total_findings > 0 {
            true_positives as f64 / total_findings as f64
        } else {
            0.0
        };

        // Calculate recall (would need additional ground truth data for all expected vulnerabilities)
        let recall = self.calculate_recall();
        let f1_score = if precision + recall > 0.0 {
            2.0 * (precision * recall) / (precision + recall)
        } else {
            0.0
        };

        // Build detector analysis
        let detector_analysis = detector_stats.into_iter().map(|(detector, (total, tp, fp))| {
            let precision = if total > 0 { tp as f64 / total as f64 } else { 0.0 };
            let recall = self.calculate_detector_recall(&detector);
            let common_reasons = false_positive_reasons.get(&detector)
                .cloned()
                .unwrap_or_default();

            (detector.clone(), DetectorAnalysis {
                detector_name: detector,
                total_findings: total,
                true_positives: tp,
                false_positives: fp,
                precision,
                recall,
                common_false_positive_reasons: common_reasons,
            })
        }).collect();

        // Build severity analysis
        let severity_analysis = severity_stats.into_iter().map(|(severity, (total, tp, fp))| {
            let fp_rate = if total > 0 { fp as f64 / total as f64 } else { 0.0 };
            (severity.clone(), SeverityAnalysis {
                severity: severity.clone(),
                total_findings: total,
                true_positives: tp,
                false_positives: fp,
                false_positive_rate: fp_rate,
            })
        }).collect();

        // Identify false positive patterns
        let false_positive_patterns = self.identify_false_positive_patterns();

        FalsePositiveAnalysis {
            total_findings,
            true_positives,
            false_positives,
            false_positive_rate,
            precision,
            recall,
            f1_score,
            detector_analysis,
            severity_analysis,
            false_positive_patterns,
        }
    }

    fn is_true_positive(&self, finding: &Finding) -> bool {
        if let Some(ground_truth) = self.ground_truth.get(&finding.file_path) {
            // Check if this finding matches any known true positive
            for tp in &ground_truth.true_positives {
                if tp.detector == finding.detector &&
                   self.line_numbers_match(tp.line_number, finding.line_number) {
                    return true;
                }
            }

            // Check if this finding is a known false positive
            for fp in &ground_truth.known_false_positives {
                if fp.detector == finding.detector &&
                   self.line_numbers_match(fp.line_number, finding.line_number) {
                    return false;
                }
            }
        }

        // If no ground truth available, use confidence threshold
        finding.confidence >= self.tolerance_threshold
    }

    fn line_numbers_match(&self, expected: usize, actual: usize) -> bool {
        // Allow some tolerance for line number matching (e.g., ±2 lines)
        (expected as i32 - actual as i32).abs() <= 2
    }

    fn record_false_positive_reason(&self, finding: &Finding, reasons: &mut HashMap<String, Vec<String>>) {
        if let Some(ground_truth) = self.ground_truth.get(&finding.file_path) {
            for fp in &ground_truth.known_false_positives {
                if fp.detector == finding.detector &&
                   self.line_numbers_match(fp.line_number, finding.line_number) {
                    reasons.entry(finding.detector.clone())
                        .or_insert_with(Vec::new)
                        .push(fp.reason.clone());
                    return;
                }
            }
        }

        // Default reason for unclassified false positives
        reasons.entry(finding.detector.clone())
            .or_insert_with(Vec::new)
            .push("Unclassified false positive".to_string());
    }

    fn calculate_recall(&self) -> f64 {
        let mut total_expected_vulnerabilities = 0;
        let mut detected_vulnerabilities = 0;

        for ground_truth in self.ground_truth.values() {
            total_expected_vulnerabilities += ground_truth.true_positives.len();

            for tp in &ground_truth.true_positives {
                if self.findings.iter().any(|f| {
                    f.detector == tp.detector &&
                    f.file_path == ground_truth.file_path &&
                    self.line_numbers_match(tp.line_number, f.line_number)
                }) {
                    detected_vulnerabilities += 1;
                }
            }
        }

        if total_expected_vulnerabilities > 0 {
            detected_vulnerabilities as f64 / total_expected_vulnerabilities as f64
        } else {
            1.0 // Perfect recall if no vulnerabilities expected
        }
    }

    fn calculate_detector_recall(&self, detector: &str) -> f64 {
        let mut total_expected = 0;
        let mut detected = 0;

        for ground_truth in self.ground_truth.values() {
            for tp in &ground_truth.true_positives {
                if tp.detector == detector {
                    total_expected += 1;

                    if self.findings.iter().any(|f| {
                        f.detector == detector &&
                        f.file_path == ground_truth.file_path &&
                        self.line_numbers_match(tp.line_number, f.line_number)
                    }) {
                        detected += 1;
                    }
                }
            }
        }

        if total_expected > 0 {
            detected as f64 / total_expected as f64
        } else {
            1.0
        }
    }

    fn identify_false_positive_patterns(&self) -> Vec<FalsePositivePattern> {
        let mut patterns = Vec::new();

        // Pattern 1: Safe external calls flagged as reentrancy
        let safe_external_calls = self.count_pattern_occurrences("reentrancy", "safe external call");
        if safe_external_calls > 0 {
            patterns.push(FalsePositivePattern {
                pattern_id: "SAFE_EXTERNAL_CALLS".to_string(),
                description: "Safe external calls incorrectly flagged as reentrancy vulnerabilities".to_string(),
                affected_detectors: vec!["reentrancy".to_string()],
                frequency: safe_external_calls,
                example_code: "function safeTransfer(address to, uint256 amount) external {\n    require(balances[msg.sender] >= amount);\n    balances[msg.sender] -= amount;\n    (bool success,) = to.call{value: amount}(\"\");\n    require(success);\n}".to_string(),
                mitigation_strategy: "Improve reentrancy detection to recognize state changes before external calls".to_string(),
            });
        }

        // Pattern 2: Library functions flagged as unprotected
        let library_functions = self.count_pattern_occurrences("access-control", "library function");
        if library_functions > 0 {
            patterns.push(FalsePositivePattern {
                pattern_id: "LIBRARY_FUNCTIONS".to_string(),
                description: "Library functions incorrectly flagged as missing access control".to_string(),
                affected_detectors: vec!["access-control".to_string()],
                frequency: library_functions,
                example_code: "library SafeMath {\n    function add(uint256 a, uint256 b) internal pure returns (uint256) {\n        return a + b;\n    }\n}".to_string(),
                mitigation_strategy: "Exclude library functions from access control checks".to_string(),
            });
        }

        // Pattern 3: View functions flagged for state changes
        let view_functions = self.count_pattern_occurrences("state-change", "view function");
        if view_functions > 0 {
            patterns.push(FalsePositivePattern {
                pattern_id: "VIEW_FUNCTIONS".to_string(),
                description: "View functions incorrectly flagged for state modifications".to_string(),
                affected_detectors: vec!["state-change".to_string()],
                frequency: view_functions,
                example_code: "function getBalance(address user) external view returns (uint256) {\n    return balances[user];\n}".to_string(),
                mitigation_strategy: "Properly handle view/pure function modifiers in analysis".to_string(),
            });
        }

        patterns
    }

    fn count_pattern_occurrences(&self, detector: &str, pattern: &str) -> usize {
        let mut count = 0;

        for ground_truth in self.ground_truth.values() {
            for fp in &ground_truth.known_false_positives {
                if fp.detector == detector && fp.reason.to_lowercase().contains(&pattern.to_lowercase()) {
                    count += 1;
                }
            }
        }

        count
    }

    pub fn generate_report(&self, analysis: &FalsePositiveAnalysis) -> String {
        let mut report = String::new();
        report.push_str("# False Positive Analysis Report\n\n");

        // Overall metrics
        report.push_str("## Overall Metrics\n\n");
        report.push_str(&format!("- Total Findings: {}\n", analysis.total_findings));
        report.push_str(&format!("- True Positives: {}\n", analysis.true_positives));
        report.push_str(&format!("- False Positives: {}\n", analysis.false_positives));
        report.push_str(&format!("- False Positive Rate: {:.2}%\n", analysis.false_positive_rate * 100.0));
        report.push_str(&format!("- Precision: {:.2}%\n", analysis.precision * 100.0));
        report.push_str(&format!("- Recall: {:.2}%\n", analysis.recall * 100.0));
        report.push_str(&format!("- F1 Score: {:.3}\n\n", analysis.f1_score));

        // Detector analysis
        report.push_str("## Detector Analysis\n\n");
        report.push_str("| Detector | Total | TP | FP | Precision | Recall |\n");
        report.push_str("|----------|-------|----|----|-----------|--------|\n");

        for (_, detector_analysis) in &analysis.detector_analysis {
            report.push_str(&format!(
                "| {} | {} | {} | {} | {:.2}% | {:.2}% |\n",
                detector_analysis.detector_name,
                detector_analysis.total_findings,
                detector_analysis.true_positives,
                detector_analysis.false_positives,
                detector_analysis.precision * 100.0,
                detector_analysis.recall * 100.0
            ));
        }

        // Severity analysis
        report.push_str("\n## Severity Analysis\n\n");
        report.push_str("| Severity | Total | TP | FP | FP Rate |\n");
        report.push_str("|----------|-------|----|----|----------|\n");

        for (_, severity_analysis) in &analysis.severity_analysis {
            report.push_str(&format!(
                "| {:?} | {} | {} | {} | {:.2}% |\n",
                severity_analysis.severity,
                severity_analysis.total_findings,
                severity_analysis.true_positives,
                severity_analysis.false_positives,
                severity_analysis.false_positive_rate * 100.0
            ));
        }

        // False positive patterns
        report.push_str("\n## Common False Positive Patterns\n\n");
        for pattern in &analysis.false_positive_patterns {
            report.push_str(&format!("### {}\n\n", pattern.pattern_id));
            report.push_str(&format!("**Description:** {}\n\n", pattern.description));
            report.push_str(&format!("**Frequency:** {} occurrences\n\n", pattern.frequency));
            report.push_str(&format!("**Affected Detectors:** {}\n\n", pattern.affected_detectors.join(", ")));
            report.push_str("**Example Code:**\n");
            report.push_str("```solidity\n");
            report.push_str(&pattern.example_code);
            report.push_str("\n```\n\n");
            report.push_str(&format!("**Mitigation Strategy:** {}\n\n", pattern.mitigation_strategy));
        }

        report
    }

    pub fn save_analysis(&self, analysis: &FalsePositiveAnalysis, output_file: &str) -> Result<(), Box<dyn std::error::Error>> {
        let json_output = serde_json::to_string_pretty(analysis)?;
        std::fs::write(output_file, json_output)?;
        println!("False positive analysis saved to: {}", output_file);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_false_positive_analyzer_creation() {
        let analyzer = FalsePositiveAnalyzer::new(0.8);
        assert_eq!(analyzer.tolerance_threshold, 0.8);
        assert!(analyzer.ground_truth.is_empty());
        assert!(analyzer.findings.is_empty());
    }

    #[test]
    fn test_line_numbers_match() {
        let analyzer = FalsePositiveAnalyzer::new(0.8);
        assert!(analyzer.line_numbers_match(10, 10));
        assert!(analyzer.line_numbers_match(10, 12));
        assert!(analyzer.line_numbers_match(10, 8));
        assert!(!analyzer.line_numbers_match(10, 15));
        assert!(!analyzer.line_numbers_match(10, 5));
    }

    #[test]
    fn test_false_positive_analysis_calculation() {
        let mut analyzer = FalsePositiveAnalyzer::new(0.8);

        // Add test findings
        analyzer.findings = vec![
            Finding {
                id: "1".to_string(),
                detector: "reentrancy".to_string(),
                severity: Severity::High,
                file_path: "test.sol".to_string(),
                line_number: 10,
                description: "Potential reentrancy".to_string(),
                confidence: 0.9,
            },
            Finding {
                id: "2".to_string(),
                detector: "access-control".to_string(),
                severity: Severity::Medium,
                file_path: "test.sol".to_string(),
                line_number: 20,
                description: "Missing access control".to_string(),
                confidence: 0.7, // Below threshold, should be FP
            },
        ];

        let analysis = analyzer.analyze();
        assert_eq!(analysis.total_findings, 2);
        assert_eq!(analysis.true_positives, 1);
        assert_eq!(analysis.false_positives, 1);
        assert_eq!(analysis.false_positive_rate, 0.5);
    }

    #[test]
    fn test_pattern_identification() {
        let _analyzer = FalsePositiveAnalyzer::new(0.8);

        // Add ground truth with known false positive patterns
        let mut ground_truth = HashMap::new();
        ground_truth.insert("test.sol".to_string(), GroundTruth {
            file_path: "test.sol".to_string(),
            true_positives: vec![],
            known_false_positives: vec![
                KnownFalsePositive {
                    detector: "reentrancy".to_string(),
                    line_number: 10,
                    reason: "safe external call".to_string(),
                    explanation: "This is a safe external call".to_string(),
                },
            ],
            annotations: HashMap::new(),
        });

        let analyzer_with_gt = FalsePositiveAnalyzer {
            ground_truth,
            findings: vec![],
            tolerance_threshold: 0.8,
        };

        let patterns = analyzer_with_gt.identify_false_positive_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.pattern_id == "SAFE_EXTERNAL_CALLS"));
    }
}