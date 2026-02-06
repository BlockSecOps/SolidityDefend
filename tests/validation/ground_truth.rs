//! Ground truth validation module for detector accuracy testing
//!
//! This module provides structures and functions for validating SolidityDefend
//! detector output against labeled ground truth data.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Ground truth dataset containing labeled vulnerability data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruthDataset {
    /// Version of the ground truth format
    pub version: String,
    /// Description of the dataset
    pub description: String,
    /// Last update timestamp
    pub last_updated: String,
    /// Contract-level ground truth data
    pub contracts: HashMap<String, ContractGroundTruth>,
    /// Dataset metadata
    pub metadata: DatasetMetadata,
}

/// Ground truth data for a single contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractGroundTruth {
    /// Contract name
    pub contract_name: String,
    /// Expected vulnerability findings that detectors should report
    pub expected_findings: Vec<ExpectedFinding>,
    /// Known false positives that detectors incorrectly report
    pub known_false_positives: Vec<KnownFalsePositive>,
    /// Sections of code that are intentionally secure
    pub clean_sections: Vec<CleanSection>,
    /// Optional notes about the contract
    #[serde(default)]
    pub notes: Option<String>,
}

/// An expected vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedFinding {
    /// Detector ID that should report this finding
    pub detector_id: String,
    /// Line range where the vulnerability exists [start, end]
    pub line_range: [u32; 2],
    /// Label: true_positive or false_positive
    pub label: String,
    /// Expected severity level
    pub severity: String,
    /// Human-readable description
    pub description: String,
    /// Vulnerability type/category
    pub vulnerability_type: String,
}

/// A known false positive that detectors may incorrectly report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownFalsePositive {
    /// Detector ID that incorrectly reports this
    pub detector_id: String,
    /// Line where the false positive is reported
    pub line: u32,
    /// Why this is a false positive
    pub reason: String,
    /// Pattern category (e.g., "safe-external-call", "library-function")
    #[serde(default)]
    pub pattern: Option<String>,
}

/// A section of code that is intentionally secure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanSection {
    /// Line range of the clean section
    pub line_range: [u32; 2],
    /// Description of why this section is secure
    pub description: String,
}

/// Dataset metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetMetadata {
    /// Total number of contracts in the dataset
    pub total_contracts: usize,
    /// Total number of expected findings
    pub total_expected_findings: usize,
    /// Breakdown by vulnerability category
    pub categories: HashMap<String, usize>,
}

/// Result of validating detector output against ground truth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// True positives: correctly detected vulnerabilities
    pub true_positives: Vec<MatchedFinding>,
    /// False negatives: missed vulnerabilities
    pub false_negatives: Vec<ExpectedFinding>,
    /// False positives: incorrect detections
    pub false_positives: Vec<ActualFinding>,
    /// Precision: TP / (TP + FP)
    pub precision: f64,
    /// Recall: TP / (TP + FN)
    pub recall: f64,
    /// F1 Score: 2 * (P * R) / (P + R)
    pub f1_score: f64,
    /// Regressions: newly missed vulnerabilities compared to baseline
    pub regressions: Vec<Regression>,
    /// Per-detector metrics
    pub detector_metrics: HashMap<String, DetectorMetrics>,
    /// Summary statistics
    pub summary: ValidationSummary,
}

/// A finding that was correctly matched
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedFinding {
    /// The expected finding from ground truth
    pub expected: ExpectedFinding,
    /// The actual finding from the detector
    pub actual: ActualFinding,
    /// Match confidence (1.0 = exact match)
    pub match_confidence: f64,
}

/// An actual finding from detector output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActualFinding {
    /// Detector ID
    pub detector_id: String,
    /// File path
    pub file_path: String,
    /// Line number
    pub line: u32,
    /// Column number
    pub column: u32,
    /// Severity level
    pub severity: String,
    /// Finding message
    pub message: String,
}

/// A regression: vulnerability that was previously detected but is now missed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Regression {
    /// The expected finding that regressed
    pub expected: ExpectedFinding,
    /// File where the regression occurred
    pub file_path: String,
    /// Previous version where this was detected
    pub previously_detected_in: Option<String>,
}

/// Metrics for a specific detector
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DetectorMetrics {
    /// Detector ID
    pub detector_id: String,
    /// True positive count
    pub true_positives: usize,
    /// False positive count
    pub false_positives: usize,
    /// False negative count
    pub false_negatives: usize,
    /// Precision
    pub precision: f64,
    /// Recall
    pub recall: f64,
    /// F1 Score
    pub f1_score: f64,
}

/// Summary statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidationSummary {
    /// Total files analyzed
    pub total_files: usize,
    /// Total expected findings
    pub total_expected: usize,
    /// Total actual findings
    pub total_actual: usize,
    /// Total true positives
    pub total_true_positives: usize,
    /// Total false positives
    pub total_false_positives: usize,
    /// Total false negatives
    pub total_false_negatives: usize,
    /// Total regressions
    pub total_regressions: usize,
}

impl GroundTruthDataset {
    /// Load ground truth from a JSON file
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let dataset: GroundTruthDataset = serde_json::from_str(&content)?;
        Ok(dataset)
    }

    /// Save ground truth to a JSON file
    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Get all expected findings across all contracts
    pub fn all_expected_findings(&self) -> Vec<(&str, &ExpectedFinding)> {
        self.contracts
            .iter()
            .flat_map(|(path, gt)| gt.expected_findings.iter().map(move |f| (path.as_str(), f)))
            .collect()
    }

    /// Get expected findings for a specific contract
    pub fn get_contract_findings(&self, path: &str) -> Option<&Vec<ExpectedFinding>> {
        self.contracts.get(path).map(|gt| &gt.expected_findings)
    }
}

/// Validator that compares detector output against ground truth
pub struct GroundTruthValidator {
    ground_truth: GroundTruthDataset,
    line_tolerance: u32,
}

impl GroundTruthValidator {
    /// Create a new validator with the given ground truth dataset
    pub fn new(ground_truth: GroundTruthDataset) -> Self {
        Self {
            ground_truth,
            line_tolerance: 3, // Allow 3 lines of difference for matching
        }
    }

    /// Set the line tolerance for matching findings
    pub fn with_line_tolerance(mut self, tolerance: u32) -> Self {
        self.line_tolerance = tolerance;
        self
    }

    /// Validate actual findings against ground truth
    pub fn validate(&self, actual_findings: &[ActualFinding]) -> ValidationResult {
        let mut true_positives = Vec::new();
        let mut false_negatives = Vec::new();
        let mut false_positives = Vec::new();
        let mut detector_metrics: HashMap<String, DetectorMetrics> = HashMap::new();

        // Track which expected findings have been matched
        let mut matched_expected: HashMap<String, Vec<bool>> = HashMap::new();
        for (path, gt) in &self.ground_truth.contracts {
            matched_expected.insert(path.clone(), vec![false; gt.expected_findings.len()]);
        }

        // Track which actual findings have been matched
        let mut matched_actual = vec![false; actual_findings.len()];

        // Match actual findings to expected findings
        for (actual_idx, actual) in actual_findings.iter().enumerate() {
            let normalized_path = self.normalize_path(&actual.file_path);

            if let Some(gt) = self.ground_truth.contracts.get(&normalized_path) {
                let mut best_match: Option<(usize, f64)> = None;

                for (expected_idx, expected) in gt.expected_findings.iter().enumerate() {
                    if self.findings_match(expected, actual) {
                        let confidence = self.match_confidence(expected, actual);
                        if best_match.map_or(true, |(_, c)| confidence > c) {
                            best_match = Some((expected_idx, confidence));
                        }
                    }
                }

                if let Some((expected_idx, confidence)) = best_match {
                    // Mark as matched
                    if let Some(matches) = matched_expected.get_mut(&normalized_path) {
                        matches[expected_idx] = true;
                    }
                    matched_actual[actual_idx] = true;

                    true_positives.push(MatchedFinding {
                        expected: gt.expected_findings[expected_idx].clone(),
                        actual: actual.clone(),
                        match_confidence: confidence,
                    });

                    // Update detector metrics
                    let metrics = detector_metrics
                        .entry(actual.detector_id.clone())
                        .or_insert_with(|| DetectorMetrics {
                            detector_id: actual.detector_id.clone(),
                            ..Default::default()
                        });
                    metrics.true_positives += 1;
                } else {
                    // Check if this is a known false positive
                    let is_known_fp = gt.known_false_positives.iter().any(|kfp| {
                        kfp.detector_id == actual.detector_id
                            && (actual.line as i32 - kfp.line as i32).abs()
                                <= self.line_tolerance as i32
                    });

                    if !is_known_fp {
                        false_positives.push(actual.clone());

                        let metrics = detector_metrics
                            .entry(actual.detector_id.clone())
                            .or_insert_with(|| DetectorMetrics {
                                detector_id: actual.detector_id.clone(),
                                ..Default::default()
                            });
                        metrics.false_positives += 1;
                    }
                }
            } else {
                // File not in ground truth - count as false positive
                false_positives.push(actual.clone());

                let metrics = detector_metrics
                    .entry(actual.detector_id.clone())
                    .or_insert_with(|| DetectorMetrics {
                        detector_id: actual.detector_id.clone(),
                        ..Default::default()
                    });
                metrics.false_positives += 1;
            }
        }

        // Find false negatives (expected findings that weren't matched)
        for (path, gt) in &self.ground_truth.contracts {
            if let Some(matches) = matched_expected.get(path) {
                for (idx, &matched) in matches.iter().enumerate() {
                    if !matched {
                        let expected = &gt.expected_findings[idx];
                        false_negatives.push(expected.clone());

                        let metrics = detector_metrics
                            .entry(expected.detector_id.clone())
                            .or_insert_with(|| DetectorMetrics {
                                detector_id: expected.detector_id.clone(),
                                ..Default::default()
                            });
                        metrics.false_negatives += 1;
                    }
                }
            }
        }

        // Calculate overall metrics
        let tp = true_positives.len() as f64;
        let fp = false_positives.len() as f64;
        let fn_ = false_negatives.len() as f64;

        let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        let recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        let f1_score = if precision + recall > 0.0 {
            2.0 * (precision * recall) / (precision + recall)
        } else {
            0.0
        };

        // Calculate per-detector metrics
        for metrics in detector_metrics.values_mut() {
            let tp = metrics.true_positives as f64;
            let fp = metrics.false_positives as f64;
            let fn_ = metrics.false_negatives as f64;

            metrics.precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
            metrics.recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
            metrics.f1_score = if metrics.precision + metrics.recall > 0.0 {
                2.0 * (metrics.precision * metrics.recall) / (metrics.precision + metrics.recall)
            } else {
                0.0
            };
        }

        let summary = ValidationSummary {
            total_files: self.ground_truth.contracts.len(),
            total_expected: self
                .ground_truth
                .contracts
                .values()
                .map(|gt| gt.expected_findings.len())
                .sum(),
            total_actual: actual_findings.len(),
            total_true_positives: true_positives.len(),
            total_false_positives: false_positives.len(),
            total_false_negatives: false_negatives.len(),
            total_regressions: 0, // Would need baseline comparison
        };

        ValidationResult {
            true_positives,
            false_negatives,
            false_positives,
            precision,
            recall,
            f1_score,
            regressions: Vec::new(),
            detector_metrics,
            summary,
        }
    }

    /// Check if an expected finding matches an actual finding
    fn findings_match(&self, expected: &ExpectedFinding, actual: &ActualFinding) -> bool {
        // Detector ID must match
        if expected.detector_id != actual.detector_id {
            return false;
        }

        // Line must be within the expected range (with tolerance)
        let line = actual.line;
        let start = expected.line_range[0].saturating_sub(self.line_tolerance);
        let end = expected.line_range[1] + self.line_tolerance;

        line >= start && line <= end
    }

    /// Calculate match confidence between expected and actual findings
    fn match_confidence(&self, expected: &ExpectedFinding, actual: &ActualFinding) -> f64 {
        let mut confidence: f64 = 0.5; // Base confidence for detector match

        // Bonus for exact line match
        if actual.line >= expected.line_range[0] && actual.line <= expected.line_range[1] {
            confidence += 0.3;
        }

        // Bonus for severity match
        if expected.severity.to_lowercase() == actual.severity.to_lowercase() {
            confidence += 0.2;
        }

        confidence.min(1.0)
    }

    /// Normalize file path for matching
    fn normalize_path(&self, path: &str) -> String {
        // Remove leading "./" and standardize separators
        let normalized = path.trim_start_matches("./");
        normalized.replace('\\', "/")
    }
}

impl ValidationResult {
    /// Generate a human-readable report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("╔══════════════════════════════════════════════════════════════╗\n");
        report.push_str("║              DETECTOR VALIDATION REPORT                      ║\n");
        report.push_str("╚══════════════════════════════════════════════════════════════╝\n\n");

        report.push_str("OVERALL METRICS\n");
        report.push_str("═══════════════\n");
        report.push_str(&format!(
            "  True Positives:  {:>4} / {} ({:.1}%)\n",
            self.summary.total_true_positives,
            self.summary.total_expected,
            if self.summary.total_expected > 0 {
                self.summary.total_true_positives as f64 / self.summary.total_expected as f64
                    * 100.0
            } else {
                0.0
            }
        ));
        report.push_str(&format!(
            "  False Negatives: {:>4} / {} ({:.1}%)  <- Missed real vulnerabilities\n",
            self.summary.total_false_negatives,
            self.summary.total_expected,
            if self.summary.total_expected > 0 {
                self.summary.total_false_negatives as f64 / self.summary.total_expected as f64
                    * 100.0
            } else {
                0.0
            }
        ));
        report.push_str(&format!(
            "  False Positives: {:>4} / {} ({:.1}%)\n",
            self.summary.total_false_positives,
            self.summary.total_actual,
            if self.summary.total_actual > 0 {
                self.summary.total_false_positives as f64 / self.summary.total_actual as f64 * 100.0
            } else {
                0.0
            }
        ));
        report.push_str("\n");
        report.push_str(&format!("  Precision: {:.1}%\n", self.precision * 100.0));
        report.push_str(&format!("  Recall:    {:.1}%\n", self.recall * 100.0));
        report.push_str(&format!("  F1 Score:  {:.3}\n", self.f1_score));

        if !self.regressions.is_empty() {
            report.push_str("\n\nREGRESSIONS (newly missed)\n");
            report.push_str("══════════════════════════\n");
            for regression in &self.regressions {
                report.push_str(&format!(
                    "  - {} @ {}:{}-{}\n",
                    regression.expected.detector_id,
                    regression.file_path,
                    regression.expected.line_range[0],
                    regression.expected.line_range[1]
                ));
                report.push_str(&format!("    {}\n", regression.expected.description));
            }
        }

        if !self.false_negatives.is_empty() {
            report.push_str("\n\nMISSED VULNERABILITIES\n");
            report.push_str("══════════════════════\n");
            for (i, fn_) in self.false_negatives.iter().take(10).enumerate() {
                report.push_str(&format!(
                    "  {}. [{}] {}\n",
                    i + 1,
                    fn_.detector_id,
                    fn_.description
                ));
                report.push_str(&format!(
                    "     Lines {}-{}, Severity: {}\n",
                    fn_.line_range[0], fn_.line_range[1], fn_.severity
                ));
            }
            if self.false_negatives.len() > 10 {
                report.push_str(&format!(
                    "  ... and {} more\n",
                    self.false_negatives.len() - 10
                ));
            }
        }

        if !self.detector_metrics.is_empty() {
            report.push_str("\n\nPER-DETECTOR METRICS\n");
            report.push_str("════════════════════\n");
            report.push_str("  Detector                    TP    FP    FN   Prec   Recall   F1\n");
            report
                .push_str("  ─────────────────────────────────────────────────────────────────\n");

            let mut sorted_metrics: Vec<_> = self.detector_metrics.values().collect();
            sorted_metrics.sort_by(|a, b| b.true_positives.cmp(&a.true_positives));

            for metrics in sorted_metrics {
                report.push_str(&format!(
                    "  {:<25} {:>4}  {:>4}  {:>4}  {:>5.1}%  {:>5.1}%  {:.3}\n",
                    metrics.detector_id,
                    metrics.true_positives,
                    metrics.false_positives,
                    metrics.false_negatives,
                    metrics.precision * 100.0,
                    metrics.recall * 100.0,
                    metrics.f1_score
                ));
            }
        }

        report
    }

    /// Check if validation passes given thresholds
    pub fn passes(&self, min_precision: f64, min_recall: f64) -> bool {
        self.precision >= min_precision && self.recall >= min_recall
    }

    /// Check if there are any regressions
    pub fn has_regressions(&self) -> bool {
        !self.regressions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_ground_truth() {
        let path = Path::new("tests/validation/ground_truth.json");
        if path.exists() {
            let dataset = GroundTruthDataset::load(path).expect("Failed to load ground truth");
            assert!(!dataset.contracts.is_empty());
        }
    }

    #[test]
    fn test_findings_match() {
        let gt = GroundTruthDataset {
            version: "1.0.0".to_string(),
            description: "Test".to_string(),
            last_updated: "2026-01-16".to_string(),
            contracts: HashMap::new(),
            metadata: DatasetMetadata {
                total_contracts: 0,
                total_expected_findings: 0,
                categories: HashMap::new(),
            },
        };

        let validator = GroundTruthValidator::new(gt);

        let expected = ExpectedFinding {
            detector_id: "reentrancy".to_string(),
            line_range: [10, 20],
            label: "true_positive".to_string(),
            severity: "critical".to_string(),
            description: "Test".to_string(),
            vulnerability_type: "classic-reentrancy".to_string(),
        };

        let actual_match = ActualFinding {
            detector_id: "reentrancy".to_string(),
            file_path: "test.sol".to_string(),
            line: 15,
            column: 1,
            severity: "critical".to_string(),
            message: "Test".to_string(),
        };

        let actual_no_match = ActualFinding {
            detector_id: "access-control".to_string(),
            file_path: "test.sol".to_string(),
            line: 15,
            column: 1,
            severity: "high".to_string(),
            message: "Test".to_string(),
        };

        assert!(validator.findings_match(&expected, &actual_match));
        assert!(!validator.findings_match(&expected, &actual_no_match));
    }

    #[test]
    fn test_validation_metrics() {
        let mut contracts = HashMap::new();
        contracts.insert(
            "test.sol".to_string(),
            ContractGroundTruth {
                contract_name: "Test".to_string(),
                expected_findings: vec![
                    ExpectedFinding {
                        detector_id: "reentrancy".to_string(),
                        line_range: [10, 20],
                        label: "true_positive".to_string(),
                        severity: "critical".to_string(),
                        description: "Reentrancy".to_string(),
                        vulnerability_type: "classic".to_string(),
                    },
                    ExpectedFinding {
                        detector_id: "access-control".to_string(),
                        line_range: [30, 40],
                        label: "true_positive".to_string(),
                        severity: "high".to_string(),
                        description: "Access control".to_string(),
                        vulnerability_type: "missing-auth".to_string(),
                    },
                ],
                known_false_positives: vec![],
                clean_sections: vec![],
                notes: None,
            },
        );

        let gt = GroundTruthDataset {
            version: "1.0.0".to_string(),
            description: "Test".to_string(),
            last_updated: "2026-01-16".to_string(),
            contracts,
            metadata: DatasetMetadata {
                total_contracts: 1,
                total_expected_findings: 2,
                categories: HashMap::new(),
            },
        };

        let validator = GroundTruthValidator::new(gt);

        // One match, one miss, one false positive
        let actual = vec![
            ActualFinding {
                detector_id: "reentrancy".to_string(),
                file_path: "test.sol".to_string(),
                line: 15,
                column: 1,
                severity: "critical".to_string(),
                message: "Found reentrancy".to_string(),
            },
            ActualFinding {
                detector_id: "unchecked-call".to_string(),
                file_path: "test.sol".to_string(),
                line: 50,
                column: 1,
                severity: "medium".to_string(),
                message: "Unchecked call".to_string(),
            },
        ];

        let result = validator.validate(&actual);

        assert_eq!(result.summary.total_true_positives, 1);
        assert_eq!(result.summary.total_false_negatives, 1);
        assert_eq!(result.summary.total_false_positives, 1);
        assert_eq!(result.precision, 0.5); // 1 TP / (1 TP + 1 FP)
        assert_eq!(result.recall, 0.5); // 1 TP / (1 TP + 1 FN)
    }
}
