//! Analysis Testing Module for SolidityDefend
//!
//! This module provides comprehensive analysis testing infrastructure including:
//! - False positive detection and analysis
//! - Accuracy validation against known datasets
//! - Performance analysis of detection algorithms
//! - Quality assurance for security analysis results

pub mod false_positives;

pub use false_positives::{
    FalsePositiveAnalyzer, FalsePositiveConfig, FalsePositiveAnalysisResult,
    VulnerabilityAnalysis, VulnerabilityFinding, Classification, Evidence,
    AnalysisStatistics, AccuracyMetrics, ConfusionMatrix, Recommendation,
};

use std::path::{Path, PathBuf};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Comprehensive analysis test suite configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisTestConfig {
    /// False positive analysis configuration
    pub false_positive_config: FalsePositiveConfig,
    /// Minimum acceptable accuracy threshold
    pub min_accuracy_threshold: f64,
    /// Maximum acceptable false positive rate
    pub max_false_positive_rate: f64,
    /// Test datasets to analyze
    pub test_datasets: Vec<String>,
    /// Output directory for results
    pub output_directory: PathBuf,
    /// Enable detailed reporting
    pub detailed_reporting: bool,
}

impl Default for AnalysisTestConfig {
    fn default() -> Self {
        Self {
            false_positive_config: FalsePositiveConfig::default(),
            min_accuracy_threshold: 0.85, // 85% minimum accuracy
            max_false_positive_rate: 0.15, // 15% maximum false positive rate
            test_datasets: vec![
                "smartbugs".to_string(),
                "solidifi".to_string(),
                "custom".to_string(),
            ],
            output_directory: PathBuf::from("target/analysis_tests"),
            detailed_reporting: true,
        }
    }
}

/// Complete analysis test suite
pub struct AnalysisTestSuite {
    config: AnalysisTestConfig,
    false_positive_analyzer: FalsePositiveAnalyzer,
}

impl AnalysisTestSuite {
    /// Create new analysis test suite
    pub fn new(config: AnalysisTestConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let false_positive_analyzer = FalsePositiveAnalyzer::new(config.false_positive_config.clone())?;

        Ok(Self {
            config,
            false_positive_analyzer,
        })
    }

    /// Run complete analysis test suite
    pub async fn run_analysis_tests(
        &mut self,
        vulnerabilities: Vec<VulnerabilityFinding>,
    ) -> Result<AnalysisTestResults, Box<dyn std::error::Error>> {
        println!("Running SolidityDefend Analysis Test Suite");
        println!("==========================================");

        // Ensure output directory exists
        std::fs::create_dir_all(&self.config.output_directory)?;

        // Load ground truth data if available
        let ground_truth_path = self.config.output_directory.join("ground_truth.json");
        if ground_truth_path.exists() {
            println!("Loading ground truth data...");
            self.false_positive_analyzer.load_ground_truth(&ground_truth_path)?;
        }

        // Run false positive analysis
        println!("Running false positive analysis...");
        let fp_analysis_result = self.false_positive_analyzer
            .analyze_vulnerabilities(vulnerabilities.clone())
            .await?;

        // Save detailed results
        let fp_results_path = self.config.output_directory.join("false_positive_analysis.json");
        fp_analysis_result.save_to_file(&fp_results_path)?;

        // Generate quality metrics
        println!("Calculating quality metrics...");
        let quality_metrics = self.calculate_quality_metrics(&fp_analysis_result);

        // Generate recommendations
        let recommendations = self.generate_analysis_recommendations(&fp_analysis_result, &quality_metrics);

        // Create comprehensive test results
        let test_results = AnalysisTestResults {
            config: self.config.clone(),
            false_positive_analysis: fp_analysis_result,
            quality_metrics,
            recommendations,
            test_summary: self.generate_test_summary(&quality_metrics),
            timestamp: chrono::Utc::now(),
        };

        // Save comprehensive results
        let results_path = self.config.output_directory.join("analysis_test_results.json");
        test_results.save_to_file(&results_path)?;

        // Generate detailed report if requested
        if self.config.detailed_reporting {
            let report_path = self.config.output_directory.join("analysis_test_report.md");
            let report = test_results.generate_comprehensive_report();
            std::fs::write(report_path, report)?;
        }

        println!("Analysis tests completed successfully!");
        println!("Results saved to: {}", self.config.output_directory.display());

        Ok(test_results)
    }

    /// Calculate quality metrics for the analysis
    fn calculate_quality_metrics(&self, fp_analysis: &FalsePositiveAnalysisResult) -> QualityMetrics {
        let total_vulnerabilities = fp_analysis.statistics.total_vulnerabilities;
        let false_positive_rate = if total_vulnerabilities > 0 {
            fp_analysis.statistics.predicted_false_positives as f64 / total_vulnerabilities as f64
        } else {
            0.0
        };

        // Calculate detection coverage by vulnerability type
        let mut coverage_by_type = HashMap::new();
        for analysis in &fp_analysis.vulnerability_analyses {
            let vuln_type = &analysis.vulnerability.vulnerability_type;
            let entry = coverage_by_type.entry(vuln_type.clone()).or_insert((0, 0));
            entry.0 += 1; // Total
            if analysis.predicted_classification == Classification::TruePositive {
                entry.1 += 1; // Detected
            }
        }

        let detection_coverage: HashMap<String, f64> = coverage_by_type.iter()
            .map(|(vuln_type, (total, detected))| {
                let coverage = if *total > 0 { *detected as f64 / *total as f64 } else { 0.0 };
                (vuln_type.clone(), coverage)
            })
            .collect();

        // Calculate confidence reliability
        let confidence_reliability = self.calculate_confidence_reliability(fp_analysis);

        // Determine overall quality score
        let quality_score = self.calculate_overall_quality_score(fp_analysis, &detection_coverage, confidence_reliability);

        QualityMetrics {
            false_positive_rate,
            detection_coverage,
            confidence_reliability,
            quality_score,
            accuracy_metrics: fp_analysis.statistics.accuracy_metrics.clone(),
            performance_score: self.calculate_performance_score(&fp_analysis.performance),
        }
    }

    /// Calculate confidence reliability metric
    fn calculate_confidence_reliability(&self, fp_analysis: &FalsePositiveAnalysisResult) -> f64 {
        // Measure how well confidence scores correlate with actual accuracy
        let distribution = &fp_analysis.statistics.confidence_distribution;

        let mut weighted_accuracy = 0.0;
        let mut total_weight = 0.0;

        for bucket in &distribution.buckets {
            if let Some(accuracy) = bucket.accuracy {
                let weight = bucket.count as f64;
                weighted_accuracy += accuracy * weight;
                total_weight += weight;
            }
        }

        if total_weight > 0.0 {
            weighted_accuracy / total_weight
        } else {
            0.0
        }
    }

    /// Calculate overall quality score
    fn calculate_overall_quality_score(
        &self,
        fp_analysis: &FalsePositiveAnalysisResult,
        detection_coverage: &HashMap<String, f64>,
        confidence_reliability: f64,
    ) -> f64 {
        let mut score = 0.0;
        let mut factors = 0;

        // Factor 1: Accuracy (if available)
        if let Some(accuracy_metrics) = &fp_analysis.statistics.accuracy_metrics {
            score += accuracy_metrics.f1_score * 0.4; // 40% weight
            factors += 1;
        }

        // Factor 2: False positive rate (inverted)
        let fp_rate = fp_analysis.statistics.predicted_false_positives as f64 /
                     fp_analysis.statistics.total_vulnerabilities.max(1) as f64;
        score += (1.0 - fp_rate) * 0.3; // 30% weight
        factors += 1;

        // Factor 3: Detection coverage (average)
        if !detection_coverage.is_empty() {
            let avg_coverage = detection_coverage.values().sum::<f64>() / detection_coverage.len() as f64;
            score += avg_coverage * 0.2; // 20% weight
            factors += 1;
        }

        // Factor 4: Confidence reliability
        score += confidence_reliability * 0.1; // 10% weight
        factors += 1;

        if factors > 0 {
            score / factors as f64
        } else {
            0.0
        }
    }

    /// Calculate performance score
    fn calculate_performance_score(&self, performance: &false_positives::PerformanceMetrics) -> f64 {
        let time_per_vuln = performance.avg_time_per_vulnerability.as_secs_f64();

        // Score based on speed (higher is better)
        let speed_score = if time_per_vuln > 0.0 {
            (1.0 / time_per_vuln).min(1.0)
        } else {
            1.0
        };

        // Score based on memory efficiency (lower usage is better)
        let memory_mb = performance.memory_usage as f64 / 1024.0 / 1024.0;
        let memory_score = if memory_mb > 0.0 {
            (100.0 / memory_mb).min(1.0)
        } else {
            1.0
        };

        (speed_score + memory_score) / 2.0
    }

    /// Generate analysis recommendations
    fn generate_analysis_recommendations(
        &self,
        fp_analysis: &FalsePositiveAnalysisResult,
        quality_metrics: &QualityMetrics,
    ) -> Vec<AnalysisRecommendation> {
        let mut recommendations = Vec::new();

        // Check if false positive rate exceeds threshold
        if quality_metrics.false_positive_rate > self.config.max_false_positive_rate {
            recommendations.push(AnalysisRecommendation {
                category: RecommendationCategory::FalsePositives,
                priority: RecommendationPriority::High,
                description: format!(
                    "False positive rate ({:.1}%) exceeds threshold ({:.1}%)",
                    quality_metrics.false_positive_rate * 100.0,
                    self.config.max_false_positive_rate * 100.0
                ),
                action_items: vec![
                    "Review and refine detection rules".to_string(),
                    "Increase confidence thresholds".to_string(),
                    "Improve context analysis".to_string(),
                ],
                estimated_impact: ImpactLevel::High,
            });
        }

        // Check if accuracy is below threshold
        if let Some(accuracy_metrics) = &quality_metrics.accuracy_metrics {
            if accuracy_metrics.accuracy < self.config.min_accuracy_threshold {
                recommendations.push(AnalysisRecommendation {
                    category: RecommendationCategory::Accuracy,
                    priority: RecommendationPriority::Critical,
                    description: format!(
                        "Overall accuracy ({:.1}%) below threshold ({:.1}%)",
                        accuracy_metrics.accuracy * 100.0,
                        self.config.min_accuracy_threshold * 100.0
                    ),
                    action_items: vec![
                        "Expand training dataset".to_string(),
                        "Improve feature extraction".to_string(),
                        "Review classification algorithms".to_string(),
                    ],
                    estimated_impact: ImpactLevel::Critical,
                });
            }
        }

        // Check detection coverage for each vulnerability type
        for (vuln_type, coverage) in &quality_metrics.detection_coverage {
            if *coverage < 0.8 { // 80% coverage threshold
                recommendations.push(AnalysisRecommendation {
                    category: RecommendationCategory::Coverage,
                    priority: RecommendationPriority::Medium,
                    description: format!(
                        "Low detection coverage for {}: {:.1}%",
                        vuln_type, coverage * 100.0
                    ),
                    action_items: vec![
                        format!("Review {} detection rules", vuln_type),
                        "Add more test cases for this vulnerability type".to_string(),
                        "Investigate missed detection patterns".to_string(),
                    ],
                    estimated_impact: ImpactLevel::Medium,
                });
            }
        }

        // Check confidence reliability
        if quality_metrics.confidence_reliability < 0.7 {
            recommendations.push(AnalysisRecommendation {
                category: RecommendationCategory::Confidence,
                priority: RecommendationPriority::Medium,
                description: format!(
                    "Low confidence reliability: {:.1}%",
                    quality_metrics.confidence_reliability * 100.0
                ),
                action_items: vec![
                    "Calibrate confidence scoring".to_string(),
                    "Improve uncertainty quantification".to_string(),
                    "Validate confidence against ground truth".to_string(),
                ],
                estimated_impact: ImpactLevel::Medium,
            });
        }

        // Add recommendations from false positive analysis
        for fp_rec in &fp_analysis.recommendations {
            recommendations.push(AnalysisRecommendation {
                category: RecommendationCategory::FalsePositives,
                priority: match fp_rec.priority {
                    false_positives::Priority::Critical => RecommendationPriority::Critical,
                    false_positives::Priority::High => RecommendationPriority::High,
                    false_positives::Priority::Medium => RecommendationPriority::Medium,
                    false_positives::Priority::Low => RecommendationPriority::Low,
                },
                description: fp_rec.description.clone(),
                action_items: vec![fp_rec.expected_impact.clone()],
                estimated_impact: match fp_rec.complexity {
                    false_positives::Complexity::Low => ImpactLevel::Low,
                    false_positives::Complexity::Medium => ImpactLevel::Medium,
                    false_positives::Complexity::High => ImpactLevel::High,
                },
            });
        }

        recommendations
    }

    /// Generate test summary
    fn generate_test_summary(&self, quality_metrics: &QualityMetrics) -> TestSummary {
        let overall_status = if quality_metrics.quality_score >= 0.85 {
            TestStatus::Passed
        } else if quality_metrics.quality_score >= 0.7 {
            TestStatus::Warning
        } else {
            TestStatus::Failed
        };

        let mut issues = Vec::new();

        if quality_metrics.false_positive_rate > self.config.max_false_positive_rate {
            issues.push("High false positive rate".to_string());
        }

        if let Some(accuracy_metrics) = &quality_metrics.accuracy_metrics {
            if accuracy_metrics.accuracy < self.config.min_accuracy_threshold {
                issues.push("Low accuracy".to_string());
            }
        }

        let low_coverage_types: Vec<String> = quality_metrics.detection_coverage.iter()
            .filter(|(_, coverage)| **coverage < 0.8)
            .map(|(vuln_type, _)| vuln_type.clone())
            .collect();

        if !low_coverage_types.is_empty() {
            issues.push(format!("Low coverage for: {}", low_coverage_types.join(", ")));
        }

        TestSummary {
            overall_status,
            quality_score: quality_metrics.quality_score,
            issues,
            recommendations_count: 0, // Will be filled by caller
        }
    }
}

/// Comprehensive analysis test results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisTestResults {
    /// Test configuration
    pub config: AnalysisTestConfig,
    /// False positive analysis results
    pub false_positive_analysis: FalsePositiveAnalysisResult,
    /// Quality metrics
    pub quality_metrics: QualityMetrics,
    /// Recommendations for improvement
    pub recommendations: Vec<AnalysisRecommendation>,
    /// Test summary
    pub test_summary: TestSummary,
    /// Test timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Quality metrics for analysis performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    /// False positive rate
    pub false_positive_rate: f64,
    /// Detection coverage by vulnerability type
    pub detection_coverage: HashMap<String, f64>,
    /// Confidence reliability score
    pub confidence_reliability: f64,
    /// Overall quality score (0.0 - 1.0)
    pub quality_score: f64,
    /// Accuracy metrics if available
    pub accuracy_metrics: Option<AccuracyMetrics>,
    /// Performance score
    pub performance_score: f64,
}

/// Analysis improvement recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRecommendation {
    /// Category of recommendation
    pub category: RecommendationCategory,
    /// Priority level
    pub priority: RecommendationPriority,
    /// Description of the issue
    pub description: String,
    /// Specific action items
    pub action_items: Vec<String>,
    /// Estimated impact of implementing this recommendation
    pub estimated_impact: ImpactLevel,
}

/// Categories of analysis recommendations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationCategory {
    FalsePositives,
    Accuracy,
    Coverage,
    Confidence,
    Performance,
    Training,
}

/// Priority levels for recommendations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Impact levels for recommendations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImpactLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Test summary information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSummary {
    /// Overall test status
    pub overall_status: TestStatus,
    /// Quality score
    pub quality_score: f64,
    /// List of issues found
    pub issues: Vec<String>,
    /// Number of recommendations generated
    pub recommendations_count: usize,
}

/// Overall test status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestStatus {
    Passed,
    Warning,
    Failed,
}

impl AnalysisTestResults {
    /// Save results to JSON file
    pub fn save_to_file(&self, file_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(file_path, json)?;
        Ok(())
    }

    /// Load results from JSON file
    pub fn load_from_file(file_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(file_path)?;
        let results = serde_json::from_str(&content)?;
        Ok(results)
    }

    /// Generate comprehensive analysis report
    pub fn generate_comprehensive_report(&self) -> String {
        let mut report = String::new();

        report.push_str("# SolidityDefend Analysis Test Report\n\n");
        report.push_str(&format!("**Generated:** {}\n", self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
        report.push_str(&format!("**Overall Status:** {:?}\n", self.test_summary.overall_status));
        report.push_str(&format!("**Quality Score:** {:.1}%\n\n", self.quality_metrics.quality_score * 100.0));

        // Executive Summary
        report.push_str("## Executive Summary\n\n");

        match self.test_summary.overall_status {
            TestStatus::Passed => {
                report.push_str("✅ **Analysis quality meets all requirements**\n\n");
                report.push_str("The security analysis system demonstrates high accuracy, low false positive rates, ");
                report.push_str("and comprehensive vulnerability detection coverage.\n\n");
            },
            TestStatus::Warning => {
                report.push_str("⚠️ **Analysis quality meets minimum requirements with concerns**\n\n");
                report.push_str("The security analysis system performs adequately but has areas requiring improvement ");
                report.push_str("to achieve optimal performance.\n\n");
            },
            TestStatus::Failed => {
                report.push_str("❌ **Analysis quality below acceptable standards**\n\n");
                report.push_str("The security analysis system requires significant improvements before deployment. ");
                report.push_str("Critical issues must be addressed.\n\n");
            },
        }

        // Quality Metrics
        report.push_str("## Quality Metrics\n\n");
        report.push_str("| Metric | Value | Status |\n");
        report.push_str("|--------|-------|--------|\n");

        let fp_status = if self.quality_metrics.false_positive_rate <= self.config.max_false_positive_rate {
            "✅ PASS"
        } else {
            "❌ FAIL"
        };
        report.push_str(&format!("| False Positive Rate | {:.1}% | {} |\n",
            self.quality_metrics.false_positive_rate * 100.0, fp_status));

        if let Some(accuracy) = &self.quality_metrics.accuracy_metrics {
            let acc_status = if accuracy.accuracy >= self.config.min_accuracy_threshold {
                "✅ PASS"
            } else {
                "❌ FAIL"
            };
            report.push_str(&format!("| Overall Accuracy | {:.1}% | {} |\n",
                accuracy.accuracy * 100.0, acc_status));
            report.push_str(&format!("| Precision | {:.1}% | - |\n", accuracy.precision * 100.0));
            report.push_str(&format!("| Recall | {:.1}% | - |\n", accuracy.recall * 100.0));
            report.push_str(&format!("| F1 Score | {:.3} | - |\n", accuracy.f1_score));
        }

        report.push_str(&format!("| Confidence Reliability | {:.1}% | - |\n",
            self.quality_metrics.confidence_reliability * 100.0));
        report.push_str(&format!("| Performance Score | {:.1}% | - |\n",
            self.quality_metrics.performance_score * 100.0));

        // Detection Coverage
        if !self.quality_metrics.detection_coverage.is_empty() {
            report.push_str("\n## Detection Coverage by Vulnerability Type\n\n");
            report.push_str("| Vulnerability Type | Coverage | Status |\n");
            report.push_str("|--------------------|----------|--------|\n");

            for (vuln_type, coverage) in &self.quality_metrics.detection_coverage {
                let status = if *coverage >= 0.8 { "✅ GOOD" } else { "⚠️ LOW" };
                report.push_str(&format!("| {} | {:.1}% | {} |\n",
                    vuln_type, coverage * 100.0, status));
            }
        }

        // False Positive Analysis Summary
        report.push_str("\n## False Positive Analysis\n\n");
        let fp_stats = &self.false_positive_analysis.statistics;
        report.push_str(&format!("- **Total Vulnerabilities Analyzed:** {}\n", fp_stats.total_vulnerabilities));
        report.push_str(&format!("- **Predicted True Positives:** {}\n", fp_stats.predicted_true_positives));
        report.push_str(&format!("- **Predicted False Positives:** {}\n", fp_stats.predicted_false_positives));
        report.push_str(&format!("- **Ground Truth Available:** {}\n", fp_stats.ground_truth_available));

        // Issues and Recommendations
        if !self.test_summary.issues.is_empty() {
            report.push_str("\n## Issues Identified\n\n");
            for (i, issue) in self.test_summary.issues.iter().enumerate() {
                report.push_str(&format!("{}. {}\n", i + 1, issue));
            }
        }

        if !self.recommendations.is_empty() {
            report.push_str("\n## Recommendations\n\n");

            let mut critical_recs: Vec<_> = self.recommendations.iter()
                .filter(|r| matches!(r.priority, RecommendationPriority::Critical))
                .collect();
            let mut high_recs: Vec<_> = self.recommendations.iter()
                .filter(|r| matches!(r.priority, RecommendationPriority::High))
                .collect();
            let mut medium_recs: Vec<_> = self.recommendations.iter()
                .filter(|r| matches!(r.priority, RecommendationPriority::Medium))
                .collect();
            let mut low_recs: Vec<_> = self.recommendations.iter()
                .filter(|r| matches!(r.priority, RecommendationPriority::Low))
                .collect();

            if !critical_recs.is_empty() {
                report.push_str("### 🔴 Critical Priority\n\n");
                for (i, rec) in critical_recs.iter().enumerate() {
                    report.push_str(&format!("{}. **{}**\n", i + 1, rec.description));
                    for action in &rec.action_items {
                        report.push_str(&format!("   - {}\n", action));
                    }
                    report.push_str("\n");
                }
            }

            if !high_recs.is_empty() {
                report.push_str("### 🟠 High Priority\n\n");
                for (i, rec) in high_recs.iter().enumerate() {
                    report.push_str(&format!("{}. **{}**\n", i + 1, rec.description));
                    for action in &rec.action_items {
                        report.push_str(&format!("   - {}\n", action));
                    }
                    report.push_str("\n");
                }
            }

            if !medium_recs.is_empty() {
                report.push_str("### 🟡 Medium Priority\n\n");
                for (i, rec) in medium_recs.iter().enumerate() {
                    report.push_str(&format!("{}. **{}**\n", i + 1, rec.description));
                    for action in &rec.action_items {
                        report.push_str(&format!("   - {}\n", action));
                    }
                    report.push_str("\n");
                }
            }

            if !low_recs.is_empty() {
                report.push_str("### 🟢 Low Priority\n\n");
                for (i, rec) in low_recs.iter().enumerate() {
                    report.push_str(&format!("{}. **{}**\n", i + 1, rec.description));
                    for action in &rec.action_items {
                        report.push_str(&format!("   - {}\n", action));
                    }
                    report.push_str("\n");
                }
            }
        }

        // Performance Analysis
        report.push_str("## Performance Analysis\n\n");
        let perf = &self.false_positive_analysis.performance;
        report.push_str(&format!("- **Total Analysis Time:** {:.2}s\n", perf.total_time.as_secs_f64()));
        report.push_str(&format!("- **Average Time per Vulnerability:** {:.3}s\n", perf.avg_time_per_vulnerability.as_secs_f64()));
        report.push_str(&format!("- **Memory Usage:** {:.1} MB\n", perf.memory_usage as f64 / 1024.0 / 1024.0));

        // Conclusion
        report.push_str("\n## Conclusion\n\n");

        match self.test_summary.overall_status {
            TestStatus::Passed => {
                report.push_str("The SolidityDefend analysis system demonstrates excellent performance across all quality metrics. ");
                report.push_str("The system is ready for production deployment with confidence in its accuracy and reliability.\n");
            },
            TestStatus::Warning => {
                report.push_str("The SolidityDefend analysis system shows good overall performance with some areas needing attention. ");
                report.push_str("Address the medium and high priority recommendations to optimize performance.\n");
            },
            TestStatus::Failed => {
                report.push_str("The SolidityDefend analysis system requires significant improvements before production deployment. ");
                report.push_str("Focus on critical and high priority recommendations to achieve acceptable quality standards.\n");
            },
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_test_config_default() {
        let config = AnalysisTestConfig::default();
        assert_eq!(config.min_accuracy_threshold, 0.85);
        assert_eq!(config.max_false_positive_rate, 0.15);
        assert!(!config.test_datasets.is_empty());
        assert!(config.detailed_reporting);
    }

    #[test]
    fn test_quality_metrics_creation() {
        let mut detection_coverage = HashMap::new();
        detection_coverage.insert("reentrancy".to_string(), 0.95);
        detection_coverage.insert("access-control".to_string(), 0.88);

        let metrics = QualityMetrics {
            false_positive_rate: 0.12,
            detection_coverage,
            confidence_reliability: 0.85,
            quality_score: 0.89,
            accuracy_metrics: None,
            performance_score: 0.75,
        };

        assert_eq!(metrics.false_positive_rate, 0.12);
        assert_eq!(metrics.quality_score, 0.89);
        assert_eq!(metrics.detection_coverage.len(), 2);
    }

    #[test]
    fn test_recommendation_creation() {
        let recommendation = AnalysisRecommendation {
            category: RecommendationCategory::FalsePositives,
            priority: RecommendationPriority::High,
            description: "High false positive rate detected".to_string(),
            action_items: vec![
                "Review detection rules".to_string(),
                "Increase confidence thresholds".to_string(),
            ],
            estimated_impact: ImpactLevel::High,
        };

        assert!(matches!(recommendation.category, RecommendationCategory::FalsePositives));
        assert!(matches!(recommendation.priority, RecommendationPriority::High));
        assert_eq!(recommendation.action_items.len(), 2);
    }

    #[test]
    fn test_test_summary_creation() {
        let summary = TestSummary {
            overall_status: TestStatus::Warning,
            quality_score: 0.75,
            issues: vec!["High false positive rate".to_string()],
            recommendations_count: 3,
        };

        assert!(matches!(summary.overall_status, TestStatus::Warning));
        assert_eq!(summary.quality_score, 0.75);
        assert_eq!(summary.issues.len(), 1);
        assert_eq!(summary.recommendations_count, 3);
    }

    #[test]
    fn test_serialization() {
        let config = AnalysisTestConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AnalysisTestConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.min_accuracy_threshold, deserialized.min_accuracy_threshold);
        assert_eq!(config.max_false_positive_rate, deserialized.max_false_positive_rate);
        assert_eq!(config.test_datasets, deserialized.test_datasets);
    }
}