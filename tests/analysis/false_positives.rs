//! False Positive Analysis for SolidityDefend
//!
//! This module implements comprehensive false positive detection and analysis
//! to improve the accuracy of security vulnerability detection.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use regex::Regex;

/// False positive analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveConfig {
    /// Minimum confidence threshold for reported vulnerabilities
    pub min_confidence: f64,
    /// Maximum acceptable false positive rate
    pub max_false_positive_rate: f64,
    /// Categories of vulnerabilities to analyze
    pub vulnerability_categories: Vec<String>,
    /// Test datasets with known ground truth
    pub test_datasets: Vec<String>,
    /// Pattern matching rules for false positive detection
    pub detection_rules: Vec<DetectionRule>,
}

/// Rule for detecting potential false positives
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    /// Rule identifier
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Vulnerability type this rule applies to
    pub vulnerability_type: String,
    /// Pattern to match in the code
    pub pattern: String,
    /// Context patterns that indicate false positive
    pub false_positive_indicators: Vec<String>,
    /// Context patterns that indicate true positive
    pub true_positive_indicators: Vec<String>,
    /// Weight/confidence of this rule
    pub weight: f64,
}

/// Analysis result for a single vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityAnalysis {
    /// Original vulnerability finding
    pub vulnerability: VulnerabilityFinding,
    /// Predicted classification (true/false positive)
    pub predicted_classification: Classification,
    /// Confidence score (0.0 - 1.0)
    pub confidence_score: f64,
    /// Ground truth classification (if available)
    pub ground_truth: Option<Classification>,
    /// Triggered detection rules
    pub triggered_rules: Vec<String>,
    /// Evidence supporting the classification
    pub evidence: Vec<Evidence>,
    /// Manual review status
    pub manual_review: Option<ManualReview>,
}

/// Classification of a vulnerability finding
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Classification {
    TruePositive,
    FalsePositive,
    Unknown,
}

/// Evidence supporting a classification decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Type of evidence
    pub evidence_type: EvidenceType,
    /// Description of the evidence
    pub description: String,
    /// Weight/importance of this evidence
    pub weight: f64,
    /// Source code context
    pub context: Option<CodeContext>,
}

/// Types of evidence for classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Pattern matching evidence
    PatternMatch,
    /// Control flow analysis
    ControlFlow,
    /// Data flow analysis
    DataFlow,
    /// Semantic analysis
    Semantic,
    /// Historical data
    Historical,
    /// Expert rules
    ExpertRules,
}

/// Code context for evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeContext {
    /// File path
    pub file_path: PathBuf,
    /// Line number
    pub line_number: usize,
    /// Code snippet
    pub code_snippet: String,
    /// Surrounding context lines
    pub context_lines: Vec<String>,
}

/// Manual review information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualReview {
    /// Reviewer identifier
    pub reviewer: String,
    /// Review timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Manual classification
    pub classification: Classification,
    /// Review comments
    pub comments: String,
    /// Confidence in manual review
    pub confidence: f64,
}

/// Original vulnerability finding from security analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    /// Vulnerability ID
    pub id: String,
    /// Vulnerability type/category
    pub vulnerability_type: String,
    /// Severity level
    pub severity: String,
    /// Description
    pub description: String,
    /// File location
    pub file_path: PathBuf,
    /// Line number
    pub line_number: usize,
    /// Column number
    pub column_number: Option<usize>,
    /// Code snippet
    pub code_snippet: String,
    /// Confidence score from original analysis
    pub confidence: f64,
    /// Rule that triggered this finding
    pub rule_id: String,
}

/// Comprehensive false positive analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveAnalysisResult {
    /// Analysis configuration
    pub config: FalsePositiveConfig,
    /// Individual vulnerability analyses
    pub vulnerability_analyses: Vec<VulnerabilityAnalysis>,
    /// Overall statistics
    pub statistics: AnalysisStatistics,
    /// Performance metrics
    pub performance: PerformanceMetrics,
    /// Recommendations for improvement
    pub recommendations: Vec<Recommendation>,
    /// Analysis timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Statistical summary of false positive analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStatistics {
    /// Total vulnerabilities analyzed
    pub total_vulnerabilities: usize,
    /// Predicted true positives
    pub predicted_true_positives: usize,
    /// Predicted false positives
    pub predicted_false_positives: usize,
    /// Vulnerabilities with ground truth
    pub ground_truth_available: usize,
    /// Accuracy metrics (when ground truth available)
    pub accuracy_metrics: Option<AccuracyMetrics>,
    /// False positive rate by vulnerability type
    pub false_positive_rates: HashMap<String, f64>,
    /// Confidence distribution
    pub confidence_distribution: ConfidenceDistribution,
}

/// Accuracy metrics for false positive detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyMetrics {
    /// Overall accuracy
    pub accuracy: f64,
    /// Precision (positive predictive value)
    pub precision: f64,
    /// Recall (sensitivity)
    pub recall: f64,
    /// Specificity
    pub specificity: f64,
    /// F1 score
    pub f1_score: f64,
    /// Area under ROC curve
    pub auc_roc: f64,
    /// Confusion matrix
    pub confusion_matrix: ConfusionMatrix,
}

/// Confusion matrix for classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfusionMatrix {
    /// True positives correctly identified as true positives
    pub true_positive: usize,
    /// False positives correctly identified as false positives
    pub true_negative: usize,
    /// False positives incorrectly identified as true positives
    pub false_positive: usize,
    /// True positives incorrectly identified as false positives
    pub false_negative: usize,
}

/// Distribution of confidence scores
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceDistribution {
    /// Confidence buckets (0.0-0.1, 0.1-0.2, etc.)
    pub buckets: Vec<ConfidenceBucket>,
    /// Mean confidence score
    pub mean_confidence: f64,
    /// Standard deviation of confidence scores
    pub std_confidence: f64,
}

/// Confidence bucket statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceBucket {
    /// Lower bound of bucket
    pub lower_bound: f64,
    /// Upper bound of bucket
    pub upper_bound: f64,
    /// Number of vulnerabilities in this bucket
    pub count: usize,
    /// Percentage of total vulnerabilities
    pub percentage: f64,
    /// Accuracy within this bucket (if ground truth available)
    pub accuracy: Option<f64>,
}

/// Performance metrics for the analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Total analysis time
    pub total_time: Duration,
    /// Average time per vulnerability
    pub avg_time_per_vulnerability: Duration,
    /// Memory usage
    pub memory_usage: usize,
    /// Rules evaluation performance
    pub rules_performance: HashMap<String, Duration>,
}

/// Recommendation for improving false positive detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Recommendation type
    pub recommendation_type: RecommendationType,
    /// Priority level
    pub priority: Priority,
    /// Description
    pub description: String,
    /// Specific vulnerability types affected
    pub affected_types: Vec<String>,
    /// Expected impact
    pub expected_impact: String,
    /// Implementation complexity
    pub complexity: Complexity,
}

/// Types of recommendations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationType {
    /// Adjust confidence thresholds
    ConfidenceThreshold,
    /// Add new detection rules
    NewDetectionRule,
    /// Modify existing rules
    ModifyRule,
    /// Improve context analysis
    ContextAnalysis,
    /// Additional manual review
    ManualReview,
    /// Training data improvement
    TrainingData,
}

/// Priority levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}

/// Implementation complexity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Complexity {
    Low,
    Medium,
    High,
}

/// False positive analyzer
pub struct FalsePositiveAnalyzer {
    config: FalsePositiveConfig,
    detection_rules: Vec<DetectionRule>,
    compiled_patterns: HashMap<String, Regex>,
    ground_truth_data: HashMap<String, Classification>,
}

impl FalsePositiveAnalyzer {
    /// Create new false positive analyzer
    pub fn new(config: FalsePositiveConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut compiled_patterns = HashMap::new();

        // Compile regex patterns for performance
        for rule in &config.detection_rules {
            let regex = Regex::new(&rule.pattern)?;
            compiled_patterns.insert(rule.id.clone(), regex);

            for indicator in &rule.false_positive_indicators {
                if !compiled_patterns.contains_key(indicator) {
                    let regex = Regex::new(indicator)?;
                    compiled_patterns.insert(indicator.clone(), regex);
                }
            }

            for indicator in &rule.true_positive_indicators {
                if !compiled_patterns.contains_key(indicator) {
                    let regex = Regex::new(indicator)?;
                    compiled_patterns.insert(indicator.clone(), regex);
                }
            }
        }

        Ok(Self {
            detection_rules: config.detection_rules.clone(),
            config,
            compiled_patterns,
            ground_truth_data: HashMap::new(),
        })
    }

    /// Load ground truth data from file
    pub fn load_ground_truth(&mut self, file_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(file_path)?;
        let ground_truth: HashMap<String, String> = serde_json::from_str(&content)?;

        for (id, classification_str) in ground_truth {
            let classification = match classification_str.as_str() {
                "true_positive" => Classification::TruePositive,
                "false_positive" => Classification::FalsePositive,
                _ => Classification::Unknown,
            };
            self.ground_truth_data.insert(id, classification);
        }

        Ok(())
    }

    /// Analyze vulnerabilities for false positives
    pub async fn analyze_vulnerabilities(
        &self,
        vulnerabilities: Vec<VulnerabilityFinding>,
    ) -> Result<FalsePositiveAnalysisResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let start_memory = self.get_memory_usage();

        let mut vulnerability_analyses = Vec::new();
        let mut rules_performance = HashMap::new();

        for vulnerability in vulnerabilities {
            let analysis = self.analyze_single_vulnerability(&vulnerability, &mut rules_performance).await?;
            vulnerability_analyses.push(analysis);
        }

        let end_memory = self.get_memory_usage();
        let total_time = start_time.elapsed();

        // Calculate statistics
        let statistics = self.calculate_statistics(&vulnerability_analyses);

        // Generate performance metrics
        let performance = PerformanceMetrics {
            total_time,
            avg_time_per_vulnerability: if vulnerability_analyses.is_empty() {
                Duration::from_secs(0)
            } else {
                Duration::from_nanos(total_time.as_nanos() / vulnerability_analyses.len() as u128)
            },
            memory_usage: end_memory.saturating_sub(start_memory),
            rules_performance,
        };

        // Generate recommendations
        let recommendations = self.generate_recommendations(&vulnerability_analyses, &statistics);

        Ok(FalsePositiveAnalysisResult {
            config: self.config.clone(),
            vulnerability_analyses,
            statistics,
            performance,
            recommendations,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Analyze a single vulnerability for false positive likelihood
    async fn analyze_single_vulnerability(
        &self,
        vulnerability: &VulnerabilityFinding,
        rules_performance: &mut HashMap<String, Duration>,
    ) -> Result<VulnerabilityAnalysis, Box<dyn std::error::Error>> {
        let mut triggered_rules = Vec::new();
        let mut evidence = Vec::new();
        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        // Read the source file for context analysis
        let source_content = std::fs::read_to_string(&vulnerability.file_path)
            .unwrap_or_else(|_| String::new());

        // Apply detection rules
        for rule in &self.detection_rules {
            if rule.vulnerability_type != vulnerability.vulnerability_type {
                continue;
            }

            let rule_start = Instant::now();

            if let Some(regex) = self.compiled_patterns.get(&rule.id) {
                if regex.is_match(&vulnerability.code_snippet) {
                    triggered_rules.push(rule.id.clone());

                    // Analyze context for false positive indicators
                    let fp_score = self.analyze_context(
                        &source_content,
                        vulnerability.line_number,
                        &rule.false_positive_indicators,
                    )?;

                    // Analyze context for true positive indicators
                    let tp_score = self.analyze_context(
                        &source_content,
                        vulnerability.line_number,
                        &rule.true_positive_indicators,
                    )?;

                    // Calculate rule score (higher = more likely false positive)
                    let rule_score = fp_score - tp_score;
                    total_score += rule_score * rule.weight;
                    total_weight += rule.weight;

                    // Add evidence
                    evidence.push(Evidence {
                        evidence_type: EvidenceType::PatternMatch,
                        description: format!("Rule '{}' matched: {}", rule.id, rule.description),
                        weight: rule.weight,
                        context: Some(CodeContext {
                            file_path: vulnerability.file_path.clone(),
                            line_number: vulnerability.line_number,
                            code_snippet: vulnerability.code_snippet.clone(),
                            context_lines: self.get_context_lines(&source_content, vulnerability.line_number, 3),
                        }),
                    });

                    if fp_score > 0.5 {
                        evidence.push(Evidence {
                            evidence_type: EvidenceType::ContextAnalysis,
                            description: "Strong false positive indicators found in context".to_string(),
                            weight: fp_score,
                            context: None,
                        });
                    }

                    if tp_score > 0.5 {
                        evidence.push(Evidence {
                            evidence_type: EvidenceType::ContextAnalysis,
                            description: "Strong true positive indicators found in context".to_string(),
                            weight: tp_score,
                            context: None,
                        });
                    }
                }
            }

            rules_performance.insert(
                rule.id.clone(),
                rules_performance.get(&rule.id).unwrap_or(&Duration::from_secs(0)) + rule_start.elapsed()
            );
        }

        // Calculate final confidence score
        let confidence_score = if total_weight > 0.0 {
            (total_score / total_weight).max(0.0).min(1.0)
        } else {
            0.5 // Default uncertainty
        };

        // Determine predicted classification
        let predicted_classification = if confidence_score > 0.6 {
            Classification::FalsePositive
        } else if confidence_score < 0.4 {
            Classification::TruePositive
        } else {
            Classification::Unknown
        };

        // Get ground truth if available
        let ground_truth = self.ground_truth_data.get(&vulnerability.id).cloned();

        Ok(VulnerabilityAnalysis {
            vulnerability: vulnerability.clone(),
            predicted_classification,
            confidence_score,
            ground_truth,
            triggered_rules,
            evidence,
            manual_review: None,
        })
    }

    /// Analyze context around a vulnerability for indicators
    fn analyze_context(
        &self,
        source_content: &str,
        line_number: usize,
        indicators: &[String],
    ) -> Result<f64, Box<dyn std::error::Error>> {
        let lines: Vec<&str> = source_content.lines().collect();
        let context_range = 10; // Look at ±10 lines around the vulnerability

        let start_line = line_number.saturating_sub(context_range).max(1);
        let end_line = (line_number + context_range).min(lines.len());

        let context_lines = if start_line <= lines.len() && end_line <= lines.len() {
            &lines[start_line.saturating_sub(1)..end_line]
        } else {
            return Ok(0.0);
        };

        let context_text = context_lines.join("\n");

        let mut matches = 0;
        let mut total_indicators = 0;

        for indicator in indicators {
            total_indicators += 1;
            if let Some(regex) = self.compiled_patterns.get(indicator) {
                if regex.is_match(&context_text) {
                    matches += 1;
                }
            }
        }

        if total_indicators > 0 {
            Ok(matches as f64 / total_indicators as f64)
        } else {
            Ok(0.0)
        }
    }

    /// Get context lines around a specific line
    fn get_context_lines(&self, source_content: &str, line_number: usize, context: usize) -> Vec<String> {
        let lines: Vec<&str> = source_content.lines().collect();
        let start = line_number.saturating_sub(context + 1);
        let end = (line_number + context).min(lines.len());

        if start < lines.len() && end <= lines.len() {
            lines[start..end].iter().map(|s| s.to_string()).collect()
        } else {
            Vec::new()
        }
    }

    /// Calculate comprehensive statistics
    fn calculate_statistics(&self, analyses: &[VulnerabilityAnalysis]) -> AnalysisStatistics {
        let total_vulnerabilities = analyses.len();
        let predicted_true_positives = analyses.iter()
            .filter(|a| a.predicted_classification == Classification::TruePositive)
            .count();
        let predicted_false_positives = analyses.iter()
            .filter(|a| a.predicted_classification == Classification::FalsePositive)
            .count();

        let ground_truth_available = analyses.iter()
            .filter(|a| a.ground_truth.is_some())
            .count();

        // Calculate accuracy metrics if ground truth is available
        let accuracy_metrics = if ground_truth_available > 0 {
            Some(self.calculate_accuracy_metrics(analyses))
        } else {
            None
        };

        // Calculate false positive rates by vulnerability type
        let mut type_counts: HashMap<String, (usize, usize)> = HashMap::new();
        for analysis in analyses {
            let vuln_type = &analysis.vulnerability.vulnerability_type;
            let entry = type_counts.entry(vuln_type.clone()).or_insert((0, 0));
            entry.0 += 1; // Total count
            if analysis.predicted_classification == Classification::FalsePositive {
                entry.1 += 1; // False positive count
            }
        }

        let false_positive_rates: HashMap<String, f64> = type_counts.iter()
            .map(|(vuln_type, (total, fp))| {
                let rate = if *total > 0 { *fp as f64 / *total as f64 } else { 0.0 };
                (vuln_type.clone(), rate)
            })
            .collect();

        // Calculate confidence distribution
        let confidence_distribution = self.calculate_confidence_distribution(analyses);

        AnalysisStatistics {
            total_vulnerabilities,
            predicted_true_positives,
            predicted_false_positives,
            ground_truth_available,
            accuracy_metrics,
            false_positive_rates,
            confidence_distribution,
        }
    }

    /// Calculate accuracy metrics when ground truth is available
    fn calculate_accuracy_metrics(&self, analyses: &[VulnerabilityAnalysis]) -> AccuracyMetrics {
        let mut tp = 0; // True positives (correctly identified as true positive)
        let mut tn = 0; // True negatives (correctly identified as false positive)
        let mut fp = 0; // False positives (incorrectly identified as true positive)
        let mut fn_count = 0; // False negatives (incorrectly identified as false positive)

        for analysis in analyses {
            if let Some(ground_truth) = &analysis.ground_truth {
                match (&analysis.predicted_classification, ground_truth) {
                    (Classification::TruePositive, Classification::TruePositive) => tp += 1,
                    (Classification::FalsePositive, Classification::FalsePositive) => tn += 1,
                    (Classification::TruePositive, Classification::FalsePositive) => fp += 1,
                    (Classification::FalsePositive, Classification::TruePositive) => fn_count += 1,
                    _ => {} // Unknown classifications are ignored
                }
            }
        }

        let total = tp + tn + fp + fn_count;
        let accuracy = if total > 0 { (tp + tn) as f64 / total as f64 } else { 0.0 };
        let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 0.0 };
        let recall = if tp + fn_count > 0 { tp as f64 / (tp + fn_count) as f64 } else { 0.0 };
        let specificity = if tn + fp > 0 { tn as f64 / (tn + fp) as f64 } else { 0.0 };
        let f1_score = if precision + recall > 0.0 {
            2.0 * (precision * recall) / (precision + recall)
        } else {
            0.0
        };

        // Simplified AUC calculation (would need ROC curve for full implementation)
        let auc_roc = (recall + specificity) / 2.0;

        AccuracyMetrics {
            accuracy,
            precision,
            recall,
            specificity,
            f1_score,
            auc_roc,
            confusion_matrix: ConfusionMatrix {
                true_positive: tp,
                true_negative: tn,
                false_positive: fp,
                false_negative: fn_count,
            },
        }
    }

    /// Calculate confidence score distribution
    fn calculate_confidence_distribution(&self, analyses: &[VulnerabilityAnalysis]) -> ConfidenceDistribution {
        let bucket_size = 0.1;
        let num_buckets = 10;
        let mut buckets = Vec::new();

        for i in 0..num_buckets {
            let lower_bound = i as f64 * bucket_size;
            let upper_bound = (i + 1) as f64 * bucket_size;

            let count = analyses.iter()
                .filter(|a| a.confidence_score >= lower_bound && a.confidence_score < upper_bound)
                .count();

            let percentage = if analyses.is_empty() {
                0.0
            } else {
                count as f64 / analyses.len() as f64 * 100.0
            };

            // Calculate accuracy for this bucket if ground truth is available
            let bucket_analyses: Vec<_> = analyses.iter()
                .filter(|a| a.confidence_score >= lower_bound && a.confidence_score < upper_bound)
                .collect();

            let accuracy = if !bucket_analyses.is_empty() {
                let correct = bucket_analyses.iter()
                    .filter(|a| {
                        if let Some(ground_truth) = &a.ground_truth {
                            &a.predicted_classification == ground_truth
                        } else {
                            false
                        }
                    })
                    .count();

                let with_ground_truth = bucket_analyses.iter()
                    .filter(|a| a.ground_truth.is_some())
                    .count();

                if with_ground_truth > 0 {
                    Some(correct as f64 / with_ground_truth as f64)
                } else {
                    None
                }
            } else {
                None
            };

            buckets.push(ConfidenceBucket {
                lower_bound,
                upper_bound,
                count,
                percentage,
                accuracy,
            });
        }

        let mean_confidence = if analyses.is_empty() {
            0.0
        } else {
            analyses.iter().map(|a| a.confidence_score).sum::<f64>() / analyses.len() as f64
        };

        let std_confidence = if analyses.len() > 1 {
            let variance = analyses.iter()
                .map(|a| (a.confidence_score - mean_confidence).powi(2))
                .sum::<f64>() / (analyses.len() - 1) as f64;
            variance.sqrt()
        } else {
            0.0
        };

        ConfidenceDistribution {
            buckets,
            mean_confidence,
            std_confidence,
        }
    }

    /// Generate recommendations for improving false positive detection
    fn generate_recommendations(
        &self,
        analyses: &[VulnerabilityAnalysis],
        statistics: &AnalysisStatistics,
    ) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Check overall false positive rate
        if statistics.predicted_false_positives as f64 / statistics.total_vulnerabilities as f64 > self.config.max_false_positive_rate {
            recommendations.push(Recommendation {
                recommendation_type: RecommendationType::ConfidenceThreshold,
                priority: Priority::High,
                description: "Consider raising confidence thresholds to reduce false positive rate".to_string(),
                affected_types: vec!["all".to_string()],
                expected_impact: "Reduce false positives, may increase false negatives".to_string(),
                complexity: Complexity::Low,
            });
        }

        // Check per-type false positive rates
        for (vuln_type, fp_rate) in &statistics.false_positive_rates {
            if *fp_rate > 0.5 {
                recommendations.push(Recommendation {
                    recommendation_type: RecommendationType::ModifyRule,
                    priority: Priority::Medium,
                    description: format!("High false positive rate for {}: {:.1}%", vuln_type, fp_rate * 100.0),
                    affected_types: vec![vuln_type.clone()],
                    expected_impact: "Improve accuracy for this vulnerability type".to_string(),
                    complexity: Complexity::Medium,
                });
            }
        }

        // Check for low confidence predictions that need manual review
        let low_confidence_count = analyses.iter()
            .filter(|a| a.confidence_score < 0.6 && a.confidence_score > 0.4)
            .count();

        if low_confidence_count > analyses.len() / 4 {
            recommendations.push(Recommendation {
                recommendation_type: RecommendationType::ManualReview,
                priority: Priority::Medium,
                description: format!("{} vulnerabilities have uncertain classification", low_confidence_count),
                affected_types: vec!["uncertain".to_string()],
                expected_impact: "Improve classification accuracy through human expertise".to_string(),
                complexity: Complexity::High,
            });
        }

        // Check if accuracy metrics are available and poor
        if let Some(accuracy_metrics) = &statistics.accuracy_metrics {
            if accuracy_metrics.accuracy < 0.8 {
                recommendations.push(Recommendation {
                    recommendation_type: RecommendationType::TrainingData,
                    priority: Priority::High,
                    description: format!("Low overall accuracy: {:.1}%", accuracy_metrics.accuracy * 100.0),
                    affected_types: vec!["all".to_string()],
                    expected_impact: "Significantly improve classification accuracy".to_string(),
                    complexity: Complexity::High,
                });
            }
        }

        recommendations
    }

    /// Get current memory usage
    fn get_memory_usage(&self) -> usize {
        // Platform-specific memory usage detection
        #[cfg(target_os = "linux")]
        {
            if let Ok(contents) = std::fs::read_to_string("/proc/self/status") {
                for line in contents.lines() {
                    if line.starts_with("VmRSS:") {
                        if let Some(kb) = line.split_whitespace().nth(1) {
                            if let Ok(kb_val) = kb.parse::<usize>() {
                                return kb_val * 1024;
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("ps")
                .args(&["-o", "rss=", "-p"])
                .arg(std::process::id().to_string())
                .output()
            {
                if let Ok(rss_str) = String::from_utf8(output.stdout) {
                    if let Ok(rss_kb) = rss_str.trim().parse::<usize>() {
                        return rss_kb * 1024;
                    }
                }
            }
        }

        0
    }
}

impl Default for FalsePositiveConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.7,
            max_false_positive_rate: 0.1, // 10%
            vulnerability_categories: vec![
                "reentrancy".to_string(),
                "access-control".to_string(),
                "arithmetic".to_string(),
                "unchecked-calls".to_string(),
                "timestamp-dependence".to_string(),
            ],
            test_datasets: vec![
                "smartbugs".to_string(),
                "solidifi".to_string(),
                "custom".to_string(),
            ],
            detection_rules: Self::default_detection_rules(),
        }
    }
}

impl FalsePositiveConfig {
    /// Generate default detection rules
    fn default_detection_rules() -> Vec<DetectionRule> {
        vec![
            DetectionRule {
                id: "reentrancy_fp_check".to_string(),
                description: "Check for reentrancy false positives".to_string(),
                vulnerability_type: "reentrancy".to_string(),
                pattern: r"\.call\{value:".to_string(),
                false_positive_indicators: vec![
                    r"require\([^)]*success[^)]*\)".to_string(),
                    r"ReentrancyGuard".to_string(),
                    r"nonReentrant".to_string(),
                    r"mutex".to_string(),
                ],
                true_positive_indicators: vec![
                    r"balances\[[^\]]*\]\s*-=".to_string(),
                    r"msg\.sender\.call".to_string(),
                ],
                weight: 1.0,
            },
            DetectionRule {
                id: "access_control_fp_check".to_string(),
                description: "Check for access control false positives".to_string(),
                vulnerability_type: "access-control".to_string(),
                pattern: r"onlyOwner|require\(.*owner".to_string(),
                false_positive_indicators: vec![
                    r"modifier\s+onlyOwner".to_string(),
                    r"require\(.*owner.*==.*msg\.sender".to_string(),
                    r"Ownable".to_string(),
                ],
                true_positive_indicators: vec![
                    r"function.*public.*{".to_string(),
                    r"function.*external.*{".to_string(),
                ],
                weight: 1.0,
            },
            DetectionRule {
                id: "arithmetic_fp_check".to_string(),
                description: "Check for arithmetic overflow false positives".to_string(),
                vulnerability_type: "arithmetic".to_string(),
                pattern: r"\+|\-|\*|\/".to_string(),
                false_positive_indicators: vec![
                    r"SafeMath".to_string(),
                    r"pragma solidity \^0\.8".to_string(),
                    r"unchecked".to_string(),
                    r"\.add\(|\.sub\(|\.mul\(|\.div\(".to_string(),
                ],
                true_positive_indicators: vec![
                    r"pragma solidity \^0\.7".to_string(),
                    r"pragma solidity \^0\.6".to_string(),
                    r"pragma solidity \^0\.5".to_string(),
                ],
                weight: 1.0,
            },
        ]
    }
}

impl FalsePositiveAnalysisResult {
    /// Save analysis result to JSON file
    pub fn save_to_file(&self, file_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(file_path, json)?;
        Ok(())
    }

    /// Load analysis result from JSON file
    pub fn load_from_file(file_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(file_path)?;
        let result = serde_json::from_str(&content)?;
        Ok(result)
    }

    /// Generate human-readable report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("# False Positive Analysis Report\n\n");
        report.push_str(&format!("**Analysis Date:** {}\n", self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
        report.push_str(&format!("**Total Vulnerabilities:** {}\n", self.statistics.total_vulnerabilities));
        report.push_str(&format!("**Predicted True Positives:** {}\n", self.statistics.predicted_true_positives));
        report.push_str(&format!("**Predicted False Positives:** {}\n\n", self.statistics.predicted_false_positives));

        // Overall statistics
        if self.statistics.total_vulnerabilities > 0 {
            let fp_rate = self.statistics.predicted_false_positives as f64 / self.statistics.total_vulnerabilities as f64;
            report.push_str(&format!("**False Positive Rate:** {:.1}%\n", fp_rate * 100.0));
        }

        // Accuracy metrics if available
        if let Some(accuracy) = &self.statistics.accuracy_metrics {
            report.push_str("\n## Accuracy Metrics\n\n");
            report.push_str(&format!("- **Overall Accuracy:** {:.1}%\n", accuracy.accuracy * 100.0));
            report.push_str(&format!("- **Precision:** {:.1}%\n", accuracy.precision * 100.0));
            report.push_str(&format!("- **Recall:** {:.1}%\n", accuracy.recall * 100.0));
            report.push_str(&format!("- **F1 Score:** {:.3}\n", accuracy.f1_score));
            report.push_str(&format!("- **AUC-ROC:** {:.3}\n", accuracy.auc_roc));
        }

        // False positive rates by vulnerability type
        if !self.statistics.false_positive_rates.is_empty() {
            report.push_str("\n## False Positive Rates by Type\n\n");
            report.push_str("| Vulnerability Type | False Positive Rate |\n");
            report.push_str("|-------------------|--------------------|\n");

            for (vuln_type, rate) in &self.statistics.false_positive_rates {
                report.push_str(&format!("| {} | {:.1}% |\n", vuln_type, rate * 100.0));
            }
            report.push_str("\n");
        }

        // Recommendations
        if !self.recommendations.is_empty() {
            report.push_str("## Recommendations\n\n");

            for (i, rec) in self.recommendations.iter().enumerate() {
                let priority_emoji = match rec.priority {
                    Priority::Critical => "🔴",
                    Priority::High => "🟠",
                    Priority::Medium => "🟡",
                    Priority::Low => "🟢",
                };

                report.push_str(&format!("{}. {} **{}**\n", i + 1, priority_emoji, rec.description));
                report.push_str(&format!("   - **Affected Types:** {}\n", rec.affected_types.join(", ")));
                report.push_str(&format!("   - **Expected Impact:** {}\n", rec.expected_impact));
                report.push_str(&format!("   - **Complexity:** {:?}\n\n", rec.complexity));
            }
        }

        // Performance metrics
        report.push_str("## Performance\n\n");
        report.push_str(&format!("- **Total Analysis Time:** {:.2}s\n", self.performance.total_time.as_secs_f64()));
        report.push_str(&format!("- **Average Time per Vulnerability:** {:.3}s\n", self.performance.avg_time_per_vulnerability.as_secs_f64()));
        report.push_str(&format!("- **Memory Usage:** {:.1} MB\n", self.performance.memory_usage as f64 / 1024.0 / 1024.0));

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_false_positive_config_default() {
        let config = FalsePositiveConfig::default();
        assert_eq!(config.min_confidence, 0.7);
        assert_eq!(config.max_false_positive_rate, 0.1);
        assert!(!config.vulnerability_categories.is_empty());
        assert!(!config.detection_rules.is_empty());
    }

    #[test]
    fn test_detection_rule_creation() {
        let rule = DetectionRule {
            id: "test_rule".to_string(),
            description: "Test rule".to_string(),
            vulnerability_type: "test".to_string(),
            pattern: r"test_pattern".to_string(),
            false_positive_indicators: vec!["fp_indicator".to_string()],
            true_positive_indicators: vec!["tp_indicator".to_string()],
            weight: 1.0,
        };

        assert_eq!(rule.id, "test_rule");
        assert_eq!(rule.vulnerability_type, "test");
        assert_eq!(rule.weight, 1.0);
    }

    #[test]
    fn test_vulnerability_analysis_creation() {
        let vulnerability = VulnerabilityFinding {
            id: "vuln_1".to_string(),
            vulnerability_type: "reentrancy".to_string(),
            severity: "high".to_string(),
            description: "Test vulnerability".to_string(),
            file_path: PathBuf::from("test.sol"),
            line_number: 10,
            column_number: Some(5),
            code_snippet: "msg.sender.call{value: amount}(\"\")".to_string(),
            confidence: 0.8,
            rule_id: "reentrancy_rule".to_string(),
        };

        let analysis = VulnerabilityAnalysis {
            vulnerability: vulnerability.clone(),
            predicted_classification: Classification::TruePositive,
            confidence_score: 0.75,
            ground_truth: Some(Classification::TruePositive),
            triggered_rules: vec!["rule_1".to_string()],
            evidence: vec![],
            manual_review: None,
        };

        assert_eq!(analysis.predicted_classification, Classification::TruePositive);
        assert_eq!(analysis.confidence_score, 0.75);
        assert_eq!(analysis.ground_truth, Some(Classification::TruePositive));
    }

    #[tokio::test]
    async fn test_false_positive_analyzer_creation() {
        let config = FalsePositiveConfig::default();
        let analyzer = FalsePositiveAnalyzer::new(config).unwrap();

        assert!(!analyzer.detection_rules.is_empty());
        assert!(!analyzer.compiled_patterns.is_empty());
    }

    #[test]
    fn test_confusion_matrix_calculation() {
        let mut analyzer = FalsePositiveAnalyzer::new(FalsePositiveConfig::default()).unwrap();

        // Add ground truth data
        analyzer.ground_truth_data.insert("1".to_string(), Classification::TruePositive);
        analyzer.ground_truth_data.insert("2".to_string(), Classification::FalsePositive);
        analyzer.ground_truth_data.insert("3".to_string(), Classification::TruePositive);
        analyzer.ground_truth_data.insert("4".to_string(), Classification::FalsePositive);

        let analyses = vec![
            VulnerabilityAnalysis {
                vulnerability: VulnerabilityFinding {
                    id: "1".to_string(),
                    vulnerability_type: "test".to_string(),
                    severity: "high".to_string(),
                    description: "Test".to_string(),
                    file_path: PathBuf::from("test.sol"),
                    line_number: 1,
                    column_number: None,
                    code_snippet: "test".to_string(),
                    confidence: 0.8,
                    rule_id: "test".to_string(),
                },
                predicted_classification: Classification::TruePositive,
                confidence_score: 0.8,
                ground_truth: Some(Classification::TruePositive),
                triggered_rules: vec![],
                evidence: vec![],
                manual_review: None,
            },
            VulnerabilityAnalysis {
                vulnerability: VulnerabilityFinding {
                    id: "2".to_string(),
                    vulnerability_type: "test".to_string(),
                    severity: "high".to_string(),
                    description: "Test".to_string(),
                    file_path: PathBuf::from("test.sol"),
                    line_number: 1,
                    column_number: None,
                    code_snippet: "test".to_string(),
                    confidence: 0.8,
                    rule_id: "test".to_string(),
                },
                predicted_classification: Classification::FalsePositive,
                confidence_score: 0.8,
                ground_truth: Some(Classification::FalsePositive),
                triggered_rules: vec![],
                evidence: vec![],
                manual_review: None,
            },
        ];

        let accuracy_metrics = analyzer.calculate_accuracy_metrics(&analyses);

        assert_eq!(accuracy_metrics.confusion_matrix.true_positive, 1);
        assert_eq!(accuracy_metrics.confusion_matrix.true_negative, 1);
        assert_eq!(accuracy_metrics.confusion_matrix.false_positive, 0);
        assert_eq!(accuracy_metrics.confusion_matrix.false_negative, 0);
        assert_eq!(accuracy_metrics.accuracy, 1.0);
    }

    #[test]
    fn test_confidence_distribution_calculation() {
        let analyzer = FalsePositiveAnalyzer::new(FalsePositiveConfig::default()).unwrap();

        let analyses = vec![
            VulnerabilityAnalysis {
                vulnerability: VulnerabilityFinding {
                    id: "1".to_string(),
                    vulnerability_type: "test".to_string(),
                    severity: "high".to_string(),
                    description: "Test".to_string(),
                    file_path: PathBuf::from("test.sol"),
                    line_number: 1,
                    column_number: None,
                    code_snippet: "test".to_string(),
                    confidence: 0.8,
                    rule_id: "test".to_string(),
                },
                predicted_classification: Classification::TruePositive,
                confidence_score: 0.25,
                ground_truth: None,
                triggered_rules: vec![],
                evidence: vec![],
                manual_review: None,
            },
            VulnerabilityAnalysis {
                vulnerability: VulnerabilityFinding {
                    id: "2".to_string(),
                    vulnerability_type: "test".to_string(),
                    severity: "high".to_string(),
                    description: "Test".to_string(),
                    file_path: PathBuf::from("test.sol"),
                    line_number: 1,
                    column_number: None,
                    code_snippet: "test".to_string(),
                    confidence: 0.8,
                    rule_id: "test".to_string(),
                },
                predicted_classification: Classification::FalsePositive,
                confidence_score: 0.75,
                ground_truth: None,
                triggered_rules: vec![],
                evidence: vec![],
                manual_review: None,
            },
        ];

        let distribution = analyzer.calculate_confidence_distribution(&analyses);

        assert_eq!(distribution.buckets.len(), 10);
        assert_eq!(distribution.mean_confidence, 0.5);
        assert!(distribution.std_confidence > 0.0);

        // Check that buckets correctly count the analyses
        let bucket_2 = &distribution.buckets[2]; // 0.2-0.3 bucket
        let bucket_7 = &distribution.buckets[7]; // 0.7-0.8 bucket

        assert_eq!(bucket_2.count, 1);
        assert_eq!(bucket_7.count, 1);
    }

    #[test]
    fn test_serialization() {
        let result = FalsePositiveAnalysisResult {
            config: FalsePositiveConfig::default(),
            vulnerability_analyses: vec![],
            statistics: AnalysisStatistics {
                total_vulnerabilities: 10,
                predicted_true_positives: 8,
                predicted_false_positives: 2,
                ground_truth_available: 5,
                accuracy_metrics: None,
                false_positive_rates: HashMap::new(),
                confidence_distribution: ConfidenceDistribution {
                    buckets: vec![],
                    mean_confidence: 0.7,
                    std_confidence: 0.1,
                },
            },
            performance: PerformanceMetrics {
                total_time: Duration::from_secs(10),
                avg_time_per_vulnerability: Duration::from_millis(100),
                memory_usage: 1024 * 1024,
                rules_performance: HashMap::new(),
            },
            recommendations: vec![],
            timestamp: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: FalsePositiveAnalysisResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result.statistics.total_vulnerabilities, deserialized.statistics.total_vulnerabilities);
        assert_eq!(result.statistics.predicted_true_positives, deserialized.statistics.predicted_true_positives);
    }
}