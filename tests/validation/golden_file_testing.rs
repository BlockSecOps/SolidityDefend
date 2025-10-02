use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenFile {
    pub test_name: String,
    pub input_file: String,
    pub expected_output: AnalysisOutput,
    pub metadata: GoldenFileMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenFileMetadata {
    pub created_at: String,
    pub updated_at: String,
    pub version: String,
    pub description: String,
    pub tags: Vec<String>,
    pub input_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalysisOutput {
    pub findings: Vec<Finding>,
    pub statistics: AnalysisStatistics,
    pub performance_metrics: PerformanceMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: String,
    pub detector: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub file_path: String,
    pub line_number: usize,
    pub column: usize,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalysisStatistics {
    pub total_files: usize,
    pub total_lines: usize,
    pub total_functions: usize,
    pub total_contracts: usize,
    pub analysis_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PerformanceMetrics {
    pub memory_usage_mb: f64,
    pub cpu_utilization: f64,
    pub analysis_time_ms: u64,
}

#[derive(Debug, Clone)]
pub struct RegressionTestResult {
    pub test_name: String,
    pub status: TestStatus,
    pub differences: Vec<Difference>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TestStatus {
    Passed,
    Failed,
    Updated,
    Skipped,
}

#[derive(Debug, Clone)]
pub struct Difference {
    pub field: String,
    pub expected: String,
    pub actual: String,
    pub severity: DifferenceSeverity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DifferenceSeverity {
    Critical,    // Breaking changes (e.g., missing critical findings)
    Major,       // Significant changes (e.g., different number of findings)
    Minor,       // Small changes (e.g., slightly different line numbers)
    Cosmetic,    // Formatting or description changes
}

pub struct GoldenFileRegression {
    golden_files_dir: PathBuf,
    test_inputs_dir: PathBuf,
    tolerance_config: ToleranceConfig,
    update_mode: bool,
}

#[derive(Debug, Clone)]
pub struct ToleranceConfig {
    pub line_number_tolerance: usize,
    pub confidence_tolerance: f64,
    pub performance_tolerance: f64,
    pub allow_new_findings: bool,
    pub ignore_cosmetic_changes: bool,
}

impl Default for ToleranceConfig {
    fn default() -> Self {
        Self {
            line_number_tolerance: 2,
            confidence_tolerance: 0.1,
            performance_tolerance: 0.2, // 20% tolerance
            allow_new_findings: false,
            ignore_cosmetic_changes: true,
        }
    }
}

impl GoldenFileRegression {
    pub fn new(golden_files_dir: &str, test_inputs_dir: &str) -> Self {
        Self {
            golden_files_dir: PathBuf::from(golden_files_dir),
            test_inputs_dir: PathBuf::from(test_inputs_dir),
            tolerance_config: ToleranceConfig::default(),
            update_mode: false,
        }
    }

    pub fn with_tolerance(mut self, config: ToleranceConfig) -> Self {
        self.tolerance_config = config;
        self
    }

    pub fn with_update_mode(mut self, update: bool) -> Self {
        self.update_mode = update;
        self
    }

    pub fn create_golden_file(&self, test_name: &str, input_file: &str, output: &AnalysisOutput) -> Result<(), Box<dyn std::error::Error>> {
        let input_hash = self.calculate_file_hash(input_file)?;
        let timestamp = chrono::Utc::now().to_rfc3339();

        let golden_file = GoldenFile {
            test_name: test_name.to_string(),
            input_file: input_file.to_string(),
            expected_output: output.clone(),
            metadata: GoldenFileMetadata {
                created_at: timestamp.clone(),
                updated_at: timestamp,
                version: "1.0.0".to_string(),
                description: format!("Golden file for {}", test_name),
                tags: vec!["regression".to_string(), "golden".to_string()],
                input_hash,
            },
        };

        self.save_golden_file(&golden_file)?;
        println!("Created golden file for test: {}", test_name);
        Ok(())
    }

    pub fn run_regression_tests(&self) -> Result<Vec<RegressionTestResult>, Box<dyn std::error::Error>> {
        let golden_files = self.load_all_golden_files()?;
        let mut results = Vec::new();

        for golden_file in golden_files {
            println!("Running regression test: {}", golden_file.test_name);

            let test_result = match self.run_single_test(&golden_file) {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("Error running test {}: {}", golden_file.test_name, e);
                    RegressionTestResult {
                        test_name: golden_file.test_name.clone(),
                        status: TestStatus::Failed,
                        differences: vec![],
                        summary: format!("Test execution failed: {}", e),
                    }
                }
            };

            results.push(test_result);
        }

        Ok(results)
    }

    fn run_single_test(&self, golden_file: &GoldenFile) -> Result<RegressionTestResult, Box<dyn std::error::Error>> {
        // Check if input file has changed
        let current_hash = self.calculate_file_hash(&golden_file.input_file)?;
        if current_hash != golden_file.metadata.input_hash {
            return Ok(RegressionTestResult {
                test_name: golden_file.test_name.clone(),
                status: TestStatus::Failed,
                differences: vec![Difference {
                    field: "input_file_hash".to_string(),
                    expected: golden_file.metadata.input_hash.clone(),
                    actual: current_hash,
                    severity: DifferenceSeverity::Critical,
                }],
                summary: "Input file has been modified since golden file creation".to_string(),
            });
        }

        // Run analysis on the input file
        let actual_output = self.run_analysis(&golden_file.input_file)?;

        // Compare outputs
        let differences = self.compare_outputs(&golden_file.expected_output, &actual_output);

        let status = if differences.is_empty() {
            TestStatus::Passed
        } else if self.update_mode && self.should_update(&differences) {
            self.update_golden_file(golden_file, &actual_output)?;
            TestStatus::Updated
        } else {
            TestStatus::Failed
        };

        let summary = self.generate_test_summary(&differences, &status);

        Ok(RegressionTestResult {
            test_name: golden_file.test_name.clone(),
            status,
            differences,
            summary,
        })
    }

    fn run_analysis(&self, input_file: &str) -> Result<AnalysisOutput, Box<dyn std::error::Error>> {
        // This would normally call the actual SolidityDefend analysis engine
        // For now, we'll create a mock implementation

        // Mock analysis - in real implementation, this would call:
        // let output = soliditydefend_engine.analyze(input_file)?;

        let mock_findings = vec![
            Finding {
                id: "REENTRANCY_001".to_string(),
                detector: "reentrancy".to_string(),
                severity: "High".to_string(),
                title: "Potential reentrancy vulnerability".to_string(),
                description: "External call before state update".to_string(),
                file_path: input_file.to_string(),
                line_number: 25,
                column: 12,
                confidence: 0.85,
            },
        ];

        let mock_statistics = AnalysisStatistics {
            total_files: 1,
            total_lines: 100,
            total_functions: 5,
            total_contracts: 1,
            analysis_duration_ms: 150,
        };

        let mock_performance = PerformanceMetrics {
            memory_usage_mb: 45.2,
            cpu_utilization: 78.5,
            analysis_time_ms: 150,
        };

        Ok(AnalysisOutput {
            findings: mock_findings,
            statistics: mock_statistics,
            performance_metrics: mock_performance,
        })
    }

    fn compare_outputs(&self, expected: &AnalysisOutput, actual: &AnalysisOutput) -> Vec<Difference> {
        let mut differences = Vec::new();

        // Compare findings
        self.compare_findings(&expected.findings, &actual.findings, &mut differences);

        // Compare statistics
        self.compare_statistics(&expected.statistics, &actual.statistics, &mut differences);

        // Compare performance metrics (with tolerance)
        self.compare_performance(&expected.performance_metrics, &actual.performance_metrics, &mut differences);

        differences
    }

    fn compare_findings(&self, expected: &[Finding], actual: &[Finding], differences: &mut Vec<Difference>) {
        // Check for missing findings
        for exp_finding in expected {
            if !self.finding_exists_in_actual(exp_finding, actual) {
                differences.push(Difference {
                    field: format!("missing_finding_{}", exp_finding.id),
                    expected: format!("{}: {}", exp_finding.detector, exp_finding.title),
                    actual: "Not found".to_string(),
                    severity: DifferenceSeverity::Critical,
                });
            }
        }

        // Check for extra findings
        if !self.tolerance_config.allow_new_findings {
            for act_finding in actual {
                if !self.finding_exists_in_expected(act_finding, expected) {
                    differences.push(Difference {
                        field: format!("extra_finding_{}", act_finding.id),
                        expected: "Not present".to_string(),
                        actual: format!("{}: {}", act_finding.detector, act_finding.title),
                        severity: DifferenceSeverity::Major,
                    });
                }
            }
        }

        // Check for differences in matching findings
        for exp_finding in expected {
            if let Some(act_finding) = self.find_matching_finding(exp_finding, actual) {
                self.compare_individual_findings(exp_finding, act_finding, differences);
            }
        }
    }

    fn finding_exists_in_actual(&self, expected_finding: &Finding, actual_findings: &[Finding]) -> bool {
        actual_findings.iter().any(|actual| self.findings_match(expected_finding, actual))
    }

    fn finding_exists_in_expected(&self, actual_finding: &Finding, expected_findings: &[Finding]) -> bool {
        expected_findings.iter().any(|expected| self.findings_match(expected, actual_finding))
    }

    fn find_matching_finding<'a>(&self, expected: &Finding, actual: &'a [Finding]) -> Option<&'a Finding> {
        actual.iter().find(|&act| self.findings_match(expected, act))
    }

    fn findings_match(&self, expected: &Finding, actual: &Finding) -> bool {
        expected.detector == actual.detector &&
        expected.file_path == actual.file_path &&
        self.line_numbers_within_tolerance(expected.line_number, actual.line_number)
    }

    fn line_numbers_within_tolerance(&self, expected: usize, actual: usize) -> bool {
        (expected as i32 - actual as i32).abs() <= self.tolerance_config.line_number_tolerance as i32
    }

    fn compare_individual_findings(&self, expected: &Finding, actual: &Finding, differences: &mut Vec<Difference>) {
        // Compare confidence
        let confidence_diff = (expected.confidence - actual.confidence).abs();
        if confidence_diff > self.tolerance_config.confidence_tolerance {
            differences.push(Difference {
                field: format!("finding_{}_confidence", expected.id),
                expected: format!("{:.3}", expected.confidence),
                actual: format!("{:.3}", actual.confidence),
                severity: DifferenceSeverity::Minor,
            });
        }

        // Compare severity
        if expected.severity != actual.severity {
            differences.push(Difference {
                field: format!("finding_{}_severity", expected.id),
                expected: expected.severity.clone(),
                actual: actual.severity.clone(),
                severity: DifferenceSeverity::Major,
            });
        }

        // Compare descriptions (cosmetic if ignore_cosmetic_changes is true)
        if expected.description != actual.description && !self.tolerance_config.ignore_cosmetic_changes {
            differences.push(Difference {
                field: format!("finding_{}_description", expected.id),
                expected: expected.description.clone(),
                actual: actual.description.clone(),
                severity: DifferenceSeverity::Cosmetic,
            });
        }
    }

    fn compare_statistics(&self, expected: &AnalysisStatistics, actual: &AnalysisStatistics, differences: &mut Vec<Difference>) {
        if expected.total_files != actual.total_files {
            differences.push(Difference {
                field: "total_files".to_string(),
                expected: expected.total_files.to_string(),
                actual: actual.total_files.to_string(),
                severity: DifferenceSeverity::Minor,
            });
        }

        if expected.total_contracts != actual.total_contracts {
            differences.push(Difference {
                field: "total_contracts".to_string(),
                expected: expected.total_contracts.to_string(),
                actual: actual.total_contracts.to_string(),
                severity: DifferenceSeverity::Major,
            });
        }
    }

    fn compare_performance(&self, expected: &PerformanceMetrics, actual: &PerformanceMetrics, differences: &mut Vec<Difference>) {
        // Check analysis time with tolerance
        let time_diff = (expected.analysis_time_ms as f64 - actual.analysis_time_ms as f64).abs() / expected.analysis_time_ms as f64;
        if time_diff > self.tolerance_config.performance_tolerance {
            differences.push(Difference {
                field: "analysis_time_ms".to_string(),
                expected: expected.analysis_time_ms.to_string(),
                actual: actual.analysis_time_ms.to_string(),
                severity: DifferenceSeverity::Minor,
            });
        }

        // Check memory usage with tolerance
        let memory_diff = (expected.memory_usage_mb - actual.memory_usage_mb).abs() / expected.memory_usage_mb;
        if memory_diff > self.tolerance_config.performance_tolerance {
            differences.push(Difference {
                field: "memory_usage_mb".to_string(),
                expected: format!("{:.1}", expected.memory_usage_mb),
                actual: format!("{:.1}", actual.memory_usage_mb),
                severity: DifferenceSeverity::Minor,
            });
        }
    }

    fn should_update(&self, differences: &[Difference]) -> bool {
        // Only update if differences are minor or cosmetic
        differences.iter().all(|diff| {
            matches!(diff.severity, DifferenceSeverity::Minor | DifferenceSeverity::Cosmetic)
        })
    }

    fn update_golden_file(&self, golden_file: &GoldenFile, new_output: &AnalysisOutput) -> Result<(), Box<dyn std::error::Error>> {
        let mut updated_golden = golden_file.clone();
        updated_golden.expected_output = new_output.clone();
        updated_golden.metadata.updated_at = chrono::Utc::now().to_rfc3339();

        self.save_golden_file(&updated_golden)?;
        println!("Updated golden file: {}", golden_file.test_name);
        Ok(())
    }

    fn generate_test_summary(&self, differences: &[Difference], status: &TestStatus) -> String {
        match status {
            TestStatus::Passed => "Test passed - output matches golden file".to_string(),
            TestStatus::Updated => format!("Golden file updated - {} differences resolved", differences.len()),
            TestStatus::Failed => {
                let critical_count = differences.iter().filter(|d| d.severity == DifferenceSeverity::Critical).count();
                let major_count = differences.iter().filter(|d| d.severity == DifferenceSeverity::Major).count();
                format!("Test failed - {} critical, {} major differences", critical_count, major_count)
            },
            TestStatus::Skipped => "Test skipped".to_string(),
        }
    }

    fn calculate_file_hash(&self, file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
        let content = fs::read(file_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn save_golden_file(&self, golden_file: &GoldenFile) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(&self.golden_files_dir)?;
        let file_path = self.golden_files_dir.join(format!("{}.json", golden_file.test_name));
        let content = serde_json::to_string_pretty(golden_file)?;
        fs::write(file_path, content)?;
        Ok(())
    }

    fn load_all_golden_files(&self) -> Result<Vec<GoldenFile>, Box<dyn std::error::Error>> {
        let mut golden_files = Vec::new();

        if !self.golden_files_dir.exists() {
            return Ok(golden_files);
        }

        for entry in fs::read_dir(&self.golden_files_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(&path)?;
                let golden_file: GoldenFile = serde_json::from_str(&content)?;
                golden_files.push(golden_file);
            }
        }

        Ok(golden_files)
    }

    pub fn generate_regression_report(&self, results: &[RegressionTestResult]) -> String {
        let mut report = String::new();
        report.push_str("# Regression Test Report\n\n");

        let passed = results.iter().filter(|r| r.status == TestStatus::Passed).count();
        let failed = results.iter().filter(|r| r.status == TestStatus::Failed).count();
        let updated = results.iter().filter(|r| r.status == TestStatus::Updated).count();

        report.push_str(&format!("## Summary\n\n"));
        report.push_str(&format!("- Total Tests: {}\n", results.len()));
        report.push_str(&format!("- Passed: {}\n", passed));
        report.push_str(&format!("- Failed: {}\n", failed));
        report.push_str(&format!("- Updated: {}\n", updated));
        report.push_str(&format!("- Success Rate: {:.1}%\n\n", (passed as f64 / results.len() as f64) * 100.0));

        report.push_str("## Test Results\n\n");
        report.push_str("| Test Name | Status | Differences | Summary |\n");
        report.push_str("|-----------|--------|-------------|----------|\n");

        for result in results {
            let status_emoji = match result.status {
                TestStatus::Passed => "✅",
                TestStatus::Failed => "❌",
                TestStatus::Updated => "🔄",
                TestStatus::Skipped => "⏭️",
            };

            report.push_str(&format!(
                "| {} | {} {:?} | {} | {} |\n",
                result.test_name,
                status_emoji,
                result.status,
                result.differences.len(),
                result.summary
            ));
        }

        // Detailed failure analysis
        let failed_tests: Vec<_> = results.iter().filter(|r| r.status == TestStatus::Failed).collect();
        if !failed_tests.is_empty() {
            report.push_str("\n## Failed Tests Details\n\n");

            for failed_test in failed_tests {
                report.push_str(&format!("### {}\n\n", failed_test.test_name));
                report.push_str(&format!("**Summary:** {}\n\n", failed_test.summary));

                if !failed_test.differences.is_empty() {
                    report.push_str("**Differences:**\n\n");
                    for diff in &failed_test.differences {
                        report.push_str(&format!(
                            "- **{}** ({}): Expected `{}`, got `{}`\n",
                            diff.field,
                            format!("{:?}", diff.severity),
                            diff.expected,
                            diff.actual
                        ));
                    }
                    report.push_str("\n");
                }
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_golden_file_regression_creation() {
        let regression = GoldenFileRegression::new("test_golden", "test_inputs");
        assert_eq!(regression.golden_files_dir, PathBuf::from("test_golden"));
        assert_eq!(regression.test_inputs_dir, PathBuf::from("test_inputs"));
        assert!(!regression.update_mode);
    }

    #[test]
    fn test_tolerance_config() {
        let config = ToleranceConfig::default();
        assert_eq!(config.line_number_tolerance, 2);
        assert_eq!(config.confidence_tolerance, 0.1);
        assert_eq!(config.performance_tolerance, 0.2);
    }

    #[test]
    fn test_findings_match() {
        let regression = GoldenFileRegression::new("test", "test");

        let finding1 = Finding {
            id: "1".to_string(),
            detector: "reentrancy".to_string(),
            severity: "High".to_string(),
            title: "Test".to_string(),
            description: "Test description".to_string(),
            file_path: "test.sol".to_string(),
            line_number: 10,
            column: 5,
            confidence: 0.8,
        };

        let finding2 = Finding {
            id: "2".to_string(),
            detector: "reentrancy".to_string(),
            severity: "High".to_string(),
            title: "Test".to_string(),
            description: "Test description".to_string(),
            file_path: "test.sol".to_string(),
            line_number: 12, // Within tolerance
            column: 5,
            confidence: 0.8,
        };

        assert!(regression.findings_match(&finding1, &finding2));
    }

    #[test]
    fn test_line_number_tolerance() {
        let regression = GoldenFileRegression::new("test", "test");
        assert!(regression.line_numbers_within_tolerance(10, 10));
        assert!(regression.line_numbers_within_tolerance(10, 12));
        assert!(regression.line_numbers_within_tolerance(10, 8));
        assert!(!regression.line_numbers_within_tolerance(10, 15));
    }

    #[test]
    fn test_difference_severity() {
        let critical = Difference {
            field: "test".to_string(),
            expected: "expected".to_string(),
            actual: "actual".to_string(),
            severity: DifferenceSeverity::Critical,
        };

        assert_eq!(critical.severity, DifferenceSeverity::Critical);
    }
}