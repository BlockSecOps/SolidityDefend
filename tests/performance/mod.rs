//! Performance Testing Module for SolidityDefend
//!
//! This module provides comprehensive performance testing infrastructure including:
//! - Performance comparison against other security analysis tools
//! - Regression testing to detect performance degradation
//! - Scalability testing with varying contract sizes
//! - Memory usage profiling and analysis

pub mod comparison;
pub mod regression;
pub mod scalability;

pub use comparison::{PerformanceComparison, BenchmarkConfig, PerformanceMetrics, ComparisonResult};
pub use regression::{RegressionTester, RegressionConfig, RegressionResult};
pub use scalability::{ScalabilityTester, ScalabilityConfig, ScalabilityResult};

use std::path::PathBuf;
use std::time::Duration;
use serde::{Deserialize, Serialize};

/// Performance test suite configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTestConfig {
    /// Output directory for test results
    pub output_dir: PathBuf,
    /// Timeout for individual tests
    pub timeout: Duration,
    /// Number of iterations for each test
    pub iterations: usize,
    /// Whether to include warmup runs
    pub warmup: bool,
    /// Memory limit in MB
    pub memory_limit: Option<usize>,
    /// Test datasets to use
    pub datasets: Vec<String>,
}

impl Default for PerformanceTestConfig {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("target/performance"),
            timeout: Duration::from_secs(300), // 5 minutes
            iterations: 5,
            warmup: true,
            memory_limit: Some(4096), // 4GB
            datasets: vec![
                "smartbugs".to_string(),
                "solidifi".to_string(),
                "custom".to_string(),
            ],
        }
    }
}

/// Complete performance test suite
pub struct PerformanceTestSuite {
    config: PerformanceTestConfig,
    comparison_tester: PerformanceComparison,
    regression_tester: RegressionTester,
    scalability_tester: ScalabilityTester,
}

impl PerformanceTestSuite {
    /// Create new performance test suite
    pub fn new(config: PerformanceTestConfig) -> Self {
        let benchmark_config = BenchmarkConfig {
            name: "SolidityDefend Performance Suite".to_string(),
            timeout: config.timeout,
            iterations: config.iterations,
            warmup: config.warmup,
            memory_limit: config.memory_limit,
            datasets: config.datasets.clone(),
        };

        let regression_config = RegressionConfig {
            baseline_version: "main".to_string(),
            threshold: 0.1, // 10% performance degradation threshold
            iterations: config.iterations,
            timeout: config.timeout,
        };

        let scalability_config = ScalabilityConfig {
            min_size: 100,
            max_size: 100000,
            size_steps: 10,
            iterations: config.iterations,
            timeout: config.timeout,
        };

        Self {
            config: config.clone(),
            comparison_tester: PerformanceComparison::new(benchmark_config),
            regression_tester: RegressionTester::new(regression_config),
            scalability_tester: ScalabilityTester::new(scalability_config),
        }
    }

    /// Run complete performance test suite
    pub async fn run_full_suite(&mut self, soliditydefend_binary: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running SolidityDefend Performance Test Suite");
        println!("===========================================");

        // Ensure output directory exists
        std::fs::create_dir_all(&self.config.output_dir)?;

        // 1. Run comparison tests against other tools
        println!("\n1. Running tool comparison tests...");
        self.setup_comparison_tools(soliditydefend_binary);

        let test_files = self.collect_test_files()?;
        self.comparison_tester.run_comparison(&test_files).await?;

        let comparison_path = self.config.output_dir.join("comparison_results.json");
        self.comparison_tester.save_results(&comparison_path)?;
        println!("   Comparison results saved to: {}", comparison_path.display());

        // 2. Run regression tests
        println!("\n2. Running regression tests...");
        let regression_result = self.regression_tester.run_regression_test(
            soliditydefend_binary,
            &test_files
        ).await?;

        let regression_path = self.config.output_dir.join("regression_results.json");
        regression_result.save_to_file(&regression_path)?;
        println!("   Regression results saved to: {}", regression_path.display());

        // 3. Run scalability tests
        println!("\n3. Running scalability tests...");
        let scalability_result = self.scalability_tester.run_scalability_test(
            soliditydefend_binary
        ).await?;

        let scalability_path = self.config.output_dir.join("scalability_results.json");
        scalability_result.save_to_file(&scalability_path)?;
        println!("   Scalability results saved to: {}", scalability_path.display());

        // 4. Generate summary report
        println!("\n4. Generating summary report...");
        self.generate_summary_report().await?;

        println!("\nPerformance test suite completed successfully!");
        println!("Results available in: {}", self.config.output_dir.display());

        Ok(())
    }

    /// Setup comparison tools
    fn setup_comparison_tools(&mut self, soliditydefend_binary: &str) {
        // Add SolidityDefend as primary tool
        self.comparison_tester.add_soliditydefend(soliditydefend_binary);
        self.comparison_tester.set_baseline("SolidityDefend");

        // Add other tools if available
        if which::which("slither").is_ok() {
            self.comparison_tester.add_slither();
            println!("   Added Slither for comparison");
        }

        if std::env::var("MYTHX_API_KEY").is_ok() {
            if let Ok(api_key) = std::env::var("MYTHX_API_KEY") {
                self.comparison_tester.add_mythx(&api_key);
                println!("   Added MythX for comparison");
            }
        }

        if which::which("securify").is_ok() {
            self.comparison_tester.add_securify();
            println!("   Added Securify for comparison");
        }

        if which::which("smartcheck").is_ok() {
            self.comparison_tester.add_smartcheck();
            println!("   Added SmartCheck for comparison");
        }
    }

    /// Collect test files from datasets
    fn collect_test_files(&self) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
        let mut test_files = Vec::new();

        for dataset in &self.config.datasets {
            let dataset_path = match dataset.as_str() {
                "smartbugs" => PathBuf::from("tests/data/smartbugs"),
                "solidifi" => PathBuf::from("tests/data/solidifi"),
                "custom" => PathBuf::from("tests/data/custom"),
                _ => continue,
            };

            if dataset_path.exists() {
                for entry in walkdir::WalkDir::new(dataset_path) {
                    let entry = entry?;
                    if entry.file_type().is_file() {
                        if let Some(ext) = entry.path().extension() {
                            if ext == "sol" {
                                test_files.push(entry.path().to_path_buf());
                            }
                        }
                    }
                }
            }
        }

        // If no test files found, create some sample files
        if test_files.is_empty() {
            test_files = self.create_sample_test_files()?;
        }

        Ok(test_files)
    }

    /// Create sample test files if none exist
    fn create_sample_test_files(&self) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
        let test_dir = self.config.output_dir.join("sample_contracts");
        std::fs::create_dir_all(&test_dir)?;

        let samples = vec![
            ("simple.sol", include_str!("../../data/contracts/simple.sol")),
            ("reentrancy.sol", include_str!("../../data/contracts/reentrancy.sol")),
            ("access_control.sol", include_str!("../../data/contracts/access_control.sol")),
        ];

        let mut test_files = Vec::new();
        for (filename, content) in samples {
            let file_path = test_dir.join(filename);
            std::fs::write(&file_path, content)?;
            test_files.push(file_path);
        }

        Ok(test_files)
    }

    /// Generate comprehensive summary report
    async fn generate_summary_report(&self) -> Result<(), Box<dyn std::error::Error>> {
        let summary_path = self.config.output_dir.join("performance_summary.md");

        let mut report = String::new();
        report.push_str("# SolidityDefend Performance Test Summary\n\n");
        report.push_str(&format!("Generated: {}\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));

        // Add comparison results
        let comparison_path = self.config.output_dir.join("comparison_results.json");
        if comparison_path.exists() {
            report.push_str("## Tool Comparison Results\n\n");
            if let Ok(content) = std::fs::read_to_string(&comparison_path) {
                if let Ok(results) = serde_json::from_str::<comparison::ComparisonReport>(&content) {
                    let ranking = self.generate_ranking_table(&results);
                    report.push_str(&ranking);
                }
            }
        }

        // Add regression results
        let regression_path = self.config.output_dir.join("regression_results.json");
        if regression_path.exists() {
            report.push_str("\n## Regression Test Results\n\n");
            if let Ok(content) = std::fs::read_to_string(&regression_path) {
                if let Ok(results) = serde_json::from_str::<regression::RegressionResult>(&content) {
                    let regression_summary = self.generate_regression_summary(&results);
                    report.push_str(&regression_summary);
                }
            }
        }

        // Add scalability results
        let scalability_path = self.config.output_dir.join("scalability_results.json");
        if scalability_path.exists() {
            report.push_str("\n## Scalability Test Results\n\n");
            if let Ok(content) = std::fs::read_to_string(&scalability_path) {
                if let Ok(results) = serde_json::from_str::<scalability::ScalabilityResult>(&content) {
                    let scalability_summary = self.generate_scalability_summary(&results);
                    report.push_str(&scalability_summary);
                }
            }
        }

        std::fs::write(summary_path, report)?;
        Ok(())
    }

    /// Generate ranking table for comparison results
    fn generate_ranking_table(&self, results: &comparison::ComparisonReport) -> String {
        let mut table = String::new();
        table.push_str("| Rank | Tool | Version | Throughput (LOC/s) | Memory (MB) | Vulnerabilities |\n");
        table.push_str("|------|------|---------|-------------------|-------------|----------------|\n");

        let mut tools: Vec<_> = results.results.iter()
            .filter(|(_, result)| result.avg_metrics.success)
            .collect();

        tools.sort_by(|a, b| b.1.avg_metrics.throughput.partial_cmp(&a.1.avg_metrics.throughput).unwrap_or(std::cmp::Ordering::Equal));

        for (rank, (name, result)) in tools.iter().enumerate() {
            table.push_str(&format!(
                "| {} | {} | {} | {:.1} | {:.1} | {} |\n",
                rank + 1,
                name,
                result.version,
                result.avg_metrics.throughput,
                result.avg_metrics.peak_memory as f64 / 1024.0 / 1024.0,
                result.avg_metrics.vulnerabilities_detected
            ));
        }

        table
    }

    /// Generate regression summary
    fn generate_regression_summary(&self, results: &regression::RegressionResult) -> String {
        let mut summary = String::new();

        if results.performance_degraded {
            summary.push_str("⚠️ **Performance Regression Detected**\n\n");
            summary.push_str(&format!("Performance degraded by {:.1}% compared to baseline\n", results.degradation_percentage * 100.0));
        } else {
            summary.push_str("✅ **No Performance Regression**\n\n");
            summary.push_str(&format!("Performance improved by {:.1}% compared to baseline\n", -results.degradation_percentage * 100.0));
        }

        summary.push_str(&format!("- Baseline: {:.2}s\n", results.baseline_time.as_secs_f64()));
        summary.push_str(&format!("- Current: {:.2}s\n", results.current_time.as_secs_f64()));
        summary.push_str(&format!("- Threshold: {:.1}%\n", results.threshold * 100.0));

        summary
    }

    /// Generate scalability summary
    fn generate_scalability_summary(&self, results: &scalability::ScalabilityResult) -> String {
        let mut summary = String::new();
        summary.push_str(&format!("**Complexity:** {}\n", results.complexity_class));
        summary.push_str(&format!("**Max Throughput:** {:.1} LOC/s\n", results.max_throughput));
        summary.push_str(&format!("**Memory Efficiency:** {:.1} MB/KLOC\n", results.memory_efficiency));

        if results.scalability_issues.is_empty() {
            summary.push_str("✅ No scalability issues detected\n");
        } else {
            summary.push_str("⚠️ Scalability issues:\n");
            for issue in &results.scalability_issues {
                summary.push_str(&format!("- {}\n", issue));
            }
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_test_config_default() {
        let config = PerformanceTestConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(300));
        assert_eq!(config.iterations, 5);
        assert!(config.warmup);
        assert_eq!(config.memory_limit, Some(4096));
        assert!(config.datasets.contains(&"smartbugs".to_string()));
    }

    #[test]
    fn test_performance_test_suite_creation() {
        let config = PerformanceTestConfig::default();
        let suite = PerformanceTestSuite::new(config);

        // Test that suite is created with correct configuration
        assert_eq!(suite.config.iterations, 5);
        assert!(suite.config.warmup);
    }
}