//! Performance Regression Testing for SolidityDefend
//!
//! This module implements performance regression testing to detect
//! performance degradation between different versions of SolidityDefend.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tokio::process::Command as AsyncCommand;

/// Configuration for regression testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionConfig {
    /// Baseline version/branch to compare against
    pub baseline_version: String,
    /// Performance degradation threshold (0.1 = 10%)
    pub threshold: f64,
    /// Number of iterations to run
    pub iterations: usize,
    /// Timeout for individual runs
    pub timeout: Duration,
}

/// Result of regression testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionResult {
    /// Whether performance has degraded beyond threshold
    pub performance_degraded: bool,
    /// Percentage of performance change (positive = degradation)
    pub degradation_percentage: f64,
    /// Baseline performance metrics
    pub baseline_time: Duration,
    /// Current version performance metrics
    pub current_time: Duration,
    /// Configured threshold
    pub threshold: f64,
    /// Detailed metrics for baseline version
    pub baseline_metrics: PerformanceSnapshot,
    /// Detailed metrics for current version
    pub current_metrics: PerformanceSnapshot,
    /// Test files used
    pub test_files: Vec<PathBuf>,
    /// Timestamp of test
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Performance snapshot for a specific version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSnapshot {
    /// Version identifier
    pub version: String,
    /// Total execution time
    pub total_time: Duration,
    /// Average time per file
    pub avg_time_per_file: Duration,
    /// Peak memory usage
    pub peak_memory: usize,
    /// Files processed successfully
    pub files_processed: usize,
    /// Total lines of code analyzed
    pub total_lines: usize,
    /// Analysis throughput
    pub throughput: f64,
    /// Individual file results
    pub file_results: HashMap<PathBuf, FilePerformance>,
}

/// Performance metrics for individual files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePerformance {
    /// File size in bytes
    pub file_size: usize,
    /// Lines of code
    pub lines_of_code: usize,
    /// Execution time
    pub execution_time: Duration,
    /// Memory usage
    pub memory_usage: usize,
    /// Number of vulnerabilities found
    pub vulnerabilities_found: usize,
    /// Success status
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Performance regression tester
pub struct RegressionTester {
    config: RegressionConfig,
    baseline_binary: Option<PathBuf>,
}

impl RegressionTester {
    /// Create new regression tester
    pub fn new(config: RegressionConfig) -> Self {
        Self {
            config,
            baseline_binary: None,
        }
    }

    /// Set path to baseline binary (if different from current)
    pub fn set_baseline_binary(&mut self, path: PathBuf) {
        self.baseline_binary = Some(path);
    }

    /// Run regression test comparing current version against baseline
    pub async fn run_regression_test(
        &self,
        current_binary: &str,
        test_files: &[PathBuf],
    ) -> Result<RegressionResult, Box<dyn std::error::Error>> {
        println!("Running performance regression test...");

        // Get baseline binary (build from baseline version if needed)
        let baseline_binary = match &self.baseline_binary {
            Some(path) => path.clone(),
            None => self.build_baseline_binary().await?,
        };

        // Run performance tests on baseline version
        println!("  Testing baseline version: {}", self.config.baseline_version);
        let baseline_metrics = self.measure_performance(
            &baseline_binary.to_string_lossy(),
            test_files,
            &self.config.baseline_version,
        ).await?;

        // Run performance tests on current version
        println!("  Testing current version...");
        let current_metrics = self.measure_performance(
            current_binary,
            test_files,
            "current",
        ).await?;

        // Calculate performance difference
        let baseline_time = baseline_metrics.total_time.as_secs_f64();
        let current_time = current_metrics.total_time.as_secs_f64();
        let degradation_percentage = (current_time - baseline_time) / baseline_time;

        let performance_degraded = degradation_percentage > self.config.threshold;

        // Generate detailed result
        let result = RegressionResult {
            performance_degraded,
            degradation_percentage,
            baseline_time: baseline_metrics.total_time,
            current_time: current_metrics.total_time,
            threshold: self.config.threshold,
            baseline_metrics,
            current_metrics,
            test_files: test_files.to_vec(),
            timestamp: chrono::Utc::now(),
        };

        // Print summary
        if performance_degraded {
            println!("  ⚠️ Performance regression detected: {:.1}% slower", degradation_percentage * 100.0);
        } else {
            println!("  ✅ No performance regression: {:.1}% change", degradation_percentage * 100.0);
        }

        Ok(result)
    }

    /// Build baseline binary from specified version
    async fn build_baseline_binary(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        println!("  Building baseline binary from {}", self.config.baseline_version);

        // Save current git state
        let current_branch = self.get_current_git_branch()?;
        let current_commit = self.get_current_git_commit()?;

        // Checkout baseline version
        let checkout_result = AsyncCommand::new("git")
            .args(&["checkout", &self.config.baseline_version])
            .output()
            .await?;

        if !checkout_result.status.success() {
            return Err(format!("Failed to checkout baseline version: {}",
                String::from_utf8_lossy(&checkout_result.stderr)).into());
        }

        // Build baseline binary
        let build_result = AsyncCommand::new("cargo")
            .args(&["build", "--release", "--bin", "soliditydefend"])
            .output()
            .await?;

        if !build_result.status.success() {
            // Restore original state
            let _ = AsyncCommand::new("git")
                .args(&["checkout", &current_commit])
                .output()
                .await;

            return Err(format!("Failed to build baseline binary: {}",
                String::from_utf8_lossy(&build_result.stderr)).into());
        }

        // Copy baseline binary to temporary location
        let baseline_binary = std::env::temp_dir().join("soliditydefend_baseline");
        std::fs::copy("target/release/soliditydefend", &baseline_binary)?;

        // Restore original git state
        AsyncCommand::new("git")
            .args(&["checkout", &current_branch])
            .output()
            .await?;

        Ok(baseline_binary)
    }

    /// Measure performance for a specific binary
    async fn measure_performance(
        &self,
        binary_path: &str,
        test_files: &[PathBuf],
        version: &str,
    ) -> Result<PerformanceSnapshot, Box<dyn std::error::Error>> {
        let mut file_results = HashMap::new();
        let mut total_time = Duration::from_secs(0);
        let mut peak_memory = 0;
        let mut files_processed = 0;
        let mut total_lines = 0;

        // Run multiple iterations for each file
        for file in test_files {
            let mut file_times = Vec::new();
            let mut file_memories = Vec::new();
            let mut file_vulns = Vec::new();
            let mut success_count = 0;
            let mut last_error = None;

            // Count lines in file
            let lines_of_code = self.count_lines_in_file(file)?;
            let file_size = std::fs::metadata(file)?.len() as usize;

            for iteration in 0..self.config.iterations {
                match self.run_single_file_test(binary_path, file).await {
                    Ok((duration, memory, vulns)) => {
                        file_times.push(duration);
                        file_memories.push(memory);
                        file_vulns.push(vulns);
                        success_count += 1;
                    }
                    Err(e) => {
                        last_error = Some(e.to_string());
                    }
                }
            }

            if success_count > 0 {
                // Calculate averages for successful runs
                let avg_time = Duration::from_nanos(
                    file_times.iter().map(|d| d.as_nanos()).sum::<u128>() / success_count as u128
                );
                let avg_memory = file_memories.iter().sum::<usize>() / success_count;
                let avg_vulns = file_vulns.iter().sum::<usize>() / success_count;

                total_time += avg_time;
                peak_memory = peak_memory.max(avg_memory);
                files_processed += 1;
                total_lines += lines_of_code;

                file_results.insert(file.clone(), FilePerformance {
                    file_size,
                    lines_of_code,
                    execution_time: avg_time,
                    memory_usage: avg_memory,
                    vulnerabilities_found: avg_vulns,
                    success: true,
                    error: None,
                });
            } else {
                file_results.insert(file.clone(), FilePerformance {
                    file_size,
                    lines_of_code,
                    execution_time: Duration::from_secs(0),
                    memory_usage: 0,
                    vulnerabilities_found: 0,
                    success: false,
                    error: last_error,
                });
            }
        }

        let avg_time_per_file = if files_processed > 0 {
            Duration::from_nanos(total_time.as_nanos() / files_processed as u128)
        } else {
            Duration::from_secs(0)
        };

        let throughput = if total_time.as_secs_f64() > 0.0 {
            total_lines as f64 / total_time.as_secs_f64()
        } else {
            0.0
        };

        Ok(PerformanceSnapshot {
            version: version.to_string(),
            total_time,
            avg_time_per_file,
            peak_memory,
            files_processed,
            total_lines,
            throughput,
            file_results,
        })
    }

    /// Run performance test on a single file
    async fn run_single_file_test(
        &self,
        binary_path: &str,
        file: &Path,
    ) -> Result<(Duration, usize, usize), Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let start_memory = self.get_memory_usage();

        // Run SolidityDefend on the file
        let output = tokio::time::timeout(
            self.config.timeout,
            AsyncCommand::new(binary_path)
                .args(&["--format", "json", "--quiet"])
                .arg(file)
                .output()
        ).await??;

        let execution_time = start_time.elapsed();
        let end_memory = self.get_memory_usage();
        let memory_used = end_memory.saturating_sub(start_memory);

        if !output.status.success() {
            return Err(format!("Analysis failed: {}",
                String::from_utf8_lossy(&output.stderr)).into());
        }

        // Parse JSON output to count vulnerabilities
        let vulnerabilities = self.count_vulnerabilities_in_json(&output.stdout)?;

        Ok((execution_time, memory_used, vulnerabilities))
    }

    /// Count vulnerabilities in JSON output
    fn count_vulnerabilities_in_json(&self, json_bytes: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
        let json_str = String::from_utf8_lossy(json_bytes);

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
            if let Some(findings) = json["findings"].as_array() {
                return Ok(findings.len());
            }
        }

        Ok(0)
    }

    /// Count lines of code in a file
    fn count_lines_in_file(&self, file: &Path) -> Result<usize, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(file)?;
        Ok(content.lines().count())
    }

    /// Get current memory usage (platform-specific)
    fn get_memory_usage(&self) -> usize {
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

    /// Get current git branch
    fn get_current_git_branch(&self) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new("git")
            .args(&["rev-parse", "--abbrev-ref", "HEAD"])
            .output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err("Failed to get current git branch".into())
        }
    }

    /// Get current git commit
    fn get_current_git_commit(&self) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new("git")
            .args(&["rev-parse", "HEAD"])
            .output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err("Failed to get current git commit".into())
        }
    }
}

impl RegressionResult {
    /// Save regression result to JSON file
    pub fn save_to_file(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load regression result from JSON file
    pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let result = serde_json::from_str(&content)?;
        Ok(result)
    }

    /// Generate human-readable summary
    pub fn generate_summary(&self) -> String {
        let mut summary = String::new();

        summary.push_str("# Performance Regression Test Results\n\n");
        summary.push_str(&format!("**Test Date:** {}\n", self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
        summary.push_str(&format!("**Baseline Version:** {}\n", self.baseline_metrics.version));
        summary.push_str(&format!("**Current Version:** current\n"));
        summary.push_str(&format!("**Threshold:** {:.1}%\n\n", self.threshold * 100.0));

        if self.performance_degraded {
            summary.push_str("## ⚠️ Performance Regression Detected\n\n");
            summary.push_str(&format!("Performance has degraded by **{:.2}%**, exceeding the {:.1}% threshold.\n\n",
                self.degradation_percentage * 100.0, self.threshold * 100.0));
        } else {
            summary.push_str("## ✅ No Performance Regression\n\n");
            if self.degradation_percentage < 0.0 {
                summary.push_str(&format!("Performance has **improved** by {:.2}%.\n\n",
                    -self.degradation_percentage * 100.0));
            } else {
                summary.push_str(&format!("Performance change: +{:.2}% (within acceptable threshold).\n\n",
                    self.degradation_percentage * 100.0));
            }
        }

        summary.push_str("## Performance Comparison\n\n");
        summary.push_str("| Metric | Baseline | Current | Change |\n");
        summary.push_str("|--------|----------|---------|--------|\n");

        let baseline_time = self.baseline_metrics.total_time.as_secs_f64();
        let current_time = self.current_metrics.total_time.as_secs_f64();
        let time_change = (current_time - baseline_time) / baseline_time * 100.0;

        summary.push_str(&format!("| Total Time | {:.2}s | {:.2}s | {:+.1}% |\n",
            baseline_time, current_time, time_change));

        let baseline_throughput = self.baseline_metrics.throughput;
        let current_throughput = self.current_metrics.throughput;
        let throughput_change = (current_throughput - baseline_throughput) / baseline_throughput * 100.0;

        summary.push_str(&format!("| Throughput | {:.1} LOC/s | {:.1} LOC/s | {:+.1}% |\n",
            baseline_throughput, current_throughput, throughput_change));

        let baseline_memory = self.baseline_metrics.peak_memory as f64 / 1024.0 / 1024.0;
        let current_memory = self.current_metrics.peak_memory as f64 / 1024.0 / 1024.0;
        let memory_change = if baseline_memory > 0.0 {
            (current_memory - baseline_memory) / baseline_memory * 100.0
        } else {
            0.0
        };

        summary.push_str(&format!("| Peak Memory | {:.1} MB | {:.1} MB | {:+.1}% |\n",
            baseline_memory, current_memory, memory_change));

        summary.push_str(&format!("| Files Processed | {} | {} | {:+} |\n",
            self.baseline_metrics.files_processed,
            self.current_metrics.files_processed,
            self.current_metrics.files_processed as i32 - self.baseline_metrics.files_processed as i32));

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_regression_config_creation() {
        let config = RegressionConfig {
            baseline_version: "v1.0.0".to_string(),
            threshold: 0.1,
            iterations: 5,
            timeout: Duration::from_secs(60),
        };

        assert_eq!(config.baseline_version, "v1.0.0");
        assert_eq!(config.threshold, 0.1);
        assert_eq!(config.iterations, 5);
    }

    #[test]
    fn test_regression_tester_creation() {
        let config = RegressionConfig {
            baseline_version: "main".to_string(),
            threshold: 0.05,
            iterations: 3,
            timeout: Duration::from_secs(30),
        };

        let tester = RegressionTester::new(config);
        assert_eq!(tester.config.baseline_version, "main");
        assert_eq!(tester.config.threshold, 0.05);
    }

    #[test]
    fn test_performance_snapshot_creation() {
        let snapshot = PerformanceSnapshot {
            version: "test".to_string(),
            total_time: Duration::from_secs(10),
            avg_time_per_file: Duration::from_secs(2),
            peak_memory: 1024 * 1024,
            files_processed: 5,
            total_lines: 1000,
            throughput: 100.0,
            file_results: HashMap::new(),
        };

        assert_eq!(snapshot.version, "test");
        assert_eq!(snapshot.total_time, Duration::from_secs(10));
        assert_eq!(snapshot.files_processed, 5);
        assert_eq!(snapshot.throughput, 100.0);
    }

    #[test]
    fn test_regression_result_creation() {
        let baseline_metrics = PerformanceSnapshot {
            version: "baseline".to_string(),
            total_time: Duration::from_secs(10),
            avg_time_per_file: Duration::from_secs(2),
            peak_memory: 1024 * 1024,
            files_processed: 5,
            total_lines: 1000,
            throughput: 100.0,
            file_results: HashMap::new(),
        };

        let current_metrics = PerformanceSnapshot {
            version: "current".to_string(),
            total_time: Duration::from_secs(12),
            avg_time_per_file: Duration::from_secs(2),
            peak_memory: 1024 * 1024,
            files_processed: 5,
            total_lines: 1000,
            throughput: 83.3,
            file_results: HashMap::new(),
        };

        let result = RegressionResult {
            performance_degraded: true,
            degradation_percentage: 0.2,
            baseline_time: Duration::from_secs(10),
            current_time: Duration::from_secs(12),
            threshold: 0.1,
            baseline_metrics,
            current_metrics,
            test_files: vec![],
            timestamp: chrono::Utc::now(),
        };

        assert!(result.performance_degraded);
        assert_eq!(result.degradation_percentage, 0.2);
        assert_eq!(result.threshold, 0.1);
    }

    #[test]
    fn test_regression_result_serialization() {
        let result = RegressionResult {
            performance_degraded: false,
            degradation_percentage: -0.05,
            baseline_time: Duration::from_secs(10),
            current_time: Duration::from_secs(9),
            threshold: 0.1,
            baseline_metrics: PerformanceSnapshot {
                version: "baseline".to_string(),
                total_time: Duration::from_secs(10),
                avg_time_per_file: Duration::from_secs(2),
                peak_memory: 1024,
                files_processed: 5,
                total_lines: 1000,
                throughput: 100.0,
                file_results: HashMap::new(),
            },
            current_metrics: PerformanceSnapshot {
                version: "current".to_string(),
                total_time: Duration::from_secs(9),
                avg_time_per_file: Duration::from_secs(1),
                peak_memory: 1024,
                files_processed: 5,
                total_lines: 1000,
                throughput: 111.1,
                file_results: HashMap::new(),
            },
            test_files: vec![],
            timestamp: chrono::Utc::now(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: RegressionResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result.performance_degraded, deserialized.performance_degraded);
        assert_eq!(result.degradation_percentage, deserialized.degradation_percentage);
        assert_eq!(result.baseline_metrics.version, deserialized.baseline_metrics.version);
    }

    #[test]
    fn test_summary_generation() {
        let result = RegressionResult {
            performance_degraded: true,
            degradation_percentage: 0.15,
            baseline_time: Duration::from_secs(10),
            current_time: Duration::from_secs(11),
            threshold: 0.1,
            baseline_metrics: PerformanceSnapshot {
                version: "v1.0.0".to_string(),
                total_time: Duration::from_secs(10),
                avg_time_per_file: Duration::from_secs(2),
                peak_memory: 1024 * 1024,
                files_processed: 5,
                total_lines: 1000,
                throughput: 100.0,
                file_results: HashMap::new(),
            },
            current_metrics: PerformanceSnapshot {
                version: "current".to_string(),
                total_time: Duration::from_secs(11),
                avg_time_per_file: Duration::from_secs(2),
                peak_memory: 1024 * 1024,
                files_processed: 5,
                total_lines: 1000,
                throughput: 90.9,
                file_results: HashMap::new(),
            },
            test_files: vec![],
            timestamp: chrono::Utc::now(),
        };

        let summary = result.generate_summary();
        assert!(summary.contains("Performance Regression Detected"));
        assert!(summary.contains("15.00%"));
        assert!(summary.contains("v1.0.0"));
    }
}