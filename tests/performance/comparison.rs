//! Performance Comparison Tests for SolidityDefend
//!
//! This module implements comprehensive performance benchmarking and comparison
//! infrastructure to measure SolidityDefend's performance against other security
//! analysis tools and across different versions.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

/// Performance benchmark configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkConfig {
    /// Name of the benchmark
    pub name: String,
    /// Timeout for individual test runs
    pub timeout: Duration,
    /// Number of iterations to run
    pub iterations: usize,
    /// Whether to include warmup runs
    pub warmup: bool,
    /// Memory limit in MB
    pub memory_limit: Option<usize>,
    /// Test datasets to use
    pub datasets: Vec<String>,
}

/// Performance metrics for a single run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Total execution time
    pub execution_time: Duration,
    /// Peak memory usage in bytes
    pub peak_memory: usize,
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Number of vulnerabilities detected
    pub vulnerabilities_detected: usize,
    /// Number of files processed
    pub files_processed: usize,
    /// Lines of code analyzed
    pub lines_analyzed: usize,
    /// Analysis throughput (LOC/second)
    pub throughput: f64,
    /// Success/failure status
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Comparison result between tools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    /// Tool name
    pub tool_name: String,
    /// Version information
    pub version: String,
    /// Average metrics across runs
    pub avg_metrics: PerformanceMetrics,
    /// Standard deviation metrics
    pub std_metrics: PerformanceMetrics,
    /// Min/max metrics
    pub min_metrics: PerformanceMetrics,
    pub max_metrics: PerformanceMetrics,
    /// Individual run results
    pub runs: Vec<PerformanceMetrics>,
    /// Relative performance compared to baseline
    pub relative_performance: Option<f64>,
}

/// Performance comparison test suite
pub struct PerformanceComparison {
    config: BenchmarkConfig,
    tools: HashMap<String, ToolConfig>,
    baseline_tool: Option<String>,
    results: HashMap<String, ComparisonResult>,
}

/// Configuration for external tools
#[derive(Debug, Clone)]
struct ToolConfig {
    command: String,
    args: Vec<String>,
    version_command: String,
    output_parser: Box<dyn Fn(&str) -> Option<PerformanceMetrics>>,
}

impl PerformanceComparison {
    /// Create new performance comparison suite
    pub fn new(config: BenchmarkConfig) -> Self {
        Self {
            config,
            tools: HashMap::new(),
            baseline_tool: None,
            results: HashMap::new(),
        }
    }

    /// Add SolidityDefend tool configuration
    pub fn add_soliditydefend(&mut self, binary_path: &str) {
        let config = ToolConfig {
            command: binary_path.to_string(),
            args: vec!["--sarif".to_string(), "--quiet".to_string()],
            version_command: format!("{} --version", binary_path),
            output_parser: Box::new(parse_soliditydefend_output),
        };
        self.tools.insert("SolidityDefend".to_string(), config);
    }

    /// Add Slither tool configuration
    pub fn add_slither(&mut self) {
        let config = ToolConfig {
            command: "slither".to_string(),
            args: vec!["--json".to_string(), "-".to_string()],
            version_command: "slither --version".to_string(),
            output_parser: Box::new(parse_slither_output),
        };
        self.tools.insert("Slither".to_string(), config);
    }

    /// Add MythX tool configuration
    pub fn add_mythx(&mut self, api_key: &str) {
        let config = ToolConfig {
            command: "mythx".to_string(),
            args: vec![
                "analyze".to_string(),
                "--api-key".to_string(),
                api_key.to_string(),
                "--format".to_string(),
                "json".to_string(),
            ],
            version_command: "mythx version".to_string(),
            output_parser: Box::new(parse_mythx_output),
        };
        self.tools.insert("MythX".to_string(), config);
    }

    /// Add Securify tool configuration
    pub fn add_securify(&mut self) {
        let config = ToolConfig {
            command: "securify".to_string(),
            args: vec!["--json".to_string()],
            version_command: "securify --version".to_string(),
            output_parser: Box::new(parse_securify_output),
        };
        self.tools.insert("Securify".to_string(), config);
    }

    /// Add SmartCheck tool configuration
    pub fn add_smartcheck(&mut self) {
        let config = ToolConfig {
            command: "smartcheck".to_string(),
            args: vec!["--output-format".to_string(), "json".to_string()],
            version_command: "smartcheck --version".to_string(),
            output_parser: Box::new(parse_smartcheck_output),
        };
        self.tools.insert("SmartCheck".to_string(), config);
    }

    /// Set baseline tool for relative performance calculations
    pub fn set_baseline(&mut self, tool_name: &str) {
        self.baseline_tool = Some(tool_name.to_string());
    }

    /// Run performance comparison on all configured tools
    pub async fn run_comparison(&mut self, test_files: &[PathBuf]) -> Result<(), Box<dyn std::error::Error>> {
        // Create temporary directory for outputs
        let temp_dir = TempDir::new()?;

        // Run benchmarks for each tool
        for (tool_name, tool_config) in &self.tools {
            println!("Running benchmark for {}", tool_name);

            let result = self.run_tool_benchmark(
                tool_name,
                tool_config,
                test_files,
                &temp_dir
            ).await?;

            self.results.insert(tool_name.clone(), result);
        }

        // Calculate relative performance if baseline is set
        if let Some(baseline_name) = &self.baseline_tool {
            if let Some(baseline_result) = self.results.get(baseline_name) {
                let baseline_time = baseline_result.avg_metrics.execution_time.as_secs_f64();

                for (tool_name, result) in &mut self.results {
                    if tool_name != baseline_name {
                        let tool_time = result.avg_metrics.execution_time.as_secs_f64();
                        result.relative_performance = Some(baseline_time / tool_time);
                    }
                }
            }
        }

        Ok(())
    }

    /// Run benchmark for a specific tool
    async fn run_tool_benchmark(
        &self,
        tool_name: &str,
        tool_config: &ToolConfig,
        test_files: &[PathBuf],
        temp_dir: &TempDir,
    ) -> Result<ComparisonResult, Box<dyn std::error::Error>> {
        // Get tool version
        let version = self.get_tool_version(tool_config)?;
        let mut runs = Vec::new();

        // Warmup runs if configured
        if self.config.warmup {
            for _ in 0..2 {
                let _ = self.run_single_benchmark(tool_config, test_files, temp_dir).await;
            }
        }

        // Actual benchmark runs
        for iteration in 0..self.config.iterations {
            println!("  Iteration {}/{}", iteration + 1, self.config.iterations);

            match self.run_single_benchmark(tool_config, test_files, temp_dir).await {
                Ok(metrics) => runs.push(metrics),
                Err(e) => {
                    let error_metrics = PerformanceMetrics {
                        execution_time: Duration::from_secs(0),
                        peak_memory: 0,
                        cpu_usage: 0.0,
                        vulnerabilities_detected: 0,
                        files_processed: 0,
                        lines_analyzed: 0,
                        throughput: 0.0,
                        success: false,
                        error: Some(e.to_string()),
                    };
                    runs.push(error_metrics);
                }
            }
        }

        // Calculate statistics
        let avg_metrics = self.calculate_average_metrics(&runs);
        let std_metrics = self.calculate_std_metrics(&runs, &avg_metrics);
        let min_metrics = self.calculate_min_metrics(&runs);
        let max_metrics = self.calculate_max_metrics(&runs);

        Ok(ComparisonResult {
            tool_name: tool_name.to_string(),
            version,
            avg_metrics,
            std_metrics,
            min_metrics,
            max_metrics,
            runs,
            relative_performance: None,
        })
    }

    /// Run single benchmark iteration
    async fn run_single_benchmark(
        &self,
        tool_config: &ToolConfig,
        test_files: &[PathBuf],
        temp_dir: &TempDir,
    ) -> Result<PerformanceMetrics, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let start_memory = get_current_memory_usage();

        // Prepare command
        let mut cmd = Command::new(&tool_config.command);
        cmd.args(&tool_config.args);

        // Add test files as arguments
        for file in test_files {
            cmd.arg(file);
        }

        // Set memory limit if configured
        if let Some(memory_limit) = self.config.memory_limit {
            set_memory_limit(&mut cmd, memory_limit);
        }

        // Set timeout
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Execute with timeout
        let output = tokio::time::timeout(
            self.config.timeout,
            tokio::task::spawn_blocking(move || cmd.output())
        ).await??;

        let execution_time = start_time.elapsed();
        let end_memory = get_current_memory_usage();
        let peak_memory = end_memory.saturating_sub(start_memory);

        // Parse output using tool-specific parser
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed_metrics = (tool_config.output_parser)(&stdout);

        let mut metrics = parsed_metrics.unwrap_or_else(|| PerformanceMetrics {
            execution_time,
            peak_memory,
            cpu_usage: 0.0,
            vulnerabilities_detected: 0,
            files_processed: test_files.len(),
            lines_analyzed: count_lines_in_files(test_files),
            throughput: 0.0,
            success: output.status.success(),
            error: if output.status.success() { None } else {
                Some(String::from_utf8_lossy(&output.stderr).to_string())
            },
        });

        // Update basic metrics
        metrics.execution_time = execution_time;
        metrics.peak_memory = peak_memory;
        metrics.files_processed = test_files.len();
        metrics.lines_analyzed = count_lines_in_files(test_files);
        metrics.success = output.status.success();

        // Calculate throughput
        if execution_time.as_secs_f64() > 0.0 {
            metrics.throughput = metrics.lines_analyzed as f64 / execution_time.as_secs_f64();
        }

        Ok(metrics)
    }

    /// Get tool version information
    fn get_tool_version(&self, tool_config: &ToolConfig) -> Result<String, Box<dyn std::error::Error>> {
        let parts: Vec<&str> = tool_config.version_command.split_whitespace().collect();
        if parts.is_empty() {
            return Ok("unknown".to_string());
        }

        let output = Command::new(parts[0])
            .args(&parts[1..])
            .output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Ok("unknown".to_string())
        }
    }

    /// Calculate average metrics across runs
    fn calculate_average_metrics(&self, runs: &[PerformanceMetrics]) -> PerformanceMetrics {
        let successful_runs: Vec<_> = runs.iter().filter(|r| r.success).collect();

        if successful_runs.is_empty() {
            return PerformanceMetrics {
                execution_time: Duration::from_secs(0),
                peak_memory: 0,
                cpu_usage: 0.0,
                vulnerabilities_detected: 0,
                files_processed: 0,
                lines_analyzed: 0,
                throughput: 0.0,
                success: false,
                error: Some("All runs failed".to_string()),
            };
        }

        let count = successful_runs.len() as f64;

        PerformanceMetrics {
            execution_time: Duration::from_secs_f64(
                successful_runs.iter().map(|r| r.execution_time.as_secs_f64()).sum::<f64>() / count
            ),
            peak_memory: (successful_runs.iter().map(|r| r.peak_memory).sum::<usize>() as f64 / count) as usize,
            cpu_usage: successful_runs.iter().map(|r| r.cpu_usage).sum::<f64>() / count,
            vulnerabilities_detected: (successful_runs.iter().map(|r| r.vulnerabilities_detected).sum::<usize>() as f64 / count) as usize,
            files_processed: successful_runs[0].files_processed,
            lines_analyzed: successful_runs[0].lines_analyzed,
            throughput: successful_runs.iter().map(|r| r.throughput).sum::<f64>() / count,
            success: true,
            error: None,
        }
    }

    /// Calculate standard deviation metrics
    fn calculate_std_metrics(&self, runs: &[PerformanceMetrics], avg: &PerformanceMetrics) -> PerformanceMetrics {
        let successful_runs: Vec<_> = runs.iter().filter(|r| r.success).collect();

        if successful_runs.len() < 2 {
            return avg.clone();
        }

        let count = successful_runs.len() as f64;

        let time_variance = successful_runs.iter()
            .map(|r| {
                let diff = r.execution_time.as_secs_f64() - avg.execution_time.as_secs_f64();
                diff * diff
            })
            .sum::<f64>() / (count - 1.0);

        let memory_variance = successful_runs.iter()
            .map(|r| {
                let diff = r.peak_memory as f64 - avg.peak_memory as f64;
                diff * diff
            })
            .sum::<f64>() / (count - 1.0);

        let throughput_variance = successful_runs.iter()
            .map(|r| {
                let diff = r.throughput - avg.throughput;
                diff * diff
            })
            .sum::<f64>() / (count - 1.0);

        PerformanceMetrics {
            execution_time: Duration::from_secs_f64(time_variance.sqrt()),
            peak_memory: memory_variance.sqrt() as usize,
            cpu_usage: 0.0, // TODO: Calculate CPU variance
            vulnerabilities_detected: 0,
            files_processed: 0,
            lines_analyzed: 0,
            throughput: throughput_variance.sqrt(),
            success: true,
            error: None,
        }
    }

    /// Calculate minimum metrics
    fn calculate_min_metrics(&self, runs: &[PerformanceMetrics]) -> PerformanceMetrics {
        let successful_runs: Vec<_> = runs.iter().filter(|r| r.success).collect();

        if successful_runs.is_empty() {
            return PerformanceMetrics {
                execution_time: Duration::from_secs(0),
                peak_memory: 0,
                cpu_usage: 0.0,
                vulnerabilities_detected: 0,
                files_processed: 0,
                lines_analyzed: 0,
                throughput: 0.0,
                success: false,
                error: None,
            };
        }

        PerformanceMetrics {
            execution_time: successful_runs.iter().map(|r| r.execution_time).min().unwrap(),
            peak_memory: successful_runs.iter().map(|r| r.peak_memory).min().unwrap(),
            cpu_usage: successful_runs.iter().map(|r| r.cpu_usage).fold(f64::INFINITY, f64::min),
            vulnerabilities_detected: successful_runs.iter().map(|r| r.vulnerabilities_detected).min().unwrap(),
            files_processed: successful_runs[0].files_processed,
            lines_analyzed: successful_runs[0].lines_analyzed,
            throughput: successful_runs.iter().map(|r| r.throughput).fold(f64::INFINITY, f64::min),
            success: true,
            error: None,
        }
    }

    /// Calculate maximum metrics
    fn calculate_max_metrics(&self, runs: &[PerformanceMetrics]) -> PerformanceMetrics {
        let successful_runs: Vec<_> = runs.iter().filter(|r| r.success).collect();

        if successful_runs.is_empty() {
            return PerformanceMetrics {
                execution_time: Duration::from_secs(0),
                peak_memory: 0,
                cpu_usage: 0.0,
                vulnerabilities_detected: 0,
                files_processed: 0,
                lines_analyzed: 0,
                throughput: 0.0,
                success: false,
                error: None,
            };
        }

        PerformanceMetrics {
            execution_time: successful_runs.iter().map(|r| r.execution_time).max().unwrap(),
            peak_memory: successful_runs.iter().map(|r| r.peak_memory).max().unwrap(),
            cpu_usage: successful_runs.iter().map(|r| r.cpu_usage).fold(f64::NEG_INFINITY, f64::max),
            vulnerabilities_detected: successful_runs.iter().map(|r| r.vulnerabilities_detected).max().unwrap(),
            files_processed: successful_runs[0].files_processed,
            lines_analyzed: successful_runs[0].lines_analyzed,
            throughput: successful_runs.iter().map(|r| r.throughput).fold(f64::NEG_INFINITY, f64::max),
            success: true,
            error: None,
        }
    }

    /// Generate comparison report
    pub fn generate_report(&self) -> ComparisonReport {
        ComparisonReport {
            benchmark_name: self.config.name.clone(),
            timestamp: chrono::Utc::now(),
            results: self.results.clone(),
            baseline_tool: self.baseline_tool.clone(),
        }
    }

    /// Save results to JSON file
    pub fn save_results(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let report = self.generate_report();
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Generate performance ranking
    pub fn get_performance_ranking(&self) -> Vec<(String, f64)> {
        let mut rankings: Vec<_> = self.results.iter()
            .filter(|(_, result)| result.avg_metrics.success)
            .map(|(name, result)| {
                let score = result.avg_metrics.throughput;
                (name.clone(), score)
            })
            .collect();

        rankings.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        rankings
    }
}

/// Complete comparison report
#[derive(Debug, Serialize, Deserialize)]
pub struct ComparisonReport {
    pub benchmark_name: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub results: HashMap<String, ComparisonResult>,
    pub baseline_tool: Option<String>,
}

// Output parsers for different tools
fn parse_soliditydefend_output(output: &str) -> Option<PerformanceMetrics> {
    // Parse SARIF output to count vulnerabilities
    if let Ok(sarif) = serde_json::from_str::<serde_json::Value>(output) {
        let mut vuln_count = 0;

        if let Some(runs) = sarif["runs"].as_array() {
            for run in runs {
                if let Some(results) = run["results"].as_array() {
                    vuln_count += results.len();
                }
            }
        }

        Some(PerformanceMetrics {
            execution_time: Duration::from_secs(0), // Will be filled by caller
            peak_memory: 0, // Will be filled by caller
            cpu_usage: 0.0,
            vulnerabilities_detected: vuln_count,
            files_processed: 0, // Will be filled by caller
            lines_analyzed: 0, // Will be filled by caller
            throughput: 0.0, // Will be calculated by caller
            success: true,
            error: None,
        })
    } else {
        None
    }
}

fn parse_slither_output(output: &str) -> Option<PerformanceMetrics> {
    // Parse Slither JSON output
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
        let vuln_count = json["results"]["detectors"].as_array()
            .map(|arr| arr.len())
            .unwrap_or(0);

        Some(PerformanceMetrics {
            execution_time: Duration::from_secs(0),
            peak_memory: 0,
            cpu_usage: 0.0,
            vulnerabilities_detected: vuln_count,
            files_processed: 0,
            lines_analyzed: 0,
            throughput: 0.0,
            success: true,
            error: None,
        })
    } else {
        None
    }
}

fn parse_mythx_output(output: &str) -> Option<PerformanceMetrics> {
    // Parse MythX JSON output
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
        let vuln_count = json["issues"].as_array()
            .map(|arr| arr.len())
            .unwrap_or(0);

        Some(PerformanceMetrics {
            execution_time: Duration::from_secs(0),
            peak_memory: 0,
            cpu_usage: 0.0,
            vulnerabilities_detected: vuln_count,
            files_processed: 0,
            lines_analyzed: 0,
            throughput: 0.0,
            success: true,
            error: None,
        })
    } else {
        None
    }
}

fn parse_securify_output(output: &str) -> Option<PerformanceMetrics> {
    // Parse Securify JSON output
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
        let vuln_count = json["results"].as_array()
            .map(|arr| arr.len())
            .unwrap_or(0);

        Some(PerformanceMetrics {
            execution_time: Duration::from_secs(0),
            peak_memory: 0,
            cpu_usage: 0.0,
            vulnerabilities_detected: vuln_count,
            files_processed: 0,
            lines_analyzed: 0,
            throughput: 0.0,
            success: true,
            error: None,
        })
    } else {
        None
    }
}

fn parse_smartcheck_output(output: &str) -> Option<PerformanceMetrics> {
    // Parse SmartCheck JSON output
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
        let vuln_count = json["vulnerabilities"].as_array()
            .map(|arr| arr.len())
            .unwrap_or(0);

        Some(PerformanceMetrics {
            execution_time: Duration::from_secs(0),
            peak_memory: 0,
            cpu_usage: 0.0,
            vulnerabilities_detected: vuln_count,
            files_processed: 0,
            lines_analyzed: 0,
            throughput: 0.0,
            success: true,
            error: None,
        })
    } else {
        None
    }
}

// Utility functions
fn get_current_memory_usage() -> usize {
    // Platform-specific memory usage detection
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        if let Ok(contents) = fs::read_to_string("/proc/self/status") {
            for line in contents.lines() {
                if line.starts_with("VmRSS:") {
                    if let Some(kb) = line.split_whitespace().nth(1) {
                        if let Ok(kb_val) = kb.parse::<usize>() {
                            return kb_val * 1024; // Convert KB to bytes
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
                    return rss_kb * 1024; // Convert KB to bytes
                }
            }
        }
    }

    // Fallback
    0
}

fn set_memory_limit(cmd: &mut Command, limit_mb: usize) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let limit_bytes = limit_mb * 1024 * 1024;
        cmd.pre_exec(move || {
            unsafe {
                libc::setrlimit(
                    libc::RLIMIT_AS,
                    &libc::rlimit {
                        rlim_cur: limit_bytes as libc::rlim_t,
                        rlim_max: limit_bytes as libc::rlim_t,
                    },
                );
            }
            Ok(())
        });
    }
}

fn count_lines_in_files(files: &[PathBuf]) -> usize {
    files.iter()
        .filter_map(|file| std::fs::read_to_string(file).ok())
        .map(|content| content.lines().count())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_performance_comparison_creation() {
        let config = BenchmarkConfig {
            name: "Test Benchmark".to_string(),
            timeout: Duration::from_secs(30),
            iterations: 3,
            warmup: true,
            memory_limit: Some(1024),
            datasets: vec!["test".to_string()],
        };

        let comparison = PerformanceComparison::new(config);
        assert_eq!(comparison.config.name, "Test Benchmark");
        assert_eq!(comparison.config.iterations, 3);
        assert!(comparison.config.warmup);
    }

    #[test]
    fn test_metrics_calculation() {
        let runs = vec![
            PerformanceMetrics {
                execution_time: Duration::from_secs(10),
                peak_memory: 1000,
                cpu_usage: 50.0,
                vulnerabilities_detected: 5,
                files_processed: 10,
                lines_analyzed: 1000,
                throughput: 100.0,
                success: true,
                error: None,
            },
            PerformanceMetrics {
                execution_time: Duration::from_secs(20),
                peak_memory: 2000,
                cpu_usage: 60.0,
                vulnerabilities_detected: 7,
                files_processed: 10,
                lines_analyzed: 1000,
                throughput: 50.0,
                success: true,
                error: None,
            },
        ];

        let config = BenchmarkConfig {
            name: "Test".to_string(),
            timeout: Duration::from_secs(30),
            iterations: 2,
            warmup: false,
            memory_limit: None,
            datasets: vec![],
        };

        let comparison = PerformanceComparison::new(config);
        let avg = comparison.calculate_average_metrics(&runs);

        assert_eq!(avg.execution_time, Duration::from_secs(15));
        assert_eq!(avg.peak_memory, 1500);
        assert_eq!(avg.cpu_usage, 55.0);
        assert_eq!(avg.vulnerabilities_detected, 6);
        assert_eq!(avg.throughput, 75.0);
    }

    #[test]
    fn test_soliditydefend_output_parsing() {
        let sarif_output = r#"{
            "runs": [{
                "results": [
                    {"ruleId": "reentrancy"},
                    {"ruleId": "access-control"}
                ]
            }]
        }"#;

        let metrics = parse_soliditydefend_output(sarif_output).unwrap();
        assert_eq!(metrics.vulnerabilities_detected, 2);
        assert!(metrics.success);
    }

    #[test]
    fn test_slither_output_parsing() {
        let slither_output = r#"{
            "results": {
                "detectors": [
                    {"check": "reentrancy-eth"},
                    {"check": "arbitrary-send-eth"},
                    {"check": "controlled-delegatecall"}
                ]
            }
        }"#;

        let metrics = parse_slither_output(slither_output).unwrap();
        assert_eq!(metrics.vulnerabilities_detected, 3);
        assert!(metrics.success);
    }

    #[test]
    fn test_report_generation() {
        let config = BenchmarkConfig {
            name: "Test Report".to_string(),
            timeout: Duration::from_secs(30),
            iterations: 1,
            warmup: false,
            memory_limit: None,
            datasets: vec![],
        };

        let comparison = PerformanceComparison::new(config);
        let report = comparison.generate_report();

        assert_eq!(report.benchmark_name, "Test Report");
        assert!(report.results.is_empty());
    }

    #[test]
    fn test_performance_ranking() {
        let mut comparison = PerformanceComparison::new(BenchmarkConfig {
            name: "Test".to_string(),
            timeout: Duration::from_secs(30),
            iterations: 1,
            warmup: false,
            memory_limit: None,
            datasets: vec![],
        });

        // Add mock results
        let result1 = ComparisonResult {
            tool_name: "Tool A".to_string(),
            version: "1.0".to_string(),
            avg_metrics: PerformanceMetrics {
                execution_time: Duration::from_secs(10),
                peak_memory: 1000,
                cpu_usage: 50.0,
                vulnerabilities_detected: 5,
                files_processed: 10,
                lines_analyzed: 1000,
                throughput: 100.0,
                success: true,
                error: None,
            },
            std_metrics: PerformanceMetrics {
                execution_time: Duration::from_secs(1),
                peak_memory: 100,
                cpu_usage: 5.0,
                vulnerabilities_detected: 1,
                files_processed: 0,
                lines_analyzed: 0,
                throughput: 10.0,
                success: true,
                error: None,
            },
            min_metrics: PerformanceMetrics {
                execution_time: Duration::from_secs(9),
                peak_memory: 900,
                cpu_usage: 45.0,
                vulnerabilities_detected: 4,
                files_processed: 10,
                lines_analyzed: 1000,
                throughput: 90.0,
                success: true,
                error: None,
            },
            max_metrics: PerformanceMetrics {
                execution_time: Duration::from_secs(11),
                peak_memory: 1100,
                cpu_usage: 55.0,
                vulnerabilities_detected: 6,
                files_processed: 10,
                lines_analyzed: 1000,
                throughput: 110.0,
                success: true,
                error: None,
            },
            runs: vec![],
            relative_performance: None,
        };

        let result2 = ComparisonResult {
            tool_name: "Tool B".to_string(),
            version: "2.0".to_string(),
            avg_metrics: PerformanceMetrics {
                execution_time: Duration::from_secs(20),
                peak_memory: 2000,
                cpu_usage: 60.0,
                vulnerabilities_detected: 3,
                files_processed: 10,
                lines_analyzed: 1000,
                throughput: 50.0,
                success: true,
                error: None,
            },
            std_metrics: PerformanceMetrics {
                execution_time: Duration::from_secs(2),
                peak_memory: 200,
                cpu_usage: 6.0,
                vulnerabilities_detected: 0,
                files_processed: 0,
                lines_analyzed: 0,
                throughput: 5.0,
                success: true,
                error: None,
            },
            min_metrics: PerformanceMetrics {
                execution_time: Duration::from_secs(18),
                peak_memory: 1800,
                cpu_usage: 54.0,
                vulnerabilities_detected: 3,
                files_processed: 10,
                lines_analyzed: 1000,
                throughput: 45.0,
                success: true,
                error: None,
            },
            max_metrics: PerformanceMetrics {
                execution_time: Duration::from_secs(22),
                peak_memory: 2200,
                cpu_usage: 66.0,
                vulnerabilities_detected: 3,
                files_processed: 10,
                lines_analyzed: 1000,
                throughput: 55.0,
                success: true,
                error: None,
            },
            runs: vec![],
            relative_performance: None,
        };

        comparison.results.insert("Tool A".to_string(), result1);
        comparison.results.insert("Tool B".to_string(), result2);

        let ranking = comparison.get_performance_ranking();
        assert_eq!(ranking.len(), 2);
        assert_eq!(ranking[0].0, "Tool A"); // Higher throughput should rank first
        assert_eq!(ranking[1].0, "Tool B");
    }
}