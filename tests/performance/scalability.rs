//! Scalability Testing for SolidityDefend
//!
//! This module implements scalability testing to measure how SolidityDefend
//! performs with varying contract sizes and complexity levels.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tokio::process::Command as AsyncCommand;
use tempfile::TempDir;

/// Configuration for scalability testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalabilityConfig {
    /// Minimum contract size (lines of code)
    pub min_size: usize,
    /// Maximum contract size (lines of code)
    pub max_size: usize,
    /// Number of size steps to test
    pub size_steps: usize,
    /// Number of iterations per size
    pub iterations: usize,
    /// Timeout for individual runs
    pub timeout: Duration,
}

/// Result of scalability testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalabilityResult {
    /// Complexity class (Linear, Quadratic, etc.)
    pub complexity_class: String,
    /// Maximum sustainable throughput
    pub max_throughput: f64,
    /// Memory efficiency (MB per KLOC)
    pub memory_efficiency: f64,
    /// Size at which performance significantly degrades
    pub degradation_threshold: Option<usize>,
    /// Detailed measurements for each size
    pub measurements: Vec<ScalabilityMeasurement>,
    /// Identified scalability issues
    pub scalability_issues: Vec<String>,
    /// Test configuration used
    pub config: ScalabilityConfig,
    /// Timestamp of test
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Performance measurement for a specific contract size
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalabilityMeasurement {
    /// Contract size in lines of code
    pub size: usize,
    /// Average execution time
    pub avg_time: Duration,
    /// Standard deviation of execution time
    pub std_time: Duration,
    /// Average memory usage
    pub avg_memory: usize,
    /// Peak memory usage
    pub peak_memory: usize,
    /// Throughput (LOC/second)
    pub throughput: f64,
    /// Number of successful runs
    pub successful_runs: usize,
    /// Number of failed runs (timeouts, errors)
    pub failed_runs: usize,
    /// Vulnerabilities detected
    pub vulnerabilities_detected: usize,
}

/// Contract generator for scalability testing
struct ContractGenerator {
    temp_dir: TempDir,
}

impl ContractGenerator {
    /// Create new contract generator
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            temp_dir: TempDir::new()?,
        })
    }

    /// Generate a Solidity contract of specified size
    fn generate_contract(&self, target_lines: usize) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let file_path = self.temp_dir.path().join(format!("test_contract_{}.sol", target_lines));

        let mut content = String::new();
        content.push_str("// SPDX-License-Identifier: MIT\n");
        content.push_str("pragma solidity ^0.8.0;\n\n");
        content.push_str(&format!("contract ScalabilityTest{} {{\n", target_lines));

        let mut current_lines = 4; // Already written 4 lines

        // Add state variables
        let state_vars = (target_lines / 20).max(1);
        for i in 0..state_vars {
            content.push_str(&format!("    uint256 public variable{};\n", i));
            content.push_str(&format!("    mapping(address => uint256) public balance{};\n", i));
            current_lines += 2;
        }

        content.push_str("\n");
        current_lines += 1;

        // Add functions with varying complexity
        while current_lines < target_lines - 10 {
            let func_lines = self.generate_function(&mut content, current_lines)?;
            current_lines += func_lines;
        }

        // Fill remaining lines with comments
        while current_lines < target_lines - 1 {
            content.push_str(&format!("    // Filler comment line {}\n", current_lines));
            current_lines += 1;
        }

        content.push_str("}\n");

        std::fs::write(&file_path, content)?;
        Ok(file_path)
    }

    /// Generate a function with potential vulnerabilities
    fn generate_function(&self, content: &mut String, func_id: usize) -> Result<usize, Box<dyn std::error::Error>> {
        let func_type = func_id % 5;
        let mut lines_added = 0;

        match func_type {
            0 => {
                // Reentrancy-vulnerable function
                content.push_str(&format!("    function vulnerableWithdraw{}(uint256 amount) external {{\n", func_id));
                content.push_str("        require(balance[msg.sender] >= amount, \"Insufficient balance\");\n");
                content.push_str("        (bool success, ) = msg.sender.call{value: amount}(\"\");\n");
                content.push_str("        require(success, \"Transfer failed\");\n");
                content.push_str("        balance[msg.sender] -= amount;\n");
                content.push_str("    }\n\n");
                lines_added = 7;
            },
            1 => {
                // Access control issue
                content.push_str(&format!("    function adminFunction{}() external {{\n", func_id));
                content.push_str("        // Missing access control\n");
                content.push_str(&format!("        variable{} = 1000;\n", func_id % 10));
                content.push_str("    }\n\n");
                lines_added = 5;
            },
            2 => {
                // Integer overflow potential
                content.push_str(&format!("    function arithmeticOperation{}(uint256 a, uint256 b) external returns (uint256) {{\n", func_id));
                content.push_str("        uint256 result = a + b; // Potential overflow\n");
                content.push_str("        return result * 2;\n");
                content.push_str("    }\n\n");
                lines_added = 5;
            },
            3 => {
                // Complex loop function
                content.push_str(&format!("    function complexLoop{}(uint256 iterations) external {{\n", func_id));
                content.push_str("        for (uint256 i = 0; i < iterations; i++) {\n");
                content.push_str("            for (uint256 j = 0; j < i; j++) {\n");
                content.push_str(&format!("                variable{} += j;\n", func_id % 10));
                content.push_str("            }\n");
                content.push_str("        }\n");
                content.push_str("    }\n\n");
                lines_added = 8;
            },
            _ => {
                // Simple getter/setter
                content.push_str(&format!("    function setVariable{}(uint256 value) external {{\n", func_id));
                content.push_str(&format!("        variable{} = value;\n", func_id % 10));
                content.push_str("    }\n\n");
                content.push_str(&format!("    function getVariable{}() external view returns (uint256) {{\n", func_id));
                content.push_str(&format!("        return variable{};\n", func_id % 10));
                content.push_str("    }\n\n");
                lines_added = 7;
            }
        }

        Ok(lines_added)
    }
}

/// Scalability tester
pub struct ScalabilityTester {
    config: ScalabilityConfig,
    generator: ContractGenerator,
}

impl ScalabilityTester {
    /// Create new scalability tester
    pub fn new(config: ScalabilityConfig) -> Self {
        let generator = ContractGenerator::new().expect("Failed to create contract generator");
        Self { config, generator }
    }

    /// Run complete scalability test
    pub async fn run_scalability_test(
        &self,
        binary_path: &str,
    ) -> Result<ScalabilityResult, Box<dyn std::error::Error>> {
        println!("Running scalability test...");

        let mut measurements = Vec::new();
        let mut scalability_issues = Vec::new();

        // Generate size points to test
        let size_points = self.generate_size_points();

        for (i, size) in size_points.iter().enumerate() {
            println!("  Testing size: {} LOC ({}/{})", size, i + 1, size_points.len());

            match self.measure_size_performance(binary_path, *size).await {
                Ok(measurement) => {
                    measurements.push(measurement);
                }
                Err(e) => {
                    println!("    Error testing size {}: {}", size, e);
                    scalability_issues.push(format!("Failed to test size {}: {}", size, e));
                }
            }
        }

        // Analyze results
        let complexity_class = self.analyze_complexity(&measurements);
        let max_throughput = measurements.iter()
            .map(|m| m.throughput)
            .fold(0.0, f64::max);

        let memory_efficiency = self.calculate_memory_efficiency(&measurements);
        let degradation_threshold = self.find_degradation_threshold(&measurements);

        // Check for specific scalability issues
        self.analyze_scalability_issues(&measurements, &mut scalability_issues);

        Ok(ScalabilityResult {
            complexity_class,
            max_throughput,
            memory_efficiency,
            degradation_threshold,
            measurements,
            scalability_issues,
            config: self.config.clone(),
            timestamp: chrono::Utc::now(),
        })
    }

    /// Generate size points to test
    fn generate_size_points(&self) -> Vec<usize> {
        let mut points = Vec::new();
        let step_size = (self.config.max_size - self.config.min_size) / self.config.size_steps;

        for i in 0..=self.config.size_steps {
            let size = self.config.min_size + (i * step_size);
            points.push(size.min(self.config.max_size));
        }

        points.sort();
        points.dedup();
        points
    }

    /// Measure performance for a specific contract size
    async fn measure_size_performance(
        &self,
        binary_path: &str,
        size: usize,
    ) -> Result<ScalabilityMeasurement, Box<dyn std::error::Error>> {
        // Generate test contract
        let contract_path = self.generator.generate_contract(size)?;

        let mut times = Vec::new();
        let mut memories = Vec::new();
        let mut successful_runs = 0;
        let mut failed_runs = 0;
        let mut total_vulnerabilities = 0;

        // Run multiple iterations
        for _ in 0..self.config.iterations {
            match self.run_single_analysis(binary_path, &contract_path).await {
                Ok((duration, memory, vulns)) => {
                    times.push(duration);
                    memories.push(memory);
                    total_vulnerabilities += vulns;
                    successful_runs += 1;
                }
                Err(_) => {
                    failed_runs += 1;
                }
            }
        }

        if successful_runs == 0 {
            return Err("All runs failed for this size".into());
        }

        // Calculate statistics
        let avg_time_nanos = times.iter().map(|d| d.as_nanos()).sum::<u128>() / successful_runs as u128;
        let avg_time = Duration::from_nanos(avg_time_nanos);

        let avg_memory = memories.iter().sum::<usize>() / successful_runs;
        let peak_memory = memories.iter().max().copied().unwrap_or(0);

        // Calculate standard deviation of times
        let variance = times.iter()
            .map(|t| {
                let diff = t.as_nanos() as f64 - avg_time_nanos as f64;
                diff * diff
            })
            .sum::<f64>() / (successful_runs as f64 - 1.0).max(1.0);
        let std_time = Duration::from_nanos(variance.sqrt() as u64);

        let throughput = if avg_time.as_secs_f64() > 0.0 {
            size as f64 / avg_time.as_secs_f64()
        } else {
            0.0
        };

        let avg_vulnerabilities = total_vulnerabilities / successful_runs;

        Ok(ScalabilityMeasurement {
            size,
            avg_time,
            std_time,
            avg_memory,
            peak_memory,
            throughput,
            successful_runs,
            failed_runs,
            vulnerabilities_detected: avg_vulnerabilities,
        })
    }

    /// Run single analysis
    async fn run_single_analysis(
        &self,
        binary_path: &str,
        contract_path: &Path,
    ) -> Result<(Duration, usize, usize), Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let start_memory = self.get_memory_usage();

        let output = tokio::time::timeout(
            self.config.timeout,
            AsyncCommand::new(binary_path)
                .args(&["--sarif", "--quiet"])
                .arg(contract_path)
                .output()
        ).await??;

        let execution_time = start_time.elapsed();
        let end_memory = self.get_memory_usage();
        let memory_used = end_memory.saturating_sub(start_memory);

        if !output.status.success() {
            return Err("Analysis failed".into());
        }

        let vulnerabilities = self.count_vulnerabilities(&output.stdout)?;

        Ok((execution_time, memory_used, vulnerabilities))
    }

    /// Count vulnerabilities in SARIF output
    fn count_vulnerabilities(&self, sarif_bytes: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
        let sarif_str = String::from_utf8_lossy(sarif_bytes);

        if let Ok(sarif) = serde_json::from_str::<serde_json::Value>(&sarif_str) {
            if let Some(runs) = sarif["runs"].as_array() {
                let mut total = 0;
                for run in runs {
                    if let Some(results) = run["results"].as_array() {
                        total += results.len();
                    }
                }
                return Ok(total);
            }
        }

        Ok(0)
    }

    /// Get current memory usage
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

    /// Analyze computational complexity
    fn analyze_complexity(&self, measurements: &[ScalabilityMeasurement]) -> String {
        if measurements.len() < 3 {
            return "Unknown".to_string();
        }

        // Simple complexity analysis based on time growth
        let mut ratios = Vec::new();
        for i in 1..measurements.len() {
            let prev = &measurements[i-1];
            let curr = &measurements[i];

            if prev.avg_time.as_secs_f64() > 0.0 {
                let size_ratio = curr.size as f64 / prev.size as f64;
                let time_ratio = curr.avg_time.as_secs_f64() / prev.avg_time.as_secs_f64();

                if size_ratio > 1.0 {
                    ratios.push(time_ratio / size_ratio);
                }
            }
        }

        if ratios.is_empty() {
            return "Unknown".to_string();
        }

        let avg_ratio = ratios.iter().sum::<f64>() / ratios.len() as f64;

        match avg_ratio {
            r if r < 1.2 => "O(1) - Constant".to_string(),
            r if r < 2.0 => "O(n) - Linear".to_string(),
            r if r < 4.0 => "O(n log n) - Linearithmic".to_string(),
            r if r < 8.0 => "O(n²) - Quadratic".to_string(),
            _ => "O(n³+) - Polynomial or worse".to_string(),
        }
    }

    /// Calculate memory efficiency (MB per KLOC)
    fn calculate_memory_efficiency(&self, measurements: &[ScalabilityMeasurement]) -> f64 {
        if measurements.is_empty() {
            return 0.0;
        }

        let total_efficiency: f64 = measurements.iter()
            .filter(|m| m.size > 0)
            .map(|m| {
                let memory_mb = m.avg_memory as f64 / 1024.0 / 1024.0;
                let size_kloc = m.size as f64 / 1000.0;
                memory_mb / size_kloc
            })
            .sum();

        let valid_measurements = measurements.iter()
            .filter(|m| m.size > 0)
            .count();

        if valid_measurements > 0 {
            total_efficiency / valid_measurements as f64
        } else {
            0.0
        }
    }

    /// Find degradation threshold
    fn find_degradation_threshold(&self, measurements: &[ScalabilityMeasurement]) -> Option<usize> {
        if measurements.len() < 3 {
            return None;
        }

        // Look for significant throughput drops
        let mut max_throughput = 0.0;
        for measurement in measurements {
            max_throughput = max_throughput.max(measurement.throughput);
        }

        for measurement in measurements {
            if measurement.throughput < max_throughput * 0.5 {
                return Some(measurement.size);
            }
        }

        None
    }

    /// Analyze specific scalability issues
    fn analyze_scalability_issues(&self, measurements: &[ScalabilityMeasurement], issues: &mut Vec<String>) {
        // Check for memory growth issues
        let mut memory_growth_rate = 0.0;
        if measurements.len() >= 2 {
            let first = &measurements[0];
            let last = &measurements[measurements.len() - 1];

            if first.size > 0 && last.size > first.size {
                let size_factor = last.size as f64 / first.size as f64;
                let memory_factor = last.avg_memory as f64 / first.avg_memory.max(1) as f64;
                memory_growth_rate = memory_factor / size_factor;
            }
        }

        if memory_growth_rate > 2.0 {
            issues.push(format!("High memory growth rate: {:.1}x faster than code size", memory_growth_rate));
        }

        // Check for timeout issues
        let timeout_rate = measurements.iter()
            .map(|m| m.failed_runs as f64 / (m.failed_runs + m.successful_runs).max(1) as f64)
            .fold(0.0, f64::max);

        if timeout_rate > 0.2 {
            issues.push(format!("High timeout rate: {:.1}% of runs failed", timeout_rate * 100.0));
        }

        // Check for inconsistent performance
        let cv_threshold = 0.3; // Coefficient of variation threshold
        for measurement in measurements {
            if measurement.avg_time.as_secs_f64() > 0.0 {
                let cv = measurement.std_time.as_secs_f64() / measurement.avg_time.as_secs_f64();
                if cv > cv_threshold {
                    issues.push(format!("High performance variability at size {}: CV = {:.2}", measurement.size, cv));
                }
            }
        }

        // Check for performance cliff
        let mut significant_drops = 0;
        for i in 1..measurements.len() {
            let prev_throughput = measurements[i-1].throughput;
            let curr_throughput = measurements[i].throughput;

            if prev_throughput > 0.0 {
                let drop_ratio = (prev_throughput - curr_throughput) / prev_throughput;
                if drop_ratio > 0.5 {
                    significant_drops += 1;
                }
            }
        }

        if significant_drops > 0 {
            issues.push(format!("Performance cliff detected: {} significant throughput drops", significant_drops));
        }
    }
}

impl ScalabilityResult {
    /// Save result to JSON file
    pub fn save_to_file(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load result from JSON file
    pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let result = serde_json::from_str(&content)?;
        Ok(result)
    }

    /// Generate scalability report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("# Scalability Test Results\n\n");
        report.push_str(&format!("**Test Date:** {}\n", self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
        report.push_str(&format!("**Size Range:** {} - {} LOC\n", self.config.min_size, self.config.max_size));
        report.push_str(&format!("**Complexity Class:** {}\n", self.complexity_class));
        report.push_str(&format!("**Max Throughput:** {:.1} LOC/s\n", self.max_throughput));
        report.push_str(&format!("**Memory Efficiency:** {:.2} MB/KLOC\n\n", self.memory_efficiency));

        // Performance summary
        report.push_str("## Performance Summary\n\n");
        report.push_str("| Size (LOC) | Avg Time (s) | Throughput (LOC/s) | Memory (MB) | Vulnerabilities |\n");
        report.push_str("|------------|--------------|-------------------|-------------|----------------|\n");

        for measurement in &self.measurements {
            let memory_mb = measurement.avg_memory as f64 / 1024.0 / 1024.0;
            report.push_str(&format!(
                "| {} | {:.2} | {:.1} | {:.1} | {} |\n",
                measurement.size,
                measurement.avg_time.as_secs_f64(),
                measurement.throughput,
                memory_mb,
                measurement.vulnerabilities_detected
            ));
        }

        // Scalability issues
        if !self.scalability_issues.is_empty() {
            report.push_str("\n## Scalability Issues\n\n");
            for issue in &self.scalability_issues {
                report.push_str(&format!("- {}\n", issue));
            }
        } else {
            report.push_str("\n## ✅ No Scalability Issues Detected\n");
        }

        // Degradation threshold
        if let Some(threshold) = self.degradation_threshold {
            report.push_str(&format!("\n## Performance Degradation\n\nSignificant performance degradation detected at {} LOC.\n", threshold));
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalability_config_creation() {
        let config = ScalabilityConfig {
            min_size: 100,
            max_size: 10000,
            size_steps: 10,
            iterations: 3,
            timeout: Duration::from_secs(60),
        };

        assert_eq!(config.min_size, 100);
        assert_eq!(config.max_size, 10000);
        assert_eq!(config.size_steps, 10);
    }

    #[test]
    fn test_contract_generator() {
        let generator = ContractGenerator::new().unwrap();
        let contract_path = generator.generate_contract(50).unwrap();

        assert!(contract_path.exists());

        let content = std::fs::read_to_string(&contract_path).unwrap();
        let line_count = content.lines().count();

        // Should be close to target size (within reasonable margin)
        assert!(line_count >= 45 && line_count <= 55);
        assert!(content.contains("pragma solidity"));
        assert!(content.contains("contract ScalabilityTest"));
    }

    #[test]
    fn test_size_points_generation() {
        let config = ScalabilityConfig {
            min_size: 100,
            max_size: 1000,
            size_steps: 5,
            iterations: 1,
            timeout: Duration::from_secs(10),
        };

        let tester = ScalabilityTester::new(config);
        let points = tester.generate_size_points();

        assert_eq!(points.len(), 6); // 0 to size_steps inclusive
        assert_eq!(points[0], 100);
        assert_eq!(points[points.len() - 1], 1000);

        // Check points are in ascending order
        for i in 1..points.len() {
            assert!(points[i] >= points[i-1]);
        }
    }

    #[test]
    fn test_complexity_analysis() {
        let config = ScalabilityConfig {
            min_size: 100,
            max_size: 1000,
            size_steps: 5,
            iterations: 1,
            timeout: Duration::from_secs(10),
        };

        let tester = ScalabilityTester::new(config);

        // Test linear complexity
        let linear_measurements = vec![
            ScalabilityMeasurement {
                size: 100,
                avg_time: Duration::from_millis(100),
                std_time: Duration::from_millis(10),
                avg_memory: 1024,
                peak_memory: 1024,
                throughput: 1000.0,
                successful_runs: 1,
                failed_runs: 0,
                vulnerabilities_detected: 1,
            },
            ScalabilityMeasurement {
                size: 200,
                avg_time: Duration::from_millis(200),
                std_time: Duration::from_millis(20),
                avg_memory: 2048,
                peak_memory: 2048,
                throughput: 1000.0,
                successful_runs: 1,
                failed_runs: 0,
                vulnerabilities_detected: 2,
            },
            ScalabilityMeasurement {
                size: 300,
                avg_time: Duration::from_millis(300),
                std_time: Duration::from_millis(30),
                avg_memory: 3072,
                peak_memory: 3072,
                throughput: 1000.0,
                successful_runs: 1,
                failed_runs: 0,
                vulnerabilities_detected: 3,
            },
        ];

        let complexity = tester.analyze_complexity(&linear_measurements);
        assert!(complexity.contains("Linear") || complexity.contains("Constant"));
    }

    #[test]
    fn test_memory_efficiency_calculation() {
        let config = ScalabilityConfig {
            min_size: 100,
            max_size: 1000,
            size_steps: 2,
            iterations: 1,
            timeout: Duration::from_secs(10),
        };

        let tester = ScalabilityTester::new(config);

        let measurements = vec![
            ScalabilityMeasurement {
                size: 1000, // 1 KLOC
                avg_time: Duration::from_millis(100),
                std_time: Duration::from_millis(10),
                avg_memory: 1024 * 1024, // 1 MB
                peak_memory: 1024 * 1024,
                throughput: 10000.0,
                successful_runs: 1,
                failed_runs: 0,
                vulnerabilities_detected: 1,
            },
            ScalabilityMeasurement {
                size: 2000, // 2 KLOC
                avg_time: Duration::from_millis(200),
                std_time: Duration::from_millis(20),
                avg_memory: 2 * 1024 * 1024, // 2 MB
                peak_memory: 2 * 1024 * 1024,
                throughput: 10000.0,
                successful_runs: 1,
                failed_runs: 0,
                vulnerabilities_detected: 2,
            },
        ];

        let efficiency = tester.calculate_memory_efficiency(&measurements);
        assert!((efficiency - 1.0).abs() < 0.1); // Should be ~1 MB/KLOC
    }

    #[test]
    fn test_degradation_threshold_detection() {
        let config = ScalabilityConfig {
            min_size: 100,
            max_size: 1000,
            size_steps: 3,
            iterations: 1,
            timeout: Duration::from_secs(10),
        };

        let tester = ScalabilityTester::new(config);

        let measurements = vec![
            ScalabilityMeasurement {
                size: 100,
                avg_time: Duration::from_millis(100),
                std_time: Duration::from_millis(10),
                avg_memory: 1024,
                peak_memory: 1024,
                throughput: 1000.0, // Good throughput
                successful_runs: 1,
                failed_runs: 0,
                vulnerabilities_detected: 1,
            },
            ScalabilityMeasurement {
                size: 500,
                avg_time: Duration::from_millis(1000),
                std_time: Duration::from_millis(100),
                avg_memory: 5120,
                peak_memory: 5120,
                throughput: 500.0, // Degraded throughput (50% of max)
                successful_runs: 1,
                failed_runs: 0,
                vulnerabilities_detected: 5,
            },
        ];

        let threshold = tester.find_degradation_threshold(&measurements);
        assert_eq!(threshold, Some(500));
    }

    #[test]
    fn test_scalability_result_serialization() {
        let result = ScalabilityResult {
            complexity_class: "Linear".to_string(),
            max_throughput: 1000.0,
            memory_efficiency: 2.5,
            degradation_threshold: Some(5000),
            measurements: vec![],
            scalability_issues: vec!["Test issue".to_string()],
            config: ScalabilityConfig {
                min_size: 100,
                max_size: 1000,
                size_steps: 5,
                iterations: 3,
                timeout: Duration::from_secs(60),
            },
            timestamp: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ScalabilityResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result.complexity_class, deserialized.complexity_class);
        assert_eq!(result.max_throughput, deserialized.max_throughput);
        assert_eq!(result.degradation_threshold, deserialized.degradation_threshold);
    }
}