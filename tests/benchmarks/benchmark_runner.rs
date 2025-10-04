use std::fs;
use chrono::Utc;

// Use crate path for library compilation
use crate::benchmarks::performance_comparison::{PerformanceBenchmark, BenchmarkResult};

pub struct BenchmarkRunner {
    output_dir: String,
    benchmark_suite: PerformanceBenchmark,
}

impl BenchmarkRunner {
    pub fn new(output_dir: &str) -> Self {
        Self {
            output_dir: output_dir.to_string(),
            benchmark_suite: PerformanceBenchmark::new(),
        }
    }

    pub fn run_all_benchmarks(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting comprehensive performance benchmarks...");

        // Create output directory
        fs::create_dir_all(&self.output_dir)?;

        // Run benchmarks
        let results = self.benchmark_suite.run_comprehensive_benchmark();

        // Generate detailed report
        let report = self.benchmark_suite.generate_performance_report(&results);

        // Save report with timestamp
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let report_path = format!("{}/performance_report_{}.md", self.output_dir, timestamp);
        fs::write(&report_path, &report)?;

        // Save raw results as JSON
        let json_results = serde_json::to_string_pretty(&results)?;
        let json_path = format!("{}/benchmark_results_{}.json", self.output_dir, timestamp);
        fs::write(&json_path, &json_results)?;

        println!("Benchmarks completed successfully!");
        println!("Report saved to: {}", report_path);
        println!("Raw data saved to: {}", json_path);

        // Print summary to console
        self.print_summary(&results);

        Ok(())
    }

    fn print_summary(&self, results: &[BenchmarkResult]) {
        println!("\n📊 BENCHMARK SUMMARY");
        println!("===================");

        for result in results {
            println!("\n🔍 Dataset: {}", result.dataset_name);

            if let Some(soliditydefend_metrics) = result.metrics.iter()
                .find(|m| m.tool_name.to_lowercase().contains("soliditydefend")) {

                println!("   ⚡ SolidityDefend Performance:");
                println!("     - Analysis time: {:.2}s", soliditydefend_metrics.analysis_time.as_secs_f64());
                println!("     - Memory usage: {:.1}MB", soliditydefend_metrics.memory_usage as f64 / 1_000_000.0);
                println!("     - Findings: {}", soliditydefend_metrics.findings_count);
                println!("     - Efficiency: {:.2} findings/sec",
                    soliditydefend_metrics.findings_count as f64 / soliditydefend_metrics.analysis_time.as_secs_f64());

                // Show comparison highlights
                let mut fastest_competitor = None;
                let mut fastest_time = f64::INFINITY;

                for metric in &result.metrics {
                    if !metric.tool_name.to_lowercase().contains("soliditydefend") {
                        let time = metric.analysis_time.as_secs_f64();
                        if time < fastest_time {
                            fastest_time = time;
                            fastest_competitor = Some(metric);
                        }
                    }
                }

                if let Some(competitor) = fastest_competitor {
                    let speed_ratio = soliditydefend_metrics.analysis_time.as_secs_f64() / competitor.analysis_time.as_secs_f64();
                    if speed_ratio < 1.0 {
                        println!("     ✅ {}x faster than {}", 1.0/speed_ratio, competitor.tool_name);
                    } else {
                        println!("     ⚠️  {}x slower than {}", speed_ratio, competitor.tool_name);
                    }
                }
            }
        }

        println!("\n🎯 Key Performance Indicators:");
        let total_datasets = results.len();
        let mut total_soliditydefend_time = 0.0;
        let mut total_findings = 0;

        for result in results {
            if let Some(metrics) = result.metrics.iter()
                .find(|m| m.tool_name.to_lowercase().contains("soliditydefend")) {
                total_soliditydefend_time += metrics.analysis_time.as_secs_f64();
                total_findings += metrics.findings_count;
            }
        }

        println!("   - Average analysis time: {:.2}s per dataset", total_soliditydefend_time / total_datasets as f64);
        println!("   - Total findings discovered: {}", total_findings);
        println!("   - Overall efficiency: {:.2} findings/sec", total_findings as f64 / total_soliditydefend_time);
    }
}

pub fn run_performance_benchmarks() -> Result<(), Box<dyn std::error::Error>> {
    let runner = BenchmarkRunner::new("benchmark_reports");
    runner.run_all_benchmarks()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_benchmark_runner_creation() {
        let runner = BenchmarkRunner::new("test_output");
        assert_eq!(runner.output_dir, "test_output");
    }

    #[test]
    fn test_output_directory_creation() {
        let test_dir = "test_benchmark_output";
        let runner = BenchmarkRunner::new(test_dir);

        // Clean up any existing test directory
        if Path::new(test_dir).exists() {
            fs::remove_dir_all(test_dir).ok();
        }

        // This would normally run benchmarks, but we'll just test directory creation
        fs::create_dir_all(&runner.output_dir).unwrap();
        assert!(Path::new(test_dir).exists());

        // Clean up
        fs::remove_dir_all(test_dir).unwrap();
    }
}

#[allow(dead_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runner = BenchmarkRunner::new("benchmark_results");
    runner.run_all_benchmarks()?;
    println!("Benchmarks completed successfully!");
    Ok(())
}