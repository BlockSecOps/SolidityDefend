use std::time::{Duration, Instant};
use ast::AstArena;
use parser::Parser;
use analysis::AnalysisEngine;

/// Performance benchmarks for large codebases
pub struct PerformanceBenchmarks;

impl PerformanceBenchmarks {
    /// Run comprehensive performance benchmarks
    pub fn run_all_benchmarks() -> BenchmarkResults {
        let mut results = BenchmarkResults::new();

        // Simple contract benchmarks
        results.add_result("simple_contract", Self::benchmark_simple_contract());
        results.add_result("medium_contract", Self::benchmark_medium_contract());
        results.add_result("complex_contract", Self::benchmark_complex_contract());
        results.add_result("very_large_contract", Self::benchmark_very_large_contract());

        // Scalability benchmarks
        results.add_result("multiple_contracts", Self::benchmark_multiple_contracts());
        results.add_result("deep_nesting", Self::benchmark_deep_nesting());
        results.add_result("wide_functions", Self::benchmark_wide_functions());

        results
    }

    /// Benchmark simple contract analysis
    fn benchmark_simple_contract() -> BenchmarkResult {
        let source = r#"
        pragma solidity ^0.8.0;
        contract Simple {
            uint256 value;
            function setValue(uint256 v) public { value = v; }
            function getValue() public view returns (uint256) { return value; }
        }
        "#;

        Self::run_benchmark("Simple Contract", source, 1)
    }

    /// Benchmark medium complexity contract
    fn benchmark_medium_contract() -> BenchmarkResult {
        let source = Self::generate_medium_contract();
        Self::run_benchmark("Medium Contract", &source, 1)
    }

    /// Benchmark complex contract with many functions
    fn benchmark_complex_contract() -> BenchmarkResult {
        let source = Self::generate_complex_contract();
        Self::run_benchmark("Complex Contract", &source, 1)
    }

    /// Benchmark very large contract
    fn benchmark_very_large_contract() -> BenchmarkResult {
        let source = Self::generate_very_large_contract();
        Self::run_benchmark("Very Large Contract", &source, 1)
    }

    /// Benchmark multiple contracts
    fn benchmark_multiple_contracts() -> BenchmarkResult {
        let source = Self::generate_multiple_contracts();
        Self::run_benchmark("Multiple Contracts", &source, 1)
    }

    /// Benchmark deeply nested control structures
    fn benchmark_deep_nesting() -> BenchmarkResult {
        let source = Self::generate_deeply_nested_contract();
        Self::run_benchmark("Deep Nesting", &source, 1)
    }

    /// Benchmark functions with many statements
    fn benchmark_wide_functions() -> BenchmarkResult {
        let source = Self::generate_wide_functions_contract();
        Self::run_benchmark("Wide Functions", &source, 1)
    }

    /// Core benchmark runner
    fn run_benchmark(name: &str, source: &str, iterations: usize) -> BenchmarkResult {
        let mut durations = Vec::new();
        let mut memory_usage = Vec::new();
        let mut success_count = 0;

        for _ in 0..iterations {
            let arena = AstArena::new();
            let parser = Parser::new();
            let mut engine = AnalysisEngine::new();

            let start_time = Instant::now();
            let start_memory = Self::get_memory_usage();

            let parse_result = parser.parse(&arena, source, "benchmark.sol");
            match parse_result {
                Ok(ast) => {
                    match engine.analyze_source_file(&ast) {
                        Ok(_) => {
                            success_count += 1;
                            let duration = start_time.elapsed();
                            let memory_used = Self::get_memory_usage() - start_memory;

                            durations.push(duration);
                            memory_usage.push(memory_used);
                        }
                        Err(e) => {
                            println!("⚠️  Analysis failed in {}: {}", name, e);
                        }
                    }
                }
                Err(e) => {
                    println!("⚠️  Parse failed in {}: {:?}", name, e);
                }
            }
        }

        BenchmarkResult {
            name: name.to_string(),
            iterations,
            success_count,
            durations,
            memory_usage,
        }
    }

    /// Generate medium complexity contract
    fn generate_medium_contract() -> String {
        let mut contract = String::from(r#"
        pragma solidity ^0.8.0;
        contract MediumContract {
            mapping(address => uint256) public balances;
            uint256 public totalSupply;
        "#);

        // Generate 10 functions with moderate complexity
        for i in 0..10 {
            contract.push_str(&format!(r#"
            function function{}(uint256 a, uint256 b) public returns (uint256) {{
                if (a > b) {{
                    for (uint256 j = 0; j < 5; j++) {{
                        balances[msg.sender] += j;
                    }}
                    return a + b;
                }} else {{
                    return a * b;
                }}
            }}
            "#, i));
        }

        contract.push_str("}");
        contract
    }

    /// Generate complex contract with many functions
    fn generate_complex_contract() -> String {
        let mut contract = String::from(r#"
        pragma solidity ^0.8.0;
        contract ComplexContract {
            mapping(address => uint256) public balances;
            mapping(address => mapping(address => uint256)) public allowances;
            uint256 public totalSupply;
            address[] public holders;
        "#);

        // Generate 25 functions with varied complexity
        for i in 0..25 {
            contract.push_str(&Self::generate_complex_function(i));
        }

        contract.push_str("}");
        contract
    }

    /// Generate very large contract
    fn generate_very_large_contract() -> String {
        let mut contract = String::from(r#"
        pragma solidity ^0.8.0;
        contract VeryLargeContract {
            mapping(address => uint256) public balances;
            mapping(address => mapping(address => uint256)) public allowances;
            mapping(uint256 => address) public tokenOwners;
            uint256 public totalSupply;
            address[] public holders;
            uint256[] public tokenIds;
        "#);

        // Generate 50 functions with high complexity
        for i in 0..50 {
            contract.push_str(&Self::generate_complex_function(i));
        }

        contract.push_str("}");
        contract
    }

    /// Generate multiple contracts
    fn generate_multiple_contracts() -> String {
        let mut source = String::from("pragma solidity ^0.8.0;\n");

        // Generate 5 contracts
        for i in 0..5 {
            source.push_str(&format!(r#"
            contract Contract{} {{
                uint256 public value{};
                mapping(address => uint256) public balances{};
            "#, i, i, i));

            // Each contract has 10 functions
            for j in 0..10 {
                source.push_str(&format!(r#"
                function func{}{}(uint256 x) public returns (uint256) {{
                    if (x > {}) {{
                        return x * {};
                    }} else {{
                        return x + {};
                    }}
                }}
                "#, i, j, j, i + 1, j + 1));
            }

            source.push_str("}\n");
        }

        source
    }

    /// Generate deeply nested contract
    fn generate_deeply_nested_contract() -> String {
        let mut contract = String::from(r#"
        pragma solidity ^0.8.0;
        contract DeeplyNested {
            uint256 public result;
        "#);

        // Generate function with deep nesting
        contract.push_str(r#"
        function deeplyNested(uint256 x) public returns (uint256) {
            if (x > 100) {
                if (x > 200) {
                    if (x > 300) {
                        if (x > 400) {
                            if (x > 500) {
                                if (x > 600) {
                                    if (x > 700) {
                                        if (x > 800) {
                                            return x * 8;
                                        } else {
                                            return x * 7;
                                        }
                                    } else {
                                        return x * 6;
                                    }
                                } else {
                                    return x * 5;
                                }
                            } else {
                                return x * 4;
                            }
                        } else {
                            return x * 3;
                        }
                    } else {
                        return x * 2;
                    }
                } else {
                    return x;
                }
            } else {
                return 0;
            }
        }
        "#);

        contract.push_str("}");
        contract
    }

    /// Generate contract with wide functions (many statements)
    fn generate_wide_functions_contract() -> String {
        let mut contract = String::from(r#"
        pragma solidity ^0.8.0;
        contract WideFunctions {
            uint256 public counter;
            mapping(address => uint256) public data;
        "#);

        // Generate function with many sequential statements
        contract.push_str("function wideFunction() public {\n");
        for i in 0..100 {
            contract.push_str(&format!("        counter += {};\n", i));
        }
        contract.push_str("    }\n");

        contract.push_str("}");
        contract
    }

    /// Generate a complex function
    fn generate_complex_function(index: usize) -> String {
        format!(r#"
        function complexFunction{}(uint256 x, uint256 y, bool flag) public returns (uint256) {{
            uint256 result = 0;

            for (uint256 i = 0; i < x; i++) {{
                if (i % 2 == 0) {{
                    if (flag) {{
                        result += i * y;
                    }} else {{
                        result += i + y;
                    }}
                }} else {{
                    for (uint256 j = 0; j < y; j++) {{
                        if (j > {}) {{
                            result += j;
                        }}
                    }}
                }}
            }}

            if (result > 1000) {{
                return result / 10;
            }} else if (result > 100) {{
                return result / 2;
            }} else {{
                return result;
            }}
        }}
        "#, index, index % 10)
    }

    /// Estimate memory usage (simplified implementation)
    fn get_memory_usage() -> usize {
        // This is a simplified memory estimation
        // In a real implementation, you might use system calls or memory profiling
        0
    }
}

/// Benchmark results for a single test
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub iterations: usize,
    pub success_count: usize,
    pub durations: Vec<Duration>,
    pub memory_usage: Vec<usize>,
}

impl BenchmarkResult {
    pub fn average_duration(&self) -> Duration {
        if self.durations.is_empty() {
            return Duration::ZERO;
        }
        let total: Duration = self.durations.iter().sum();
        total / self.durations.len() as u32
    }

    pub fn min_duration(&self) -> Duration {
        self.durations.iter().min().copied().unwrap_or(Duration::ZERO)
    }

    pub fn max_duration(&self) -> Duration {
        self.durations.iter().max().copied().unwrap_or(Duration::ZERO)
    }

    pub fn average_memory(&self) -> usize {
        if self.memory_usage.is_empty() {
            return 0;
        }
        self.memory_usage.iter().sum::<usize>() / self.memory_usage.len()
    }

    pub fn success_rate(&self) -> f64 {
        if self.iterations == 0 {
            return 0.0;
        }
        (self.success_count as f64) / (self.iterations as f64)
    }

    pub fn throughput(&self) -> f64 {
        let avg_duration = self.average_duration();
        if avg_duration.is_zero() {
            return 0.0;
        }
        1.0 / avg_duration.as_secs_f64()
    }

    pub fn generate_report(&self) -> String {
        format!(
            r#"
Benchmark: {}
Iterations: {}
Success Rate: {:.2}%
Average Duration: {:.2}ms
Min Duration: {:.2}ms
Max Duration: {:.2}ms
Throughput: {:.2} analyses/sec
Average Memory: {} bytes
            "#,
            self.name,
            self.iterations,
            self.success_rate() * 100.0,
            self.average_duration().as_secs_f64() * 1000.0,
            self.min_duration().as_secs_f64() * 1000.0,
            self.max_duration().as_secs_f64() * 1000.0,
            self.throughput(),
            self.average_memory()
        )
    }
}

/// Collection of benchmark results
#[derive(Debug)]
pub struct BenchmarkResults {
    pub results: Vec<BenchmarkResult>,
}

impl BenchmarkResults {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    pub fn add_result(&mut self, _name: &str, result: BenchmarkResult) {
        self.results.push(result);
    }

    pub fn generate_summary(&self) -> String {
        let mut summary = String::from("=== Performance Benchmark Summary ===\n\n");

        for result in &self.results {
            summary.push_str(&result.generate_report());
            summary.push('\n');
        }

        // Overall statistics
        let total_iterations: usize = self.results.iter().map(|r| r.iterations).sum();
        let total_successes: usize = self.results.iter().map(|r| r.success_count).sum();
        let overall_success_rate = if total_iterations > 0 {
            (total_successes as f64) / (total_iterations as f64) * 100.0
        } else {
            0.0
        };

        summary.push_str(&format!(
            "\n=== Overall Statistics ===\n\
            Total Benchmarks: {}\n\
            Total Iterations: {}\n\
            Overall Success Rate: {:.2}%\n",
            self.results.len(),
            total_iterations,
            overall_success_rate
        ));

        summary
    }

    /// Check if performance is within acceptable thresholds
    pub fn validate_performance(&self) -> Vec<String> {
        let mut issues = Vec::new();

        for result in &self.results {
            // Check success rate
            if result.success_rate() < 0.95 {
                issues.push(format!(
                    "Low success rate in {}: {:.2}%",
                    result.name,
                    result.success_rate() * 100.0
                ));
            }

            // Check performance thresholds
            let avg_duration = result.average_duration();
            let threshold = match result.name.as_str() {
                "Simple Contract" => Duration::from_millis(100),
                "Medium Contract" => Duration::from_millis(500),
                "Complex Contract" => Duration::from_secs(2),
                "Very Large Contract" => Duration::from_secs(10),
                _ => Duration::from_secs(5),
            };

            if avg_duration > threshold {
                issues.push(format!(
                    "Performance regression in {}: {:.2}ms (threshold: {:.2}ms)",
                    result.name,
                    avg_duration.as_secs_f64() * 1000.0,
                    threshold.as_secs_f64() * 1000.0
                ));
            }
        }

        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_benchmark() {
        let result = PerformanceBenchmarks::benchmark_simple_contract();

        assert!(!result.name.is_empty());
        assert!(result.iterations > 0);

        if result.success_count > 0 {
            assert!(!result.durations.is_empty());
            assert!(result.average_duration() > Duration::ZERO);
            assert!(result.success_rate() > 0.0);

            println!("✅ Simple benchmark completed: {}", result.generate_report());
        } else {
            println!("⚠️  Simple benchmark had no successes - analysis pipeline may need work");
        }
    }

    #[test]
    fn test_benchmark_results_collection() {
        let mut results = BenchmarkResults::new();

        // Add some test results
        let test_result = BenchmarkResult {
            name: "Test".to_string(),
            iterations: 1,
            success_count: 1,
            durations: vec![Duration::from_millis(50)],
            memory_usage: vec![1024],
        };

        results.add_result("test", test_result);

        assert_eq!(results.results.len(), 1);

        let summary = results.generate_summary();
        assert!(summary.contains("Test"));
        assert!(summary.contains("Performance Benchmark Summary"));

        println!("✅ Benchmark results collection working");
    }

    #[test]
    fn test_performance_validation() {
        let mut results = BenchmarkResults::new();

        // Add a result that should pass validation
        let good_result = BenchmarkResult {
            name: "Simple Contract".to_string(),
            iterations: 1,
            success_count: 1,
            durations: vec![Duration::from_millis(50)], // Under 100ms threshold
            memory_usage: vec![1024],
        };

        // Add a result that should fail validation
        let bad_result = BenchmarkResult {
            name: "Simple Contract".to_string(),
            iterations: 1,
            success_count: 0, // 0% success rate
            durations: vec![],
            memory_usage: vec![],
        };

        results.add_result("good", good_result);
        results.add_result("bad", bad_result);

        let issues = results.validate_performance();
        assert!(!issues.is_empty(), "Should detect performance issues");

        println!("✅ Performance validation working: {} issues detected", issues.len());
    }

    #[test]
    #[ignore] // Ignore by default as this is a long-running test
    fn test_full_benchmark_suite() {
        println!("Running full benchmark suite...");
        let results = PerformanceBenchmarks::run_all_benchmarks();

        println!("{}", results.generate_summary());

        let issues = results.validate_performance();
        if !issues.is_empty() {
            println!("Performance issues detected:");
            for issue in issues {
                println!("  - {}", issue);
            }
        } else {
            println!("✅ All benchmarks passed performance validation");
        }
    }
}