# Testing Documentation

Comprehensive testing infrastructure for SolidityDefend's analysis engine.

## Table of Contents

- [Overview](#overview)
- [Test Infrastructure](#test-infrastructure)
- [Integration Tests](#integration-tests)
- [Test Fixtures](#test-fixtures)
- [Performance Benchmarks](#performance-benchmarks)
- [Regression Tests](#regression-tests)
- [Running Tests](#running-tests)
- [Test Architecture](#test-architecture)

## Overview

SolidityDefend includes a comprehensive testing infrastructure with 150+ tests covering the entire analysis pipeline. The testing system validates everything from basic parsing to complex security detector accuracy across realistic contract scenarios.

### Test Categories

1. **Integration Tests**: Complete AST → IR → CFG → Dataflow pipeline validation
2. **Test Fixtures**: Arena-allocated AST fixtures for realistic scenarios
3. **Performance Benchmarks**: Scalability testing for large codebases
4. **Regression Tests**: Security detector accuracy validation with automated thresholds

## Test Infrastructure

### Location
All comprehensive tests are located in `crates/analysis/tests/`:

```
crates/analysis/tests/
├── mod.rs                    # Unified test runner
├── integration_tests.rs      # Pipeline integration tests
├── test_fixtures.rs         # Arena-allocated AST fixtures
├── performance_benchmarks.rs # Scalability benchmarks
└── regression_tests.rs      # Detector accuracy validation
```

### Architecture

```rust
// Unified test runner orchestrating all test types
pub struct UnifiedTestRunner {
    basic_tests: BasicTests,
    integration_tests: IntegrationTests,
    test_fixtures: TestFixtures,
    performance_benchmarks: PerformanceBenchmarks,
    regression_tests: RegressionTests,
}
```

## Integration Tests

### Purpose
Validate the complete analysis pipeline from AST construction through dataflow analysis.

### Test Scenarios

#### 1. Simple Contract Analysis
```solidity
contract SimpleContract {
    uint256 public value;
    function setValue(uint256 _value) public {
        value = _value;
    }
}
```

#### 2. Control Flow Analysis
```solidity
contract ControlFlow {
    function complexFlow(uint256 x) public pure returns (uint256) {
        if (x > 10) {
            return x * 2;
        } else {
            return x + 1;
        }
    }
}
```

#### 3. Dataflow Analysis
```solidity
contract DataFlowExample {
    mapping(address => uint256) balances;

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
```

### Validation Points
- ✅ AST construction with proper arena allocation
- ✅ Symbol resolution and type checking
- ✅ IR generation in SSA form
- ✅ CFG construction with dominance analysis
- ✅ Dataflow analysis convergence

## Test Fixtures

### Purpose
Provide arena-allocated AST test fixtures for realistic contract scenarios.

### Available Fixtures

#### Basic Contracts
- **Simple Contract**: Basic state variable and function
- **Constructor Contract**: Contract with initialization logic
- **Multiple Functions**: Contract with various function types

#### Token Contracts
- **ERC20 Token**: Standard ERC20 implementation
- **ERC721 NFT**: Non-fungible token contract
- **Token with Minting**: Mintable token implementation

#### DeFi Protocols
- **Staking Contract**: Token staking mechanism
- **Lending Protocol**: Basic lending/borrowing
- **DEX Router**: Decentralized exchange routing

#### Security Patterns
- **Access Control**: Role-based access patterns
- **Reentrancy Guard**: Protection mechanisms
- **Oracle Integration**: Price feed integration

#### Complex Scenarios
- **Inheritance Chain**: Multi-level contract inheritance
- **Library Usage**: Contracts using external libraries
- **Assembly Blocks**: Inline assembly usage

### Usage Example

```rust
let fixtures = TestFixtures::new();
let contract = fixtures.erc20_contract()?;

// Contract is arena-allocated and ready for analysis
let analysis_result = engine.analyze_source_file(contract);
assert!(analysis_result.is_ok());
```

## Performance Benchmarks

### Purpose
Validate system performance and scalability across different complexity levels.

### Benchmark Categories

#### 1. Simple Analysis (< 100 lines)
- **Target**: Basic contracts with minimal complexity
- **Expected**: < 10ms analysis time
- **Memory**: < 1MB peak usage

#### 2. Medium Complexity (100-1,000 lines)
- **Target**: Standard contracts with moderate complexity
- **Expected**: < 100ms analysis time
- **Memory**: < 10MB peak usage

#### 3. High Complexity (1,000-5,000 lines)
- **Target**: Large contracts with significant complexity
- **Expected**: < 1s analysis time
- **Memory**: < 50MB peak usage

#### 4. Very High Complexity (5,000-10,000+ lines)
- **Target**: Enterprise-scale contracts
- **Expected**: < 10s analysis time
- **Memory**: < 200MB peak usage

### Metrics Tracked
- **Analysis Time**: End-to-end processing duration
- **Memory Usage**: Peak memory consumption
- **Cache Hit Rate**: Caching system effectiveness
- **Throughput**: Lines of code processed per second

## Regression Tests

### Purpose
Ensure security detector accuracy and prevent performance degradation.

### Test Methodology

#### 1. Expected Results Validation
```rust
pub struct ExpectedResult {
    pub detector: &'static str,
    pub finding_count: usize,
    pub severity_distribution: HashMap<Severity, usize>,
    pub confidence_threshold: f64,
}
```

#### 2. Performance Thresholds
- **Analysis Time**: Must remain within 10% of baseline
- **Memory Usage**: Must not exceed 20% increase
- **False Positive Rate**: Must stay below 5%
- **Detection Accuracy**: Must maintain >95% true positive rate

#### 3. Automated Validation
- Baseline metrics established for known contracts
- Automatic comparison against previous results
- Alert system for significant deviations
- Trend analysis for gradual degradation detection

### Test Contracts
- **Vulnerable Patterns**: Contracts with known security issues
- **Safe Patterns**: Contracts with proper security implementations
- **Edge Cases**: Unusual but valid Solidity constructs
- **Real-world Examples**: Actual deployed contract code (anonymized)

## Running Tests

### All Tests
```bash
# Run complete test suite including comprehensive infrastructure
cargo test -p analysis
```

### Specific Test Categories
```bash
# Integration tests for full pipeline
cargo test -p analysis integration_tests

# Arena-allocated test fixtures
cargo test -p analysis test_fixtures

# Performance benchmarks
cargo test -p analysis performance_benchmarks

# Regression tests for detector accuracy
cargo test -p analysis regression_tests

# Basic smoke tests
cargo test -p analysis basic_tests
```

### Detailed Output
```bash
# Run with detailed output and logging
RUST_LOG=debug cargo test -p analysis -- --nocapture

# Run specific test with backtrace
RUST_BACKTRACE=1 cargo test -p analysis test_name -- --nocapture
```

### Performance Testing
```bash
# Run only performance benchmarks
cargo test -p analysis performance --release

# Run with memory profiling
cargo test -p analysis --features memory-profiling
```

## Test Architecture

### Arena Lifetime Management

The testing infrastructure properly handles Rust's borrow checker constraints with arena-allocated ASTs:

```rust
impl TestFixtures {
    pub fn parse_and_analyze(&self, source: &str) -> AnalysisResult<()> {
        let parse_result = self.parser.parse(&self.arena, source, "test.sol");

        match parse_result {
            Ok(ast) => {
                // Perform analysis while AST is borrowed
                let analysis_result = self.engine.analyze_source_file(&ast);

                // Explicit drop to end arena borrowing
                drop(ast);

                // Continue with analysis result
                analysis_result
            }
            Err(e) => Err(e.into()),
        }
    }
}
```

### Memory Management

- **Arena Allocation**: All AST nodes allocated in single memory arena
- **Explicit Drops**: Strategic `drop()` calls to manage borrow lifetimes
- **Memory Tracking**: Built-in memory usage monitoring
- **Cleanup**: Automatic arena cleanup after test completion

### Error Handling

```rust
#[derive(Debug)]
pub enum TestError {
    ParseError(String),
    AnalysisError(String),
    ValidationError(String),
    PerformanceError(String),
}

impl From<AnalysisError> for TestError {
    fn from(err: AnalysisError) -> Self {
        TestError::AnalysisError(err.to_string())
    }
}
```

### Test Utilities

```rust
pub fn assert_analysis_success(result: &AnalysisResult) {
    assert!(result.is_ok(), "Analysis should succeed");
    assert!(!result.findings.is_empty(), "Should produce findings");
}

pub fn assert_performance_within_bounds(duration: Duration, limit: Duration) {
    assert!(duration <= limit,
        "Performance test exceeded limit: {:?} > {:?}", duration, limit);
}

pub fn validate_memory_usage(peak_mb: f64, limit_mb: f64) {
    assert!(peak_mb <= limit_mb,
        "Memory usage exceeded limit: {:.2}MB > {:.2}MB", peak_mb, limit_mb);
}
```

## Test Results Summary

### Current Status
✅ **Basic Tests**: 5/5 PASSING
✅ **Integration Tests**: 4/4 PASSING
✅ **Test Fixtures**: 15+ fixtures AVAILABLE
✅ **Performance Tests**: 4/4 benchmarks RUNNING
✅ **Regression Tests**: Automated validation ACTIVE

### Coverage Metrics
- **Pipeline Coverage**: 100% (AST → IR → CFG → Dataflow)
- **Detector Coverage**: 17/17 detectors tested
- **Contract Pattern Coverage**: 15+ realistic scenarios
- **Performance Coverage**: 4 complexity levels validated

## Contributing to Tests

### Adding New Test Fixtures

1. Add fixture to `test_fixtures.rs`:
```rust
pub fn new_pattern_contract(&self) -> AnalysisResult<&SourceUnit> {
    let source = r#"
        contract NewPattern {
            // Your contract code here
        }
    "#;
    self.parse_contract(source, "new_pattern.sol")
}
```

2. Register in test suite:
```rust
#[test]
fn test_new_pattern_analysis() {
    let fixtures = TestFixtures::new();
    let contract = fixtures.new_pattern_contract().unwrap();

    // Add your test assertions
    assert_analysis_success(&contract);
}
```

### Adding Performance Benchmarks

1. Define benchmark in `performance_benchmarks.rs`:
```rust
#[test]
fn benchmark_new_complexity_level() {
    let start = Instant::now();

    // Run analysis
    let result = analyze_complex_scenario();

    let duration = start.elapsed();
    assert_performance_within_bounds(duration, Duration::from_secs(5));
}
```

### Adding Regression Tests

1. Define expected results in `regression_tests.rs`:
```rust
const NEW_DETECTOR_EXPECTED: ExpectedResult = ExpectedResult {
    detector: "new-detector",
    finding_count: 3,
    severity_distribution: [(Severity::High, 1), (Severity::Medium, 2)].into(),
    confidence_threshold: 0.8,
};
```

## See Also

- [Architecture Documentation](ARCHITECTURE.md) - Technical architecture overview
- [Contributing Guidelines](../CONTRIBUTING.md) - Development contribution guide
- [Usage Examples](USAGE.md) - How to use the testing infrastructure
- [Performance Guide](PERFORMANCE.md) - Performance optimization techniques