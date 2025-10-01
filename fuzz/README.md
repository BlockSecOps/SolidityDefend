# SolidityDefend Fuzzing Infrastructure

This directory contains comprehensive fuzzing targets for SolidityDefend using both libFuzzer and honggfuzz.

## Overview

Fuzzing is a critical testing technique that automatically generates random inputs to find bugs, vulnerabilities, and edge cases. This infrastructure tests all major components of SolidityDefend to ensure robustness and reliability.

## Fuzzing Targets

### 1. Parser Fuzzing (`fuzz_parser`)
- Tests the Solidity parser with malformed and edge-case inputs
- Generates structured Solidity code using `Arbitrary` trait
- Validates that parser never panics on any input
- Tests both valid and intentionally malformed Solidity code

### 2. Analyzer Fuzzing (`fuzz_analyzer`)
- Tests the analysis engine with various contract configurations
- Fuzzes analysis parameters and settings
- Validates consistent analysis results
- Tests incremental analysis behavior

### 3. Detector Fuzzing (`fuzz_detectors`)
- Individual testing of each security detector
- Tests detector sensitivity and configuration
- Validates detector accuracy and consistency
- Tests pattern matching and vulnerability identification

### 4. Code Generation Fuzzing (`fuzz_solidity_generator`)
- Tests Solidity code generation utilities
- Generates contracts with varying complexity levels
- Tests vulnerability injection and detection
- Validates generated code structure and syntax

### 5. SARIF Output Fuzzing (`fuzz_sarif_output`)
- Tests SARIF report generation and validation
- Fuzzes SARIF structure and metadata
- Validates JSON schema compliance
- Tests serialization/deserialization consistency

## Running Fuzzing Tests

### Prerequisites
```bash
# Install fuzzing tools
cargo install cargo-fuzz
cargo install honggfuzz

# Or use the system package manager
# For Ubuntu/Debian:
sudo apt-get install honggfuzz

# For macOS:
brew install honggfuzz
```

### libFuzzer (Recommended)
```bash
# Build and run a specific fuzzing target
cargo fuzz run fuzz_parser

# Run with custom options
cargo fuzz run fuzz_parser -- -max_total_time=3600 -max_len=10000

# Run with reduced verbosity
cargo fuzz run fuzz_analyzer -- -verbosity=1

# List all available targets
cargo fuzz list
```

### honggfuzz
```bash
# Set the fuzzing engine
export HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz"

# Run honggfuzz target
cargo hfuzz run fuzz_parser

# Run with custom parameters
cargo hfuzz run fuzz_analyzer -- -n 4 -t 60
```

### Running All Targets
```bash
# Script to run all fuzzing targets for a specified duration
./scripts/run_all_fuzz.sh 300  # Run for 5 minutes each
```

## Fuzzing Configuration

### libFuzzer Options
Common options you can pass to libFuzzer:
- `-max_total_time=N`: Run for N seconds total
- `-max_len=N`: Maximum input length
- `-timeout=N`: Timeout per test case
- `-rss_limit_mb=N`: Memory limit in MB
- `-dict=file`: Use dictionary file for input generation
- `-verbosity=N`: Output verbosity (0-3)

### honggfuzz Options
Common honggfuzz options:
- `-t N`: Timeout per fuzzing iteration
- `-n N`: Number of fuzzing threads
- `-x`: Use Intel BTS/PT for coverage feedback
- `-s`: Silent mode
- `-v`: Verbose mode

## Corpus Management

### Seed Corpus
Each fuzzing target can have a seed corpus in `fuzz/corpus/<target>/`:
```bash
# Create seed inputs for parser fuzzing
mkdir -p fuzz/corpus/fuzz_parser
echo 'pragma solidity ^0.8.0; contract Test {}' > fuzz/corpus/fuzz_parser/basic.sol
```

### Minimizing Corpus
```bash
# Minimize the corpus to remove redundant test cases
cargo fuzz cmin fuzz_parser

# Minimize a specific test case
cargo fuzz tmin fuzz_parser crash_file.txt
```

## Analyzing Results

### Crash Analysis
When fuzzing finds a crash, it will be saved to:
- libFuzzer: `fuzz/artifacts/fuzz_<target>/`
- honggfuzz: `fuzz/hfuzz_workspace/<target>/`

```bash
# Reproduce a crash
cargo fuzz run fuzz_parser fuzz/artifacts/fuzz_parser/crash-abc123

# Debug with AddressSanitizer
RUSTFLAGS="-Zsanitizer=address" cargo fuzz run fuzz_parser
```

### Coverage Analysis
```bash
# Generate coverage report
cargo fuzz coverage fuzz_parser

# View coverage in browser
cargo fuzz coverage fuzz_parser --dev
```

## Continuous Fuzzing

### CI Integration
The fuzzing infrastructure is designed to run in CI environments:

```yaml
# .github/workflows/fuzz.yml
name: Fuzzing
on:
  schedule:
    - cron: '0 2 * * *'  # Run nightly
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target: [fuzz_parser, fuzz_analyzer, fuzz_detectors]
    steps:
      - uses: actions/checkout@v3
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: nightly
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      - name: Run fuzzing
        run: |
          cd fuzz
          timeout 300 cargo fuzz run ${{ matrix.target }} || true
```

### Long-term Fuzzing
For extended fuzzing campaigns:

```bash
# Run indefinitely until crash found
cargo fuzz run fuzz_parser -- -max_total_time=0

# Run with AFL-style status updates
cargo fuzz run fuzz_analyzer -- -print_final_stats=1
```

## Best Practices

### 1. Start Small
Begin with short fuzzing sessions to ensure everything works:
```bash
cargo fuzz run fuzz_parser -- -max_total_time=60
```

### 2. Use Dictionaries
Create dictionaries for domain-specific fuzzing:
```bash
# Create Solidity keyword dictionary
cat > fuzz/fuzz_parser.dict << EOF
"contract"
"function"
"modifier"
"pragma"
"solidity"
EOF

cargo fuzz run fuzz_parser -- -dict=fuzz/fuzz_parser.dict
```

### 3. Monitor Resource Usage
Fuzzing can be resource-intensive:
```bash
# Limit memory usage
cargo fuzz run fuzz_analyzer -- -rss_limit_mb=2048

# Use fewer threads on constrained systems
cargo hfuzz run fuzz_parser -- -n 2
```

### 4. Regular Corpus Updates
Periodically update and minimize your corpus:
```bash
# Weekly corpus maintenance
cargo fuzz cmin fuzz_parser
cargo fuzz cmin fuzz_analyzer
# ... repeat for all targets
```

## Expected Failures

During initial development, fuzzing targets are designed to fail until full implementation:

### Parser Target
- Should find parsing edge cases and malformed input handling
- May discover infinite loops or excessive memory usage
- Expected to find unhandled syntax combinations

### Analyzer Target
- Should find inconsistencies in analysis results
- May discover configuration edge cases
- Expected to find non-deterministic behavior

### Detector Targets
- Should find false positives/negatives
- May discover detector interaction issues
- Expected to find edge cases in pattern matching

## Debugging Fuzzing Issues

### Common Problems

1. **OOM (Out of Memory)**
   ```bash
   # Reduce memory usage
   cargo fuzz run target -- -rss_limit_mb=1024 -max_len=1000
   ```

2. **Timeout Issues**
   ```bash
   # Increase timeout
   cargo fuzz run target -- -timeout=30
   ```

3. **Infinite Loops**
   ```bash
   # Add timeout and use debug build
   RUSTFLAGS="-C opt-level=0" cargo fuzz run target -- -timeout=5
   ```

### Instrumentation
Enable additional debugging:
```bash
# Use AddressSanitizer
RUSTFLAGS="-Zsanitizer=address" cargo fuzz run fuzz_parser

# Use MemorySanitizer
RUSTFLAGS="-Zsanitizer=memory" cargo fuzz run fuzz_parser

# Use ThreadSanitizer
RUSTFLAGS="-Zsanitizer=thread" cargo fuzz run fuzz_parser
```

## Contributing

When adding new fuzzing targets:

1. **Create the target file** in `fuzz_targets/`
2. **Add entry to Cargo.toml**
3. **Implement `Arbitrary` trait** for custom input types
4. **Add validation functions** to catch issues
5. **Create seed corpus** with interesting test cases
6. **Document expected failures** and edge cases
7. **Update this README** with target description

### Target Template
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    // Define your input structure
}

fuzz_target!(|data: &[u8]| {
    if let Ok(mut unstructured) = Unstructured::new(data) {
        if let Ok(input) = FuzzInput::arbitrary(&mut unstructured) {
            // Your fuzzing logic here
            fuzz_target_function(&input);
        }
    }
});

fn fuzz_target_function(input: &FuzzInput) {
    // Implement your fuzzing target
}
```

## Performance Guidelines

### Target Performance
- Parser: >1000 exec/sec on modern hardware
- Analyzer: >500 exec/sec for simple contracts
- Detectors: >2000 exec/sec per detector
- SARIF Output: >5000 exec/sec for small reports

### Optimization Tips
1. Use `--release` builds for performance testing
2. Profile with `cargo fuzz run target -- -print_pcs=1`
3. Minimize allocations in hot paths
4. Use streaming parsers for large inputs
5. Implement early exit conditions

## Security Considerations

Fuzzing can expose security vulnerabilities:

1. **Parser Vulnerabilities**
   - Buffer overflows in parsing logic
   - Integer overflows in size calculations
   - Stack overflow from recursive parsing

2. **Logic Vulnerabilities**
   - Inconsistent analysis results
   - Missing validation checks
   - Race conditions in parallel processing

3. **Output Vulnerabilities**
   - JSON injection in SARIF output
   - Path traversal in file operations
   - Information disclosure in error messages

All findings should be treated as potential security issues and properly validated.