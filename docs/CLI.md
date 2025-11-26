# Command-Line Reference

Complete reference for all SolidityDefend command-line options and features.

## Table of Contents

- [Basic Syntax](#basic-syntax)
- [Global Options](#global-options)
- [Commands](#commands)
- [Output Options](#output-options)
- [Filtering Options](#filtering-options)
- [Environment Variables](#environment-variables)
- [Exit Codes](#exit-codes)
- [Examples](#examples)

## Basic Syntax

```
soliditydefend [OPTIONS] [COMMAND] [FILES]...
```

## Global Options

### Help and Version

```bash
-h, --help          Show help information
-V, --version       Show version information
```

### Configuration

```bash
-c, --config <FILE>    Configuration file path (.soliditydefend.yml)
--init-config          Create a default configuration file in the current directory
```

**Examples:**
```bash
# Create default configuration file
soliditydefend --init-config

# Use custom configuration file
soliditydefend --config custom-config.yml contracts/

# Use default configuration from current directory
soliditydefend contracts/  # Loads .soliditydefend.yml if present
```

### Input Files

```bash
<FILES>...          Solidity files to analyze (.sol)
```

**Examples:**
```bash
soliditydefend contract.sol
soliditydefend file1.sol file2.sol file3.sol
soliditydefend contracts/*.sol
soliditydefend src/**/*.sol
```

### Project Mode (v1.4.0+)

```bash
-p, --project <DIR>     Analyze entire project directory
--framework <TYPE>      Framework type: foundry, hardhat, plain (auto-detect if not specified)
```

**Examples:**
```bash
# Analyze a Foundry project (auto-detects from foundry.toml)
soliditydefend --project ./my-foundry-project

# Analyze a Hardhat project (auto-detects from hardhat.config.js)
soliditydefend --project ./my-hardhat-project

# Force framework type
soliditydefend --project ./my-project --framework foundry

# Combine with output options
soliditydefend --project ./my-project --format json --output results.json
```

**Framework Auto-Detection:**
- **Foundry**: Detected from `foundry.toml`, reads `src` directory, excludes `lib/`, `out/`, `cache/`
- **Hardhat**: Detected from `hardhat.config.js` or `hardhat.config.ts`, reads `contracts/`, excludes `node_modules/`, `artifacts/`
- **Plain**: Scans all `.sol` files in directory

## Commands

### analyze (default)

Analyze Solidity files for security vulnerabilities.

```bash
soliditydefend [OPTIONS] <FILES>...
```

This is the default command when no command is specified.

### list-detectors

List all available security detectors.

```bash
soliditydefend --list-detectors
```

**Output:**
```
Available Detectors:
===================
  missing-access-control - Missing Access Control (High)
  unprotected-initializer - Unprotected Initializer (High)
  default-visibility - Default Visibility (Medium)
  classic-reentrancy - Classic Reentrancy (High)
  readonly-reentrancy - Read-Only Reentrancy (Medium)
  division-before-multiplication - Division Order (Medium)
  missing-zero-address-check - Zero Address Check (Medium)
  array-bounds - Array Bounds (Medium)
  parameter-consistency - Parameter Consistency (Low)
  single-oracle-source - Single Oracle Source (High)
  missing-price-validation - Missing Price Validation (Medium)
  flashloan-vulnerable-patterns - Flash Loan Vulnerable Patterns (High)
  unchecked-external-call - Unchecked External Call (Medium)
  sandwich-attack - Sandwich Attack (Medium)
  front-running - Front Running (Medium)
  block-dependency - Block Dependency (Medium)
  tx-origin-auth - Tx Origin Authentication (High)
```

## Output Options

### Format Selection

```bash
-f, --format <FORMAT>   Output format [default: console]
```

**Available Formats:**
- `console` - Human-readable colored output (default)
- `json` - Machine-readable JSON format

**Examples:**
```bash
soliditydefend -f console contract.sol     # Default
soliditydefend -f json contract.sol        # JSON output
```

### Output Destination

```bash
-o, --output <FILE>     Output file (stdout if not specified)
```

**Examples:**
```bash
soliditydefend -o results.txt contract.sol           # Console to file
soliditydefend -f json -o results.json contract.sol  # JSON to file
```

## Filtering Options

### Severity Filtering

```bash
-s, --min-severity <LEVEL>   Minimum severity level [default: info]
```

**Severity Levels** (from lowest to highest):
- `info` - Informational messages
- `low` - Low severity issues
- `medium` - Medium severity issues
- `high` - High severity issues
- `critical` - Critical security vulnerabilities

**Examples:**
```bash
soliditydefend -s info contract.sol      # All issues (default)
soliditydefend -s low contract.sol       # Low and above
soliditydefend -s medium contract.sol    # Medium and above
soliditydefend -s high contract.sol      # High and critical only
soliditydefend -s critical contract.sol  # Critical only
```

## Environment Variables

SolidityDefend respects several environment variables for configuration:

### Cache Configuration

```bash
SOLIDITYDEFEND_CACHE_DIR    # Cache directory [default: ~/.cache/soliditydefend]
SOLIDITYDEFEND_CACHE_SIZE   # Maximum cache size in MB [default: 1024]
```

**Examples:**
```bash
export SOLIDITYDEFEND_CACHE_DIR=/tmp/sd-cache
export SOLIDITYDEFEND_CACHE_SIZE=2048
soliditydefend contract.sol
```

### Performance Configuration

```bash
SOLIDITYDEFEND_MAX_MEMORY   # Maximum memory usage in MB [default: 4096]
SOLIDITYDEFEND_THREADS      # Number of analysis threads [default: auto]
```

**Examples:**
```bash
export SOLIDITYDEFEND_MAX_MEMORY=8192    # 8GB limit
export SOLIDITYDEFEND_THREADS=8          # Use 8 threads
soliditydefend contracts/
```

### Logging Configuration

```bash
RUST_LOG                    # Logging level and filters
SOLIDITYDEFEND_LOG_LEVEL    # Simplified log level [debug|info|warn|error]
```

**Examples:**
```bash
export RUST_LOG=debug                        # Debug everything
export RUST_LOG=soliditydefend=info          # Info level for SolidityDefend
export SOLIDITYDEFEND_LOG_LEVEL=debug        # Simple debug mode
soliditydefend contract.sol
```

### Output Configuration

```bash
NO_COLOR                    # Disable colored output [any value]
CLICOLOR_FORCE             # Force colored output [any value]
```

**Examples:**
```bash
NO_COLOR=1 soliditydefend contract.sol        # No colors
CLICOLOR_FORCE=1 soliditydefend contract.sol  # Force colors
```

## Exit Codes

SolidityDefend uses standard exit codes to indicate the result of analysis:

| Exit Code | Meaning |
|-----------|---------|
| `0` | Success - No high/critical severity issues found |
| `1` | Analysis found high or critical severity issues |
| `2` | Command-line argument error |
| `3` | File not found or cannot be read |
| `4` | Parse error in Solidity file |
| `5` | Internal error or unexpected failure |

**Examples:**
```bash
# Check exit code in scripts
soliditydefend contract.sol
if [ $? -eq 0 ]; then
    echo "No critical issues found"
else
    echo "Issues found or error occurred"
fi

# Use in CI/CD
soliditydefend contracts/ || exit 1
```

## Examples

### Basic Analysis

```bash
# Analyze single file
soliditydefend MyContract.sol

# Analyze multiple files
soliditydefend Contract1.sol Contract2.sol

# Analyze all files in directory
soliditydefend contracts/*.sol

# Recursive analysis
soliditydefend src/**/*.sol
```

### Output Format Examples

```bash
# Default console output
soliditydefend contract.sol

# JSON output to stdout
soliditydefend -f json contract.sol

# JSON output to file
soliditydefend -f json -o analysis.json contract.sol

```

### Severity Filtering Examples

```bash
# All issues
soliditydefend contract.sol

# Only medium severity and above
soliditydefend -s medium contract.sol

# Only high and critical
soliditydefend -s high contract.sol

# Only critical issues
soliditydefend -s critical contract.sol
```

### Advanced Usage Examples

```bash
# Custom cache directory
SOLIDITYDEFEND_CACHE_DIR=/tmp/cache soliditydefend contract.sol

# Limit memory usage
SOLIDITYDEFEND_MAX_MEMORY=2048 soliditydefend large-project/

# Debug logging
RUST_LOG=debug soliditydefend contract.sol

# No colored output for CI
NO_COLOR=1 soliditydefend -f json -o results.json contracts/

# Force colors even when piping
CLICOLOR_FORCE=1 soliditydefend contract.sol | less -R
```

### CI/CD Integration Examples

```bash
# GitHub Actions / GitLab CI
soliditydefend -f json -o security.json contracts/

# Jenkins pipeline
soliditydefend -f json -o security-report.json contracts/
if [ $? -ne 0 ]; then
    echo "Security issues found!"
    exit 1
fi

# Simple pass/fail check
soliditydefend -s high contracts/ > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Security check passed"
else
    echo "❌ Security issues found"
    exit 1
fi
```

### Combining with Other Tools

```bash
# Filter JSON output with jq
soliditydefend -f json contract.sol | jq '.findings[].title'

# Count issues by severity
soliditydefend -f json contract.sol | \
  jq '.summary.by_severity | to_entries | .[] | "\(.key): \(.value)"'

# Extract file paths with issues
soliditydefend -f json contracts/ | \
  jq -r '.findings[].file_path' | sort | uniq

# Grep for specific patterns in console output
soliditydefend contract.sol | grep -i "reentrancy"

# Save only critical issues
soliditydefend -s critical -f json contracts/ | \
  jq '.findings[] | select(.severity == "critical")' > critical-issues.json
```

### Scripting Examples

```bash
#!/bin/bash
# security-check.sh - Comprehensive security analysis script

FILES=${1:-"contracts/*.sol"}
OUTPUT_DIR="security-reports/$(date +%Y-%m-%d)"
mkdir -p "$OUTPUT_DIR"

echo "🔍 Running SolidityDefend analysis..."

# Generate all formats
soliditydefend -f console "$FILES" > "$OUTPUT_DIR/report.txt"
soliditydefend -f json "$FILES" > "$OUTPUT_DIR/report.json"

# Check results
CRITICAL=$(jq '.summary.by_severity.critical // 0' "$OUTPUT_DIR/report.json")
HIGH=$(jq '.summary.by_severity.high // 0' "$OUTPUT_DIR/report.json")

echo "📊 Analysis complete:"
echo "   Critical: $CRITICAL"
echo "   High: $HIGH"
echo "   Reports saved to: $OUTPUT_DIR"

# Exit with error if critical/high issues found
if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
    echo "❌ Security issues found!"
    exit 1
else
    echo "✅ No critical issues found"
    exit 0
fi
```

## Troubleshooting

### Common Command-Line Issues

#### Invalid Arguments

```bash
# Error: Invalid format
soliditydefend -f xml contract.sol
# Error: unknown variant `xml`, expected one of `console`, `json`

# Error: Invalid severity
soliditydefend -s extreme contract.sol
# Error: unknown variant `extreme`, expected one of `info`, `low`, `medium`, `high`, `critical`
```

#### File Access Issues

```bash
# Error: File not found
soliditydefend nonexistent.sol
# Error: File not found: nonexistent.sol

# Error: Permission denied
soliditydefend /root/contract.sol
# Error: Permission denied: /root/contract.sol
```

#### Output Issues

```bash
# Error: Cannot write to output file
soliditydefend -o /root/results.json contract.sol
# Error: Permission denied: /root/results.json

# Error: Invalid output directory
soliditydefend -o /nonexistent/path/results.json contract.sol
# Error: No such file or directory: /nonexistent/path/results.json
```

### Getting Help

```bash
# Show help
soliditydefend --help

# Show version
soliditydefend --version

# List available detectors
soliditydefend --list-detectors

# Debug information
RUST_LOG=debug soliditydefend contract.sol 2>&1 | head -20
```

### Performance Troubleshooting

```bash
# Monitor memory usage
/usr/bin/time -v soliditydefend large-project/

# Limit memory
SOLIDITYDEFEND_MAX_MEMORY=1024 soliditydefend contracts/

# Use fewer threads
SOLIDITYDEFEND_THREADS=2 soliditydefend contracts/

# Clear cache
rm -rf ~/.cache/soliditydefend
soliditydefend contract.sol
```

## Future Features

The following options are planned for future releases:

```bash
# Detector selection (planned)
--detectors <LIST>          # Comma-separated list of detectors to run
--exclude-detectors <LIST>  # Detectors to exclude

# Configuration file (planned)
-c, --config <FILE>         # Configuration file path

# Watch mode (planned)
-w, --watch                 # Watch files for changes and re-analyze

# Baseline comparison (planned)
--baseline <FILE>           # Compare against baseline results

# Performance options (planned)
--max-files <N>             # Maximum files to analyze in parallel
--timeout <SECONDS>         # Analysis timeout per file
```

## See Also

- [Installation Guide](INSTALLATION.md) - How to install SolidityDefend
- [Usage Guide](USAGE.md) - Examples and tutorials
- [Configuration Guide](CONFIGURATION.md) - Configuration options
- [Detector Documentation](DETECTORS.md) - Available security detectors
- [Output Formats](OUTPUT.md) - Output format specifications