# Usage Guide

This comprehensive guide provides examples and tutorials for using SolidityDefend effectively. All core detector functionality is operational, including DeFi security analysis, MEV protection, and standard vulnerability detection.

## Table of Contents

- [Quick Start](#quick-start)
- [Basic Usage](#basic-usage)
- [Advanced Usage](#advanced-usage)
- [Output Formats](#output-formats)
- [Integration Examples](#integration-examples)
- [Best Practices](#best-practices)
- [Common Scenarios](#common-scenarios)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Analyze a Single Contract

```bash
# Basic analysis
soliditydefend MyContract.sol

# With colored output (default in terminals)
soliditydefend MyContract.sol --format console
```

### Analyze Multiple Files

```bash
# Multiple specific files
soliditydefend Contract1.sol Contract2.sol Contract3.sol

# All Solidity files in directory
soliditydefend src/*.sol

# Recursive analysis
soliditydefend src/**/*.sol
```

### Filter by Severity

```bash
# Only high and critical issues
soliditydefend --min-severity high MyContract.sol

# Only critical issues
soliditydefend --min-severity critical MyContract.sol
```

## Basic Usage

### Command Structure

```bash
soliditydefend [OPTIONS] <FILES>...
```

### Essential Options

```bash
# Output format
-f, --format <FORMAT>    # console (default), json, sarif

# Output file
-o, --output <FILE>      # Save results to file

# Severity filter
-s, --min-severity <LEVEL>  # info, low, medium, high, critical

# List available detectors
--list-detectors

# Show help
--help
```

### Examples

```bash
# Console output (default)
soliditydefend contract.sol

# JSON output to file
soliditydefend -f json -o results.json contract.sol

# SARIF format for CI/CD
soliditydefend -f sarif -o results.sarif src/*.sol

# High severity issues only
soliditydefend -s high contract.sol
```

## Advanced Usage

### Working with Large Projects

```bash
# Analyze entire project with progress
soliditydefend contracts/**/*.sol

# Save results and continue on errors
soliditydefend --continue-on-error contracts/ -o full-report.json

# Parallel analysis (automatic, uses all CPU cores)
soliditydefend contracts/
```

### Combining with Other Tools

```bash
# Pipe to grep for specific issues
soliditydefend contract.sol | grep -i "reentrancy"

# Count issues by severity
soliditydefend -f json contract.sol | jq '.findings | group_by(.severity) | map({severity: .[0].severity, count: length})'

# Find files with critical issues
soliditydefend -f json -s critical src/ | jq -r '.findings[].file_path' | sort | uniq
```

## Output Formats

### Console Output (Default)

Beautiful, human-readable output with colors and code snippets:

```bash
soliditydefend MyContract.sol
```

**Example Output:**
```
📊 SolidityDefend Analysis Report

🔍 Analyzing: MyContract.sol

⚠️  HIGH: Missing Access Control
   ├─ Location: MyContract.sol:15:5
   ├─ Function: withdraw() should have access control
   └─ Suggestion: Add onlyOwner modifier

   12 │ contract MyContract {
   13 │     mapping(address => uint256) public balances;
   14 │
   15 │     function withdraw() public {  ← Issue here
   16 │         payable(msg.sender).transfer(balances[msg.sender]);
   17 │     }
   18 │ }

🔥 CRITICAL: Classic Reentrancy
   ├─ Location: MyContract.sol:16:9
   ├─ External call before state change
   └─ Fix: Update state before external call

Summary: 2 issues found (1 critical, 1 high)
```

### JSON Output

Machine-readable format for automated processing:

```bash
soliditydefend -f json contract.sol
```

**Example Output:**
```json
{
  "version": "0.1.0",
  "timestamp": "2024-01-01T12:00:00Z",
  "summary": {
    "files_analyzed": 1,
    "total_findings": 2,
    "by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 0,
      "low": 0,
      "info": 0
    }
  },
  "findings": [
    {
      "id": "missing-access-control-001",
      "detector": "missing-access-control",
      "title": "Missing Access Control",
      "description": "Function withdraw() should have access control",
      "severity": "high",
      "confidence": "high",
      "file_path": "MyContract.sol",
      "start_line": 15,
      "end_line": 17,
      "start_column": 5,
      "end_column": 6,
      "code_snippet": "function withdraw() public {\n    payable(msg.sender).transfer(balances[msg.sender]);\n}",
      "fix_suggestion": "Add onlyOwner modifier",
      "references": ["https://docs.soliditydefend.com/detectors/access-control"]
    }
  ]
}
```

### SARIF Output

Industry-standard format for security tools:

```bash
soliditydefend -f sarif -o results.sarif contract.sol
```

## Integration Examples

### CI/CD Integration

#### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Analysis

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3

    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable

    - name: Install SolidityDefend
      run: cargo install soliditydefend

    - name: Run Security Analysis
      run: |
        soliditydefend -f sarif -o results.sarif contracts/

    - name: Upload SARIF to GitHub
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: results.sarif

    - name: Fail on Critical Issues
      run: |
        if soliditydefend -f json -s critical contracts/ | jq -e '.summary.by_severity.critical > 0'; then
          echo "Critical security issues found!"
          exit 1
        fi
```

#### GitLab CI

```yaml
# .gitlab-ci.yml
security_analysis:
  stage: test
  image: rust:latest
  script:
    - cargo install soliditydefend
    - soliditydefend -f json -o security-report.json contracts/
    - soliditydefend -f sarif -o security-report.sarif contracts/
  artifacts:
    reports:
      sast: security-report.sarif
    paths:
      - security-report.json
  allow_failure: false
```

### IDE Integration

#### VS Code

```json
// .vscode/tasks.json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "SolidityDefend: Analyze Current File",
      "type": "shell",
      "command": "soliditydefend",
      "args": ["${file}"],
      "group": "build",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "panel": "new"
      }
    },
    {
      "label": "SolidityDefend: Analyze Project",
      "type": "shell",
      "command": "soliditydefend",
      "args": ["contracts/**/*.sol"],
      "group": "build"
    }
  ]
}
```

#### Vim/Neovim

```vim
" Add to your .vimrc or init.vim
command! SolidityDefend !soliditydefend %
nnoremap <leader>sd :SolidityDefend<CR>
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: soliditydefend
        name: SolidityDefend Security Analysis
        entry: soliditydefend
        language: system
        files: \\.sol$
        args: [--min-severity, high]
```

## Best Practices

### 1. Start with High Severity Issues

```bash
# Focus on critical and high severity first
soliditydefend -s high contracts/

# Then gradually lower the threshold
soliditydefend -s medium contracts/
soliditydefend -s low contracts/
```

### 2. Use Appropriate Output Formats

```bash
# For human review
soliditydefend contracts/

# For CI/CD pipelines
soliditydefend -f sarif contracts/

# For automated processing
soliditydefend -f json contracts/
```

### 3. Organize Analysis by Component

```bash
# Analyze by contract type
soliditydefend contracts/tokens/*.sol
soliditydefend contracts/governance/*.sol
soliditydefend contracts/defi/*.sol

# Analyze interfaces separately
soliditydefend interfaces/*.sol
```

### 4. Save and Compare Results

```bash
# Save baseline
soliditydefend -f json -o baseline.json contracts/

# After changes, compare
soliditydefend -f json -o current.json contracts/

# Use diff tools to compare
jq -S . baseline.json > baseline.sorted.json
jq -S . current.json > current.sorted.json
diff baseline.sorted.json current.sorted.json
```

## Common Scenarios

### Security Audit Workflow

```bash
# 1. Initial scan for critical issues
soliditydefend -f json -s critical -o critical-issues.json contracts/

# 2. Comprehensive analysis
soliditydefend -f json -o full-analysis.json contracts/

# 3. Generate human-readable report
soliditydefend -f console contracts/ > audit-report.txt

# 4. Create SARIF for tools integration
soliditydefend -f sarif -o security.sarif contracts/
```

### Development Workflow

```bash
# Quick check during development
soliditydefend -s high MyContract.sol

# Pre-commit check
soliditydefend -s medium contracts/

# Full analysis before deployment
soliditydefend contracts/ -o deployment-check.json
```

### Continuous Monitoring

```bash
#!/bin/bash
# monitor.sh - Run daily security checks

DATE=$(date +%Y-%m-%d)
OUTPUT_DIR="reports/$DATE"
mkdir -p "$OUTPUT_DIR"

# Generate reports
soliditydefend -f json -o "$OUTPUT_DIR/security.json" contracts/
soliditydefend -f sarif -o "$OUTPUT_DIR/security.sarif" contracts/

# Check for new critical issues
CRITICAL_COUNT=$(jq '.summary.by_severity.critical' "$OUTPUT_DIR/security.json")
if [ "$CRITICAL_COUNT" -gt 0 ]; then
    echo "⚠️  $CRITICAL_COUNT critical issues found!"
    # Send notification (Slack, email, etc.)
fi
```

### Comparing Contract Versions

```bash
# Analyze old version
soliditydefend -f json -o v1-analysis.json contracts-v1/

# Analyze new version
soliditydefend -f json -o v2-analysis.json contracts-v2/

# Compare issue counts
echo "V1 Issues: $(jq '.summary.total_findings' v1-analysis.json)"
echo "V2 Issues: $(jq '.summary.total_findings' v2-analysis.json)"

# Find new issues
jq -s '.[1].findings - .[0].findings' v1-analysis.json v2-analysis.json
```

## Troubleshooting

### Common Issues

#### "No issues found" but expecting results

```bash
# Check if files are being parsed
soliditydefend --list-detectors  # Verify detectors are available

# Try with lower severity threshold
soliditydefend -s info contract.sol

# Verify file syntax
solc --parse-only contract.sol
```

#### Analysis is too slow

```bash
# Analyze smaller batches
soliditydefend contracts/batch1/*.sol
soliditydefend contracts/batch2/*.sol

# Use specific detectors only (future feature)
# soliditydefend --detectors reentrancy,access-control contracts/
```

#### Memory issues with large projects

```bash
# Process files individually
for file in contracts/*.sol; do
    soliditydefend "$file" >> all-results.txt
done

# Or use find with exec
find contracts -name "*.sol" -exec soliditydefend {} \;
```

### Performance Tips

1. **Use release builds**: Ensure you're using optimized builds
2. **SSD storage**: Use SSD for better I/O performance
3. **Sufficient RAM**: 4GB+ recommended for large projects
4. **Exclude test files**: Focus on production contracts

### Getting More Information

```bash
# Verbose output (when available)
RUST_LOG=debug soliditydefend contract.sol

# Check version and build info
soliditydefend --version

# List all available detectors
soliditydefend --list-detectors
```

## Advanced Features

### Environment Variables

```bash
# Customize cache location
export SOLIDITYDEFEND_CACHE_DIR=/tmp/sd-cache

# Set memory limit
export SOLIDITYDEFEND_MAX_MEMORY=4096

# Configure logging
export RUST_LOG=soliditydefend=info
```

### Integration with Build Tools

#### Hardhat

```javascript
// hardhat.config.js
task("security", "Run security analysis", async () => {
  const { exec } = require("child_process");

  exec("soliditydefend contracts/", (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error}`);
      return;
    }
    console.log(stdout);
  });
});
```

#### Foundry

```bash
# Add to Makefile
security:
    soliditydefend src/ -o security-report.json

security-ci:
    soliditydefend -f sarif -o security.sarif src/
    @if [ $$(jq '.summary.by_severity.critical + .summary.by_severity.high' security-report.json) -gt 0 ]; then \
        echo "High severity issues found!"; \
        exit 1; \
    fi
```

#### Truffle

```javascript
// truffle-config.js
module.exports = {
  plugins: ["soliditydefend-truffle"],  // Future plugin
  soliditydefend: {
    outputFormat: "json",
    minSeverity: "medium",
    outputFile: "security-report.json"
  }
};
```

## Next Steps

- **Configuration**: Learn about [configuration options](CONFIGURATION.md)
- **CLI Reference**: See all [available commands](CLI.md)
- **Detectors**: Understand what each [detector does](DETECTORS.md)
- **Output Formats**: Details about [output formats](OUTPUT.md)