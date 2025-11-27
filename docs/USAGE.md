# Usage Guide

This comprehensive guide provides examples and tutorials for using SolidityDefend Community Edition effectively. All core detector functionality is operational, including DeFi security analysis, MEV protection, and standard vulnerability detection.

> **Note**: This documentation covers SolidityDefend Community Edition features. Advanced features like SARIF output format and enterprise integrations are available in the Enterprise Edition. See [Enterprise Edition Features](#enterprise-edition-features) for details.

## Table of Contents

- [Quick Start](#quick-start)
- [Project Mode (v1.4.0+)](#project-mode-v140)
- [Basic Usage](#basic-usage)
- [Advanced Usage](#advanced-usage)
- [Output Formats](#output-formats)
- [Integration Examples](#integration-examples)
- [Best Practices](#best-practices)
- [Common Scenarios](#common-scenarios)
- [Troubleshooting](#troubleshooting)
- [Enterprise Edition Features](#enterprise-edition-features)

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

## Project Mode (v1.4.0+)

**NEW in v1.4.0**: Analyze entire Foundry and Hardhat projects with automatic directory and framework detection. Just pass a directory path!

### Automatic Directory Detection

Simply pass a directory path and SolidityDefend automatically detects and analyzes the project:

```bash
# Just pass a directory - auto-detects everything!
soliditydefend ./my-foundry-project
soliditydefend ./my-hardhat-project

# Works with relative and absolute paths
soliditydefend ~/projects/my-defi-app
soliditydefend /home/user/contracts/vault
```

### Foundry Projects

```bash
# Auto-detect directory and framework (RECOMMENDED)
solidifydefend ./my-foundry-project

# Or use explicit project flag
soliditydefend --project ./my-foundry-project

# With JSON output for CI/CD
soliditydefend ./my-foundry-project -f json -o results.json

# Filter by severity
soliditydefend ./my-foundry-project --min-severity high
```

**Foundry Behavior:**
- Auto-detects from `foundry.toml`
- Reads `src` directory from config (default: `src/`)
- Excludes: `lib/`, `out/`, `cache/`, `broadcast/`

### Hardhat Projects

```bash
# Auto-detect directory and framework (RECOMMENDED)
soliditydefend ./my-hardhat-project

# Or use explicit project flag
soliditydefend --project ./my-hardhat-project

# Force Hardhat framework
soliditydefend ./my-project --framework hardhat
```

**Hardhat Behavior:**
- Auto-detects from `hardhat.config.js` or `hardhat.config.ts`
- Reads `paths.sources` from config (default: `contracts/`)
- Excludes: `node_modules/`, `artifacts/`, `cache/`, `typechain/`

### Plain Projects

```bash
# Analyze directory without framework detection
soliditydefend --project ./my-project --framework plain
```

**Plain Behavior:**
- Scans all `.sol` files in directory recursively
- No directory exclusions (manual filtering via glob patterns)

### Project Mode Examples

```bash
# Full workflow for Foundry project (just pass directory!)
cd my-foundry-project
soliditydefend . -f json -o security-report.json
cat security-report.json | jq '.summary'

# CI/CD integration
soliditydefend . --min-severity high -f json || exit 1

# Compare two projects
soliditydefend ./project-v1 -f json -o v1.json
soliditydefend ./project-v2 -f json -o v2.json
```

## Basic Usage

### Command Structure

```bash
soliditydefend [OPTIONS] <FILES>...
```

### Essential Options

```bash
# Output format
-f, --format <FORMAT>    # console (default), json

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
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔒 BlockSecOps.com - Enterprise-Grade DevSecOps Platform for Smart Contracts
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Found 2 issues in 1 file:

⚠️  HIGH: Function 'withdraw' should have access control
   ├─ Location: MyContract.sol:15:5
   ├─ Detector: missing-access-control
   ├─ CWE: CWE-284
   └─ Fix: Add onlyOwner modifier

🔥 CRITICAL: External call before state change
   ├─ Location: MyContract.sol:16:9
   ├─ Detector: classic-reentrancy
   ├─ CWE: CWE-841
   └─ Fix: Update state before external call


📊 Analysis Summary
┌─────────────────┬───────┐
│ Severity        │ Count │
├─────────────────┼───────┤
│ 🔥 Critical     │     1 │
│ ⚠️  High        │     1 │
│ ⚡ Medium       │     0 │
│ 📝 Low          │     0 │
│ ℹ️  Info        │     0 │
├─────────────────┼───────┤
│ Total Issues    │     2 │
└─────────────────┴───────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔒 BlockSecOps.com - Enterprise-Grade DevSecOps Platform for Smart Contracts
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### JSON Output

Machine-readable format for automated processing:

```bash
soliditydefend -f json contract.sol
```

**Example Output:**
```json
{
  "version": "1.3.6",
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

*Note: SARIF output format is available in Enterprise Edition. Community Edition supports console and JSON output formats, which provide comprehensive analysis results suitable for most use cases.*

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
        soliditydefend -f json -o results.json contracts/

    - name: Upload Security Report
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: results.json

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
  artifacts:
    paths:
      - security-report.json
  allow_failure: false

# Note: SARIF format and advanced SAST integration available in Enterprise Edition
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

# For automated processing and CI/CD pipelines
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

# 4. Save comprehensive results for further analysis
soliditydefend -f json -o comprehensive-analysis.json contracts/

# Note: SARIF format for advanced tools integration available in Enterprise Edition
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
soliditydefend -f console > "$OUTPUT_DIR/security-report.txt" contracts/

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
    soliditydefend -f json -o security-report.json src/
    @if [ $$(jq '.summary.by_severity.critical + .summary.by_severity.high' security-report.json) -gt 0 ]; then \
        echo "High severity issues found!"; \
        exit 1; \
    fi

# Note: SARIF output for advanced CI/CD integration available in Enterprise Edition
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

## Enterprise Edition Features

SolidityDefend Enterprise Edition includes all Community Edition features plus advanced capabilities for enterprise environments:

### SARIF Output Format

Industry-standard Static Analysis Results Interchange Format (SARIF) provides:
- Rich metadata for security findings
- Tool interoperability with enterprise security platforms
- Advanced CI/CD integration capabilities
- Seamless integration with GitHub Security, GitLab SAST, and other enterprise tools

```bash
# Enterprise Edition only
soliditydefend -f sarif -o results.sarif contracts/
```

### Advanced CI/CD Integration

Enterprise Edition includes native support for:
- GitHub Security tab integration via SARIF upload
- GitLab SAST reporting
- Azure DevOps security dashboards
- Jenkins security plugins
- Custom enterprise tool integrations

### Enterprise Support

- Priority technical support
- Custom detector development
- Enterprise deployment assistance
- Training and consultation services

For more information about Enterprise Edition features and pricing, visit our website or contact our sales team.

## Next Steps

- **Configuration**: Learn about [configuration options](CONFIGURATION.md)
- **CLI Reference**: See all [available commands](CLI.md)
- **Detectors**: Understand what each [detector does](DETECTORS.md)
- **Output Formats**: Details about [output formats](OUTPUT.md)