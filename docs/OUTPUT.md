# Output Format Documentation

Complete specification for all output formats supported by SolidityDefend.

## Table of Contents

- [Overview](#overview)
- [Console Output](#console-output)
- [JSON Output](#json-output)
- [SARIF Output](#sarif-output)
- [Output Comparison](#output-comparison)
- [Integration Examples](#integration-examples)
- [Customization](#customization)

## Overview

SolidityDefend supports three output formats designed for different use cases:

| Format | Use Case | Features |
|--------|----------|----------|
| **Console** | Human review, development | Colors, code snippets, interactive |
| **JSON** | Automation, CI/CD | Structured data, programmatic processing |
| **SARIF** | Security tools, enterprise | Industry standard, tool interoperability |

### Format Selection

```bash
# Console (default)
soliditydefend contract.sol
soliditydefend -f console contract.sol

# JSON
soliditydefend -f json contract.sol

# SARIF
soliditydefend -f sarif contract.sol
```

## Console Output

The console format provides human-readable output with colors, code snippets, and clear issue descriptions.

### Example Console Output

```
📊 SolidityDefend Analysis Report

🔍 Analyzing: contracts/MyToken.sol

🔥 CRITICAL: Classic Reentrancy
   ├─ Location: MyToken.sol:45:9
   ├─ Function: withdraw()
   ├─ External call before state change
   └─ Fix: Update balances before external call

   42 │ function withdraw() public {
   43 │     uint256 amount = balances[msg.sender];
   44 │     require(amount > 0, "No balance");
   45 │     msg.sender.call{value: amount}("");  ← Issue here
   46 │     balances[msg.sender] = 0;           ← State change after call
   47 │ }

⚠️  HIGH: Missing Access Control
   ├─ Location: MyToken.sol:25:5
   ├─ Function: mint() should have access control
   └─ Suggestion: Add onlyOwner modifier

   23 │ contract MyToken {
   24 │     mapping(address => uint256) public balances;
   25 │     function mint(address to, uint256 amount) public {  ← Issue here
   26 │         balances[to] += amount;
   27 │     }

⚡ MEDIUM: Zero Address Check Missing
   ├─ Location: MyToken.sol:30:5
   ├─ Parameter 'to' in transfer() not validated
   └─ Fix: Add require(to != address(0))

   29 │ }
   30 │ function transfer(address to, uint256 amount) public {  ← Issue here
   31 │     balances[msg.sender] -= amount;

📊 Analysis Summary
┌─────────────────┬───────┐
│ Severity        │ Count │
├─────────────────┼───────┤
│ 🔥 Critical     │     1 │
│ ⚠️  High        │     1 │
│ ⚡ Medium       │     1 │
│ 📝 Low          │     0 │
│ ℹ️  Info        │     0 │
├─────────────────┼───────┤
│ Total Issues    │     3 │
└─────────────────┴───────┘

⏱️  Analysis Time: 0.25s
📁 Files Analyzed: 1
❌ Analysis failed due to high-severity issues
```

### Console Format Features

#### Color Coding
- 🔥 **Critical**: Red background
- ⚠️ **High**: Red text
- ⚡ **Medium**: Yellow text
- 📝 **Low**: Blue text
- ℹ️ **Info**: Gray text

#### Code Snippets
- **Context**: 2 lines before and after the issue
- **Line Numbers**: Exact location reference
- **Highlighting**: Issue line marked with arrow (`←`)
- **Indentation**: Preserved original formatting

#### Interactive Elements
- **Clickable Paths**: File paths that open in editors
- **Expandable Details**: Detailed explanations on request
- **Progress Indicators**: Real-time analysis progress

### Console Customization

```bash
# Disable colors
NO_COLOR=1 soliditydefend contract.sol

# Force colors in pipes
CLICOLOR_FORCE=1 soliditydefend contract.sol | less -R

# Custom width
SOLIDITYDEFEND_OUTPUT_WIDTH=120 soliditydefend contract.sol

# Compact output
SOLIDITYDEFEND_COMPACT=true soliditydefend contract.sol
```

## JSON Output

The JSON format provides structured data for programmatic processing and integration with other tools.

### JSON Schema

```json
{
  "$schema": "https://schema.soliditydefend.com/output/v1.0.0.json",
  "version": "0.1.0",
  "timestamp": "2024-01-01T12:00:00Z",
  "summary": {
    "files_analyzed": 1,
    "total_findings": 3,
    "analysis_time_ms": 250,
    "by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 1,
      "low": 0,
      "info": 0
    }
  },
  "findings": [
    {
      "id": "classic-reentrancy-001",
      "detector": "classic-reentrancy",
      "title": "Classic Reentrancy",
      "description": "External call before state change in withdraw() function",
      "severity": "critical",
      "confidence": "high",
      "category": "reentrancy",
      "file_path": "contracts/MyToken.sol",
      "start_line": 45,
      "end_line": 45,
      "start_column": 9,
      "end_column": 47,
      "code_snippet": "msg.sender.call{value: amount}(\"\");",
      "context_before": [
        "function withdraw() public {",
        "    uint256 amount = balances[msg.sender];",
        "    require(amount > 0, \"No balance\");"
      ],
      "context_after": [
        "    balances[msg.sender] = 0;",
        "}"
      ],
      "fix_suggestion": "Update balances before external call",
      "fix_code": "balances[msg.sender] = 0;\nmsg.sender.call{value: amount}(\"\");",
      "references": [
        "https://docs.soliditydefend.com/detectors/reentrancy",
        "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/"
      ],
      "tags": ["external-call", "state-change", "reentrancy"],
      "metadata": {
        "function_name": "withdraw",
        "function_visibility": "public",
        "external_call_type": "low-level-call",
        "state_variables_modified": ["balances"]
      }
    }
  ],
  "metrics": {
    "lines_of_code": 156,
    "functions_analyzed": 8,
    "contracts_analyzed": 1,
    "external_calls_found": 3,
    "state_variables_found": 2
  },
  "configuration": {
    "detectors_enabled": 17,
    "min_severity": "info",
    "analysis_depth": "deep"
  }
}
```

### JSON Field Descriptions

#### Root Object
- `version`: SolidityDefend version
- `timestamp`: Analysis execution time (ISO 8601)
- `summary`: High-level analysis results
- `findings`: Array of security issues found
- `metrics`: Code analysis statistics
- `configuration`: Analysis settings used

#### Finding Object
- `id`: Unique identifier for the finding
- `detector`: Detector that found the issue
- `title`: Human-readable issue title
- `description`: Detailed issue description
- `severity`: Issue severity level
- `confidence`: Detector confidence level
- `category`: Issue category classification
- `file_path`: Path to the file containing the issue
- `start_line`/`end_line`: Line number range
- `start_column`/`end_column`: Column number range
- `code_snippet`: Exact code that triggered the finding
- `context_before`/`context_after`: Surrounding code lines
- `fix_suggestion`: Recommended fix description
- `fix_code`: Suggested code replacement
- `references`: Links to documentation and resources
- `tags`: Machine-readable issue tags
- `metadata`: Additional detector-specific information

### JSON Processing Examples

#### Extract Critical Issues
```bash
soliditydefend -f json contract.sol | jq '.findings[] | select(.severity == "critical")'
```

#### Count Issues by Severity
```bash
soliditydefend -f json contract.sol | jq '.summary.by_severity'
```

#### Get File Paths with Issues
```bash
soliditydefend -f json contracts/ | jq -r '.findings[].file_path' | sort | uniq
```

#### Filter by Detector
```bash
soliditydefend -f json contract.sol | jq '.findings[] | select(.detector == "reentrancy")'
```

#### Generate Summary Report
```bash
soliditydefend -f json contracts/ | jq '{
  total_files: .summary.files_analyzed,
  total_issues: .summary.total_findings,
  critical: .summary.by_severity.critical,
  high: .summary.by_severity.high,
  analysis_time: .summary.analysis_time_ms
}'
```

## SARIF Output

Static Analysis Results Interchange Format (SARIF) is the industry standard for security analysis tools.

### SARIF Schema Version

SolidityDefend outputs SARIF 2.1.0 compliant JSON, ensuring compatibility with major security platforms.

### Example SARIF Output

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SolidityDefend",
          "version": "0.1.0",
          "informationUri": "https://github.com/soliditydefend/cli",
          "organization": "SolidityDefend",
          "shortDescription": {
            "text": "Static analysis security tool for Solidity smart contracts"
          },
          "fullDescription": {
            "text": "A high-performance static analysis security tool for Solidity smart contracts, built with Rust for speed and accuracy."
          },
          "rules": [
            {
              "id": "classic-reentrancy",
              "name": "ClassicReentrancy",
              "shortDescription": {
                "text": "Classic Reentrancy"
              },
              "fullDescription": {
                "text": "Detects the classic reentrancy vulnerability where external calls are made before state updates"
              },
              "help": {
                "text": "Ensure state updates occur before external calls to prevent reentrancy attacks",
                "markdown": "Ensure state updates occur before external calls to prevent reentrancy attacks. See [reentrancy documentation](https://docs.soliditydefend.com/detectors/reentrancy) for details."
              },
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "category": "reentrancy",
                "severity": "critical",
                "confidence": "high",
                "tags": ["security", "reentrancy", "external-calls"]
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "classic-reentrancy",
          "ruleIndex": 0,
          "level": "error",
          "message": {
            "text": "External call before state change in withdraw() function",
            "markdown": "External call before state change in `withdraw()` function. Update balances before external call to prevent reentrancy."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "contracts/MyToken.sol",
                  "uriBaseId": "SRCROOT"
                },
                "region": {
                  "startLine": 45,
                  "endLine": 45,
                  "startColumn": 9,
                  "endColumn": 47,
                  "snippet": {
                    "text": "msg.sender.call{value: amount}(\"\");"
                  }
                },
                "contextRegion": {
                  "startLine": 42,
                  "endLine": 47,
                  "snippet": {
                    "text": "function withdraw() public {\n    uint256 amount = balances[msg.sender];\n    require(amount > 0, \"No balance\");\n    msg.sender.call{value: amount}(\"\");\n    balances[msg.sender] = 0;\n}"
                  }
                }
              }
            }
          ],
          "fixes": [
            {
              "description": {
                "text": "Update state before external call"
              },
              "artifactChanges": [
                {
                  "artifactLocation": {
                    "uri": "contracts/MyToken.sol"
                  },
                  "replacements": [
                    {
                      "deletedRegion": {
                        "startLine": 45,
                        "endLine": 46,
                        "startColumn": 5,
                        "endColumn": 29
                      },
                      "insertedContent": {
                        "text": "    balances[msg.sender] = 0;\n    msg.sender.call{value: amount}(\"\");"
                      }
                    }
                  ]
                }
              ]
            }
          ],
          "properties": {
            "detector": "classic-reentrancy",
            "category": "reentrancy",
            "confidence": "high",
            "function_name": "withdraw",
            "external_call_type": "low-level-call"
          }
        }
      ],
      "columnKind": "utf16CodeUnits",
      "originalUriBaseIds": {
        "SRCROOT": {
          "uri": "file:///workspace/"
        }
      }
    }
  ]
}
```

### SARIF Features

#### Tool Information
- **Tool Metadata**: Name, version, organization
- **Rule Definitions**: Complete rule descriptions and help
- **Configuration**: Default severity levels and settings

#### Result Details
- **Location Information**: Precise file, line, and column positions
- **Code Snippets**: Both the specific issue and surrounding context
- **Fix Suggestions**: Automated fix descriptions and code changes
- **Rich Messages**: Both plain text and Markdown formatting

#### Integration Benefits
- **GitHub Integration**: Automatic security tab population
- **IDE Support**: Built-in SARIF viewers in VS Code, IntelliJ
- **CI/CD Compatibility**: Jenkins, Azure DevOps, GitLab CI
- **Security Platforms**: Compatibility with enterprise security tools

### SARIF Processing

#### Upload to GitHub Security Tab
```yaml
# GitHub Actions
- name: Upload SARIF to GitHub
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: security-report.sarif
```

#### Convert SARIF to Other Formats
```bash
# Convert SARIF to CSV (using sarif-om)
sarif-om convert -i security.sarif -o security.csv

# Convert SARIF to HTML report
sarif-html -i security.sarif -o security.html
```

#### Filter SARIF Results
```bash
# Extract only critical/high severity issues
jq '.runs[0].results[] | select(.level == "error")' security.sarif
```

## Output Comparison

### Feature Matrix

| Feature | Console | JSON | SARIF |
|---------|---------|------|-------|
| **Human Readable** | ✅ Excellent | ❌ No | ⚡ Limited |
| **Machine Readable** | ❌ No | ✅ Excellent | ✅ Excellent |
| **Code Snippets** | ✅ Rich | ✅ Basic | ✅ Rich |
| **Colors/Formatting** | ✅ Yes | ❌ No | ❌ No |
| **Fix Suggestions** | ✅ Text | ✅ Text + Code | ✅ Structured |
| **Tool Integration** | ⚡ Limited | ✅ Good | ✅ Excellent |
| **Industry Standard** | ❌ No | ❌ No | ✅ Yes |
| **File Size** | Small | Medium | Large |
| **Processing Speed** | Fast | Fast | Medium |

### Use Case Recommendations

#### Console Format - Best For:
- **Development**: Real-time feedback during coding
- **Code Review**: Human review of security issues
- **Learning**: Understanding security vulnerabilities
- **Terminal Workflows**: Command-line focused development

#### JSON Format - Best For:
- **CI/CD Pipelines**: Automated security testing
- **Custom Tooling**: Building custom analysis tools
- **Data Processing**: Statistical analysis of security trends
- **API Integration**: Programmatic access to results

#### SARIF Format - Best For:
- **Enterprise Integration**: Large organization security workflows
- **Tool Interoperability**: Multi-tool security analysis
- **Compliance Reporting**: Standardized security documentation
- **Platform Integration**: GitHub, Azure DevOps, enterprise platforms

## Integration Examples

### CI/CD Integration

#### GitHub Actions with Multiple Formats
```yaml
name: Security Analysis
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3

    - name: Install SolidityDefend
      run: cargo install soliditydefend

    # Console output for PR comments
    - name: Run Analysis (Console)
      id: console-analysis
      run: |
        soliditydefend contracts/ > security-console.txt
        echo "console-output<<EOF" >> $GITHUB_OUTPUT
        cat security-console.txt >> $GITHUB_OUTPUT
        echo "EOF" >> $GITHUB_OUTPUT

    # JSON for processing
    - name: Run Analysis (JSON)
      run: soliditydefend -f json -o security.json contracts/

    # SARIF for GitHub Security tab
    - name: Run Analysis (SARIF)
      run: soliditydefend -f sarif -o security.sarif contracts/

    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: security.sarif

    - name: Process Results
      run: |
        CRITICAL=$(jq '.summary.by_severity.critical' security.json)
        HIGH=$(jq '.summary.by_severity.high' security.json)

        if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
          echo "❌ Security issues found: $CRITICAL critical, $HIGH high"
          exit 1
        fi

    - name: Comment PR
      uses: actions/github-script@v6
      with:
        script: |
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: '```\n${{ steps.console-analysis.outputs.console-output }}\n```'
          })
```

#### Jenkins Pipeline
```groovy
pipeline {
    agent any

    stages {
        stage('Security Analysis') {
            steps {
                script {
                    // Run analysis in all formats
                    sh 'soliditydefend -f console contracts/ > console-report.txt'
                    sh 'soliditydefend -f json -o security.json contracts/'
                    sh 'soliditydefend -f sarif -o security.sarif contracts/'

                    // Parse JSON results
                    def results = readJSON file: 'security.json'
                    def critical = results.summary.by_severity.critical
                    def high = results.summary.by_severity.high

                    // Archive reports
                    archiveArtifacts artifacts: '*.txt,*.json,*.sarif'

                    // Publish SARIF
                    publishSarif results: [file: 'security.sarif']

                    // Fail if critical/high issues
                    if (critical > 0 || high > 0) {
                        error("Security issues found: ${critical} critical, ${high} high")
                    }
                }
            }
        }
    }
}
```

### IDE Integration

#### VS Code Tasks
```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "SolidityDefend: Console Analysis",
      "type": "shell",
      "command": "soliditydefend",
      "args": ["${file}"],
      "group": "build",
      "presentation": {
        "reveal": "always",
        "panel": "new"
      },
      "problemMatcher": {
        "owner": "soliditydefend",
        "fileLocation": ["relative", "${workspaceFolder}"],
        "pattern": {
          "regexp": "^(.*):(\\d+):(\\d+):\\s+(error|warning|info):\\s+(.*)$",
          "file": 1,
          "line": 2,
          "column": 3,
          "severity": 4,
          "message": 5
        }
      }
    },
    {
      "label": "SolidityDefend: SARIF Analysis",
      "type": "shell",
      "command": "soliditydefend",
      "args": ["-f", "sarif", "-o", "security.sarif", "${workspaceFolder}/contracts/"],
      "group": "build"
    }
  ]
}
```

### Custom Processing Scripts

#### Python Results Processor
```python
#!/usr/bin/env python3
import json
import sys
from collections import defaultdict

def process_security_results(json_file):
    """Process SolidityDefend JSON output"""
    with open(json_file) as f:
        data = json.load(f)

    # Group findings by file
    by_file = defaultdict(list)
    for finding in data['findings']:
        by_file[finding['file_path']].append(finding)

    # Generate summary
    summary = data['summary']
    print(f"📊 Security Analysis Summary")
    print(f"Files analyzed: {summary['files_analyzed']}")
    print(f"Total issues: {summary['total_findings']}")
    print(f"Analysis time: {summary['analysis_time_ms']}ms")

    # Print severity breakdown
    severities = summary['by_severity']
    for severity, count in severities.items():
        if count > 0:
            print(f"{severity.title()}: {count}")

    # Print findings by file
    for file_path, findings in by_file.items():
        print(f"\n📁 {file_path}")
        for finding in findings:
            severity_emoji = {
                'critical': '🔥',
                'high': '⚠️',
                'medium': '⚡',
                'low': '📝',
                'info': 'ℹ️'
            }
            emoji = severity_emoji.get(finding['severity'], '❓')
            print(f"  {emoji} {finding['title']} (line {finding['start_line']})")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python process_results.py security.json")
        sys.exit(1)

    process_security_results(sys.argv[1])
```

#### Bash Report Generator
```bash
#!/bin/bash
# generate_report.sh - Generate comprehensive security report

JSON_FILE="$1"
if [ -z "$JSON_FILE" ]; then
    echo "Usage: $0 <security.json>"
    exit 1
fi

# Extract data using jq
TOTAL_FILES=$(jq -r '.summary.files_analyzed' "$JSON_FILE")
TOTAL_ISSUES=$(jq -r '.summary.total_findings' "$JSON_FILE")
CRITICAL=$(jq -r '.summary.by_severity.critical' "$JSON_FILE")
HIGH=$(jq -r '.summary.by_severity.high' "$JSON_FILE")
MEDIUM=$(jq -r '.summary.by_severity.medium' "$JSON_FILE")
LOW=$(jq -r '.summary.by_severity.low' "$JSON_FILE")

# Generate HTML report
cat > security-report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Security Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; font-weight: bold; }
        .medium { color: #ffc107; font-weight: bold; }
        .low { color: #17a2b8; }
        .summary { background: #f8f9fa; padding: 20px; border-radius: 5px; }
        .finding { margin: 20px 0; padding: 15px; border-left: 4px solid #ccc; }
    </style>
</head>
<body>
    <h1>🔒 Security Analysis Report</h1>

    <div class="summary">
        <h2>📊 Summary</h2>
        <p><strong>Files Analyzed:</strong> $TOTAL_FILES</p>
        <p><strong>Total Issues:</strong> $TOTAL_ISSUES</p>
        <p><span class="critical">Critical: $CRITICAL</span> |
           <span class="high">High: $HIGH</span> |
           <span class="medium">Medium: $MEDIUM</span> |
           <span class="low">Low: $LOW</span></p>
    </div>

    <h2>🔍 Findings</h2>
EOF

# Add findings to HTML
jq -r '.findings[] | "<div class=\"finding\"><h3 class=\"\(.severity)\">\(.title)</h3><p><strong>File:</strong> \(.file_path):\(.start_line)</p><p><strong>Description:</strong> \(.description)</p><p><strong>Fix:</strong> \(.fix_suggestion)</p></div>"' "$JSON_FILE" >> security-report.html

echo "</body></html>" >> security-report.html

echo "📄 HTML report generated: security-report.html"
```

## Customization

### Environment Variables

```bash
# Console output customization
export NO_COLOR=1                              # Disable colors
export CLICOLOR_FORCE=1                        # Force colors
export SOLIDITYDEFEND_OUTPUT_WIDTH=120         # Custom width
export SOLIDITYDEFEND_COMPACT=true             # Compact mode
export SOLIDITYDEFEND_NO_SNIPPETS=true         # Disable code snippets

# JSON output customization
export SOLIDITYDEFEND_JSON_PRETTY=true         # Pretty-print JSON
export SOLIDITYDEFEND_JSON_SNIPPETS=true       # Include code snippets
export SOLIDITYDEFEND_JSON_FIXES=true          # Include fix suggestions

# SARIF output customization
export SOLIDITYDEFEND_SARIF_MINIMAL=true       # Minimal SARIF output
export SOLIDITYDEFEND_SARIF_FIXES=true         # Include fix suggestions
```

### Output Filtering

```bash
# Filter by severity in JSON
soliditydefend -f json contracts/ | jq '.findings[] | select(.severity == "high" or .severity == "critical")'

# Filter by detector
soliditydefend -f json contracts/ | jq '.findings[] | select(.detector == "reentrancy")'

# Custom summary
soliditydefend -f json contracts/ | jq '{
  files: .summary.files_analyzed,
  critical_high: (.summary.by_severity.critical + .summary.by_severity.high),
  time: .summary.analysis_time_ms
}'
```

### Future Customization Options

*Note: These features are planned for future releases*

```toml
# soliditydefend.toml
[output.console]
colors = true
snippets = true
width = 120
compact = false

[output.json]
pretty = true
include_snippets = true
include_fixes = true
include_metadata = true

[output.sarif]
include_fixes = true
minimal = false
organization = "MyCompany"
```

## Best Practices

### Format Selection Guidelines

1. **Development Phase**: Use console format for immediate feedback
2. **Code Review**: Use console format for human-readable issues
3. **CI/CD Pipelines**: Use JSON for processing, SARIF for integration
4. **Documentation**: Use console output in documentation and tutorials
5. **Compliance**: Use SARIF for regulatory and enterprise requirements

### Performance Considerations

- **Console**: Fastest rendering, smallest output
- **JSON**: Fast processing, medium file size
- **SARIF**: More processing overhead, largest files

### Storage and Archival

```bash
# Compress SARIF files for archival
gzip security.sarif

# Store multiple formats
mkdir reports/$(date +%Y-%m-%d)
soliditydefend -f console contracts/ > reports/$(date +%Y-%m-%d)/console.txt
soliditydefend -f json -o reports/$(date +%Y-%m-%d)/security.json contracts/
soliditydefend -f sarif -o reports/$(date +%Y-%m-%d)/security.sarif contracts/
```

## See Also

- [Usage Guide](USAGE.md) - How to use different output formats effectively
- [CLI Reference](CLI.md) - Command-line options for output control
- [Integration Examples](USAGE.md#integration-examples) - Real-world integration patterns
- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) - Official SARIF documentation