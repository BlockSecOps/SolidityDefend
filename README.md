# SolidityDefend

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/SolidityOps/SolidityDefend/releases)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/SolidityOps/SolidityDefend#license)
[![Rust Version](https://img.shields.io/badge/rustc-1.75+-blue.svg)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)
[![Detectors](https://img.shields.io/badge/detectors-100-brightgreen.svg)](https://github.com/SolidityOps/SolidityDefend/blob/main/docs/DETECTORS.md)

A high-performance static analysis security tool for Solidity smart contracts, built with Rust for speed and accuracy. SolidityDefend helps developers identify security vulnerabilities, code quality issues, and potential exploits before deploying to production.

## Features

- **100+ Security Detectors** - Comprehensive coverage of vulnerabilities including reentrancy, access control, oracle manipulation, MEV attacks, DeFi exploits, cross-chain security, and more
- **Lightning Fast Analysis** - Built with Rust for optimal performance with advanced caching and incremental analysis
- **Multiple Output Formats** - Console output with syntax highlighting and code snippets, or JSON for CI/CD integration
- **URL-Based Analysis** - Analyze contracts directly from Etherscan, Polygonscan, BscScan, and Arbiscan URLs
- **Flexible Configuration** - YAML-based configuration system for customizing analysis behavior
- **CI/CD Ready** - Exit codes, severity filtering, and JSON output for seamless integration
- **Modern Vulnerability Coverage** - Detectors for 2024/2025 attack patterns including Account Abstraction (ERC-4337), cross-chain bridges, and advanced DeFi protocols

## Installation

### Download Pre-built Binary

Download the latest release for your platform:

**Linux (x86_64)**
```bash
curl -LO https://github.com/SolidityOps/SolidityDefend/releases/download/v1.0.0/soliditydefend-v1.0.0-linux-x86_64.tar.gz
tar -xzf soliditydefend-v1.0.0-linux-x86_64.tar.gz
sudo mv soliditydefend /usr/local/bin/
```

**macOS (Intel)**
```bash
curl -LO https://github.com/SolidityOps/SolidityDefend/releases/download/v1.0.0/soliditydefend-v1.0.0-macos-x86_64.tar.gz
tar -xzf soliditydefend-v1.0.0-macos-x86_64.tar.gz
sudo mv soliditydefend /usr/local/bin/
```

**macOS (Apple Silicon)**
```bash
curl -LO https://github.com/SolidityOps/SolidityDefend/releases/download/v1.0.0/soliditydefend-v1.0.0-macos-aarch64.tar.gz
tar -xzf soliditydefend-v1.0.0-macos-aarch64.tar.gz
sudo mv soliditydefend /usr/local/bin/
```

**Windows (x86_64)**
```powershell
# Download from: https://github.com/SolidityOps/SolidityDefend/releases/download/v1.0.0/soliditydefend-v1.0.0-windows-x86_64.zip
# Extract and add to PATH
```

### Build from Source

Requires Rust 1.75.0 or later:

```bash
git clone https://github.com/SolidityOps/SolidityDefend.git
cd SolidityDefend
cargo build --release
sudo mv target/release/soliditydefend /usr/local/bin/
```

### Docker

```bash
# Pull the image
docker pull ghcr.io/solidityops/soliditydefend:latest

# Or build locally
docker build -f docker/Dockerfile -t soliditydefend .
```

## Quick Start

### Analyze a Single Contract

```bash
soliditydefend contract.sol
```

### Analyze Multiple Files

```bash
soliditydefend src/**/*.sol
```

### Analyze from Blockchain Explorer

```bash
# From transaction hash
soliditydefend --from-url https://etherscan.io/tx/0x1234...

# From contract address
soliditydefend --from-url https://etherscan.io/address/0x1234...

# Setup API keys (required for URL analysis)
soliditydefend --setup-api-keys
```

### Filter by Severity

```bash
# Show only high and critical issues
soliditydefend -s high contract.sol
```

### JSON Output for CI/CD

```bash
soliditydefend -f json -o results.json contract.sol
```

### List Available Detectors

```bash
soliditydefend --list-detectors
```

## Usage Examples

### Basic Analysis

```bash
# Analyze with default settings
soliditydefend MyContract.sol

# Analyze entire project
soliditydefend contracts/**/*.sol
```

### CI/CD Integration

```bash
# Exit with error code if high/critical issues found
soliditydefend --exit-code-level high contracts/*.sol

# Generate JSON report for further processing
soliditydefend -f json -o security-report.json contracts/*.sol
```

### Docker Usage

```bash
# Analyze contracts in current directory
docker run -v $(pwd):/analysis soliditydefend /analysis/*.sol

# With JSON output
docker run -v $(pwd):/analysis soliditydefend -f json -o /analysis/report.json /analysis/*.sol
```

### Configuration File

Create a `.soliditydefend.yml` configuration file:

```bash
soliditydefend --init-config
```

Then customize your analysis settings:

```yaml
min_severity: medium
output_format: console
detectors:
  disable:
    - inefficient-storage
  enable_all: true
```

## Security Detectors

SolidityDefend includes **100 production-ready security detectors** across multiple categories:

### Core Security (15 detectors)
- Access Control & Authentication
- Reentrancy Protection (classic & read-only)
- Input Validation
- Logic & State Machine Bugs
- External Call Safety

### DeFi & Oracle Security (16 detectors)
- Oracle Manipulation & Price Validation
- Flash Loan Attack Protection
- Slippage Protection
- Reward Manipulation
- Liquidity Pool Vulnerabilities
- Vault Security (ERC-4626)

### MEV & Timing Attacks (9 detectors)
- Front-Running Detection
- Sandwich Attack Prevention
- Block Timestamp Dependencies
- Transaction Ordering Exploits
- Deadline Manipulation

### Advanced Features (20 detectors)
- Account Abstraction (ERC-4337) Security
- Cross-Chain Bridge Vulnerabilities
- Governance Attack Vectors
- Staking & Validator Security

### Code Quality & Gas Optimization (10 detectors)
- Gas Griefing Prevention
- DoS via Unbounded Operations
- Inefficient Storage Patterns
- Variable Shadowing
- Deprecated Function Usage

### Token Standards (8 detectors)
- ERC-20 Approve Race Conditions
- ERC-777 Hook Reentrancy
- ERC-721/1155 Callback Exploits
- Infinite Approval Risks

### Additional Categories (22+ detectors)
- Upgradeable Proxy Security
- Randomness Vulnerabilities
- Centralization Risks
- Token Supply Manipulation

For a complete list of detectors with descriptions, run:
```bash
soliditydefend --list-detectors
```

Or see the full [Detector Documentation](docs/DETECTORS.md).

## Configuration

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-f, --format` | Output format: `console` or `json` (default: console) |
| `-o, --output` | Output file path (default: stdout) |
| `-s, --min-severity` | Minimum severity: `info`, `low`, `medium`, `high`, `critical` |
| `--exit-code-level` | Exit with error when findings at or above severity level |
| `--no-cache` | Disable caching for fresh analysis |
| `--clear-cache` | Clear all cached results |
| `-c, --config` | Path to configuration file |
| `--from-url` | Analyze from blockchain explorer URL |

### Configuration File

Create `.soliditydefend.yml` in your project root:

```yaml
# Minimum severity to report
min_severity: medium

# Output format
output_format: console

# Detector configuration
detectors:
  enable_all: true
  disable:
    - detector-name-1
    - detector-name-2

# Cache settings
cache:
  enabled: true
  max_size_mb: 500

# Exit code configuration
exit_code:
  level: high
  on_analysis_error: true
```

## Output Formats

### Console Output

Human-readable output with:
- Color-coded severity levels
- Source code snippets
- Line numbers and file paths
- Fix suggestions when available

### JSON Output

Structured output for programmatic processing:

```json
{
  "findings": [
    {
      "detector": "reentrancy-eth",
      "severity": "high",
      "message": "Reentrancy vulnerability detected",
      "location": {
        "file": "contract.sol",
        "line": 42,
        "column": 5
      },
      "suggestion": "Use ReentrancyGuard or checks-effects-interactions pattern"
    }
  ],
  "summary": {
    "total": 10,
    "critical": 0,
    "high": 2,
    "medium": 5,
    "low": 3,
    "info": 0
  }
}
```

## System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Memory**: 4GB+ RAM recommended for large projects
- **Disk Space**: 100MB for binary, additional space for cache
- **Rust**: 1.75.0+ (if building from source)

## Documentation

- [Installation Guide](docs/INSTALLATION.md) - Detailed installation instructions
- [Usage Examples](docs/USAGE.md) - Comprehensive tutorials and examples
- [CLI Reference](docs/CLI.md) - Complete command-line documentation
- [Configuration Guide](docs/CONFIGURATION.md) - Configuration options
- [Detector Documentation](docs/DETECTORS.md) - All 100+ detectors explained
- [Output Formats](docs/OUTPUT.md) - Output format specifications

## Support

- **Issues**: [GitHub Issues](https://github.com/SolidityOps/SolidityDefend/issues)
- **Documentation**: [docs/](docs/)
- **Examples**: See [docs/USAGE.md](docs/USAGE.md) for detailed examples

## Versioning

SolidityDefend follows [Semantic Versioning](https://semver.org/):

- **Current Version**: 1.0.0
- **Stable Release**: v1.0.0 (Production Ready)
- **Detectors**: 100 production-ready security detectors

Version format: `MAJOR.MINOR.PATCH`
- **MAJOR**: Breaking changes
- **MINOR**: New features, backward-compatible
- **PATCH**: Bug fixes, backward-compatible

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Reporting bugs
- Suggesting features
- Submitting pull requests
- Development setup

---

**Built with Rust for security, performance, and reliability.**
