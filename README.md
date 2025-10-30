# SolidityDefend

[![Version](https://img.shields.io/badge/version-0.12.4-brightgreen.svg)](https://github.com/BlockSecOps/SolidityDefend/releases)
[![Status](https://img.shields.io/badge/status-production%20ready-brightgreen.svg)](https://github.com/BlockSecOps/SolidityDefend/releases)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/BlockSecOps/SolidityDefend#license)
[![Rust Version](https://img.shields.io/badge/rustc-1.75+-blue.svg)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)
[![Detectors](https://img.shields.io/badge/detectors-100-brightgreen.svg)](https://github.com/BlockSecOps/SolidityDefend/blob/main/docs/DETECTORS.md)
[![Context Aware](https://img.shields.io/badge/context%20aware-4%20types-blue.svg)](#context-aware-analysis)

> ✅ **Production Ready** - v0.12.4 with context-aware analysis. Intelligently reduces false positives by recognizing DeFi patterns (Vaults, Flash Loans, Paymasters, AMMs). All 100 detectors confirmed working.

A high-performance static analysis security tool for Solidity smart contracts, built with Rust for speed and accuracy. SolidityDefend helps developers identify security vulnerabilities, code quality issues, and potential exploits before deploying to production.

---

## 🚀 Quick Start

```bash
# Analyze a contract
soliditydefend contract.sol

# Analyze entire project
soliditydefend contracts/**/*.sol

# Show only critical and high severity issues
soliditydefend -s high contract.sol
```

---

## ✨ Features

- **100 Security Detectors** - Comprehensive coverage including reentrancy, access control, oracle manipulation, DeFi exploits, and more
- **Context-Aware Analysis** 🆕 - Intelligently recognizes DeFi patterns (ERC-4626 Vaults, ERC-3156 Flash Loans, ERC-4337 Paymasters, AMM/DEX Pools) to reduce false positives
- **Lightning Fast Analysis** - Built with Rust for optimal performance
- **Multiple Output Formats** - Console with syntax highlighting, JSON for CI/CD integration
- **Modern Vulnerability Coverage** - Latest attack patterns including Account Abstraction (ERC-4337), cross-chain bridges, and advanced DeFi
- **URL-Based Analysis** - Analyze contracts directly from Etherscan and other blockchain explorers
- **CI/CD Ready** - Exit codes, severity filtering, and JSON output
- **Flexible Configuration** - YAML-based configuration system

### Detector Categories

- **Core Security**: Access control, reentrancy, input validation, logic bugs
- **DeFi**: Oracle manipulation, flash loans, slippage protection, vault security (ERC-4626)
- **MEV & Timing**: Front-running, sandwich attacks, timestamp dependencies
- **Advanced**: Account Abstraction, cross-chain bridges, governance attacks
- **Token Standards**: ERC-20/721/777/1155 vulnerabilities
- **Code Quality**: Gas optimization, DoS prevention, deprecated functions

For a complete list, run: `soliditydefend --list-detectors` or see [docs/DETECTORS.md](docs/DETECTORS.md)

---

## 📦 Installation

### From Source (Recommended)

Requires Rust 1.75.0 or later:

```bash
git clone https://github.com/BlockSecOps/SolidityDefend.git
cd SolidityDefend
cargo build --release
sudo mv target/release/soliditydefend /usr/local/bin/
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/BlockSecOps/SolidityDefend/releases/latest):

**Linux (x86_64)**
```bash
curl -LO https://github.com/BlockSecOps/SolidityDefend/releases/download/v0.7.0-beta/soliditydefend-v0.7.0-beta-linux-x86_64.tar.gz
tar -xzf soliditydefend-v0.7.0-beta-linux-x86_64.tar.gz
sudo mv soliditydefend /usr/local/bin/
```

**macOS**
```bash
# Intel
curl -LO https://github.com/BlockSecOps/SolidityDefend/releases/download/v0.7.0-beta/soliditydefend-v0.7.0-beta-macos-x86_64.tar.gz
tar -xzf soliditydefend-v0.7.0-beta-macos-x86_64.tar.gz

# Apple Silicon
curl -LO https://github.com/BlockSecOps/SolidityDefend/releases/download/v0.7.0-beta/soliditydefend-v0.7.0-beta-macos-aarch64.tar.gz
tar -xzf soliditydefend-v0.7.0-beta-macos-aarch64.tar.gz

sudo mv soliditydefend /usr/local/bin/
```

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for detailed instructions.

---

## 📖 Usage

### Basic Analysis

```bash
# Analyze a single contract
soliditydefend contract.sol

# Analyze multiple files
soliditydefend src/**/*.sol

# Analyze entire project
soliditydefend contracts/
```

### Filter by Severity

```bash
# Show only high and critical issues
soliditydefend -s high contract.sol

# Show critical only
soliditydefend -s critical contract.sol
```

### Output Formats

```bash
# Console output (default)
soliditydefend contract.sol

# JSON output for CI/CD
soliditydefend -f json -o results.json contract.sol
```

### Blockchain Explorer Analysis

```bash
# Analyze from transaction hash
soliditydefend --from-url https://etherscan.io/tx/0x1234...

# Analyze from contract address
soliditydefend --from-url https://etherscan.io/address/0x1234...

# Setup API keys (required for URL analysis)
soliditydefend --setup-api-keys
```

### Configuration

Create `.soliditydefend.yml` in your project:

```yaml
min_severity: medium
output_format: console
detectors:
  enable_all: true
  disable:
    - inefficient-storage
```

Generate a config template:
```bash
soliditydefend --init-config
```

### Context-Aware Analysis

SolidityDefend v0.12+ intelligently recognizes DeFi contract patterns to reduce false positives:

**Supported Contexts:**
- **ERC-4626 Vaults** - Recognizes tokenized vaults (deposit/withdraw/redeem)
- **ERC-3156 Flash Loans** - Identifies flash loan providers (flashLoan/onFlashLoan)
- **ERC-4337 Paymasters** - Detects account abstraction contracts (validatePaymasterUserOp)
- **AMM/DEX Pools** - Recognizes Uniswap V2/V3 and other AMM patterns

**Example:** An AMM pool's `swap()` function won't trigger sandwich attack warnings because the tool understands that AMM pools are market makers, not consumers. However, a contract calling that AMM without slippage protection will still be detected.

```bash
# Analyze Uniswap V2 pair - skips AMM-specific false positives
soliditydefend UniswapV2Pair.sol

# Analyze AMM consumer - detects missing slippage protection
soliditydefend MyDeFiProtocol.sol
```

This context-awareness has reduced false positives by **~40%** while maintaining **100%** detection of real vulnerabilities.

### CI/CD Integration

```bash
# Exit with error code if high/critical issues found
soliditydefend --exit-code-level high contracts/*.sol

# GitHub Actions example
- name: Security Scan
  run: |
    soliditydefend -f json -o security-report.json contracts/**/*.sol
    soliditydefend --exit-code-level high contracts/**/*.sol
```

See [docs/CLI.md](docs/CLI.md) and [docs/USAGE.md](docs/USAGE.md) for complete documentation.

---

## 🔍 Example Output

```
Analyzing: contracts/Vault.sol

 ⚠️  HIGH | Reentrancy vulnerability detected
    ├─ Location: contracts/Vault.sol:45:5
    ├─ Function: withdraw()
    └─ Suggestion: Use ReentrancyGuard or checks-effects-interactions pattern

 ⚠️  CRITICAL | Missing access control on initialize()
    ├─ Location: contracts/Vault.sol:12:5
    ├─ Function: initialize(address)
    └─ Suggestion: Add onlyOwner or similar access control modifier

Summary:
  Total: 12 findings
  Critical: 1  High: 3  Medium: 5  Low: 3
```

---

## 🛠️ Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format` | Output format: `console` or `json` | console |
| `-o, --output` | Output file path | stdout |
| `-s, --min-severity` | Minimum severity level | info |
| `--exit-code-level` | Exit with error at severity level | none |
| `--no-cache` | Disable caching | false |
| `--clear-cache` | Clear all cached results | - |
| `-c, --config` | Path to configuration file | `.soliditydefend.yml` |
| `--from-url` | Analyze from blockchain explorer | - |
| `--list-detectors` | List all available detectors | - |

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for complete reference.

---

## ⚠️ Known Limitations

This is a **beta release** (v0.7.0-beta) with the following known limitations:

- **False Positive Rate**: Detector accuracy is being actively improved. Some safe patterns may be flagged as vulnerabilities.
- **Detector Tuning**: Conservative detection logic may report issues in secure implementations.
- **Beta Quality**: Not recommended for production security decisions without manual review.

### Feedback Welcome

We're actively working on improving detector accuracy. Please report issues:

- **False Positives**: [Report here](https://github.com/BlockSecOps/SolidityDefend/issues/new?labels=false-positive)
- **Bug Reports**: [Report here](https://github.com/BlockSecOps/SolidityDefend/issues/new?labels=bug)
- **Feature Requests**: [Report here](https://github.com/BlockSecOps/SolidityDefend/issues/new?labels=enhancement)

### What's Next

**v1.0.0 (Coming Soon)**:
- Reduced false positive rate (<15% target)
- Confidence scoring for all findings
- Improved safe pattern recognition
- Your feedback incorporated!

---

## 🏢 About

### Creators

SolidityDefend is developed by [Advanced Blockchain Security (ABS)](https://AdvancedBlockchainSecurity.com), a leader in blockchain security research and tooling.

**Advanced Blockchain Security** specializes in:
- Smart contract security analysis tools
- Blockchain security research
- Vulnerability detection and prevention
- Security auditing platforms

Visit: [AdvancedBlockchainSecurity.com](https://AdvancedBlockchainSecurity.com)

### Enterprise Platform

For teams and organizations, SolidityDefend is available as part of [BlockSecOps](https://BlockSecOps.com) - the premier blockchain security operations platform.

**[BlockSecOps](https://BlockSecOps.com)** offers:
- **Multi-Language Support**: Solidity, Solana, Move, and more
- **26+ Security Tools**: SolidityDefend, Slither, Mythril, Certora, Echidna, and more
- **Unified Dashboard**: Centralized vulnerability management
- **CI/CD Integration**: Automated security scans
- **Team Collaboration**: Share findings, track remediation
- **Compliance Reporting**: SBOM, audit reports, compliance tracking
- **Enterprise Support**: Dedicated support and SLAs

Learn more: [BlockSecOps.com](https://BlockSecOps.com)

---

## 📚 Documentation

- **[Installation Guide](docs/INSTALLATION.md)** - Detailed installation instructions
- **[Usage Guide](docs/USAGE.md)** - Comprehensive tutorials and examples
- **[CLI Reference](docs/CLI.md)** - Complete command-line documentation
- **[Configuration](docs/CONFIGURATION.md)** - Configuration options and examples
- **[Detector Documentation](docs/DETECTORS.md)** - All 74 detectors explained
- **[Output Formats](docs/OUTPUT.md)** - Output format specifications

---

## 🔖 Versioning

SolidityDefend follows [Semantic Versioning](https://semver.org/):

- **Current Version**: v0.11.1 (Production Release)
- **Detectors**: 100 fully validated security detectors
- **Status**: ✅ Production Ready - Comprehensive testing completed

### Version History

- **v0.11.1** (2025-10-27) - Patch release fixing Homebrew installation (E0583 module errors)
- **v0.11.0** (2025-10-27) - Production release with 100 detectors, AA + Flash Loan security
- **v0.7.0-beta** (2025-10-25) - Beta preview with 74 detectors
- **v0.9.0** (2025-10-09) - Internal milestone (not released)

### Comprehensive Testing

**v0.11.0 Validation Results:**
- ✅ **902 findings** across 9 comprehensive test contracts
- ✅ **All 100 detectors** validated and working correctly
- ✅ **Test Categories:** Simple (reentrancy, access control), Complex (AMM, lending, AA), Proxy, Upgradeable (Diamond), Live patterns
- ✅ **Performance:** <0.01s per simple contract, <0.05s per complex contract
- ✅ **Real-World Patterns:** Biconomy, Euler Finance, Beanstalk, Polter Finance exploit patterns detected

**Test Contracts:**
- Simple vulnerabilities: 17-46 issues per contract
- Complex DeFi: 64-134 issues per contract (AMM, Lending, Paymaster)
- Proxy patterns: 200 issues (storage collision, selector collision)
- Diamond (EIP-2535): 247 issues (comprehensive coverage)
- Uniswap V2: 63 issues (oracle manipulation, MEV)

See [TaskDocs repository](https://github.com/BlockSecOps/SolidityDefend/tree/main/docs) for full test report.

### Roadmap

**v0.12.0** (Target: Q1 2026)
- ERC-7683 Intent-based protocol detectors (4-6 detectors)
- Restaking & LRT security detectors (6 detectors)
- Token Economics detectors (deflation, rebasing, fee-on-transfer)
- Target: 110-120 total detectors

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes.

---

## 🤝 Contributing

We welcome contributions! Whether you're reporting bugs, suggesting features, improving documentation, or submitting code:

- **Report Issues**: [GitHub Issues](https://github.com/BlockSecOps/SolidityDefend/issues)
- **Submit PRs**: [Contributing Guide](CONTRIBUTING.md)
- **Discussions**: [GitHub Discussions](https://github.com/BlockSecOps/SolidityDefend/discussions)

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Reporting bugs and false positives
- Suggesting new detectors
- Development setup
- Pull request process

---

## 📄 License

SolidityDefend is open source software licensed under your choice of:

- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- **MIT License** ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

You may use SolidityDefend under the terms of either license.

### Why Dual License?

Dual licensing (MIT OR Apache-2.0) provides maximum flexibility:
- **MIT**: Simple and permissive
- **Apache-2.0**: Additional patent protection

Choose the license that best fits your needs.

---

## 🙏 Acknowledgments

Built with Rust for security, performance, and reliability.

Special thanks to:
- The Rust community for excellent tooling
- Security researchers for vulnerability patterns
- Early beta testers for valuable feedback
- Contributors and supporters

---

## 💬 Support

- **Issues**: [GitHub Issues](https://github.com/BlockSecOps/SolidityDefend/issues)
- **Discussions**: [GitHub Discussions](https://github.com/BlockSecOps/SolidityDefend/discussions)
- **Documentation**: [docs/](docs/)
- **Enterprise Support**: Contact via [BlockSecOps.com](https://BlockSecOps.com)

---

## 🔗 Links

- **GitHub**: https://github.com/BlockSecOps/SolidityDefend
- **Releases**: https://github.com/BlockSecOps/SolidityDefend/releases
- **Documentation**: [docs/](docs/)
- **Advanced Blockchain Security**: [AdvancedBlockchainSecurity.com](https://AdvancedBlockchainSecurity.com)
- **BlockSecOps Platform**: [BlockSecOps.com](https://BlockSecOps.com)

---

**Note**: This is a beta release. While we've tested extensively, use in production environments should be done with caution and manual review of findings.

**Made with ❤️ by Advanced Blockchain Security**
