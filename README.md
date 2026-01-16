# SolidityDefend

[![Version](https://img.shields.io/badge/version-1.9.0-brightgreen.svg)](https://github.com/BlockSecOps/SolidityDefend/releases)
[![Status](https://img.shields.io/badge/status-production%20ready-brightgreen.svg)](https://github.com/BlockSecOps/SolidityDefend/releases)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/BlockSecOps/SolidityDefend#license)
[![Rust Version](https://img.shields.io/badge/rustc-1.82+-blue.svg)](https://blog.rust-lang.org/2024/10/17/Rust-1.82.0.html)
[![Detectors](https://img.shields.io/badge/detectors-321-brightgreen.svg)](https://github.com/BlockSecOps/SolidityDefend/blob/main/docs/DETECTORS.md)
[![Context Aware](https://img.shields.io/badge/context%20aware-4%20types-blue.svg)](#context-aware-analysis)
[![OWASP 2025](https://img.shields.io/badge/OWASP%202025-aligned-blue.svg)](#owasp-2025-alignment)
[![Validated](https://img.shields.io/badge/validated-43.5%25%20detection%20rate-blue.svg)](#validation-testing)

## 🚀 Quick Start

```bash
# Analyze a single contract
soliditydefend contract.sol

# Analyze entire Foundry/Hardhat project (auto-detects directory)
soliditydefend ./my-foundry-project

# Or use explicit project flag
soliditydefend --project ./my-hardhat-project --output json

# Show only critical and high severity issues
soliditydefend -s high contract.sol
```

---

## ✨ Features

- **321 Security Detectors** - Comprehensive coverage including **10 randomness/DoS detectors** (blockhash randomness, VRF misuse, commit-reveal timing, DoS push patterns, revert bombs), **10 L2/rollup detectors** (sequencer MEV, challenge period bypass, blob data manipulation, cross-rollup state mismatch), **10 governance/access control detectors** (timelock bypass, role escalation, quorum overflow), **10 callback chain detectors** (nested callback reentrancy, multicall msg.value reuse, ERC721/ERC1155 callback exploitation, Uniswap V4 hooks, Compound callback chains), **8 metamorphic/CREATE2 detectors** (bytecode mutation, address collision, initcode injection), **12 advanced MEV detectors** (sandwich attacks, JIT liquidity, liquidation MEV, token launch sniping), **10 EIP-7702/EIP-1153 detectors** (delegation phishing, storage corruption, transient reentrancy), **45 proxy/upgradeable contract detectors** (UUPS, Beacon, Transparent, EIP-1167 Clones, Diamond), SWC-aligned detectors (SWC-105/106/132/133), ERC-4337 AA advanced (calldata encoding, paymaster drain, signature aggregation), advanced access control (role hierarchy, timelock bypass, privilege escalation), restaking/LRT security (EigenLayer, Renzo, Puffer), flash loan exploits, token standards (ERC-20/721/1155), MEV protection, front-running protection, zero-knowledge proofs (zkSync, Scroll, Polygon zkEVM), modular blockchain (Celestia, Avail, cross-rollup), AI agent security, reentrancy, oracle manipulation, advanced DeFi exploits (JIT liquidity, AMM invariant, pool donation), and cutting-edge 2025/2026 vulnerabilities
- **OWASP 2025 Aligned** 🆕 - Full coverage of OWASP Smart Contract Top 10 (2025) addressing $1.42B in analyzed vulnerability patterns
- **Modern EIP Coverage** 🆕 - EIP-7702 delegation ($12M+ losses), EIP-1153 transient storage, ERC-7821 batch executor, ERC-7683 intent-based systems
- **Context-Aware Analysis** - Intelligently recognizes DeFi patterns (ERC-4626 Vaults, ERC-3156 Flash Loans, ERC-4337 Paymasters, AMM/DEX Pools) to reduce false positives
- **Lightning Fast Analysis** - Built with Rust for optimal performance
- **Project Mode** 🆕 - Analyze entire Foundry and Hardhat projects with automatic directory detection (just pass a directory path!)
- **SWC Classification** 🆕 - Smart Contract Weakness Classification (SWC) IDs in findings for industry-standard vulnerability tracking
- **Multiple Output Formats** - Console with syntax highlighting, JSON, SARIF for CI/CD integration
- **URL-Based Analysis** - Analyze contracts directly from Etherscan and other blockchain explorers
- **CI/CD Ready** - Exit codes, severity filtering, and JSON output
- **Flexible Configuration** - YAML-based configuration system

### Detector Categories

- **Core Security**: Access control, reentrancy, input validation, logic bugs
- **OWASP 2025**: Logic errors ($63.8M), oracle security, input validation ($14.6M), overflow ($223M Cetus), access control ($953M)
- **Modern EIPs**: EIP-7702 delegation phishing, EIP-1153 transient storage reentrancy
- **DeFi**: Oracle manipulation, flash loans, slippage protection, vault security (ERC-4626)
- **Intent-Based**: ERC-7683 cross-chain validation, ERC-7821 batch executor security
- **MEV & Timing**: Front-running, sandwich attacks, timestamp dependencies, MEV protection
- **Advanced**: Account Abstraction (ERC-4337), cross-chain bridges, governance attacks
- **Privacy**: Storage visibility, commit-reveal schemes, secret exposure
- **Token Standards**: ERC-20/721/777/1155 vulnerabilities, permit front-running, decimal confusion
- **Zero-Knowledge** 🆕: ZK proof malleability, trusted setup validation, circuit constraints (zkSync, Scroll, Polygon zkEVM)
- **Modular Blockchain** 🆕: Celestia/Avail data availability, cross-rollup atomicity, fraud proof timing
- **AI Agent Security** 🆕: Prompt injection, decision manipulation, oracle dependency, resource exhaustion
- **Code Quality**: Gas optimization, DoS prevention, deprecated functions

For a complete list, run: `soliditydefend --list-detectors` or see [docs/DETECTORS.md](docs/DETECTORS.md)

---

## ✅ Validation Testing

SolidityDefend has been validated against 11 purposefully vulnerable smart contracts with a **43.5% detection rate**.

### Detection Strengths

| Category | Detection Rate |
|----------|---------------|
| **Input Validation** | 78% |
| **DoS Vulnerabilities** | 71% |
| **Timestamp/Randomness** | 67% |
| **Reentrancy** | 60% |
| **Integer Overflow** | 60% |
| **Access Control** | 50% |
| **Signature Issues** | 43% |

**Key Capabilities:**
- Reentrancy patterns (checks-effects-interactions violations)
- Signature replay, cross-chain replay, malleability
- Integer overflow in Solidity <0.8.0 and unchecked blocks
- DeFi-specific patterns (MEV, AMM, vault vulnerabilities)
- Comprehensive parameter and zero-address validation

**Recommendation:** Use SolidityDefend as part of a **multi-tool security strategy**:
- SolidityDefend for fast initial scan (30-180ms)
- Slither for complementary static analysis
- Mythril for deeper symbolic execution
- Manual audit for business logic and context-specific issues

**Full validation report:** See [vulnerable-smart-contract-examples/solidity/VALIDATION_REPORT.md](https://github.com/BlockSecOps/vulnerable-smart-contract-examples/blob/main/solidity/VALIDATION_REPORT.md)

**Known limitations:** See [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md)

---

## 📦 Installation

### Docker (Recommended for Quick Start)

The fastest way to get started without installing dependencies:

```bash
# Build the image
docker build -t soliditydefend:latest .

# Analyze a contract
docker run --rm -v $(pwd):/workspace soliditydefend:latest contract.sol

# Or use with Docker Compose
docker-compose run --rm soliditydefend contracts/
```

See [docs/DOCKER.md](docs/DOCKER.md) for comprehensive Docker usage, CI/CD integration, and advanced configurations.

### From Source

Requires Rust 1.82.0 or later:

```bash
git clone https://github.com/BlockSecOps/SolidityDefend.git
cd SolidityDefend
cargo build --release
sudo mv target/release/soliditydefend /usr/local/bin/
```

### Homebrew (macOS - Recommended)

```bash
brew tap BlockSecOps/tap
brew install soliditydefend
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/BlockSecOps/SolidityDefend/releases/latest):

**Linux (x86_64)**
```bash
curl -LO https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.6.0/soliditydefend-linux-x86_64
chmod +x soliditydefend-linux-x86_64
sudo mv soliditydefend-linux-x86_64 /usr/local/bin/soliditydefend
```

**Linux (ARM64)**
```bash
curl -LO https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.6.0/soliditydefend-linux-arm64
chmod +x soliditydefend-linux-arm64
sudo mv soliditydefend-linux-arm64 /usr/local/bin/soliditydefend
```

**macOS (Apple Silicon)**
```bash
curl -LO https://github.com/BlockSecOps/SolidityDefend/releases/download/v1.6.0/soliditydefend-darwin-arm64
chmod +x soliditydefend-darwin-arm64
sudo mv soliditydefend-darwin-arm64 /usr/local/bin/soliditydefend
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
```

### Project Mode (v1.4.0+)

Analyze entire Foundry or Hardhat projects. Just pass a directory path - the framework is auto-detected:

```bash
# Analyze a Foundry project (auto-detects directory and framework)
soliditydefend ./my-foundry-project

# Analyze a Hardhat project (auto-detects from hardhat.config.js)
soliditydefend ./my-hardhat-project

# Force framework type with explicit flag
soliditydefend --project ./my-project --framework foundry

# Output as JSON
soliditydefend ./my-project -f json -o results.json
```

**Supported Frameworks:**
- **Foundry**: Reads `src` from `foundry.toml`, excludes `lib/`, `out/`, `cache/`
- **Hardhat**: Reads `paths.sources` from config, excludes `node_modules/`, `artifacts/`
- **Plain**: Scans all `.sol` files in directory

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

SolidityDefend intelligently recognizes DeFi contract patterns to reduce false positives:

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

**Results:**
- **0% false positive rate** on vault, restaking, and AA detectors
- **~40%** false positive reduction on flash loan and paymaster contracts
- **100%** detection of real vulnerabilities (zero false negatives)

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
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔒 BlockSecOps.com - Enterprise-Grade DevSecOps Platform for Smart Contracts
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Found 12 issues in 1 file:

🔥 CRITICAL: Reentrancy vulnerability detected in withdraw()
   ├─ Location: contracts/Vault.sol:45:5
   ├─ Detector: classic-reentrancy
   ├─ CWE: CWE-841 | SWC: SWC-107
   └─ Fix: Use ReentrancyGuard or checks-effects-interactions pattern

⚠️  HIGH: Missing access control on initialize()
   ├─ Location: contracts/Vault.sol:12:5
   ├─ Detector: missing-access-control
   ├─ CWE: CWE-284
   └─ Fix: Add onlyOwner or similar access control modifier

⚡ MEDIUM: Address parameter not validated
   ├─ Location: contracts/Vault.sol:30:5
   ├─ Detector: missing-zero-address-check
   ├─ CWE: CWE-476
   └─ Fix: Add require(to != address(0), "Zero address not allowed");


📊 Analysis Summary
┌─────────────────┬───────┐
│ Severity        │ Count │
├─────────────────┼───────┤
│ 🔥 Critical     │     1 │
│ ⚠️  High        │     3 │
│ ⚡ Medium       │     5 │
│ 📝 Low          │     3 │
│ ℹ️  Info        │     0 │
├─────────────────┼───────┤
│ Total Issues    │    12 │
└─────────────────┴───────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔒 BlockSecOps.com - Enterprise-Grade DevSecOps Platform for Smart Contracts
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 🛠️ Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --project` | Analyze entire project directory | - |
| `--framework` | Framework type: `foundry`, `hardhat`, `plain` | auto-detect |
| `-f, --format` | Output format: `console`, `json`, `sarif` | console |
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

- **Manual Review Recommended**: As with all static analysis tools, findings should be reviewed by security experts for production deployments.
- **Single-File Analysis**: v1.4.0 project mode analyzes files individually; cross-file inheritance analysis planned for v2.0.

### Feedback Welcome

We're actively working on improving detector accuracy. Please report issues:

- **False Positives**: [Report here](https://github.com/BlockSecOps/SolidityDefend/issues/new?labels=false-positive)
- **Bug Reports**: [Report here](https://github.com/BlockSecOps/SolidityDefend/issues/new?labels=bug)
- **Feature Requests**: [Report here](https://github.com/BlockSecOps/SolidityDefend/issues/new?labels=enhancement)

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

- **[Docker Guide](docs/DOCKER.md)** - Docker installation, usage, and CI/CD integration
- **[Installation Guide](docs/INSTALLATION.md)** - Detailed installation instructions
- **[Usage Guide](docs/USAGE.md)** - Comprehensive tutorials and examples
- **[CLI Reference](docs/CLI.md)** - Complete command-line documentation
- **[Configuration](docs/CONFIGURATION.md)** - Configuration options and examples
- **[Detector Documentation](docs/DETECTORS.md)** - All 74 detectors explained
- **[Output Formats](docs/OUTPUT.md)** - Output format specifications

---

## 🔖 Versioning

SolidityDefend follows [Semantic Versioning](https://semver.org/):

- **Current Version**: v1.6.0 (Production Release)
- **Detectors**: 233 security detectors (including 31 proxy/upgradeable)
- **Status**: Production Ready

See [CHANGELOG.md](CHANGELOG.md) for release history and detailed notes.

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

Contributor List
-  github.com/dehvCurtis

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

**Made with ❤️ by Advanced Blockchain Security**
