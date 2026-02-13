# SolidityDefend

[![Version](https://img.shields.io/badge/version-1.10.24-brightgreen.svg)](https://github.com/BlockSecOps/SolidityDefend/releases)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)

> Enterprise-grade static analysis for Solidity smart contracts

**Developed by [BlockSecOps](https://blocksecops.com)** - Smart Contract Security Experts

## Quick Start

```bash
brew tap BlockSecOps/tap && brew install soliditydefend
soliditydefend contract.sol
```

## Features

- **67 Precision-Tuned Detectors** - Reentrancy, access control, oracle manipulation, flash loans, MEV, and more
- **Context-Aware Analysis** - Structural FP filter across all detectors plus Safe Patterns Library with 56+ categories. Zero false positives on secure benchmarks (0 FPs on 23 secure contract suites). Recognizes ReentrancyGuard, SafeERC20, OpenZeppelin/Aave/Compound/Uniswap protocols, proxy patterns, access control, and more
- **Modern EIP Coverage** - EIP-7702, EIP-1153, ERC-7683, ERC-7821, ERC-4337
- **Project-Aware Scanning** - True project understanding with dependency graph, cross-contract analysis, and smart file ordering
- **Dependency Scanning** - Audit OpenZeppelin and other imported libraries with `--include-deps`
- **Cross-Contract Analysis** - Detect vulnerabilities spanning multiple contracts with `--cross-contract`
- **Lightning Fast** - 30-180ms analysis time, built in Rust
- **CI/CD Ready** - JSON/SARIF output, exit codes, severity filtering
- **100% Recall** - Validated against 117-contract ground truth suite (77/77 TPs, 0 parse errors, 0 false negatives)

See [docs/detectors/](docs/detectors/README.md) for the complete detector list.

## Installation

### Homebrew (macOS)
```bash
brew tap BlockSecOps/tap
brew install soliditydefend
```

### Pre-built Binaries (Recommended)
Pre-built binaries are automatically built by GitHub Actions on each release. Download from [GitHub Releases](https://github.com/BlockSecOps/SolidityDefend/releases/latest):

- Linux x86_64 / aarch64
- macOS x86_64 / ARM64 (Apple Silicon)
- Windows x86_64

All binaries are stripped and include SHA256 checksums for verification.

### From Source

**Requirements:** Rust 1.82+ ([install](https://rustup.rs))

```bash
# Clone the repository
git clone https://github.com/BlockSecOps/SolidityDefend.git
cd SolidityDefend

# Build release binary
cargo build --release

# Install (choose one)
sudo cp target/release/soliditydefend /usr/local/bin/    # System-wide
cp target/release/soliditydefend ~/.local/bin/           # User only
```

**Verify installation:**
```bash
soliditydefend --version
```

### Docker
Docker images are automatically built and published to Docker Hub by GitHub Actions on each release.

```bash
# Pull from Docker Hub (multi-platform: linux/amd64, linux/arm64)
docker pull blocksecops/soliditydefend:latest

# Run analysis (mount current directory)
docker run --rm -v $(pwd):/workspace blocksecops/soliditydefend:latest contract.sol

# Or build locally from source
docker build -t soliditydefend:latest .
```

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for details.

## Usage

```bash
# Single contract
soliditydefend contract.sol

# Foundry/Hardhat project (auto-detects framework)
soliditydefend ./my-project

# Verbose mode - see discovered files, dependency graph, and more
soliditydefend ./my-project --verbose

# Include dependency libraries (OpenZeppelin, etc.) in analysis
soliditydefend ./my-project --include-deps

# Cross-contract vulnerability detection
soliditydefend ./my-project --cross-contract

# Filter by severity
soliditydefend -s high contract.sol

# JSON output for CI/CD
soliditydefend -f json -o results.json contract.sol

# CI/CD: exit with error if high/critical found
soliditydefend --exit-code-level high contracts/*.sol
```

See [docs/USAGE.md](docs/USAGE.md) for complete usage guide.

## Example Output

```
CRITICAL: Reentrancy vulnerability detected in withdraw()
   Location: contracts/Vault.sol:45:5
   Detector: classic-reentrancy
   CWE: CWE-841
   Fix: Use ReentrancyGuard or checks-effects-interactions pattern

HIGH: Missing access control on initialize()
   Location: contracts/Vault.sol:12:5
   Detector: missing-access-control
   CWE: CWE-284
   Fix: Add onlyOwner or similar access control modifier
```

Tested against OpenZeppelin, Compound, Uniswap Permit2, and Aave V3 contracts. Typical analysis: 20-50ms per contract, 2-8s for full projects. See [docs/TESTING.md](docs/TESTING.md) for benchmarks.

## Configuration

Create `.soliditydefend.yml`:
```yaml
min_severity: medium
detectors:
  disabled_detectors: [inefficient-storage]  # Disable specific detectors
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for all options.

## Documentation

| Document | Description |
|----------|-------------|
| [Installation](docs/INSTALLATION.md) | Installation methods |
| [Usage](docs/USAGE.md) | Usage guide and examples |
| [CLI Reference](docs/CLI.md) | Command-line options |
| [Detectors](docs/detectors/README.md) | All 71 detectors |
| [Configuration](docs/CONFIGURATION.md) | Configuration reference |
| [Output Formats](docs/OUTPUT.md) | JSON and console output |
| [Docker](docs/DOCKER.md) | Docker usage, CI/CD, and versioning |
| [GitHub Actions](docs/GITHUB_ACTIONS.md) | CI/CD pipeline setup |
| [Testing](docs/TESTING.md) | Testing and benchmarks |
| [Validation](docs/VALIDATION.md) | Ground truth validation framework |
| [Baseline](docs/baseline/README.md) | FP reduction baselines |
| [Changelog](docs/CHANGELOG.md) | Version history |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

Copyright 2024-2026 Advanced Blockchain Security (ABS). See [NOTICE](NOTICE) for attribution requirements.

---

**[BlockSecOps](https://blocksecops.com)** - Smart Contract Security Audits & Tools
