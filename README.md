# SolidityDefend

[![Version](https://img.shields.io/badge/version-1.10.15-brightgreen.svg)](https://github.com/BlockSecOps/SolidityDefend/releases)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)

> Enterprise-grade static analysis for Solidity smart contracts

**Developed by [BlockSecOps](https://blocksecops.com)** - Smart Contract Security Experts

## Quick Start

```bash
brew tap BlockSecOps/tap && brew install soliditydefend
soliditydefend contract.sol
```

## Features

- **333 Security Detectors** - Reentrancy, access control, oracle manipulation, flash loans, MEV, and more
- **Context-Aware Analysis** - Safe Patterns Library with 36+ FP reduction categories: ReentrancyGuard, SafeERC20, OpenZeppelin/Aave/Compound/Uniswap protocols, ERC-4626 vaults, Chainlink oracles, proxy patterns (UUPS, Diamond, EIP-1967), inline access control, timelocks, multi-sig, Permit2, transient storage locks, immutable address calls, and more
- **Modern EIP Coverage** - EIP-7702, EIP-1153, ERC-7683, ERC-7821, ERC-4337
- **Project-Aware Scanning** - True project understanding with dependency graph, cross-contract analysis, and smart file ordering
- **Dependency Scanning** - Audit OpenZeppelin and other imported libraries with `--include-deps`
- **Cross-Contract Analysis** - Detect vulnerabilities spanning multiple contracts with `--cross-contract`
- **Lightning Fast** - 30-180ms analysis time, built in Rust
- **CI/CD Ready** - JSON/SARIF output, exit codes, severity filtering
- **100% Recall** - Validated against ground truth test suite

See [docs/DETECTORS.md](docs/DETECTORS.md) for the complete detector list.

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
=== SolidityDefend Project Analysis ===
Framework: Foundry (auto-detected)
Project Root: /path/to/my-project

Source Directories:
  [SCAN] src - 5 files
  [SKIP] test - excluded by default
  [SKIP] script - excluded by default
  [DEPS] lib - use --include-deps to scan

Found 12 issues in 5 files:

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

=== Project Security Summary ===
Contracts Analyzed: 5 (5 source, 0 dependencies)

Findings Overview:
  Critical: 1 (IMMEDIATE ACTION REQUIRED)
  High:     3 (should be addressed)
  Medium:   5
  Low:      3

Protocol Risk Score: 6.5/10 (Medium Risk)

Analysis completed in 0.45s
```

## Real-World Testing

Tested against production contracts from leading protocols:

| Test Case | Source | Framework | Files | Findings | Time |
|-----------|--------|-----------|-------|----------|------|
| Proxy Contracts | OpenZeppelin v5.0 | Plain | 6 | 28 (4 Crit, 17 High) | 0.08s |
| Upgradeable Contracts | OZ + Compound | Plain | 5 | 139 (21 Crit, 31 High) | 1.02s |
| Foundry Project | Uniswap Permit2 | Foundry | 4 | 54 (2 Crit, 30 High) | 0.05s |
| Hardhat Project | Aave V3 Core | Hardhat | 5 | 146 (23 Crit, 44 High) | 0.31s |

**Contracts Tested:**
- OpenZeppelin: Proxy.sol, ERC1967Proxy, TransparentUpgradeableProxy, BeaconProxy
- Compound: Comptroller (62KB), ComptrollerStorage
- Uniswap: Permit2, SignatureTransfer, AllowanceTransfer
- Aave: Pool.sol, PoolStorage, SupplyLogic, BorrowLogic

## Performance

Real-world benchmarks on production contracts:

| Task | Time | Details |
|------|------|---------|
| Single contract | 20-50ms | Typical ERC-20/721 contract |
| Complex contract | 100-180ms | Diamond proxy, vault systems |
| Full project | 2-8s | 50-100 contracts (Foundry/Hardhat) |
| CI/CD pipeline | <10s | Average DeFi project |

Built in Rust for maximum performance. Zero runtime dependencies.

## Configuration

Create `.soliditydefend.yml`:
```yaml
min_severity: medium
detectors:
  disable: [inefficient-storage]
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for all options.

## Documentation

| Document | Description |
|----------|-------------|
| [Installation](docs/INSTALLATION.md) | Installation methods |
| [Usage](docs/USAGE.md) | Usage guide and examples |
| [CLI Reference](docs/CLI.md) | Command-line options |
| [Detectors](docs/DETECTORS.md) | All 333 detectors |
| [Configuration](docs/CONFIGURATION.md) | Configuration reference |
| [Testing](docs/TESTING.md) | Real-world testing and validation |
| [Docker](docs/DOCKER.md) | Docker usage and CI/CD |
| [Validation](docs/VALIDATION.md) | Validation test results |

### Task Documentation

Developer documentation in [TaskDocs-SolidityDefend/](TaskDocs-SolidityDefend/):
- [Release Process](TaskDocs-SolidityDefend/RELEASE.md)
- [Testing Protocols](TaskDocs-SolidityDefend/TESTING-PROTOCOLS.md)
- [FP Reduction Guide](TaskDocs-SolidityDefend/FP-REDUCTION.md)
- [Detector Development](TaskDocs-SolidityDefend/DETECTOR-DEVELOPMENT.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

Copyright 2024-2026 Advanced Blockchain Security (ABS). See [NOTICE](NOTICE) for attribution requirements.

---

**[BlockSecOps](https://blocksecops.com)** - Smart Contract Security Audits & Tools
