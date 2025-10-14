# Test Contracts

**SolidityDefend v1.0.0 Test Suite**
**Last Updated**: October 13, 2025
**Total Contracts**: 32

This directory contains Solidity test contracts with various vulnerabilities for validating the SolidityDefend analyzer.

---

## 📋 Quick Reference

**For detailed vulnerability inventory**, see: [VULNERABILITY_INVENTORY.md](./VULNERABILITY_INVENTORY.md)

This comprehensive document provides:
- Complete vulnerability listings for each contract
- Line numbers and severity levels
- Expected detector IDs
- Attack scenarios and mitigation examples
- Testing methodology and metrics

---

## 📁 Directory Structure

The test contracts have been organized into logical categories:

```
tests/contracts/
├── basic_vulnerabilities/       # Simple, focused vulnerability examples
│   ├── access_control_issues.sol
│   ├── reentrancy_issues.sol
│   └── validation_issues.sol
│
├── clean_examples/              # Secure contracts (false positive testing)
│   └── clean_contract.sol
│
├── complex_scenarios/           # Multi-vulnerability real-world scenarios
│   └── 2025_vulnerabilities/
│       ├── cross_chain/BridgeVault.sol
│       ├── defi/FlashLoanArbitrage.sol
│       ├── governance/DAOGovernance.sol
│       ├── mev/MEVProtectedDEX.sol
│       └── yield_farming/LiquidityMining.sol
│
├── cross_chain/                 # Cross-chain and bridge vulnerabilities
│   └── phase13_legacy/
│       ├── bridge_chain_id/           (6 contracts)
│       ├── bridge_message_verification/ (4 contracts)
│       └── bridge_token_minting/       (4 contracts)
│
├── erc4626_vaults/             # ERC-4626 vault-specific vulnerabilities
│   ├── VulnerableVault_*.sol        (5 vulnerable contracts)
│   └── SecureVault_*.sol            (4 secure mitigation examples)
│
├── README.md                    # This file
└── VULNERABILITY_INVENTORY.md   # Detailed vulnerability documentation
```

---

## 🎯 Contract Categories

### 1. Basic Vulnerabilities (3 contracts)

Simple, focused test cases for core vulnerability types.

| Contract | Vulnerabilities | Primary Focus |
|----------|----------------|---------------|
| `access_control_issues.sol` | 4+ | Missing access control, unprotected initializers |
| `reentrancy_issues.sol` | 2+ | Classic reentrancy, state-after-call |
| `validation_issues.sol` | 5+ | Input validation, zero address, array bounds |

**Usage**:
```bash
./target/release/soliditydefend tests/contracts/basic_vulnerabilities/
```

---

### 2. Clean Examples (1 contract)

Secure contracts for false positive testing.

| Contract | Expected Issues | Purpose |
|----------|----------------|---------|
| `clean_contract.sol` | 0 | Baseline for false positive detection |

**Note**: Any detections on this contract indicate false positives that need investigation.

**Usage**:
```bash
./target/release/soliditydefend tests/contracts/clean_examples/clean_contract.sol
```

---

### 3. Complex Scenarios (5 contracts)

Real-world, multi-vulnerability contracts representing modern 2025 attack patterns.

| Contract | Vulnerabilities | Category | Complexity |
|----------|----------------|----------|------------|
| `FlashLoanArbitrage.sol` | 12+ | DeFi | High |
| `DAOGovernance.sol` | 18+ | Governance | Very High |
| `BridgeVault.sol` | 10+ | Cross-Chain | High |
| `MEVProtectedDEX.sol` | 8+ | MEV | High |
| `LiquidityMining.sol` | 10+ | Yield Farming | High |

**Key Features**:
- Multiple vulnerability types per contract
- Real-world attack scenarios from 2024-2025
- Comprehensive documentation of issues
- Attack scenario descriptions

**Usage**:
```bash
./target/release/soliditydefend tests/contracts/complex_scenarios/2025_vulnerabilities/defi/FlashLoanArbitrage.sol
```

---

### 4. Cross-Chain Vulnerabilities (14 contracts)

Bridge and cross-chain security test cases.

#### Bridge Chain ID Validation (6 contracts)
- `vulnerable_simple.sol` - Basic chain-ID bypass
- `vulnerable_complex.sol` - Complex chain-ID scenarios
- `clean.sol` - Proper chain-ID validation
- `test_camel.sol`, `test_medium.sol`, `test_modifier.sol` - Edge cases

#### Bridge Message Verification (4 contracts)
- `vulnerable_simple.sol` - Missing message verification
- `vulnerable_complex.sol` - Complex verification bypass
- `test_merkle.sol` - Merkle proof issues
- `clean.sol` - Proper message verification

#### Bridge Token Minting (4 contracts)
- `vulnerable_simple.sol` - Unrestricted minting
- `vulnerable_complex.sol` - Complex minting vulnerabilities
- `test_modifier.sol` - Modifier bypass scenarios
- `clean.sol` - Proper minting access control

**Usage**:
```bash
./target/release/soliditydefend tests/contracts/cross_chain/phase13_legacy/bridge_chain_id/
```

---

### 5. ERC-4626 Vaults (9 contracts)

Comprehensive vault security test suite.

#### Vulnerable Vaults (5 contracts)

| Contract | Primary Vulnerability | CWE | Severity |
|----------|----------------------|-----|----------|
| `VulnerableVault_Inflation.sol` | Share inflation attack | 682 | Critical |
| `VulnerableVault_Donation.sol` | Donation attack | 682 | Critical |
| `VulnerableVault_FeeManipulation.sol` | Fee calculation errors | 682 | High |
| `VulnerableVault_HookReentrancy.sol` | Hook callback reentrancy | 841 | Critical |
| `VulnerableVault_WithdrawalDOS.sol` | Withdrawal denial of service | 400 | High |

#### Secure Vaults (4 mitigation examples)

| Contract | Mitigation Strategy | Protected Against |
|----------|--------------------|--------------------|
| `SecureVault_VirtualShares.sol` | Virtual shares offset | Inflation attack |
| `SecureVault_DeadShares.sol` | Dead shares at deployment | First depositor attack |
| `SecureVault_MinimumDeposit.sol` | Enforced minimum deposit | Small deposit manipulation |
| `SecureVault_InternalAccounting.sol` | Internal balance tracking | Donation attack |

**Usage**:
```bash
# Test vulnerable vault
./target/release/soliditydefend tests/contracts/erc4626_vaults/VulnerableVault_Inflation.sol

# Verify secure vault (should have 0 vault-specific issues)
./target/release/soliditydefend tests/contracts/erc4626_vaults/SecureVault_VirtualShares.sol
```

---

## 🔍 Testing Workflow

### 1. Individual Contract Analysis

```bash
./target/release/soliditydefend tests/contracts/<category>/<contract>.sol
```

### 2. Category Testing

```bash
# Test all basic vulnerabilities
./target/release/soliditydefend tests/contracts/basic_vulnerabilities/

# Test all ERC-4626 vaults
./target/release/soliditydefend tests/contracts/erc4626_vaults/

# Test all cross-chain contracts
./target/release/soliditydefend tests/contracts/cross_chain/
```

### 3. Full Suite Testing

```bash
# Test all contracts
./target/release/soliditydefend tests/contracts/

# Generate JSON output for analysis
find tests/contracts -name "*.sol" -type f | while read contract; do
    ./target/release/soliditydefend "$contract" --format json > "results/$(basename $contract .sol).json"
done
```

### 4. Comparison with Inventory

```bash
# 1. Run analysis
./target/release/soliditydefend tests/contracts/basic_vulnerabilities/access_control_issues.sol --format json > actual.json

# 2. Compare with VULNERABILITY_INVENTORY.md expected vulnerabilities
# 3. Calculate metrics: True Positives, False Positives, False Negatives
```

---

## 📊 Vulnerability Statistics

### By Category

| Category | Contracts | Vulnerable | Clean | Complexity |
|----------|-----------|-----------|-------|------------|
| Basic Vulnerabilities | 3 | 3 | 0 | Simple |
| Clean Examples | 1 | 0 | 1 | Simple |
| Complex Scenarios | 5 | 5 | 0 | High |
| Cross-Chain | 14 | 9 | 5 | Medium-High |
| ERC-4626 Vaults | 9 | 5 | 4 | Medium |
| **TOTAL** | **32** | **22** | **10** | **Mixed** |

### By Severity

| Severity | Approximate Count | Percentage |
|----------|------------------|------------|
| Critical | 35+ | 45% |
| High | 25+ | 32% |
| Medium | 15+ | 19% |
| Low | 3+ | 4% |
| **TOTAL** | **78+** | **100%** |

### Top Vulnerability Types

1. **Access Control** (8+ instances) - Missing modifiers, unprotected functions
2. **Reentrancy** (6+ instances) - Classic, read-only, cross-contract
3. **DeFi/Oracle** (15+ instances) - Price manipulation, flash loans, oracle attacks
4. **Governance** (12+ instances) - Flash loan attacks, delegation issues
5. **Cross-Chain** (10+ instances) - Bridge validation, chain-ID, replay attacks
6. **ERC-4626 Vaults** (8+ instances) - Share inflation, donation, hook reentrancy
7. **MEV** (6+ instances) - Frontrunning, sandwich attacks, slippage
8. **Validation** (8+ instances) - Zero address, input validation, bounds checks

---

## 🎓 Key Test Contracts

### Best for Learning

1. **access_control_issues.sol** - Start here for access control vulnerabilities
2. **reentrancy_issues.sol** - Classic reentrancy examples
3. **VulnerableVault_Inflation.sol** - Modern ERC-4626 attack (Cetus DEX reference)
4. **FlashLoanArbitrage.sol** - Real-world DeFi vulnerabilities
5. **DAOGovernance.sol** - Comprehensive governance attack vectors

### Best for Benchmarking

1. **clean_contract.sol** - False positive baseline
2. **FlashLoanArbitrage.sol** - Complex multi-vulnerability detection
3. **DAOGovernance.sol** - High vulnerability count (18+)
4. **Cross-chain suite** - Bridge-specific detectors

### Best for Specific Detectors

| Detector Category | Test Contract |
|-------------------|---------------|
| Access Control | `access_control_issues.sol` |
| Reentrancy | `reentrancy_issues.sol` |
| Flash Loans | `FlashLoanArbitrage.sol` |
| Governance | `DAOGovernance.sol` |
| Cross-Chain | `cross_chain/phase13_legacy/bridge_*` |
| ERC-4626 Vaults | `erc4626_vaults/VulnerableVault_*` |
| MEV | `complex_scenarios/2025_vulnerabilities/mev/MEVProtectedDEX.sol` |

---

## 📖 Documentation

### Main Documentation

- **[VULNERABILITY_INVENTORY.md](./VULNERABILITY_INVENTORY.md)** - Complete vulnerability listings
  - Line-by-line vulnerability documentation
  - Expected detector IDs
  - Attack scenarios
  - Severity classifications
  - Testing commands

- **[../../docs/DETECTORS.md](../../docs/DETECTORS.md)** - Complete detector reference
  - All 100 detectors documented
  - Detection patterns
  - CWE mappings
  - Example code

### Additional Resources

- **Attack Scenarios**: See VULNERABILITY_INVENTORY.md for detailed attack descriptions
- **Mitigation Examples**: Check secure vault contracts for best practices
- **Testing Methodology**: VULNERABILITY_INVENTORY.md includes comprehensive testing guide

---

## 🔧 Maintenance

### Adding New Test Contracts

1. **Choose appropriate category** (or create new one)
2. **Document vulnerabilities** in VULNERABILITY_INVENTORY.md:
   - File location and contract name
   - Complexity level
   - Detailed vulnerability table with line numbers
   - Expected detection count
   - Test command
3. **Update this README** with contract summary
4. **Update statistics** (vulnerability counts, severity distribution)
5. **Test detection**: Verify documented vulnerabilities are detected

### Updating Existing Contracts

1. **Update line numbers** in VULNERABILITY_INVENTORY.md if code changes
2. **Re-test detection** to verify expected counts
3. **Update documentation** if vulnerability patterns change
4. **Version control**: Document changes in git commit

---

## ⚠️ Important Notes

- **Intentional Vulnerabilities**: All vulnerable contracts contain intentional security issues for testing. DO NOT use in production.
- **Line Numbers**: May shift if contracts are modified. Always verify against current code.
- **Detection Counts**: Expected counts are minimums. Detectors may find additional related issues.
- **False Positives**: Clean contracts may still trigger some detections. Document these for detector improvement.
- **Severity Context**: Actual severity depends on contract context and usage.

---

## 🚀 Quick Start

```bash
# 1. Build SolidityDefend
cargo build --release --bin soliditydefend

# 2. Test basic vulnerabilities
./target/release/soliditydefend tests/contracts/basic_vulnerabilities/access_control_issues.sol

# 3. Test clean contract (false positive check)
./target/release/soliditydefend tests/contracts/clean_examples/clean_contract.sol

# 4. Test complex scenario
./target/release/soliditydefend tests/contracts/complex_scenarios/2025_vulnerabilities/defi/FlashLoanArbitrage.sol

# 5. Test full suite
./target/release/soliditydefend tests/contracts/

# 6. Compare with inventory
# Check VULNERABILITY_INVENTORY.md for expected results
```

---

**Maintained by**: SolidityDefend Development Team
**Version**: 1.0.0
**Last Verified**: October 13, 2025
