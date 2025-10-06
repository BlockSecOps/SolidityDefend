# Test Contracts

This directory contains Solidity test contracts with various vulnerabilities for validating the SolidityDefend analyzer.

## Test Contract Inventory

### Basic Test Contracts

| Contract | Issues | Description |
|----------|--------|-------------|
| `access_control_issues.sol` | 7 | Missing access modifiers, unprotected initializers, unchecked external calls |
| `clean_contract.sol` | 3 | Minimal issues - baseline for false positive testing |
| `reentrancy_issues.sol` | 5 | Classic reentrancy vulnerabilities, state machine issues |
| `validation_issues.sol` | 3 | Input validation, zero address checks, parameter consistency |

### 2025 Advanced Vulnerabilities

Modern attack vectors found in DeFi, DAO, and cross-chain protocols.

| Contract | Issues | Category | Description |
|----------|--------|----------|-------------|
| `2025_vulnerabilities/governance/DAOGovernance.sol` | 9 | Governance | Flash loan governance attacks, delegation vulnerabilities, external calls in loops |
| `2025_vulnerabilities/defi/FlashLoanArbitrage.sol` | 15 | DeFi | Flash loan vulnerabilities, MEV exploitation, price oracle manipulation |
| `2025_vulnerabilities/mev/MEVProtectedDEX.sol` | 15 | MEV | Front-running, sandwich attacks, slippage manipulation |
| `2025_vulnerabilities/cross_chain/BridgeVault.sol` | 17 | Cross-Chain | Bridge vulnerabilities, replay attacks, validation issues |
| `2025_vulnerabilities/yield_farming/LiquidityMining.sol` | 26 | Yield Farming | Reward manipulation, flash loan attacks, oracle exploits |

## Vulnerability Categories Tested

### Access Control (7 issues in access_control_issues.sol)
- Missing access control modifiers on critical functions
- Unprotected initializer functions
- State modification without authorization
- External call validation failures

**Key Detections:**
- `missing-access-modifiers` - Functions performing critical operations without proper access control
- `unprotected-initializer` - Initialize functions callable by anyone
- `unchecked-external-call` - External calls without return value checks

### Reentrancy (5 issues in reentrancy_issues.sol)
- Classic reentrancy attack vectors
- State updates after external calls
- Missing reentrancy guards

**Key Detections:**
- `classic-reentrancy` - State changes after external calls
- `invalid-state-transition` - State machine vulnerabilities

### Input Validation (3 issues in validation_issues.sol)
- Missing zero address checks
- Parameter consistency issues
- Array bounds validation

**Key Detections:**
- `missing-zero-address-check` - Missing validation for zero addresses
- `parameter-consistency` - Inconsistent parameter validation

### Governance Attacks (9 issues in DAOGovernance.sol)
Modern DAO governance vulnerabilities including:
- **Flash loan governance attacks** (propose, delegate functions)
- **Missing snapshot protection** - Using current balances instead of historical snapshots
- **External calls in loops** - DoS vulnerability in proposal execution
- **Missing access modifiers** - Critical governance functions without proper protection

**Key Detections:**
- `test-governance` - Flash loan attacks on voting power
- `external-calls-loop` - External calls within loops
- `missing-access-modifiers` - Emergency functions without access control

### DeFi Vulnerabilities (15 issues in FlashLoanArbitrage.sol)
Flash loan and arbitrage attack vectors:
- Flash loan price manipulation
- Oracle dependency vulnerabilities
- MEV extraction opportunities
- Missing slippage protection

**Key Detections:**
- `flashloan-vulnerable-patterns` - Functions vulnerable to flash loan attacks
- `single-oracle-source` - Reliance on single price oracle
- `front-running` - Time-sensitive operations

### MEV Vulnerabilities (15 issues in MEVProtectedDEX.sol)
Maximal Extractable Value exploitation:
- Front-running vulnerabilities
- Sandwich attack vectors
- Transaction ordering dependencies
- Block timestamp manipulation

**Key Detections:**
- `front-running` - Functions vulnerable to front-running
- `sandwich-attack` - Price-dependent operations without protection
- `block-dependency` - Block number/timestamp dependencies

### Cross-Chain Vulnerabilities (17 issues in BridgeVault.sol)
Bridge and cross-chain security issues:
- Replay attack vulnerabilities
- Message authentication failures
- Cross-chain state inconsistencies
- Bridge validation issues

**Key Detections:**
- Multiple access control issues
- External call validation failures
- Missing zero address checks

### Yield Farming Vulnerabilities (26 issues in LiquidityMining.sol)
Most complex test contract with extensive vulnerabilities:
- Reward calculation manipulation
- Flash loan attacks on staking
- Oracle price manipulation
- Division precision issues
- Timestamp dependencies

**Key Detections:**
- `division-before-multiplication` - Precision loss vulnerabilities
- `block-dependency` - Timestamp manipulation risks
- `flashloan-vulnerable-patterns` - Flash loan attack vectors
- `unchecked-external-call` - Missing return value validation

## Usage

Run analysis on individual contracts:

```bash
# Basic contracts
soliditydefend tests/contracts/access_control_issues.sol
soliditydefend tests/contracts/reentrancy_issues.sol
soliditydefend tests/contracts/validation_issues.sol

# 2025 advanced vulnerabilities
soliditydefend tests/contracts/2025_vulnerabilities/governance/DAOGovernance.sol
soliditydefend tests/contracts/2025_vulnerabilities/defi/FlashLoanArbitrage.sol
soliditydefend tests/contracts/2025_vulnerabilities/mev/MEVProtectedDEX.sol
soliditydefend tests/contracts/2025_vulnerabilities/cross_chain/BridgeVault.sol
soliditydefend tests/contracts/2025_vulnerabilities/yield_farming/LiquidityMining.sol
```

Run analysis on entire directory:

```bash
soliditydefend tests/contracts/
```

## Expected Results Summary

| Severity | Total Issues |
|----------|-------------|
| Critical | 40+ |
| High | 30+ |
| Medium | 20+ |
| Low | 5+ |

Total across all test contracts: **95+ vulnerabilities**

## Notes

- **clean_contract.sol** (3 issues) is expected to have minimal findings - used for false positive testing
- Contracts in `2025_vulnerabilities/` directory represent modern attack vectors discovered in 2024-2025
- Some contracts intentionally contain multiple instances of the same vulnerability type for comprehensive testing
- Interface functions may trigger false positives (e.g., IERC20 functions without bodies)

## Maintaining Test Contracts

When adding new test contracts:
1. Document expected vulnerability count in this README
2. List key vulnerability types being tested
3. Add contract to appropriate category section
4. Update total vulnerability count
5. Verify detection with: `soliditydefend <contract-path>`

## References

For detailed information about each vulnerability type, see:
- [DETECTORS.md](../../docs/DETECTORS.md) - Complete detector documentation
- [test_cases.md](2025_vulnerabilities/test_cases.md) - Detailed vulnerability descriptions
