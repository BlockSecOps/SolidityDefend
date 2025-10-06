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

## Phase 8-11 Test Contracts (External)

Comprehensive test contracts for Phases 8-11 detectors are located in `/tmp/`:

### Phase 8: Advanced Logic & Architecture (6 contracts)

| Contract | Issues | Category | Description |
|----------|--------|----------|-------------|
| `/tmp/upgradeable_proxy_vulnerable_1.sol` | 4 | Proxy Issues | Unprotected upgrade, no init guard, unsafe delegatecall |
| `/tmp/upgradeable_proxy_vulnerable_2.sol` | 6 | Proxy Issues | No timelock, transparent proxy issues, no storage gap |
| `/tmp/token_supply_vulnerable_1.sol` | 7 | Token Supply | Mint without cap/access control/rate limit |
| `/tmp/token_supply_vulnerable_2.sol` | 6 | Token Supply | Missing totalSupply updates, rebasing, flash mint |
| `/tmp/circular_dependency_vulnerable_1.sol` | 6 | Circular Deps | Callback loops, no depth limits |
| `/tmp/circular_dependency_vulnerable_2.sol` | 7 | Circular Deps | Cross-contract dependencies, event cycles |

**Total Phase 8 Findings**: 36 vulnerabilities detected

### Phase 9: Gas & Optimization Issues (10 contracts)

| Contract | Issues | Category | Description |
|----------|--------|----------|-------------|
| `/tmp/gas_griefing_vulnerable_1.sol` | 3 | Gas | External calls in loops ✅ |
| `/tmp/gas_griefing_vulnerable_2.sol` | 1 | Gas | Gas griefing vectors ✅ |
| `/tmp/dos_unbounded_operation_vulnerable_1.sol` | 2 | DoS | Unbounded array iterations ✅ |
| `/tmp/dos_unbounded_operation_vulnerable_2.sol` | 2 | DoS | Unbounded operations ✅ |
| `/tmp/excessive_gas_usage_vulnerable_1.sol` | 0 | Gas | Inefficient loops ⚠️ Stub |
| `/tmp/excessive_gas_usage_vulnerable_2.sol` | 0 | Gas | Gas optimization issues ⚠️ Stub |
| `/tmp/inefficient_storage_vulnerable_1.sol` | 0 | Storage | Poor storage packing ⚠️ Stub |
| `/tmp/inefficient_storage_vulnerable_2.sol` | 0 | Storage | Storage inefficiencies ⚠️ Stub |
| `/tmp/redundant_checks_vulnerable_1.sol` | 0 | Validation | Duplicate requires ⚠️ Stub |
| `/tmp/redundant_checks_vulnerable_2.sol` | 0 | Validation | Redundant validation ⚠️ Stub |

**Total Phase 9 Findings**: 8 vulnerabilities detected (only functional detectors)

### Phase 10: Advanced Security (8 contracts)

| Contract | Issues | Category | Description |
|----------|--------|----------|-------------|
| `/tmp/front_running_mitigation_vulnerable_1.sol` | 0 | MEV | No MEV protection ⚠️ Stub |
| `/tmp/front_running_mitigation_vulnerable_2.sol` | 0 | MEV | Missing commit-reveal ⚠️ Stub |
| `/tmp/price_oracle_stale_vulnerable_1.sol` | 0 | Oracle | No staleness checks ⚠️ Stub |
| `/tmp/price_oracle_stale_vulnerable_2.sol` | 0 | Oracle | Missing heartbeat ⚠️ Stub |
| `/tmp/centralization_risk_vulnerable_1.sol` | 0 | Access Control | Single owner control ⚠️ Stub |
| `/tmp/centralization_risk_vulnerable_2.sol` | 0 | Access Control | No multisig ⚠️ Stub |
| `/tmp/insufficient_randomness_vulnerable_1.sol` | 0 | Randomness | block.timestamp RNG ⚠️ Stub |
| `/tmp/insufficient_randomness_vulnerable_2.sol` | 0 | Randomness | blockhash randomness ⚠️ Stub |

**Total Phase 10 Findings**: 0 (all stub implementations)

### Phase 11: Code Quality & Best Practices (10 contracts)

| Contract | Issues | Category | Description |
|----------|--------|----------|-------------|
| `/tmp/shadowing_variables_vulnerable_1.sol` | 0 | Code Quality | Variable shadowing ⚠️ Stub |
| `/tmp/shadowing_variables_vulnerable_2.sol` | 0 | Code Quality | State/parameter conflicts ⚠️ Stub |
| `/tmp/unchecked_math_vulnerable_1.sol` | 0 | Arithmetic | Unchecked operations ⚠️ Stub |
| `/tmp/unchecked_math_vulnerable_2.sol` | 0 | Arithmetic | Overflow potential ⚠️ Stub |
| `/tmp/missing_input_validation_vulnerable_1.sol` | 0 | Validation | No zero checks ⚠️ Stub |
| `/tmp/missing_input_validation_vulnerable_2.sol` | 0 | Validation | Missing bounds checks ⚠️ Stub |
| `/tmp/deprecated_functions_vulnerable_1.sol` | 0 | Code Quality | .send(), selfdestruct ⚠️ Stub |
| `/tmp/deprecated_functions_vulnerable_2.sol` | 0 | Code Quality | throw, block.difficulty ⚠️ Stub |
| `/tmp/unsafe_type_casting_vulnerable_1.sol` | 0 | Type Safety | Unsafe downcasts ⚠️ Stub |
| `/tmp/unsafe_type_casting_vulnerable_2.sol` | 0 | Type Safety | int to uint conversion ⚠️ Stub |

**Total Phase 11 Findings**: 0 (all stub implementations)

## Expected Results Summary

| Severity | Total Issues |
|----------|-------------|
| Critical | 40+ |
| High | 50+ |
| Medium | 30+ |
| Low | 5+ |

Total across all test contracts: **125+ vulnerabilities** (95+ in repository, 52+ in Phase 8-11 tests)

## Notes

- **clean_contract.sol** (3 issues) is expected to have minimal findings - used for false positive testing
- Contracts in `2025_vulnerabilities/` directory represent modern attack vectors discovered in 2024-2025
- Some contracts intentionally contain multiple instances of the same vulnerability type for comprehensive testing
- Interface functions may trigger false positives (e.g., IERC20 functions without bodies)

## Test Scripts

Shell scripts for batch testing Phase 8-11 detectors are available in `/tmp/`:
- `/tmp/test_all.sh` - Phase 8 detector tests
- `/tmp/test_phase9.sh` - Phase 9 detector tests
- `/tmp/test_phase10.sh` - Phase 10 detector tests
- `/tmp/test_phase11.sh` - Phase 11 detector tests

Run all tests:
```bash
chmod +x /tmp/test_*.sh
for script in /tmp/test_*.sh; do $script; done
```

Comprehensive test report: `/tmp/comprehensive_test_report.md`

## Maintaining Test Contracts

When adding new test contracts:
1. Document expected vulnerability count in this README
2. List key vulnerability types being tested
3. Add contract to appropriate category section
4. Update total vulnerability count
5. Verify detection with: `soliditydefend <contract-path>`
6. For Phase 8-11 detectors, place test contracts in `/tmp/` and create corresponding test scripts

## References

For detailed information about each vulnerability type, see:
- [DETECTORS.md](../../docs/DETECTORS.md) - Complete detector documentation
- [test_cases.md](2025_vulnerabilities/test_cases.md) - Detailed vulnerability descriptions
