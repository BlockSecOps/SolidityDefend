# SolidityDefend Task Documentation

This directory contains task-specific documentation for SolidityDefend development and operations.

## Contents

| Document | Description |
|----------|-------------|
| [RELEASE.md](RELEASE.md) | Release process and checklist |
| [TESTING-PROTOCOLS.md](TESTING-PROTOCOLS.md) | Real-world testing protocols |
| [FP-REDUCTION.md](FP-REDUCTION.md) | False positive reduction guide and Safe Patterns Library |
| [DETECTOR-DEVELOPMENT.md](DETECTOR-DEVELOPMENT.md) | Adding new detectors |

## Quick Reference

### Current Version
- **Version:** 1.10.13
- **Detectors:** 333
- **Frameworks:** Foundry, Hardhat, Plain
- **Safe Pattern Modules:** 11

### Key Metrics

| Metric | Value |
|--------|-------|
| Unit Tests | 33 passing |
| FP Regression Tests | 12 passing |
| Detectors | 333 |
| Safe Pattern Modules | 11 |
| Analysis Speed | 30-180ms per contract |
| Framework Detection | Foundry, Hardhat, Plain |

### Safe Patterns Library

Modules for context-aware FP reduction in `crates/detectors/src/safe_patterns/`:

| Module | Patterns Detected |
|--------|-------------------|
| `oracle_patterns` | Chainlink, TWAP, multi-oracle, staleness, deviation bounds |
| `flash_loan_patterns` | ERC-3156 compliance, callback validation, state validation |
| `restaking_patterns` | EigenLayer delegation, AVS validation, slashing, withdrawals |
| `vault_patterns` | ERC-4626 inflation protection, dead shares, virtual shares |
| `amm_patterns` | AMM pools, slippage protection, TWAP |
| `reentrancy_patterns` | ReentrancyGuard, CEI pattern |

### Real-World Test Results

| Protocol | Findings | Time |
|----------|----------|------|
| OpenZeppelin v5.0 | 28 | 0.08s |
| Compound Comptroller | 139 | 1.02s |
| Uniswap Permit2 | 54 | 0.05s |
| Aave V3 | 146 | 0.31s |
