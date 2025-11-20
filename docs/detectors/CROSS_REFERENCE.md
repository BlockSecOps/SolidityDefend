# SolidityDefend Detector Cross-Reference Tables

**Generated:** 2025-11-19
**Version:** v1.3.7

---

## Table of Contents

1. [Detectors by Severity](#detectors-by-severity)
2. [Detectors by Category](#detectors-by-category)
3. [Detectors by EIP/ERC](#detectors-by-eiperc)
4. [CWE Mappings](#cwe-mappings)
5. [Modern Vulnerability Coverage](#modern-vulnerability-coverage)

---

## Detectors by Severity

### Critical Severity

**Total:** ~120 detectors

Key Critical Detectors:
- All EIP-7702 detectors (6)
- All ERC-4337 Account Abstraction detectors (21)
- All Flash Loan detectors (7)
- All Reentrancy detectors (9)
- ERC-7683 Intent-Based detectors (5)
- Zero-Knowledge proof detectors (5)
- Oracle manipulation detectors (9)
- MEV exploitation detectors (13)

### High Severity

**Total:** ~50 detectors

Includes:
- Access control bypass
- Upgrade security issues
- Token standard violations
- Cross-chain replay attacks

### Medium Severity

**Total:** ~25 detectors

Includes:
- Input validation issues
- Array bounds checking
- Type casting issues

### Low/Info Severity

**Total:** ~10 detectors

Includes:
- Code quality checks
- Gas optimization suggestions
- Deprecated function usage

---

## Detectors by Category

### Access Control (6 detectors)

| ID | Name | Severity |
|----|------|----------|
| `access-control-missing-modifiers` | Missing Access Control Modifiers | High |
| `access-control-unprotected-init` | Unprotected Initializer | Critical |
| `access-control-default-visibility` | Default Visibility | High |
| `role-hierarchy-bypass` | Role Hierarchy Bypass | Critical |
| `time-locked-admin-bypass` | Time-Locked Admin Bypass | Critical |
| `privilege-escalation-paths` | Privilege Escalation Paths | Critical |

### Account Abstraction (21 detectors)

| Category | Count |
|----------|-------|
| ERC-4337 Core | 8 |
| Session Keys | 2 |
| Social Recovery | 2 |
| Bundler DoS | 3 |
| Paymaster Abuse | 3 |
| Account Takeover | 3 |

**Key Detectors:**
- `aa-signature-aggregation` - Signature Aggregation Vulnerabilities
- `aa-session-key-vulnerabilities` - Session Key Exploits
- `aa-social-recovery` - Social Recovery Attack Vectors
- `aa-bundler-dos` - Bundler Denial of Service
- `erc4337-paymaster-abuse` - Paymaster Fund Drainage
- `aa-account-takeover` - Account Takeover Vulnerabilities
- `erc4337-gas-griefing` - Gas Griefing Attacks
- `aa-nonce-management` - Nonce Bypass Exploits

### DeFi (15 detectors)

| ID | Name | Severity |
|----|------|----------|
| `vault-share-inflation` | Vault Share Inflation | Critical |
| `vault-donation-attack` | Vault Donation Attack | Critical |
| `vault-withdrawal-dos` | Vault Withdrawal DoS | High |
| `vault-fee-manipulation` | Vault Fee Manipulation | Critical |
| `vault-hook-reentrancy` | Vault Hook Reentrancy | Critical |
| `amm-k-invariant-violation` | AMM K Invariant Violation | Critical |
| `amm-liquidity-manipulation` | Liquidity Pool Manipulation | Critical |
| `lending-liquidation-abuse` | Lending Liquidation Abuse | Critical |
| `lending-borrow-bypass` | Lending Borrow Bypass | Critical |
| `defi-jit-liquidity-attacks` | JIT Liquidity Attacks | Critical |
| `defi-yield-farming-exploits` | Yield Farming Exploits | Critical |
| `liquidity-bootstrapping-abuse` | Liquidity Bootstrapping Abuse | High |
| `price-impact-manipulation` | Price Impact Manipulation | Critical |
| `uniswapv4-hook-issues` | UniswapV4 Hook Issues | Critical |
| `defi-liquidity-pool-manipulation` | Liquidity Pool Manipulation | Critical |

### EIPs (Modern Standards - 19 detectors)

#### EIP-1153: Transient Storage (5 detectors)
- `transient-storage-reentrancy` - Low-gas reentrancy via TSTORE/TLOAD
- `transient-storage-composability` - Cross-contract composability issues
- `transient-storage-state-leak` - State leakage between transactions
- `transient-storage-misuse` - Incorrect usage patterns
- `transient-reentrancy-guard` - Guard bypass vulnerabilities

#### EIP-7702: Account Delegation (6 detectors)
- `eip7702-delegate-access-control` - Missing authorization checks
- `eip7702-sweeper-detection` - Malicious sweeper contracts (97% of 2025 delegations)
- `eip7702-batch-phishing` - Batch transaction phishing
- `eip7702-txorigin-bypass` - tx.origin authentication bypass
- `eip7702-storage-collision` - Storage collision attacks
- `eip7702-init-frontrun` - Initialization front-running ($1.54M exploit)

#### ERC-7821: Batch Executor (4 detectors)
- `erc7821-batch-authorization` - Batch authorization bypass
- `erc7821-token-approval` - Token approval manipulation
- `erc7821-replay-protection` - Replay attack vulnerabilities
- `erc7821-msg-sender-validation` - msg.sender validation issues

#### ERC-7683: Intent-Based (5 detectors)
- `erc7683-signature-replay` - Cross-chain signature replay
- `erc7683-filler-frontrunning` - Filler front-running attacks
- `erc7683-unsafe-permit2` - Unsafe Permit2 integration
- `erc7683-settlement-validation` - Settlement validation bypass
- `erc7683-cross-chain-replay` - Cross-chain replay attacks

### Flash Loans (7 detectors)

| ID | Name | Severity |
|----|------|----------|
| `flashloan-price-oracle-manipulation` | Price Oracle Manipulation | Critical |
| `flashloan-governance-attack` | Governance Attack via Flash Loan | Critical |
| `flashloan-callback-reentrancy` | Flash Loan Callback Reentrancy | Critical |
| `flashmint-token-inflation` | Flash Mint Token Inflation | Critical |
| `flash-loan-staking` | Flash Loan Staking Exploit | Critical |
| `flash-loan-price-manipulation-advanced` | Advanced Price Manipulation | Critical |
| `flash-loan-collateral-swap` | Collateral Swap Attack | Critical |

### MEV (13 detectors)

| ID | Name | Severity |
|----|------|----------|
| `sandwich-attack` | Sandwich Attack Vulnerability | Critical |
| `mev-frontrunning` | Front-Running Vulnerability | Critical |
| `mev-backrunning` | Back-Running Opportunities | High |
| `deadline-manipulation` | Deadline Manipulation | High |
| `timestamp-manipulation` | Timestamp Manipulation | High |
| `block-stuffing-vulnerable` | Block Stuffing Vulnerability | High |
| `mev-extractable-value` | MEV Extractable Value | Medium |
| `auction-timing-manipulation` | Auction Timing Manipulation | High |
| `create2-frontrunning` | CREATE2 Front-Running | Critical |
| `validator-front-running` | Validator Front-Running | Critical |
| `token-permit-front-running` | Token Permit Front-Running | High |
| `sandwich-resistant-swap` | Insufficient Sandwich Resistance | Medium |
| `jit-liquidity-sandwich` | JIT Liquidity Sandwich | Critical |

### Oracle (9 detectors)

| ID | Name | Severity |
|----|------|----------|
| `single-oracle-source` | Single Oracle Source | Critical |
| `oracle-price-validation` | Insufficient Price Validation | Critical |
| `oracle-manipulation` | Oracle Manipulation | Critical |
| `price-oracle-stale` | Stale Price Data | High |
| `erc7683-oracle-dependency` | ERC-7683 Oracle Dependency | Critical |
| `restaking-lrt-oracle-manipulation` | LRT Oracle Manipulation | Critical |
| `autonomous-contract-oracle-dependency` | AI Oracle Dependency | High |
| `flashloan-price-oracle-manipulation` | Flash Loan Price Manipulation | Critical |
| `price-impact-manipulation` | Price Impact Manipulation | Critical |

### Reentrancy (9 detectors)

| ID | Name | Severity |
|----|------|----------|
| `classic-reentrancy` | Classic Reentrancy | Critical |
| `read-only-reentrancy` | Read-Only Reentrancy | Critical |
| `transient-storage-reentrancy` | Transient Storage Reentrancy (EIP-1153) | Critical |
| `flashloan-callback-reentrancy` | Flash Loan Callback Reentrancy | Critical |
| `erc777-reentrancy-hooks` | ERC-777 Reentrancy via Hooks | Critical |
| `erc721-callback-reentrancy` | ERC-721 Callback Reentrancy | Critical |
| `diamond-init-reentrancy` | Diamond Init Reentrancy | Critical |
| `vault-hook-reentrancy` | Vault Hook Reentrancy | Critical |
| `hook-reentrancy-enhanced` | Enhanced Hook Reentrancy | Critical |

### Restaking & LRT (5 detectors)

| ID | Name | Severity |
|----|------|----------|
| `restaking-eigenpool-withdrawal-manipulation` | EigenLayer Withdrawal Manipulation | Critical |
| `restaking-lrt-share-inflation` | LRT Share Inflation Attack | Critical |
| `restaking-lrt-oracle-manipulation` | LRT Oracle Manipulation | Critical |
| `restaking-slashing-front-running` | Slashing Front-Running | High |
| `restaking-validator-collusion` | Validator Collusion | High |

### Zero-Knowledge (5 detectors)

| ID | Name | Severity |
|----|------|----------|
| `zk-trusted-setup-bypass` | Trusted Setup Bypass | Critical |
| `zk-proof-malleability` | Proof Malleability | Critical |
| `zk-circuit-under-constrained` | Under-Constrained Circuit | Critical |
| `zk-recursive-proof-validation` | Recursive Proof Validation | High |
| `zk-proof-bypass` | ZK Proof Bypass | Critical |

---

## Detectors by EIP/ERC

### EIP-1153: Transient Storage (Cancun, 2024)

| Detector ID | Vulnerability |
|-------------|--------------|
| `transient-storage-reentrancy` | Low-gas reentrancy (breaks transfer/send safety) |
| `transient-storage-composability` | Cross-contract state inconsistency |
| `transient-storage-state-leak` | Transaction-to-transaction state leaks |
| `transient-storage-misuse` | Incorrect TSTORE/TLOAD usage |
| `transient-reentrancy-guard` | Reentrancy guard bypass |

**Real-World Impact:** ChainSecurity research (2024) showed EIP-1153 breaks decade-old security assumptions about 2300 gas stipend.

### EIP-7702: Account Delegation (2025)

| Detector ID | Vulnerability | Impact |
|-------------|--------------|---------|
| `eip7702-delegate-access-control` | Missing authorization | $12M+ phishing attacks |
| `eip7702-sweeper-detection` | Malicious sweeper contracts | 97% of 2025 delegations |
| `eip7702-init-frontrun` | Initialization front-running | $1.54M single attack (Aug 2025) |
| `eip7702-batch-phishing` | Batch transaction phishing | Widespread exploitation |
| `eip7702-txorigin-bypass` | tx.origin bypass | Authentication failure |
| `eip7702-storage-collision` | Storage collision | State corruption |

**Real-World Impact:** Most critical EIP of 2025, responsible for $12M+ in losses.

### ERC-4337: Account Abstraction (2023-2024)

| Detector ID | Vulnerability | Real-World Case |
|-------------|--------------|-----------------|
| `aa-signature-aggregation` | Signature manipulation | Multiple incidents |
| `aa-session-key-vulnerabilities` | Session key bypass | Production exploits |
| `erc4337-paymaster-abuse` | Paymaster fund drainage | Biconomy nonce bypass (2024) |
| `aa-bundler-dos` | Bundler DoS | Network disruption |
| `aa-account-takeover` | Account takeover | Multiple wallets affected |
| `erc4337-gas-griefing` | Gas griefing | ~0.05 ETH per exploit |
| `aa-nonce-management` | Nonce bypass | Biconomy exploit |

**Real-World Impact:** Biconomy nonce bypass (2024), Alchemy audit findings (2025).

### ERC-7821: Batch Executor (2024)

| Detector ID | Vulnerability |
|-------------|--------------|
| `erc7821-batch-authorization` | Batch authorization bypass |
| `erc7821-token-approval` | Token approval manipulation in batch |
| `erc7821-replay-protection` | Missing replay protection |
| `erc7821-msg-sender-validation` | msg.sender confusion in batch |

### ERC-7683: Intent-Based (2024-2025)

| Detector ID | Vulnerability |
|-------------|--------------|
| `erc7683-signature-replay` | Cross-chain signature replay |
| `erc7683-filler-frontrunning` | Filler front-running |
| `erc7683-unsafe-permit2` | Unsafe Permit2 integration |
| `erc7683-settlement-validation` | Settlement validation bypass |
| `erc7683-oracle-dependency` | Oracle manipulation in intent settlement |

### ERC-20 Token Standard

| Detector ID | Vulnerability |
|-------------|--------------|
| `erc20-approve-race` | Approve race condition |
| `erc20-infinite-approval` | Infinite approval vulnerability |
| `erc20-transfer-return-bomb` | Transfer return bomb |

### ERC-721 NFT Standard

| Detector ID | Vulnerability |
|-------------|--------------|
| `erc721-callback-reentrancy` | Callback reentrancy |
| `erc721-enumeration-dos` | Enumeration DoS |

### ERC-777 Advanced Token

| Detector ID | Vulnerability |
|-------------|--------------|
| `erc777-reentrancy-hooks` | Reentrancy via hooks |

---

## CWE Mappings

### CWE-284: Improper Access Control

**Detectors:** 25+

Key detectors:
- All access control detectors (6)
- `eip7702-delegate-access-control`
- `aa-account-takeover`
- `erc4337-entrypoint-trust`

### CWE-345: Insufficient Verification of Data Authenticity

**Detectors:** 15+

Key detectors:
- `weak-signature-validation`
- `signature-malleability`
- `aa-signature-aggregation`
- `erc7683-signature-replay`

### CWE-20: Improper Input Validation

**Detectors:** 10

All input-validation category detectors plus:
- `array-length-mismatch`
- `missing-input-validation`
- `zero-address-validation`

### CWE-691: Insufficient Control Flow Management

**Detectors:** 9

All reentrancy detectors:
- `classic-reentrancy`
- `read-only-reentrancy`
- `transient-storage-reentrancy`
- etc.

### CWE-362: Concurrent Execution using Shared Resource

**Detectors:** 13

All MEV and front-running detectors:
- `sandwich-attack`
- `mev-frontrunning`
- `create2-frontrunning`
- etc.

---

## Modern Vulnerability Coverage (2024-2025)

### 2024 Vulnerabilities ✅

- [x] **EIP-1153 Transient Storage** (5 detectors)
- [x] **ERC-4337 Account Abstraction** (21 detectors)
- [x] **Biconomy Nonce Bypass** (`aa-nonce-management`)
- [x] **UniswapV4 Hooks** (`uniswapv4-hook-issues`)
- [x] **Flash Loan Governance** (`flashloan-governance-attack`)
- [x] **LRT Share Inflation** (`restaking-lrt-share-inflation`)
- [x] **Zero-Knowledge Circuits** (5 detectors)

### 2025 Vulnerabilities ✅

- [x] **EIP-7702 Account Delegation** (6 detectors) - $12M+ attacks
- [x] **EIP-7702 Sweepers** (`eip7702-sweeper-detection`) - 97% of delegations
- [x] **EIP-7702 Init Front-Run** (`eip7702-init-frontrun`) - $1.54M attack
- [x] **ERC-7821 Batch Executor** (4 detectors)
- [x] **ERC-7683 Intent-Based** (5 detectors)
- [x] **Modular Blockchain** (5 detectors)
- [x] **AI Agent Security** (4 detectors)
- [x] **Restaking/LRT** (5 detectors)

### Historical Coverage ✅

- [x] **The DAO Reentrancy** (`classic-reentrancy`)
- [x] **Parity Multisig** (`multisig-bypass`, `uninitialized-storage`)
- [x] **Parity Suicide** (`selfdestruct-abuse`)
- [x] **Bancor/bZx Flash Loans** (7 flash loan detectors)
- [x] **Cream Finance Oracle** (`oracle-manipulation`)
- [x] **Wormhole Bridge** (`bridge-message-verification`)

---

## Quick Reference

### By Use Case

**Auditing DeFi Protocols:**
- All `defi/` detectors (15)
- All `flash-loans/` detectors (7)
- All `oracle/` detectors (9)
- All `mev/` detectors (13)

**Auditing Account Abstraction Wallets:**
- All `account-abstraction/` detectors (21)
- All `eips/` ERC-4337 detectors

**Auditing Modern 2025 Protocols:**
- All `eips/` EIP-7702 detectors (6)
- All `eips/` ERC-7683 detectors (5)
- All `eips/` ERC-7821 detectors (4)
- All `eips/` EIP-1153 detectors (5)

**Auditing Upgradeable Contracts:**
- All `upgrades/` detectors (7)
- Diamond pattern detectors (5)

**Auditing Cross-Chain Bridges:**
- All `cross-chain/` detectors (7)
- L2-specific detectors (3)

---

**Cross-Reference Generated By:** SolidityDefend Documentation System
**Date:** 2025-11-03
**Total Detectors:** 202 implementations, 195 unique IDs
