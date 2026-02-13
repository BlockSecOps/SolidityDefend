# SolidityDefend Detector Documentation

Complete reference for all security detectors in SolidityDefend v1.10.24+.

**Last Updated:** 2026-02-13
**Version:** v1.10.24+
**Total Detectors:** 67
**Categories:** 28

---

## Detector Metadata File

For tool integration (BlockSecOps, CI/CD pipelines, etc.), the complete detector metadata is available in JSON format:

**File:** [`all_detectors.json`](all_detectors.json)

**Contents:**
- 67 detector entries with structured metadata
- Detector ID, name, description, severity
- Category mappings (28 categories)
- CWE IDs (40+ detectors mapped)
- SWC IDs (10+ detectors mapped)

**Example entry:**
```json
{
  "id": "classic-reentrancy",
  "name": "Classic Reentrancy",
  "description": "State changes after external calls enable reentrancy attacks",
  "severity": "high",
  "categories": ["ReentrancyAttacks"],
  "cwe": ["CWE-841"],
  "swc": ["SWC-107"]
}
```

---

## Quick Navigation

### By Category

- **[Code Quality](code-quality/)** - 38 detectors
- **[Account Abstraction](account-abstraction/)** - 21 detectors
- **[DeFi](defi/)** - 19 detectors
- **[EIPs](eips/)** - 24 detectors (includes Phase 51: EIP-3074/4844/6780/PUSH0)
- **[MEV](mev/)** - 28 detectors
- **[Deployment](deployment/)** - 12 detectors
- **[Callback Chain](callback-chain/)** - 10 detectors
- **[Governance & Access Control](governance-access-control/)** - 10 detectors
- **[L2/Rollup & Cross-Chain](l2-rollup/)** - 10 detectors
- **[Randomness & DoS](randomness-dos/)** - 10 detectors 🆕
- **[Input Validation](input-validation/)** - 12 detectors
- **[Access Control](access-control/)** - 10 detectors
- **[Tokens](tokens/)** - 10 detectors
- **[Cross-Chain](cross-chain/)** - 10 detectors
- **[Flash Loans](flash-loans/)** - 9 detectors
- **[Oracle](oracle/)** - 8 detectors
- **[Upgrades](upgrades/)** - 8 detectors
- **[Restaking](restaking/)** - 6 detectors
- **[Reentrancy](reentrancy/)** - 5 detectors
- **[Zero-Knowledge](zero-knowledge/)** - 5 detectors
- **[Gas Optimization](gas-optimization/)** - 5 detectors
- **[Governance](governance/)** - 3 detectors

---

## Documentation Structure

Each category contains comprehensive documentation for all detectors:
- **Detector ID** - Unique identifier for CLI usage
- **Severity Level** - Critical, High, Medium, Low, or Info
- **Categories** - Primary vulnerability classifications
- **Description** - What the detector identifies
- **Vulnerable Patterns** - Common attack vectors detected
- **Remediation** - Step-by-step fixes and best practices
- **CWE Mappings** - Industry-standard weakness classifications
- **Source File** - Implementation reference

---

## Severity Distribution

- **Critical Severity:** ~18 detectors
- **High Severity:** ~23 detectors
- **Medium Severity:** ~17 detectors
- **Low/Info Severity:** ~9 detectors

---

## Safe Patterns Library (FP Reduction)

SolidityDefend includes a **Safe Patterns Library** for context-aware false positive reduction. Detectors automatically recognize secure implementations and skip or reduce severity for properly protected contracts.

### Available Modules

| Module | Patterns Detected |
|--------|-------------------|
| `oracle_patterns` | Chainlink, TWAP, multi-oracle, staleness checks, deviation bounds |
| `flash_loan_patterns` | ERC-3156 compliance, callback validation, reentrancy protection |
| `restaking_patterns` | EigenLayer delegation, AVS validation, withdrawal delays |
| `vault_patterns` | ERC-4626 inflation protection, dead shares, virtual shares |
| `amm_patterns` | AMM classification, slippage protection, TWAP oracles |
| `reentrancy_patterns` | ReentrancyGuard, checks-effects-interactions |

### Effect on Detection

When safe patterns are detected:
- **Skip entirely**: Contracts with comprehensive safety measures produce no findings
- **Reduce severity**: Partial safety measures lower finding severity (e.g., Critical → High)
- **Add context**: Findings include information about detected protections

See [TaskDocs-SolidityDefend/FP-REDUCTION.md](../../TaskDocs-SolidityDefend/FP-REDUCTION.md) for implementation details.

---

## New in v1.5.0 - SWC Coverage Expansion

### SWC-Aligned Detectors
- **SWC-105:** Unprotected Ether Withdrawal (Critical)
- **SWC-106:** Unprotected SELFDESTRUCT (Critical)
- **SWC-132:** Unexpected Ether Balance (Medium)
- **SWC-133:** Hash Collision with Variable Length Args (High)

These detectors expand our coverage of the [Smart Contract Weakness Classification (SWC) Registry](https://swcregistry.io/).

---

## Modern Security Coverage (2024-2026)

SolidityDefend v1.3.0 includes comprehensive coverage for:

### Account Abstraction (ERC-4337)
- EntryPoint trust and validation
- Paymaster abuse and fund drainage
- Session key vulnerabilities
- Bundler DoS attacks
- Signature aggregation bypasses
- User operation replay attacks

### Modern EIPs & Standards
- **EIP-7702:** Account delegation security
- **ERC-7683:** Cross-chain intent validation
- **ERC-7821:** Batch executor security
- **Transient Storage (EIP-1153):** State management issues

### DeFi Protocol Security
- AMM invariant manipulation
- Flash loan attack vectors
- Vault share inflation
- JIT liquidity exploitation
- MEV protection gaps
- Oracle manipulation

### Layer 2 & Cross-Chain
- Bridge message validation
- Cross-rollup atomicity
- Data availability failures
- Fraud proof timing issues

### Zero-Knowledge Proofs
- Circuit under-constrained detection
- Proof malleability issues
- Trusted setup bypasses
- Recursive proof validation

### Restaking & LRT Security
- Delegation manipulation
- Slashing condition bypasses
- Reward calculation exploits
- AVS validation issues

---

## Usage

To run specific detectors by category:

```bash
# Run all AA detectors
soliditydefend scan --category AccountAbstraction contracts/

# Run specific detector by ID
soliditydefend scan --detector aa-account-takeover contracts/

# List all available detectors
soliditydefend --list-detectors
```

---

**Maintained by:** Advanced Blockchain Security
**Generated:** 2026-02-13
**Total Detectors:** 67
**Metadata File:** [all_detectors.json](all_detectors.json) - Machine-readable detector catalog
