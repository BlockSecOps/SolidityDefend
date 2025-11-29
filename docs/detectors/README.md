# SolidityDefend Detector Documentation

Complete reference for all **215 security detectors** in SolidityDefend v1.4.1.

**Last Updated:** 2025-11-29
**Version:** v1.4.1
**Total Detectors:** 215 (in tool)
**Categories:** 22

---

## Detector Metadata File

For tool integration (BlockSecOps, CI/CD pipelines, etc.), the complete detector metadata is available in JSON format:

**File:** [`all_detectors.json`](all_detectors.json)

**Contents:**
- 215 detector entries with structured metadata
- Detector ID, name, description, severity
- Category mappings (22 categories)
- CWE IDs (10 detectors mapped)
- SWC IDs (16 detectors mapped)

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

- **[Code Quality](code-quality/)** - 33 detectors
- **[Account Abstraction](account-abstraction/)** - 21 detectors
- **[DeFi](defi/)** - 19 detectors
- **[EIPs](eips/)** - 16 detectors
- **[MEV](mev/)** - 15 detectors
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

- **Critical Severity:** 55 detectors (26%)
- **High Severity:** 92 detectors (43%)
- **Medium Severity:** 60 detectors (28%)
- **Low/Info Severity:** 8 detectors (4%)

---

## Modern Security Coverage (2024-2025)

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
**Generated:** 2025-11-29
**Documentation Coverage:** 215 detectors (100% of tool) 🎉
**Metadata File:** [all_detectors.json](all_detectors.json) - Machine-readable detector catalog
