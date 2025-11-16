# SolidityDefend Detector Documentation

Complete reference for all **209 security detectors** in SolidityDefend v1.3.6.

**Last Updated:** 2025-11-16
**Version:** v1.3.6
**Total Detectors:** 209 (in tool)
**Categories:** 17

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
**Generated:** 2025-11-16
**Documentation Coverage:** 209 detectors (100% of tool) 🎉
