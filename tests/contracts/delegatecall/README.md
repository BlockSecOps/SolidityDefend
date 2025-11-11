# Delegatecall Pattern Test Contracts

This directory contains test contracts for validating delegatecall-related vulnerability detectors in SolidityDefend v1.4.0.

## Purpose

These contracts demonstrate both vulnerable and secure implementations of proxy patterns, delegatecall usage, and upgrade mechanisms. They serve as:
1. **Test cases** for detector validation
2. **Educational examples** for developers
3. **Benchmarks** for detection rate measurement

## Directory Structure

```
delegatecall/
├── vulnerable/          # Contracts with intentional vulnerabilities
│   ├── UnprotectedProxyUpgrade.sol
│   ├── ProxyStorageCollision.sol
│   ├── UserControlledDelegatecall.sol
│   ├── UnprotectedFallbackDelegatecall.sol
│   ├── FallbackShadowing.sol
│   ├── DelegatecallReturnIgnored.sol
│   ├── UntrustedLibraryDelegatecall.sol
│   ├── ConstructorDelegatecall.sol
│   ├── DiamondSelectorCollision.sol
│   └── DiamondWithoutLoupe.sol
├── secure/              # Secure reference implementations
│   ├── SecureProxyUpgrade.sol
│   ├── EIP1967CompliantProxy.sol
│   ├── WhitelistedDelegatecall.sol
│   ├── ProtectedFallbackDelegatecall.sol
│   ├── NoShadowingProxy.sol
│   ├── DelegatecallReturnChecked.sol
│   ├── ImmutableLibraryDelegatecall.sol
│   ├── SafeConstructorInit.sol
│   ├── SecureDiamondFacets.sol
│   └── EIP2535CompliantDiamond.sol
└── README.md            # This file
```

## Vulnerability Categories

### 1. Proxy Pattern Vulnerabilities

**Test:** `UnprotectedProxyUpgrade.sol` (vulnerable) vs `SecureProxyUpgrade.sol` (secure)
- **Detector:** `proxy-upgrade-unprotected`
- **CWE:** CWE-284 (Improper Access Control)
- **Severity:** Critical
- **Pattern:** Upgrade function without access control

**Test:** `ProxyStorageCollision.sol` (vulnerable) vs `EIP1967CompliantProxy.sol` (secure)
- **Detector:** `proxy-storage-collision`
- **CWE:** CWE-662 (Improper Synchronization)
- **Severity:** High
- **Pattern:** Storage layout conflicts between proxy and implementation

**Test:** `UserControlledDelegatecall.sol` (vulnerable) vs `WhitelistedDelegatecall.sol` (secure)
- **Detector:** `delegatecall-user-controlled`
- **CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Severity:** Critical
- **Pattern:** Delegatecall to user-provided address

### 2. Fallback Function Vulnerabilities

**Test:** `UnprotectedFallbackDelegatecall.sol` (vulnerable) vs `ProtectedFallbackDelegatecall.sol` (secure)
- **Detector:** `fallback-delegatecall-unprotected`
- **CWE:** CWE-284 (Improper Access Control)
- **Severity:** High
- **Pattern:** Fallback with delegatecall without caller validation

**Test:** `FallbackShadowing.sol` (vulnerable) vs `NoShadowingProxy.sol` (secure)
- **Detector:** `fallback-function-shadowing`
- **CWE:** CWE-670 (Always-Incorrect Control Flow Implementation)
- **Severity:** Medium
- **Pattern:** Fallback shadows intended implementation functions

### 3. Advanced Delegatecall Patterns

**Test:** `DelegatecallReturnIgnored.sol` (vulnerable) vs `DelegatecallReturnChecked.sol` (secure)
- **Detector:** `delegatecall-return-ignored`
- **CWE:** CWE-252 (Unchecked Return Value)
- **Severity:** High
- **Pattern:** Delegatecall without return value validation

**Test:** `UntrustedLibraryDelegatecall.sol` (vulnerable) vs `ImmutableLibraryDelegatecall.sol` (secure)
- **Detector:** `delegatecall-untrusted-library`
- **CWE:** CWE-494 (Download of Code Without Integrity Check)
- **Severity:** High
- **Pattern:** Delegatecall to mutable library address

**Test:** `ConstructorDelegatecall.sol` (vulnerable) vs `SafeConstructorInit.sol` (secure)
- **Detector:** `delegatecall-in-constructor`
- **CWE:** CWE-665 (Improper Initialization)
- **Severity:** Medium
- **Pattern:** Delegatecall during contract initialization

### 4. Diamond Pattern Vulnerabilities

**Test:** `DiamondSelectorCollision.sol` (vulnerable) vs `SecureDiamondFacets.sol` (secure)
- **Detector:** `diamond-selector-collision`
- **CWE:** CWE-694 (Use of Multiple Resources with Duplicate Identifier)
- **Severity:** High
- **Pattern:** Function selector collisions across facets

**Test:** `DiamondWithoutLoupe.sol` (vulnerable) vs `EIP2535CompliantDiamond.sol` (secure)
- **Detector:** `diamond-loupe-missing`
- **CWE:** CWE-1059 (Incomplete Documentation)
- **Severity:** Low
- **Pattern:** Missing EIP-2535 loupe functions

## Running Tests

### With SolidityDefend CLI

```bash
# Test single file
soliditydefend tests/contracts/delegatecall/vulnerable/UnprotectedProxyUpgrade.sol

# Test all vulnerable contracts
soliditydefend tests/contracts/delegatecall/vulnerable/*.sol

# Test with JSON output
soliditydefend --format json tests/contracts/delegatecall/vulnerable/ > results.json
```

### Expected Detections

Each vulnerable contract should trigger its corresponding detector:

```
✓ UnprotectedProxyUpgrade.sol → proxy-upgrade-unprotected
✓ ProxyStorageCollision.sol → proxy-storage-collision
✓ UserControlledDelegatecall.sol → delegatecall-user-controlled
✓ UnprotectedFallbackDelegatecall.sol → fallback-delegatecall-unprotected
✓ FallbackShadowing.sol → fallback-function-shadowing
✓ DelegatecallReturnIgnored.sol → delegatecall-return-ignored
✓ UntrustedLibraryDelegatecall.sol → delegatecall-untrusted-library
✓ ConstructorDelegatecall.sol → delegatecall-in-constructor
✓ DiamondSelectorCollision.sol → diamond-selector-collision
✓ DiamondWithoutLoupe.sol → diamond-loupe-missing
```

### Secure Contracts (Should NOT Trigger)

Secure reference implementations should pass all checks:

```
✓ SecureProxyUpgrade.sol → No findings
✓ EIP1967CompliantProxy.sol → No findings
✓ WhitelistedDelegatecall.sol → No findings
... (all secure contracts should have zero findings)
```

## Real-World Context

These vulnerabilities are based on actual exploits:

- **Wormhole Bridge ($320M, 2022)** - Unprotected upgrade
- **Audius ($6M, 2022)** - Unprotected delegatecall
- **Parity Wallet ($280M, 2017)** - Delegatecall to user-controlled address
- **Various proxy upgrade attacks (2023-2024)** - Storage collisions, selector conflicts

## Validation Metrics

### Detection Rate Goal

- **Baseline (v1.3.2):** 38%
- **Target (v1.4.0):** 70%+
- **Measurement:** Run all 10 vulnerable + 10 secure contracts

### Success Criteria

1. ✅ All 10 vulnerable contracts detected
2. ✅ Zero false positives on secure contracts
3. ✅ <5% false positive rate overall
4. ✅ Analysis time <200ms per contract

## Contributing

When adding new test contracts:

1. **Create both vulnerable and secure versions**
2. **Add clear comments** explaining the vulnerability
3. **Include real-world exploit references** when available
4. **Update this README** with new test cases
5. **Verify detection** before committing

## References

- [EIP-1967: Standard Proxy Storage Slots](https://eips.ethereum.org/EIPS/eip-1967)
- [EIP-2535: Diamond Standard](https://eips.ethereum.org/EIPS/eip-2535)
- [OpenZeppelin Proxy Contracts](https://docs.openzeppelin.com/contracts/4.x/api/proxy)
- [CWE Definitions](https://cwe.mitre.org/)

---

**Created:** 2025-11-08
**Version:** v1.4.0 Phase 1
**Status:** In Development
