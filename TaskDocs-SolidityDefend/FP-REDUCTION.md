# False Positive Reduction Guide

Strategies and patterns for reducing false positives in SolidityDefend detectors.

## Overview

False positives occur when detectors flag code that is actually safe. This damages user trust and wastes auditor time. This guide documents patterns for reducing FPs.

## Common FP Patterns

### 1. Standard Library Contracts

**Problem:** Flagging OpenZeppelin, Solmate, and other audited libraries.

**Solution:** Skip contracts from known safe sources:

```rust
let is_safe_library = source.contains("@openzeppelin")
    || source.contains("@uniswap")
    || source.contains("Solmate")
    || source.contains("OpenZeppelin");

if is_safe_library {
    return Ok(findings);
}
```

### 2. Proxy Base Contracts

**Problem:** Flagging `delegatecall` in proxy contracts where it's intentional.

**Solution:** Detect proxy patterns and skip:

```rust
let is_proxy_contract = source.contains("abstract contract Proxy")
    || source.contains("TransparentUpgradeableProxy")
    || source.contains("UUPSUpgradeable")
    || source.contains("ERC1967")
    || source.contains("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");

if is_proxy_contract {
    return Ok(findings);
}
```

### 3. Solidity 0.8+ Contracts

**Problem:** Flagging integer overflow in contracts with built-in checks.

**Solution:** Check Solidity version:

```rust
let is_solidity_08_plus = source.contains("pragma solidity ^0.8")
    || source.contains("pragma solidity >=0.8")
    || source.contains("pragma solidity 0.8");

if is_solidity_08_plus {
    return Ok(findings); // Built-in overflow protection
}
```

### 4. Well-Known Protocol Patterns

**Problem:** Flagging intentional patterns in established protocols.

**Examples:**
- Compound's underscore-prefixed public admin functions
- Permit2's signature transfer patterns
- ERC-4626 vault share minting

**Solution:** Detect protocol-specific patterns:

```rust
// Compound pattern
let is_compound_style = source.contains("Comptroller")
    || source.contains("CToken")
    || source.contains("Compound");

// Permit2 pattern
let is_permit_protocol = source.contains("Permit2")
    || source.contains("IAllowanceTransfer")
    || source.contains("@uniswap/permit2");

// ERC-4626 vault
let is_vault = source.contains("ERC4626")
    || source.contains("vault")
    || source.contains("totalAssets");
```

## Implementation Pattern

### Standard FP Reduction Block

Add this pattern at the start of `detect()`:

```rust
fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let source = &ctx.source_code;

    // FP Reduction: Skip known safe patterns
    let is_safe_pattern = /* pattern checks */;

    if is_safe_pattern {
        return Ok(findings);
    }

    // Normal detection logic...
}
```

### Detector Categories with FP Issues

| Category | Common FP Sources |
|----------|-------------------|
| Proxy | OpenZeppelin proxy bases |
| Upgradeable | Initializable, UUPS |
| Storage | EIP-1967 slots |
| Signature | Permit2, ECDSA |
| Access Control | Compound admin patterns |
| DeFi | ERC-4626, AMM pools |

## Testing FP Reduction

### Before/After Comparison

```bash
# Before changes
./target/release/soliditydefend /tmp/oz-contracts/ 2>&1 | grep -c "HIGH\|CRITICAL"

# After changes
cargo build --release
./target/release/soliditydefend /tmp/oz-contracts/ 2>&1 | grep -c "HIGH\|CRITICAL"
```

### Specific Contract Tests

```bash
# Test against known false positive sources
soliditydefend /tmp/realworld-tests/proxy/
# Should have reduced findings for abstract proxy bases

soliditydefend /tmp/realworld-tests/foundry-permit2/
# Should not flag Permit2 as "permit signature exploit"
```

## FP Reduction History

### v1.10.13 Reductions

| Detector | FP Source | Fix |
|----------|-----------|-----|
| `hardware-wallet-delegation` | Standard proxies | Skip proxy contracts |
| `storage-collision` | Proxy base contracts | Skip EIP-1967 patterns |
| `uninitialized-storage` | Solidity 0.8+ | Skip 0.8+ contracts |
| `signature-malleability` | ECDSA libraries | Skip OZ ECDSA |
| `permit-signature-exploit` | Permit2 | Skip Permit2 contracts |
| `sweeper-detection` | Uniswap | Skip legitimate protocols |

### Metrics

| Version | OZ Proxy FPs | Permit2 FPs | Compound FPs |
|---------|--------------|-------------|--------------|
| 1.10.12 | 26 | 105 | 145 |
| 1.10.13 | 15 (-42%) | 76 (-28%) | 109 (-25%) |

## Best Practices

1. **Conservative Detection** - Prefer false negatives over false positives
2. **Context Awareness** - Use contract context to determine intent
3. **Protocol Recognition** - Maintain list of known safe patterns
4. **Version Checking** - Account for Solidity version differences
5. **Documentation** - Document why patterns are skipped

## Adding New FP Fixes

1. Identify the FP pattern with real-world contracts
2. Determine the safe pattern to detect
3. Add detection logic at start of `detect()`
4. Test with original FP-triggering contracts
5. Verify no true positives are lost
6. Document the fix in this guide
