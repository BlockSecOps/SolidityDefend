# Unprotected Proxy Upgrade

**Detector ID:** `proxy-upgrade-unprotected`
**Category:** Proxy / Access Control
**Severity:** 🔥 **CRITICAL**
**CWE:** [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
**Confidence:** High

---

## Description

This detector identifies upgradeable proxy contracts where the upgrade function lacks proper access control, allowing **anyone** to upgrade the implementation contract. This is one of the most critical vulnerabilities in smart contracts, potentially leading to complete contract takeover.

When an upgrade function is publicly accessible without restrictions, an attacker can:
1. Deploy a malicious implementation contract
2. Call the unprotected upgrade function
3. Redirect all proxy calls to their malicious code
4. Drain funds, steal data, or completely compromise the contract

---

## Vulnerability Pattern

### ❌ Vulnerable Code

```solidity
contract VulnerableProxy {
    address public implementation;

    // CRITICAL: Anyone can call this!
    function upgradeTo(address newImplementation) external {
        implementation = newImplementation;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

**Why it's vulnerable:**
- No access control on `upgradeTo()`
- Function is `external` and callable by anyone
- Attacker can set `implementation` to malicious contract
- All subsequent calls execute attacker's code

---

### ✅ Secure Code

```solidity
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureProxy is Ownable {
    address private implementation;

    event Upgraded(address indexed implementation);

    // SECURE: Only owner can upgrade
    function upgradeTo(address newImplementation) external onlyOwner {
        require(newImplementation != address(0), "Invalid implementation");
        require(_isContract(newImplementation), "Must be contract");

        implementation = newImplementation;
        emit Upgraded(newImplementation);
    }

    function _isContract(address account) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(account) }
        return size > 0;
    }

    fallback() external payable {
        address impl = implementation;
        require(impl != address(0), "Implementation not set");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

**Security improvements:**
1. ✅ **Access Control**: `onlyOwner` modifier restricts upgrade
2. ✅ **Validation**: Checks implementation is not zero address
3. ✅ **Contract Check**: Ensures implementation is a contract
4. ✅ **Event Emission**: Transparency through `Upgraded` event
5. ✅ **Private Storage**: Implementation address is private

---

## Real-World Exploits

### Wormhole Bridge ($320M, February 2022)

**Impact:** $320 million stolen in one of the largest DeFi hacks

**Attack Vector:**
1. Wormhole used a proxy pattern for upgradeable contracts
2. Attacker exploited a signature verification flaw
3. Bypassed access control to call upgrade function
4. Upgraded to malicious implementation
5. Minted 120,000 wrapped ETH (wETH) out of thin air

**Root Cause:** Insufficient access control on critical upgrade function

**Reference:** [Rekt News - Wormhole](https://rekt.news/wormhole-rekt/)

---

### Audius ($6M, July 2022)

**Impact:** $6 million in AUDIO tokens stolen

**Attack Vector:**
1. Audius governance contract had unprotected delegatecall
2. Attacker proposed malicious governance action
3. Used delegatecall to execute arbitrary code
4. Transferred tokens to attacker address

**Root Cause:** Unprotected delegatecall in governance (similar to unprotected upgrade)

**Reference:** [Audius Post-Mortem](https://blog.audius.co/article/audius-governance-takeover-post-mortem-7-23-22)

---

## Detection Strategy

The detector analyzes contracts for the following patterns:

### 1. Upgrade Function Identification

Searches for functions with upgrade-related names:
- `upgradeTo()`
- `upgrade()`
- `setImplementation()`
- `updateImplementation()`
- `changeImplementation()`
- `_authorizeUpgrade()` (UUPS pattern)

### 2. Access Control Validation

Checks for access control mechanisms:

**Modifier-Based:**
```solidity
function upgradeTo(address impl) external onlyOwner { }  // ✅ Safe
function upgradeTo(address impl) external { }             // ❌ Vulnerable
```

**Inline Checks:**
```solidity
function upgradeTo(address impl) external {
    require(msg.sender == owner, "Only owner");  // ✅ Safe
    implementation = impl;
}
```

### 3. Implementation Storage Modification

Verifies the function actually modifies proxy implementation:
- Direct assignment: `_implementation = newImpl;`
- Assembly `sstore`: `sstore(slot, newImpl)`
- EIP-1967 standard slots

### 4. Visibility Check

Only flags `public` or `external` functions (internal/private are safe)

---

## Common Patterns Detected

### Pattern 1: Direct Storage Assignment

```solidity
// Vulnerable
function upgradeTo(address newImplementation) external {
    _implementation = newImplementation;  // No access control!
}
```

### Pattern 2: EIP-1967 Slot Modification

```solidity
// Vulnerable
function upgradeTo(address newImplementation) external {
    bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    assembly {
        sstore(slot, newImplementation)  // No access control!
    }
}
```

### Pattern 3: UUPS Pattern (Missing Authorization)

```solidity
// Vulnerable UUPS
function _authorizeUpgrade(address) internal override {
    // Empty! Should check authorization
}
```

---

## Recommended Fixes

### Option 1: OpenZeppelin Ownable

```solidity
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyProxy is Ownable {
    function upgradeTo(address newImpl) external onlyOwner {
        _setImplementation(newImpl);
    }
}
```

### Option 2: Role-Based Access Control

```solidity
import "@openzeppelin/contracts/access/AccessControl.sol";

contract MyProxy is AccessControl {
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    function upgradeTo(address newImpl) external onlyRole(UPGRADER_ROLE) {
        _setImplementation(newImpl);
    }
}
```

### Option 3: Timelock + Governance

```solidity
contract MyProxy {
    address public timelock;

    modifier onlyTimelock() {
        require(msg.sender == timelock, "Only timelock");
        _;
    }

    function upgradeTo(address newImpl) external onlyTimelock {
        _setImplementation(newImpl);
    }
}
```

### Option 4: Multi-Signature

```solidity
contract MyProxy {
    address[] public signers;
    mapping(bytes32 => uint256) public approvals;

    function proposeUpgrade(address newImpl) external {
        bytes32 proposalId = keccak256(abi.encode(newImpl));
        // Multi-sig approval logic...
    }
}
```

---

## Standard Proxy Patterns

### Transparent Proxy (OpenZeppelin)

```solidity
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

// Admin is the only one who can upgrade
// Regular users interact with implementation
```

### UUPS (Universal Upgradeable Proxy Standard)

```solidity
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

contract MyImplementation is UUPSUpgradeable {
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
```

### Beacon Proxy

```solidity
import "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

// Beacon controls implementation for multiple proxies
// Only beacon owner can upgrade all proxies at once
```

---

## Best Practices

1. ✅ **Always use access control** on upgrade functions
2. ✅ **Validate new implementation** (non-zero, is-contract check)
3. ✅ **Emit events** for transparency
4. ✅ **Use established patterns** (OpenZeppelin libraries)
5. ✅ **Consider timelock** for governance-based upgrades
6. ✅ **Test upgrade process** thoroughly
7. ✅ **Document upgrade procedures** for users
8. ✅ **Consider immutability** if upgrades aren't needed

---

## Testing

### Vulnerable Contract Test

```solidity
// Test file: tests/contracts/delegatecall/vulnerable/UnprotectedProxyUpgrade.sol
contract UnprotectedProxyUpgrade {
    address public implementation;

    function upgradeTo(address newImpl) external {
        implementation = newImpl;  // Should be detected
    }
}
```

### Expected Detection

```
🔥 CRITICAL: Unprotected Proxy Upgrade
   ├─ Location: UnprotectedProxyUpgrade.sol:4:5
   ├─ Function: upgradeTo
   ├─ CWE: CWE-284
   └─ Fix: Add access control modifier like 'onlyOwner'
```

---

## References

- [EIP-1967: Standard Proxy Storage Slots](https://eips.ethereum.org/EIPS/eip-1967)
- [OpenZeppelin Proxy Contracts](https://docs.openzeppelin.com/contracts/4.x/api/proxy)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [Wormhole Hack Analysis](https://rekt.news/wormhole-rekt/)
- [Audius Governance Takeover](https://blog.audius.co/article/audius-governance-takeover-post-mortem-7-23-22)

---

## Related Detectors

- `missing-access-modifiers` - General access control issues
- `dangerous-delegatecall` - Unsafe delegatecall patterns
- `proxy-storage-collision` - Storage layout conflicts in proxies
- `delegatecall-user-controlled` - User-controlled delegatecall targets

---

**Last Updated:** 2025-11-08
**Version:** v1.4.0
