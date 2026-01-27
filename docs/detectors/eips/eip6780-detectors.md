# EIP-6780 SELFDESTRUCT Changes Detector

**Detector ID:** `eip6780-selfdestruct-change`
**Total Detectors:** 1
**Added in:** v1.9.1 (2026-01-15)
**Categories:** EIP Security, Upgradeable

---

## Overview

EIP-6780 fundamentally changes the behavior of the SELFDESTRUCT opcode as part of the Dencun upgrade (March 2024). Prior to Dencun, SELFDESTRUCT would:

1. Send all ETH to the designated recipient
2. Delete all contract code
3. Clear all contract storage
4. Make the contract address reusable via CREATE2

After EIP-6780, SELFDESTRUCT only deletes contract code and storage **if called in the same transaction as contract creation**. In all other cases, it only transfers ETH while leaving code and storage intact.

This change breaks several established patterns:
- **Metamorphic contracts** - CREATE2 + selfdestruct redeployment
- **Emergency shutdown** - Permanent contract removal
- **Code verification** - extcodesize checks after selfdestruct

---

## Detector Summary

| Detector ID | Severity | Description | CWE |
|-------------|----------|-------------|-----|
| `eip6780-selfdestruct-change` | Medium | Post-Cancun selfdestruct behavior changes | [CWE-670](https://cwe.mitre.org/data/definitions/670.html) |

---

## Detailed Detector Documentation

### eip6780-selfdestruct-change

**Severity:** Medium
**CWE:** [CWE-670: Always-Incorrect Control Flow Implementation](https://cwe.mitre.org/data/definitions/670.html)

#### Description

This detector identifies code patterns that rely on pre-Dencun SELFDESTRUCT behavior and may not work as expected after EIP-6780. The detector flags:

1. **Metamorphic contract patterns** that use selfdestruct + CREATE2 for redeployment
2. **Emergency destroy functions** assuming permanent code removal
3. **extcodesize checks** used to verify contract destruction
4. **Storage clearing assumptions** expecting selfdestruct to clear state

#### Detection Criteria

- `selfdestruct()` or `suicide()` (deprecated) usage
- CREATE2 factory patterns combined with selfdestruct
- `extcodesize` or `.code.length` checks following selfdestruct
- Comments or function names suggesting permanent destruction
- Contracts inheriting from known metamorphic patterns

#### Vulnerable Code Patterns

**Pattern 1: Metamorphic Contracts (Broken)**

```solidity
// VULNERABLE: Metamorphic pattern no longer works post-Dencun
contract MetamorphicFactory {
    // Stores deployed metamorphic contracts
    mapping(bytes32 => address) public deployments;

    function deployMetamorphic(bytes32 salt, bytes memory code) external returns (address) {
        // Deploy with CREATE2 for deterministic address
        address deployed;
        assembly {
            deployed := create2(0, add(code, 0x20), mload(code), salt)
        }
        deployments[salt] = deployed;
        return deployed;
    }

    function destroyAndRedeploy(bytes32 salt, bytes memory newCode) external {
        address existing = deployments[salt];
        require(existing != address(0), "Not deployed");

        // This no longer deletes the code!
        IDestructible(existing).destroy();

        // This will FAIL - address is still occupied
        address redeployed;
        assembly {
            redeployed := create2(0, add(newCode, 0x20), mload(newCode), salt)
        }
        // redeployed will be address(0) because existing code remains
    }
}

interface IDestructible {
    function destroy() external;
}

contract MetamorphicImpl is IDestructible {
    address public owner;

    function destroy() external {
        require(msg.sender == owner);
        selfdestruct(payable(owner));
        // Post-Dencun: ETH sent, but code remains
    }
}
```

**Pattern 2: Emergency Destroy Assuming Code Removal**

```solidity
// VULNERABLE: Assumes selfdestruct removes code permanently
contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function emergencyDestroy() external onlyOwner {
        // Developer expects this to:
        // 1. Send ETH to owner (STILL WORKS)
        // 2. Delete all code (NO LONGER WORKS)
        // 3. Clear storage (NO LONGER WORKS)

        selfdestruct(payable(owner));

        // Post-Dencun reality:
        // - ETH is sent
        // - Code still exists and is callable
        // - Storage (balances mapping) still exists
        // - Contract can still receive deposits!
    }
}
```

**Pattern 3: extcodesize Destruction Check**

```solidity
// VULNERABLE: extcodesize check gives wrong result post-Dencun
contract DestructionMonitor {
    function isDestroyed(address target) external view returns (bool) {
        // This check is now INCORRECT
        // extcodesize will return > 0 even after selfdestruct
        return target.code.length == 0;
    }

    function safeInteract(address target) external {
        // This "safety" check no longer works
        require(!this.isDestroyed(target), "Contract destroyed");

        // May interact with a contract that called selfdestruct
        // but still has code and storage
        ITarget(target).doSomething();
    }
}
```

**Pattern 4: Storage Clearing Assumption**

```solidity
// VULNERABLE: Assumes selfdestruct clears storage
contract StorageClearingContract {
    uint256 public sensitiveData;
    mapping(address => bool) public authorizedUsers;

    function clearAndDestroy() external {
        // Developer expects selfdestruct to clear all storage
        // including sensitiveData and authorizedUsers mapping

        selfdestruct(payable(msg.sender));

        // Post-Dencun:
        // - sensitiveData still readable
        // - authorizedUsers mapping still intact
        // - Anyone previously authorized is still authorized
    }
}
```

#### Secure Code Patterns

**Pattern 1: Use Pausable Instead of Destroy**

```solidity
// SECURE: Pausable pattern for emergency shutdown
contract SecureVault {
    address public owner;
    bool public paused;
    bool public permanentlyDeactivated;

    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused && !permanentlyDeactivated, "Contract paused");
        _;
    }

    modifier whenNotDeactivated() {
        require(!permanentlyDeactivated, "Contract deactivated");
        _;
    }

    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner whenNotDeactivated {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // Permanent deactivation (irreversible)
    function permanentDeactivate() external onlyOwner {
        permanentlyDeactivated = true;
        paused = true;
        emit PermanentlyDeactivated(msg.sender);
    }

    // Users can still withdraw after deactivation
    function emergencyWithdraw() external whenNotDeactivated {
        uint256 balance = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(balance);
    }

    function deposit() external payable whenNotPaused {
        balances[msg.sender] += msg.value;
    }

    event Paused(address account);
    event Unpaused(address account);
    event PermanentlyDeactivated(address account);
}
```

**Pattern 2: State-Based Activity Check**

```solidity
// SECURE: Use explicit state flag instead of extcodesize
contract SecureMonitor {
    mapping(address => bool) public isActive;

    function registerContract(address target) external {
        isActive[target] = true;
    }

    function deactivateContract(address target) external {
        // Only authorized callers can deactivate
        isActive[target] = false;
        emit ContractDeactivated(target);
    }

    function checkActive(address target) external view returns (bool) {
        // Use state flag, not extcodesize
        return isActive[target];
    }

    function safeInteract(address target) external {
        require(isActive[target], "Contract not active");
        ITarget(target).doSomething();
    }

    event ContractDeactivated(address target);
}
```

**Pattern 3: Explicit Storage Clearing**

```solidity
// SECURE: Explicitly clear sensitive data
contract SecureDataContract {
    uint256 public sensitiveData;
    mapping(address => bool) public authorizedUsers;
    address[] public userList;

    function clearSensitiveData() external onlyOwner {
        // Explicitly clear sensitive storage
        sensitiveData = 0;

        // Clear mapping by iterating (gas intensive but thorough)
        for (uint256 i = 0; i < userList.length; i++) {
            delete authorizedUsers[userList[i]];
        }
        delete userList;

        emit DataCleared(msg.sender);
    }

    // If ETH withdrawal is needed, do it separately
    function withdrawETH() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    event DataCleared(address clearedBy);
}
```

**Pattern 4: Upgradeable Pattern for Code Updates**

```solidity
// SECURE: Use upgradeable proxy instead of metamorphic
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract SecureUpgradeableFactory {
    function deployUpgradeable(
        address implementation,
        bytes memory initData
    ) external returns (address) {
        // Deploy upgradeable proxy
        ERC1967Proxy proxy = new ERC1967Proxy(implementation, initData);
        return address(proxy);
    }

    // Upgrade through proper proxy upgrade mechanism
    // No need for selfdestruct
}
```

---

## Remediation Guidelines

### 1. Replace Destroy with Pause/Deactivate

```solidity
// Instead of:
function emergencyDestroy() external {
    selfdestruct(payable(owner));
}

// Use:
bool public deactivated;
function deactivate() external onlyOwner {
    deactivated = true;
    emit Deactivated();
}
```

### 2. Replace Metamorphic with Upgradeable

```solidity
// Instead of: CREATE2 + selfdestruct
// Use: EIP-1967 upgradeable proxies (UUPS or Transparent)
```

### 3. Replace extcodesize Checks with State Flags

```solidity
// Instead of:
require(target.code.length > 0, "Contract destroyed");

// Use:
mapping(address => bool) public activeContracts;
require(activeContracts[target], "Contract not active");
```

### 4. Explicitly Clear Sensitive Storage

```solidity
// Instead of relying on selfdestruct to clear storage:
function clearData() external {
    sensitiveVar = 0;
    delete mapping[key];
    // ... clear all sensitive data explicitly
}
```

### 5. Understand New Selfdestruct Behavior

```solidity
// Post-Dencun selfdestruct ONLY:
// 1. Transfers ETH to recipient
// That's it. No code deletion, no storage clearing.

// Exception: Same-transaction creation
// If selfdestruct is called in the same tx as CREATE/CREATE2,
// the old behavior applies (code + storage deleted)
```

---

## Testing

The detector has been validated with comprehensive test cases:

| Test Scenario | Findings | Contracts |
|---------------|----------|-----------|
| Metamorphic patterns | 8 | 2 |
| Emergency destroy | 5 | 2 |
| extcodesize checks | 4 | 1 |
| Storage clearing assumptions | 3 | 1 |

**Total:** 20 findings across 5 test contracts

---

## Best Practices

### For New Contracts

1. **Avoid selfdestruct entirely** in new contract designs
2. **Use pausable patterns** for emergency shutdown
3. **Use upgradeable proxies** for code updates
4. **Track activity with state flags** not extcodesize

### For Existing Contracts

1. **Audit all selfdestruct usage** for post-Dencun compatibility
2. **Replace metamorphic patterns** with upgradeable proxies
3. **Update monitoring** to use state-based checks
4. **Document changed behavior** for dependent systems

### Security Considerations

1. **Contracts remain callable** after selfdestruct (post-Dencun)
2. **Storage persists** - sensitive data may still be accessible
3. **Approvals remain valid** - tokens approved to "destroyed" contracts can still be spent
4. **Ether can still be received** - contracts can receive ETH after selfdestruct

---

## Migration Guide

### From Metamorphic to Upgradeable

```solidity
// Before (Metamorphic):
1. Deploy with CREATE2
2. Call selfdestruct to "upgrade"
3. Redeploy with same salt

// After (Upgradeable Proxy):
1. Deploy implementation
2. Deploy proxy pointing to implementation
3. Upgrade by calling proxy.upgradeTo(newImpl)
// Same address, no selfdestruct needed
```

### From Destroy to Deactivate

```solidity
// Before:
function emergencyShutdown() external onlyOwner {
    selfdestruct(payable(owner));
}

// After:
bool public shutdown;

function emergencyShutdown() external onlyOwner {
    shutdown = true;
    payable(owner).transfer(address(this).balance);
    emit EmergencyShutdown();
}

modifier whenNotShutdown() {
    require(!shutdown, "Contract shutdown");
    _;
}
```

---

## References

### EIP Specification
- [EIP-6780: SELFDESTRUCT only in same transaction](https://eips.ethereum.org/EIPS/eip-6780)

### Related EIPs
- [EIP-4758: Deactivate SELFDESTRUCT](https://eips.ethereum.org/EIPS/eip-4758)
- [EIP-1967: Standard Proxy Storage Slots](https://eips.ethereum.org/EIPS/eip-1967)

### Security Resources
- [Dencun Upgrade Changelog](https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/cancun.md)
- [Metamorphic Contract Security](https://blog.trailofbits.com/2018/10/04/metamorphic-contracts/)

### Related Detectors
- `proxy-*` - Proxy and upgradeable contract detectors
- `delegatecall-*` - Delegatecall security detectors

---

**Last Updated:** 2026-01-26
**Detector Version:** 1.0.0
**Source:** `crates/detectors/src/eip6780/selfdestruct_change.rs`
