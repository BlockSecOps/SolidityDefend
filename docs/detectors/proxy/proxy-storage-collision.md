# Proxy Storage Collision Detector

**Detector ID:** `proxy-storage-collision`
**Severity:** High / Medium
**Confidence:** Medium
**CWE:** [CWE-662: Improper Synchronization](https://cwe.mitre.org/data/definitions/662.html)

## Overview

The Proxy Storage Collision detector identifies storage layout conflicts that can occur between proxy and implementation contracts in upgradeable proxy patterns. Storage collisions happen when both the proxy and implementation contracts use the same storage slots for different variables, leading to state corruption, loss of control, and potential fund theft.

## Vulnerability Description

In delegatecall-based proxy patterns, the implementation contract's code executes in the context of the proxy's storage. If both contracts define state variables in the same storage slots, the implementation can accidentally or maliciously overwrite critical proxy variables such as:

- The implementation address itself
- Admin/owner addresses
- Access control flags
- Critical configuration data

This vulnerability is particularly dangerous because it can lead to complete contract takeover with minimal trace.

## Detection Strategy

The detector performs three main checks:

### 1. Sequential Storage Layout Detection

Identifies proxy contracts using sequential storage slots (0, 1, 2...) for critical variables instead of EIP-1967 compliant pseudo-random slots:

```solidity
// VULNERABLE - Sequential storage
contract VulnerableProxy {
    address public implementation;  // Slot 0 - COLLISION RISK!
    address public admin;           // Slot 1 - COLLISION RISK!
}
```

**Detection Logic:**
- Identifies contracts with proxy-like characteristics (fallback functions, delegatecall usage)
- Checks for proxy variable names (`implementation`, `admin`, `logic`, `beacon`, etc.)
- Verifies absence of EIP-1967 compliant storage slot declarations
- Reports High severity finding if sequential storage is detected

### 2. Missing Storage Gap Detection

Identifies upgradeable contracts lacking storage gap reservations:

```solidity
// VULNERABLE - No storage gap
contract UpgradeableV1 {
    address public owner;    // Future upgrades can't safely add variables above this
    uint256 public value;
}

contract UpgradeableV2 is UpgradeableV1 {
    address public newFeature;  // COLLISION with child contracts!
}
```

**Detection Logic:**
- Identifies contracts with upgrade patterns (`initialize`, `upgrade` functions)
- Checks for presence of `__gap` storage variables
- Reports Medium severity finding if gap is missing

### 3. Inheritance Storage Collision Detection

Warns about potential collisions in inheritance hierarchies:

```solidity
// WARNING - Inheritance collision potential
contract Parent {
    address public owner;  // Slot 0
}

contract Child is Parent {
    address public token;  // Needs to start at slot 1, not 0!
}
```

**Detection Logic:**
- Checks contracts with non-empty inheritance lists
- Validates presence of state variables in both parent and child
- Reports Low severity warning to verify layout compatibility

## Real-World Impact

### Historical Exploits

1. **Parity Wallet Freeze (2017)**
   - Impact: $280M+ permanently frozen
   - Cause: Storage collision in library contract
   - Result: `selfdestruct` called on shared library, bricking all dependent wallets

2. **Multiple Proxy Upgrade Failures**
   - Impact: State corruption, fund loss, emergency pauses
   - Cause: Adding variables without storage gaps
   - Result: Overwritten storage slots corrupting contract state

### Common Attack Scenarios

**Scenario 1: Implementation Address Overwrite**
```solidity
// Proxy stores implementation in slot 0
contract Proxy {
    address public implementation;  // Slot 0
}

// Implementation also uses slot 0
contract Implementation {
    address public owner;  // Slot 0 - COLLISION!

    function initialize(address _owner) external {
        owner = _owner;  // OVERWRITES proxy's implementation variable!
    }
}

// Attack: Deploy malicious implementation, call initialize
// Result: Proxy now delegates to attacker's contract
```

**Scenario 2: Admin Escalation**
```solidity
contract Proxy {
    address public implementation;  // Slot 0
    address public admin;           // Slot 1
}

contract Implementation {
    address public owner;    // Slot 0
    uint256 public balance;  // Slot 1 - Overwrites admin!

    function deposit() external payable {
        balance += msg.value;  // Corrupts proxy's admin variable
    }
}
```

## Vulnerable Code Examples

### Example 1: Basic Storage Collision

```solidity
// VULNERABLE: Proxy uses sequential storage
contract VulnerableProxy {
    address public implementation;  // Slot 0
    address public admin;           // Slot 1

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

// VULNERABLE: Implementation uses same slots
contract VulnerableImplementation {
    address public owner;    // Slot 0 - COLLISION with implementation!
    uint256 public balance;  // Slot 1 - COLLISION with admin!

    function initialize(address _owner) external {
        owner = _owner;  // Overwrites proxy.implementation!
    }
}
```

### Example 2: Missing Storage Gap

```solidity
// VULNERABLE: No storage gap for future upgrades
contract UpgradeableContractV1 {
    address public owner;
    uint256 public value;

    function initialize(address _owner) external {
        require(owner == address(0), "Already initialized");
        owner = _owner;
    }
}

// PROBLEM: Can't safely add new variables in V2
contract UpgradeableContractV2 is UpgradeableContractV1 {
    // Adding this collides with child contracts!
    address public newFeature;
}
```

## Secure Code Examples

### Example 1: EIP-1967 Compliant Proxy

```solidity
// SECURE: Uses EIP-1967 pseudo-random storage slots
contract EIP1967Proxy {
    /**
     * @dev Storage slot with implementation address
     * keccak256("eip1967.proxy.implementation") - 1
     * = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
     */
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    bytes32 private constant ADMIN_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    function implementation() public view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setImplementation(address newImplementation) private {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    fallback() external payable {
        _delegate(implementation());
    }

    function _delegate(address impl) private {
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

**Why This Works:**
- EIP-1967 slots use `keccak256(label) - 1` to generate pseudo-random positions
- These slots are deterministic but extremely unlikely to collide with sequential storage
- Implementation contract can safely use slots 0, 1, 2... without conflicts
- Standardized approach supported by OpenZeppelin and other libraries

### Example 2: Storage Gaps

```solidity
// SECURE: Storage gap allows future upgrades
contract SecureUpgradeableV1 {
    /**
     * @dev Reserve 50 storage slots for future variables
     * When adding new variables in V2, reduce gap size accordingly
     */
    uint256[50] private __gap;

    // Actual state variables come AFTER the gap
    address public owner;
    uint256 public value;
    mapping(address => uint256) public balances;

    function initialize(address _owner) external {
        require(owner == address(0), "Already initialized");
        owner = _owner;
    }
}

// SECURE: Can safely add variables by reducing gap
contract SecureUpgradeableV2 is SecureUpgradeableV1 {
    // New variables added here use slots from the gap
    address public newFeature;      // Uses gap slot
    uint256 public anotherFeature;  // Uses gap slot

    // Reduce gap to account for new variables
    uint256[48] private __gapV2;   // 50 - 2 = 48
}
```

### Example 3: Namespaced Storage (Diamond Pattern)

```solidity
// SECURE: Namespaced storage eliminates collision risk
library LibDiamond {
    bytes32 constant DIAMOND_STORAGE_POSITION =
        keccak256("diamond.standard.diamond.storage");

    struct DiamondStorage {
        mapping(bytes4 => address) selectorToFacet;
        address contractOwner;
        // ... other diamond-specific state
    }

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }
}

contract DiamondFacet {
    function someFunction() external {
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        // Access namespaced storage safely
        require(msg.sender == ds.contractOwner, "Not owner");
    }
}
```

## Recommended Fixes

### Fix 1: Migrate to EIP-1967 Storage Slots

**For New Contracts:**
```solidity
contract SecureProxy {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    bytes32 private constant ADMIN_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    // Use assembly to read/write these slots
}
```

**For Existing Contracts:**
- Migration is extremely risky and may require complex data migration
- Consider using TransparentProxy pattern with separate admin contract
- Thoroughly audit any migration strategy before deployment

### Fix 2: Add Storage Gaps

```solidity
contract UpgradeableBase {
    // Add gap BEFORE state variables
    uint256[50] private __gap;

    // Then add your state variables
    address public owner;
    uint256 public value;
}
```

**Gap Sizing Guidelines:**
- 50 slots is standard for most contracts (2KB of storage)
- Critical infrastructure: 100+ slots
- Reduce gap when adding variables in upgrades
- Never remove the gap entirely

### Fix 3: Storage Layout Validation

Use Hardhat or Foundry plugins to validate storage layouts:

```javascript
// hardhat.config.js
module.exports = {
  storageLayout: {
    contracts: ["MyUpgradeableContract"],
    pretty: true
  }
};
```

```bash
# Foundry storage inspection
forge inspect MyContract storage-layout
```

## Best Practices

### 1. Always Use EIP-1967 for Proxies

Use battle-tested implementations:
- OpenZeppelin's `TransparentUpgradeableProxy`
- OpenZeppelin's `UUPSUpgradeable`
- OpenZeppelin's `BeaconProxy`

### 2. Storage Gap Checklist

- [ ] Add `__gap` variable in all upgradeable base contracts
- [ ] Size gap appropriately (50-100 slots)
- [ ] Place gap BEFORE other state variables
- [ ] Reduce gap when adding variables in upgrades
- [ ] Document gap usage in comments

### 3. Inheritance Best Practices

```solidity
// CORRECT: Linearized storage layout
contract Base {
    uint256[50] private __gapBase;
    address public baseVar1;
}

contract Middle is Base {
    uint256[50] private __gapMiddle;
    uint256 public middleVar1;
}

contract Final is Middle {
    uint256[50] private __gapFinal;
    bool public finalVar1;
}
```

### 4. Pre-Deployment Validation

```bash
# 1. Inspect storage layout
forge inspect MyProxy storage-layout > proxy-layout.json
forge inspect MyImplementation storage-layout > impl-layout.json

# 2. Compare layouts manually or with tools

# 3. Run upgrade simulation tests
forge test --match-test testUpgrade
```

### 5. Deployment Checklist

- [ ] Verify proxy uses EIP-1967 slots
- [ ] Verify implementation has storage gaps
- [ ] Compare storage layouts (no overlaps in slots 0-N)
- [ ] Test initialization process
- [ ] Test upgrade process
- [ ] Verify access controls on upgrade functions
- [ ] Document storage layout for future reference

## Testing Guidelines

### Test 1: Storage Collision Detection

```solidity
function testDetectsStorageCollision() public {
    // Deploy vulnerable proxy
    VulnerableProxy proxy = new VulnerableProxy(address(impl));

    // Cast to implementation interface
    VulnerableImplementation(address(proxy)).initialize(attacker);

    // Verify implementation was overwritten
    assertEq(proxy.implementation(), attacker, "Storage collision occurred");
}
```

### Test 2: EIP-1967 Compliance

```solidity
function testEIP1967Compliance() public {
    bytes32 IMPLEMENTATION_SLOT = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    // Deploy proxy
    EIP1967Proxy proxy = new EIP1967Proxy(address(impl));

    // Read implementation from correct slot
    address storedImpl = address(uint160(uint256(vm.load(address(proxy), IMPLEMENTATION_SLOT))));
    assertEq(storedImpl, address(impl), "Implementation stored in wrong slot");
}
```

### Test 3: Storage Gap Validation

```solidity
function testStorageGapPresent() public {
    // Use Foundry's storage inspection
    bytes32 gapSlot = bytes32(uint256(0)); // First slot
    uint256 gapSize = uint256(vm.load(address(upgradeable), gapSlot));

    // Note: This is simplified - real validation needs more complex logic
    assertTrue(gapSize == 0, "Gap should be empty");
}
```

## Configuration

The detector uses the following patterns:

**EIP-1967 Standard Slots:**
- `eip1967.proxy.implementation`
- `eip1967.proxy.admin`
- `eip1967.proxy.beacon`
- `org.zeppelinos.proxy.implementation` (legacy)
- `org.zeppelinos.proxy.admin` (legacy)

**Proxy Variable Names:**
- `_implementation`, `implementation`
- `_admin`, `admin`
- `_logic`, `logic`
- `_beacon`, `beacon`

**Storage Gap Pattern:**
- `__gap` (standard OpenZeppelin convention)

## References

### Standards
- [EIP-1967: Standard Proxy Storage Slots](https://eips.ethereum.org/EIPS/eip-1967)
- [EIP-1822: Universal Upgradeable Proxy Standard (UUPS)](https://eips.ethereum.org/EIPS/eip-1822)
- [EIP-2535: Diamond Standard](https://eips.ethereum.org/EIPS/eip-2535)

### Security Resources
- [OpenZeppelin Proxy Upgrade Pattern](https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies)
- [SWC-112: Delegatecall to Untrusted Callee](https://swcregistry.io/docs/SWC-112)
- [Parity Wallet Hack Analysis](https://blog.openzeppelin.com/on-the-parity-wallet-multisig-hack-405a8c12e8f7)

### Tools
- [Hardhat Storage Layout Plugin](https://hardhat.org/hardhat-runner/docs/advanced/building-plugins)
- [Foundry Storage Inspector](https://book.getfoundry.sh/reference/forge/forge-inspect)
- [OpenZeppelin Upgrades Plugins](https://docs.openzeppelin.com/upgrades-plugins/1.x/)

## Related Detectors

- `proxy-upgrade-unprotected`: Detects unprotected proxy upgrade functions
- `delegatecall-user-controlled`: Detects user-controlled delegatecall targets
- `diamond-storage-collision`: Detects collisions in Diamond proxy pattern
- `storage-layout-upgrade`: Validates storage layout compatibility across upgrades
- `uninitialized-storage`: Detects uninitialized storage pointers

## Version History

- **v1.3.2** (2025-11-08): Initial implementation
  - Sequential storage detection
  - Missing storage gap detection
  - Inheritance collision warnings
  - EIP-1967 compliance checking

---

**Last Updated:** 2025-11-08
**Detector Version:** 1.0.0
**Maintainer:** SolidityDefend Team
