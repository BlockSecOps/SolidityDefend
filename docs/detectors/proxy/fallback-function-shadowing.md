# Fallback Function Shadowing

**Detector ID:** `fallback-function-shadowing`
**Category:** Proxy / Access Control
**Severity:** ⚡ **MEDIUM**
**CWE:** [CWE-670: Always-Incorrect Control Flow Implementation](https://cwe.mitre.org/data/definitions/670.html)
**Confidence:** Medium

---

## Description

This detector identifies cases where a proxy contract's functions shadow functions intended for the implementation contract, causing calls to be misrouted or intercepted. Function shadowing occurs when a proxy defines public/external functions with the same names or selectors as implementation functions, preventing the implementation's version from ever being reached.

When function shadowing occurs:
1. Users call what they think is an implementation function
2. The proxy's version executes instead (wrong context)
3. Implementation logic never runs
4. State updates may occur in wrong locations
5. Critical functionality becomes unreachable

---

## Vulnerability Pattern

### ❌ Vulnerable Code

```solidity
contract VulnerableProxy {
    address public implementation;
    address public admin;

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    // VULNERABLE: This shadows the implementation's upgrade function!
    function upgradeImplementation(address newImpl) external {
        // This does nothing useful, but users might call it
        // thinking they're upgrading. The real upgrade function
        // in the implementation is now unreachable!
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
- The proxy defines `upgradeImplementation()` which shadows the implementation's function
- Users calling `upgradeImplementation()` get the proxy's empty version
- The implementation's actual upgrade logic is unreachable
- System appears to work but upgrades fail silently

### ❌ Hardcoded Selector Interception

```solidity
contract SelectorInterceptProxy {
    address public implementation;

    bytes4 private constant ADMIN_SELECTOR = 0xf851a440; // admin()
    bytes4 private constant OWNER_SELECTOR = 0x8da5cb5b; // owner()

    address public admin;

    fallback() external payable {
        bytes4 selector = msg.sig;

        // VULNERABLE: Hardcoded selectors intercepted
        if (selector == ADMIN_SELECTOR || selector == OWNER_SELECTOR) {
            assembly {
                mstore(0, sload(admin.slot))
                return(0, 32)
            }
        }

        // Implementation's admin() and owner() functions unreachable!
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

### ❌ Receive Function Shadowing

```solidity
contract ReceiveShadowingProxy {
    address public implementation;
    uint256 public receivedCount;

    receive() external payable {
        receivedCount++;
        // Implementation's receive() never executes!
    }

    fallback() external payable {
        // Delegates to implementation
    }
}
```

---

## ✅ Secure Implementations

### Option 1: Transparent Proxy Pattern (Recommended)

```solidity
contract TransparentProxy {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    bytes32 private constant ADMIN_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    modifier ifAdmin() {
        if (msg.sender == _getAdmin()) {
            _;
        } else {
            _delegate(_getImplementation());
        }
    }

    // Admin functions only callable by admin
    function upgradeTo(address newImplementation) external ifAdmin {
        _setImplementation(newImplementation);
    }

    function changeAdmin(address newAdmin) external ifAdmin {
        _setAdmin(newAdmin);
    }

    // Non-admin calls always delegate
    fallback() external payable {
        _delegate(_getImplementation());
    }

    receive() external payable {
        _delegate(_getImplementation());
    }

    function _delegate(address impl) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { impl := sload(slot) }
    }

    function _setImplementation(address newImplementation) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { sstore(slot, newImplementation) }
    }

    function _getAdmin() internal view returns (address adm) {
        bytes32 slot = ADMIN_SLOT;
        assembly { adm := sload(slot) }
    }

    function _setAdmin(address newAdmin) internal {
        bytes32 slot = ADMIN_SLOT;
        assembly { sstore(slot, newAdmin) }
    }
}
```

**Why it's secure:**
- `ifAdmin` modifier ensures admin calls don't delegate
- User calls always delegate to implementation
- No function name/selector conflicts possible
- Clear separation of admin and user interfaces

### Option 2: UUPS Proxy (Universal Upgradeable Proxy Standard)

```solidity
contract UUPSProxy {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    constructor(address _implementation, bytes memory _data) {
        _setImplementation(_implementation);
        if (_data.length > 0) {
            (bool success, ) = _implementation.delegatecall(_data);
            require(success, "Initialization failed");
        }
    }

    // NO admin functions in proxy!
    // All upgrade logic in implementation
    fallback() external payable {
        address impl = _getImplementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}

    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { impl := sload(slot) }
    }

    function _setImplementation(address newImplementation) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { sstore(slot, newImplementation) }
    }
}
```

**Why it's secure:**
- Zero proxy functions (no shadowing risk)
- All upgrade logic lives in implementation
- Minimal proxy code reduces attack surface

### Option 3: Beacon Proxy

```solidity
contract BeaconProxy {
    address public immutable beacon;

    constructor(address _beacon, bytes memory _data) {
        beacon = _beacon;
        if (_data.length > 0) {
            (bool success, ) = _getImplementation().delegatecall(_data);
            require(success, "Initialization failed");
        }
    }

    // No proxy functions - just beacon reference
    fallback() external payable {
        address impl = _getImplementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}

    function _getImplementation() internal view returns (address) {
        return IBeacon(beacon).implementation();
    }
}

interface IBeacon {
    function implementation() external view returns (address);
}
```

---

## Real-World Impact

### Known Issues

While there are no major documented exploits specifically labeled as "function shadowing," the vulnerability has appeared in various forms:

1. **Proxy Admin Function Confusion**: Multiple projects have had issues where admin functions were defined in both proxy and implementation, leading to:
   - Failed upgrades (calling proxy's no-op version)
   - Incorrect state updates (proxy context vs implementation context)
   - User confusion about which function to call

2. **Transparent Proxy Evolution**: The Transparent Proxy pattern (OpenZeppelin) was specifically designed to solve shadowing issues by:
   - Completely separating admin and user interfaces
   - Preventing any possibility of function conflicts
   - Making it impossible to accidentally call wrong function

3. **EIP-1967 Rationale**: The standard specifically addresses shadowing concerns by:
   - Recommending minimal proxy interfaces
   - Using EIP-1967 storage slots to avoid conflicts
   - Encouraging implementation-side upgrade logic (UUPS)

---

## Detection Strategy

The detector identifies shadowing risks by:

1. **Proxy Contract Detection**:
   - Contract name contains "proxy"
   - Contains fallback with delegatecall
   - Uses EIP-1967 storage slots

2. **Function Name Analysis**:
   - Checks for common admin function names (upgradeTo, transferOwnership, initialize, etc.)
   - Detects public/external functions that could shadow implementation

3. **ifAdmin Pattern Check**:
   - Looks for transparent proxy's ifAdmin modifier
   - Validates admin separation pattern

4. **Hardcoded Selector Detection**:
   - Identifies fallback functions with selector checks
   - Flags hardcoded bytes4 selector constants
   - Detects msg.sig-based routing

5. **Receive Function Check**:
   - Identifies proxies with both receive() and delegating fallback
   - Flags potential ETH handling conflicts

---

## Mitigation Recommendations

### For New Proxies

1. **Use Battle-Tested Patterns**:
   ```solidity
   // OpenZeppelin TransparentUpgradeableProxy
   import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

   // Or UUPS
   import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
   ```

2. **Minimize Proxy Interface**:
   - Keep proxy functions to absolute minimum
   - Use internal/private for helper functions
   - Avoid public getters that might conflict

3. **Document Function Separation**:
   ```solidity
   /**
    * @notice ADMIN FUNCTIONS (proxy-side)
    * These functions are ONLY callable by admin and execute in proxy context:
    * - upgradeTo(address)
    * - changeAdmin(address)
    *
    * @notice USER FUNCTIONS (implementation-side)
    * All other calls delegate to implementation
    */
   ```

### For Existing Proxies

1. **Audit Function Names**:
   ```bash
   # Check for potential conflicts
   # Compare proxy functions vs implementation functions
   cast interface MyProxy.sol
   cast interface MyImplementation.sol
   ```

2. **Add Tests**:
   ```solidity
   function testNoShadowing() public {
       // Verify implementation functions are reachable
       vm.prank(user);
       proxy.call(abi.encodeWithSignature("criticalFunction()"));

       // Verify admin functions work
       vm.prank(admin);
       proxy.upgradeTo(newImpl);
   }
   ```

3. **Document Behavior**:
   ```markdown
   # Proxy Architecture

   ## Admin Functions (Proxy Context)
   - `upgradeTo(address)` - Admin only, executes in proxy
   - `admin()` - Admin only, returns proxy admin

   ## Implementation Functions (Delegatecall)
   - All other functions delegate to implementation
   - Users cannot call admin functions
   ```

---

## Configuration

### Enable/Disable

```yaml
# .soliditydefend.yml
detectors:
  fallback-function-shadowing:
    enabled: true
    severity: medium
```

### Severity Levels

- **Medium**: Default setting
  - Potential for misrouted calls
  - May cause functionality failures
  - State corruption possible but limited

Could be **High** if:
- Financial functions affected
- Critical admin functions shadowed
- Production system with high value

---

## Best Practices

### Do's ✅

1. **Use Standard Patterns**: Stick to OpenZeppelin or other audited proxy implementations
2. **Separate Interfaces**: Clear separation between admin and user functions
3. **Test Thoroughly**: Verify all implementation functions are reachable
4. **Document Everything**: Clear documentation of proxy vs implementation functions
5. **Use EIP-1967**: Standard storage slots prevent accidental conflicts

### Don'ts ❌

1. **Don't Define Functions in Both**: Avoid defining same function in proxy and implementation
2. **Don't Hardcode Selectors**: Use storage-based routing (Diamond pattern) if needed
3. **Don't Mix Contexts**: Be clear about which functions execute where
4. **Don't Skip Tests**: Always test proxy-implementation integration
5. **Don't Roll Your Own**: Use established proxy patterns unless absolutely necessary

---

## Related Detectors

- `proxy-upgrade-unprotected`: Detects unprotected upgrade functions
- `proxy-storage-collision`: Detects storage layout conflicts
- `diamond-selector-collision`: Detects selector conflicts in Diamond proxies

---

## References

- [EIP-1967: Standard Proxy Storage Slots](https://eips.ethereum.org/EIPS/eip-1967)
- [EIP-1822: Universal Upgradeable Proxy Standard (UUPS)](https://eips.ethereum.org/EIPS/eip-1822)
- [OpenZeppelin Transparent Proxy](https://docs.openzeppelin.com/contracts/4.x/api/proxy#TransparentUpgradeableProxy)
- [OpenZeppelin UUPS Proxy](https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable)
- [CWE-670: Always-Incorrect Control Flow Implementation](https://cwe.mitre.org/data/definitions/670.html)

---

**Last Updated:** 2025-11-11
**Detector Version:** 1.3.3+
