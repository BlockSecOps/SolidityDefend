# Unprotected Fallback Delegatecall

**Detector ID:** `fallback-delegatecall-unprotected`
**Severity:** MEDIUM
**CWE:** CWE-284 (Improper Access Control)
**Category:** Access Control, External Calls

## Description

This detector identifies fallback and receive functions that perform delegatecall operations without proper access controls. Fallback functions are automatically invoked when a contract receives calls to non-existent functions or direct ETH transfers. If these functions perform unprotected delegatecalls, anyone can trigger arbitrary code execution in the contract's context.

## Vulnerability

Fallback and receive functions serve as catch-all handlers for contract interactions. They are automatically called in the following situations:

1. **Fallback**: Called when no other function matches the signature
2. **Fallback with Data**: Called when ETH is sent with calldata to non-existent function
3. **Receive**: Called when contract receives plain ETH (no data)

When these functions perform delegatecall without access control, any external caller can:
- Execute arbitrary logic in the contract's context
- Read and modify storage
- Transfer funds
- Bypass intended access restrictions

### Attack Vectors

1. **Direct Fallback Invocation**: Call non-existent function to trigger fallback
2. **ETH Transfer Attack**: Send ETH to trigger receive/fallback
3. **Encoded Call Attack**: Send crafted calldata to execute specific logic
4. **Proxy Confusion**: Misuse proxy pattern where fallback should be restricted

### Impact

- **Unauthorized Code Execution**: Any user can trigger delegatecall
- **State Manipulation**: Critical variables can be modified
- **Fund Theft**: Contract balance can be drained
- **Access Control Bypass**: Admin functions executed by anyone
- **Contract Bricking**: State corruption can make contract unusable

## Vulnerable Code Examples

### Pattern 1: Basic Unprotected Fallback

```solidity
contract UnprotectedFallback {
    address public implementation;
    address public owner;

    constructor(address _implementation) {
        implementation = _implementation;
        owner = msg.sender;
    }

    // CRITICAL: Anyone can trigger delegatecall via fallback!
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

**Attack**: Anyone can call any function on the implementation via the fallback, including admin functions.

### Pattern 2: Receive with Delegatecall

```solidity
contract UnprotectedReceive {
    address public logic;

    constructor(address _logic) {
        logic = _logic;
    }

    // VULNERABLE: Anyone sending ETH triggers delegatecall
    receive() external payable {
        (bool success, ) = logic.delegatecall(
            abi.encodeWithSignature("handlePayment()")
        );
        require(success, "Payment handling failed");
    }
}
```

**Risk**: Anyone can trigger `handlePayment()` by sending ETH, potentially draining funds or corrupting state.

### Pattern 3: Conditional Fallback Without Validation

```solidity
contract ConditionalFallback {
    address public impl;
    bool public useFallback;

    function setUseFallback(bool enabled) external {
        useFallback = enabled;  // Anyone can enable
    }

    // VULNERABLE: If enabled, anyone can use fallback
    fallback() external payable {
        if (useFallback) {
            (bool success, ) = impl.delegatecall(msg.data);
            require(success);
        }
    }
}
```

**Attack**: Enable fallback delegation, then call arbitrary functions.

### Pattern 4: Fallback with User Data

```solidity
contract FallbackWithUserData {
    address public executor;

    constructor(address _executor) {
        executor = _executor;
    }

    // VULNERABLE: User controls msg.data passed to delegatecall
    fallback() external payable {
        (bool success, bytes memory result) = executor.delegatecall(msg.data);
        require(success, "Execution failed");

        assembly {
            return(add(result, 32), mload(result))
        }
    }
}
```

**Risk**: User can craft any calldata to execute arbitrary functions in `executor`.

### Pattern 5: Mixed Access Control

```solidity
contract MixedAccessControl {
    address public implementation;
    address public owner;

    constructor(address _impl) {
        implementation = _impl;
        owner = msg.sender;
    }

    // Protected function
    function upgradeTo(address newImpl) external {
        require(msg.sender == owner, "Only owner");
        implementation = newImpl;
    }

    // VULNERABLE: Fallback not protected
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

**Issue**: `upgradeTo` is protected, but fallback allows anyone to call implementation functions directly.

## Secure Implementations

### Solution 1: Transparent Proxy Pattern

```solidity
contract TransparentProxy {
    address private immutable _admin;
    address private _implementation;

    event Upgraded(address indexed implementation);

    constructor(address admin_, address implementation_) {
        require(admin_ != address(0), "Invalid admin");
        require(implementation_ != address(0), "Invalid implementation");
        _admin = admin_;
        _implementation = implementation_;
    }

    modifier ifAdmin() {
        if (msg.sender == _admin) {
            _;
        } else {
            _fallback();
        }
    }

    // SECURE: Admin functions only callable by admin
    function upgradeTo(address newImplementation) external ifAdmin {
        require(newImplementation != address(0), "Invalid implementation");
        _implementation = newImplementation;
        emit Upgraded(newImplementation);
    }

    function admin() external ifAdmin returns (address) {
        return _admin;
    }

    function implementation() external ifAdmin returns (address) {
        return _implementation;
    }

    // SECURE: Fallback only for non-admin
    fallback() external payable {
        _fallback();
    }

    receive() external payable {
        _fallback();
    }

    function _fallback() internal {
        // Admin cannot use fallback - prevents admin from accidentally
        // calling implementation functions
        require(msg.sender != _admin, "Admin cannot fallback");

        address impl = _implementation;
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

**Benefits**:
- Admin cannot accidentally call implementation functions
- Clear separation between admin and user interfaces
- Prevents function selector collisions

### Solution 2: UUPS Pattern (Upgrade Logic in Implementation)

```solidity
contract UUPSProxy {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    constructor(address _implementation) {
        require(_implementation != address(0), "Invalid implementation");
        _setImplementation(_implementation);
    }

    // SECURE: No upgrade function in proxy
    // Upgrade logic is in implementation, access-controlled there

    fallback() external payable {
        _delegate(_getImplementation());
    }

    receive() external payable {
        _delegate(_getImplementation());
    }

    function _delegate(address implementation) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
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
}
```

**Benefits**:
- No proxy admin functions to protect
- Upgrade logic in implementation (access-controlled there)
- Simpler proxy contract

### Solution 3: Minimal Proxy (EIP-1167)

```solidity
// SECURE: Minimal proxy delegates to immutable implementation
contract MinimalProxy {
    // Implementation address is hardcoded in bytecode
    // No storage, no admin functions, no upgrade capability

    fallback() external payable {
        address impl = /* implementation address from bytecode */;

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

// Factory creates minimal proxies
contract MinimalProxyFactory {
    function createProxy(address implementation) external returns (address proxy) {
        bytes20 targetBytes = bytes20(implementation);
        assembly {
            let clone := mload(0x40)
            mstore(clone, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(clone, 0x14), targetBytes)
            mstore(add(clone, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            proxy := create(0, clone, 0x37)
        }
    }
}
```

**Benefits**:
- Minimal gas cost
- No upgrade capability (secure by design)
- Implementation immutable

### Solution 4: Beacon Proxy

```solidity
contract BeaconProxy {
    address private immutable _beacon;

    event BeaconUpgraded(address indexed beacon);

    constructor(address beacon) {
        require(beacon != address(0), "Invalid beacon");
        _beacon = beacon;
    }

    // SECURE: Beacon is immutable, upgrade logic in beacon contract
    function _implementation() internal view returns (address) {
        return IBeacon(_beacon).implementation();
    }

    fallback() external payable {
        _delegate(_implementation());
    }

    receive() external payable {
        _delegate(_implementation());
    }

    function _delegate(address implementation) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

interface IBeacon {
    function implementation() external view returns (address);
}

// Beacon contract (access-controlled)
contract UpgradeableBeacon is IBeacon {
    address public implementation;
    address public owner;

    constructor(address implementation_) {
        implementation = implementation_;
        owner = msg.sender;
    }

    function upgradeTo(address newImplementation) external {
        require(msg.sender == owner, "Only owner");
        implementation = newImplementation;
    }
}
```

**Benefits**:
- Single beacon for multiple proxies
- Upgrade all proxies at once
- Clear access control in beacon

### Solution 5: Access-Controlled Fallback

```solidity
contract ProtectedFallback {
    address public implementation;
    address public owner;
    mapping(address => bool) public authorizedCallers;

    constructor(address _implementation) {
        implementation = _implementation;
        owner = msg.sender;
        authorizedCallers[msg.sender] = true;
    }

    modifier onlyAuthorized() {
        require(
            msg.sender == owner || authorizedCallers[msg.sender],
            "Not authorized"
        );
        _;
    }

    function authorize(address caller) external {
        require(msg.sender == owner, "Only owner");
        authorizedCallers[caller] = true;
    }

    // SECURE: Only authorized callers can use fallback
    fallback() external payable onlyAuthorized {
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

## Detection Strategy

The detector identifies the following patterns:

### 1. **Unprotected Fallback with Delegatecall**
```solidity
fallback() external payable {
    target.delegatecall(msg.data);  // DETECTED: No access control
}
```

### 2. **Unprotected Receive with Delegatecall**
```solidity
receive() external payable {
    logic.delegatecall(...);  // DETECTED: No modifier
}
```

### 3. **Missing Access Control Modifiers**
- No `onlyOwner`, `onlyAdmin`, or similar modifiers
- No `require(msg.sender == ...)` checks
- No whitelist validation

### 4. **Assembly Delegatecall in Fallback**
```solidity
fallback() external payable {
    assembly {
        let result := delegatecall(...)  // DETECTED if no protection
    }
}
```

## Real-World Impact

### Historical Vulnerabilities

**Proxy Pattern Exploits (2018-2024)**
- Multiple DeFi protocols exploited via unprotected fallback
- Common in early proxy implementations before Transparent Proxy pattern
- Led to development of EIP-1967 and standardized proxy patterns

**Attack Patterns**
- Calling admin functions via fallback
- Bypassing intended access controls
- Draining funds through unprotected delegation

### Attack Scenarios

**Scenario 1: Admin Function Bypass**
```solidity
// Implementation has admin function
contract Implementation {
    function withdrawAll() external onlyAdmin {
        payable(admin).transfer(address(this).balance);
    }
}

// Proxy with unprotected fallback
// Attacker calls: proxy.call(abi.encodeWithSignature("withdrawAll()"))
// Result: Funds drained without being admin
```

**Scenario 2: State Corruption**
```solidity
// Attacker sends ETH to trigger receive
// Receive function delegates to logic that modifies critical state
// Contract left in invalid state
```

## Best Practices

### 1. **Use Transparent Proxy Pattern**
- Separate admin and user interfaces
- Admin cannot use fallback
- Prevents function collisions

### 2. **Implement Access Control**
```solidity
fallback() external payable onlyAuthorized {
    _delegate(implementation);
}
```

### 3. **Use UUPS for Simpler Access Control**
- Upgrade logic in implementation
- No proxy admin to protect

### 4. **Document Fallback Behavior**
```solidity
/// @notice Fallback delegates to implementation (users only)
/// @dev Admin must use explicit functions, not fallback
fallback() external payable { ... }
```

### 5. **Test Fallback Security**
- Verify unauthorized users cannot use fallback
- Test that admin functions are protected
- Validate access control works correctly

### 6. **Consider Immutable Implementation**
If upgrades not needed:
```solidity
address public immutable implementation;
```

## Mitigation Checklist

- [ ] Fallback function has access control modifier
- [ ] Or uses Transparent Proxy pattern (admin separation)
- [ ] Or uses UUPS pattern (upgrade in implementation)
- [ ] Receive function protected if it delegates
- [ ] Admin functions not callable via fallback
- [ ] Tests verify unauthorized access fails
- [ ] Documentation explains fallback behavior
- [ ] Security audit completed
- [ ] Upgrade mechanism documented
- [ ] Emergency pause capability exists

## Testing Recommendations

### Unit Tests
```solidity
function testUnauthorizedCannotUseFallback() public {
    vm.prank(attacker);
    vm.expectRevert("Not authorized");
    (bool success, ) = address(proxy).call(abi.encodeWithSignature("someFunction()"));
    assertFalse(success);
}

function testAdminCannotUseFallback() public {
    // In Transparent Proxy pattern
    vm.prank(admin);
    vm.expectRevert("Admin cannot fallback");
    (bool success, ) = address(proxy).call(abi.encodeWithSignature("someFunction()"));
}

function testAuthorizedCanUseFallback() public {
    vm.prank(authorizedUser);
    (bool success, ) = address(proxy).call(abi.encodeWithSignature("someFunction()"));
    assertTrue(success);
}
```

### Integration Tests
- Test full proxy upgrade flow
- Verify access control across all paths
- Test with real implementation contracts

### Fuzz Testing
```solidity
function testFuzzFallbackAccess(address caller) public {
    vm.prank(caller);
    if (caller != admin && !authorizedCallers[caller]) {
        vm.expectRevert();
    }
    (bool success, ) = address(proxy).call(data);
}
```

## References

- **CWE-284**: Improper Access Control
- **EIP-1967**: Standard Proxy Storage Slots
- **EIP-1822**: Universal Upgradeable Proxy Standard (UUPS)
- **EIP-1167**: Minimal Proxy Contract (Clone Factory)
- **OpenZeppelin**: Transparent Proxy implementation
- **SWC-106**: Unprotected SELFDESTRUCT Instruction

## Related Detectors

- `proxy-upgrade-unprotected` - Unprotected upgrade functions
- `delegatecall-user-controlled` - User controls delegatecall target
- `fallback-function-shadowing` - Function collision in proxies
- `delegatecall-return-ignored` - Unchecked delegatecall returns

## Severity Justification

**MEDIUM Severity** because:
- Requires specific proxy pattern to be exploitable
- Impact depends on implementation functions
- Well-known pattern with established mitigations
- Often caught in security reviews
- Transparent Proxy pattern widely adopted

However, severity can be HIGH if:
- Implementation has critical unprotected functions
- Large amounts of funds at risk
- No other access control mechanisms
- Contract already deployed and widely used

---

**Last Updated:** 2025-11-11
**Detector Version:** 1.3.4
