# User-Controlled Delegatecall Target

**Detector ID:** `delegatecall-user-controlled`
**Severity:** HIGH
**CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Category:** External Calls, Access Control

## Description

This detector identifies contracts that allow users to control the target address of delegatecall operations. Delegatecall executes code from another contract in the context of the calling contract, granting complete access to storage, balance, and state. When users can specify the delegatecall target, they can execute arbitrary malicious code with full contract privileges.

## Vulnerability

Delegatecall is a powerful but dangerous operation that executes external code while maintaining the calling contract's context (storage, balance, msg.sender, msg.value). This means:

1. **Storage Access**: Delegated code can read/write any storage slot
2. **Fund Control**: Can transfer all contract funds
3. **State Manipulation**: Can modify critical variables (owner, balances, permissions)
4. **Access Control Bypass**: Executes with caller's privileges

When users control the delegatecall target address, they can deploy malicious contracts and execute them with full contract privileges.

### Attack Vectors

1. **Direct User Input**: Function parameter specifies delegatecall target
2. **User-Controlled Storage**: Target loaded from user-modifiable storage
3. **Indirect Control**: Target derived from user input (mapping lookup, calculation)
4. **Proxy Misconfiguration**: Upgradeable proxy with public upgrade function

### Impact

- **Complete Takeover**: Attacker gains full contract control
- **Fund Theft**: All ETH and tokens can be stolen via selfdestruct
- **Storage Corruption**: Critical state variables can be modified
- **Access Control Bypass**: Owner/admin privileges can be seized
- **Irreversible Damage**: Contract can be destroyed or permanently corrupted

## Vulnerable Code Examples

### Pattern 1: Direct User-Controlled Target

```solidity
contract DirectUserControlled {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // CRITICAL VULNERABILITY: User controls target address
    function execute(address target, bytes calldata data) external payable {
        (bool success, ) = target.delegatecall(data);
        require(success, "Execution failed");
    }
}
```

**Attack**:
```solidity
contract MaliciousTarget {
    function attack() external {
        // This executes in victim's context!
        // Steal all funds
        selfdestruct(payable(msg.sender));
    }
}

// Attacker calls: execute(maliciousTarget, abi.encodeWithSignature("attack()"))
// Result: All funds stolen, contract destroyed
```

### Pattern 2: User-Controlled via Storage

```solidity
contract IndirectUserControlled {
    mapping(address => address) public userLibraries;

    function registerLibrary(address lib) external {
        userLibraries[msg.sender] = lib;  // User sets their library
    }

    // VULNERABLE: Delegates to user-registered library
    function executeLibrary(bytes calldata data) external {
        address lib = userLibraries[msg.sender];
        (bool success, ) = lib.delegatecall(data);
        require(success, "Execution failed");
    }
}
```

**Risk**: Users register malicious libraries, then execute them with full privileges.

### Pattern 3: Proxy with Public Upgrade

```solidity
contract VulnerableProxy {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    // VULNERABLE: Anyone can change implementation
    function upgradeTo(address newImplementation) external {
        implementation = newImplementation;  // No access control!
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

**Attack**: Attacker calls `upgradeTo()` with malicious implementation, then uses fallback to execute it.

### Pattern 4: Parameterized Library Selection

```solidity
contract ParameterizedDelegatecall {
    mapping(string => address) public libraries;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function registerLibrary(string memory name, address lib) external {
        require(msg.sender == owner, "Only owner");
        libraries[name] = lib;
    }

    // VULNERABLE: User controls which library via string parameter
    function executeLibrary(string memory name, bytes memory data) external {
        address lib = libraries[name];
        require(lib != address(0), "Library not found");

        (bool success, ) = lib.delegatecall(data);
        require(success, "Execution failed");
    }
}
```

**Risk**: If attacker compromises owner or finds a way to register their own library, they control execution.

### Pattern 5: Module System with User Selection

```solidity
contract ModularContract {
    address[] public modules;

    function addModule(address module) external {
        modules.push(module);  // No validation!
    }

    // VULNERABLE: User selects module by index
    function executeModule(uint256 index, bytes calldata data) external {
        require(index < modules.length, "Invalid index");

        (bool success, ) = modules[index].delegatecall(data);
        require(success, "Module execution failed");
    }
}
```

**Attack**: Attacker adds malicious module, then executes it.

## Secure Implementations

### Solution 1: Whitelist of Trusted Targets

```solidity
contract WhitelistedDelegatecall {
    mapping(address => bool) public trustedLibraries;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Only owner can whitelist libraries
    function addTrustedLibrary(address lib) external {
        require(msg.sender == owner, "Only owner");
        require(lib != address(0), "Invalid address");
        trustedLibraries[lib] = true;
    }

    function removeTrustedLibrary(address lib) external {
        require(msg.sender == owner, "Only owner");
        trustedLibraries[lib] = false;
    }

    // SECURE: Only whitelisted targets allowed
    function execute(address target, bytes calldata data) external {
        require(trustedLibraries[target], "Target not trusted");

        (bool success, ) = target.delegatecall(data);
        require(success, "Execution failed");
    }
}
```

### Solution 2: Immutable Library Address

```solidity
contract ImmutableLibrary {
    address public immutable library;  // SECURE: Cannot be changed

    constructor(address _library) {
        require(_library != address(0), "Invalid library");
        library = _library;
    }

    // SECURE: Only delegates to immutable library
    function execute(bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = library.delegatecall(data);
        require(success, "Execution failed");
        return result;
    }
}
```

### Solution 3: Protected Proxy Upgrade

```solidity
contract SecureProxy {
    address private _implementation;
    address public owner;

    event Upgraded(address indexed implementation);

    constructor(address implementation_) {
        require(implementation_ != address(0), "Invalid implementation");
        _implementation = implementation_;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    // SECURE: Only owner can upgrade, with validation
    function upgradeTo(address newImplementation) external onlyOwner {
        require(newImplementation != address(0), "Invalid address");
        require(newImplementation != _implementation, "Same implementation");

        // Verify it's a contract
        uint256 size;
        assembly { size := extcodesize(newImplementation) }
        require(size > 0, "Not a contract");

        _implementation = newImplementation;
        emit Upgraded(newImplementation);
    }

    fallback() external payable {
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

    receive() external payable {}
}
```

### Solution 4: Function Selector Routing

```solidity
contract SelectorBasedDelegatecall {
    mapping(bytes4 => address) public selectorToLibrary;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Only owner maps selectors to libraries
    function registerSelector(bytes4 selector, address lib) external {
        require(msg.sender == owner, "Only owner");
        require(lib != address(0), "Invalid library");
        selectorToLibrary[selector] = lib;
    }

    // SECURE: Uses msg.sig, not user input
    fallback() external payable {
        address lib = selectorToLibrary[msg.sig];
        require(lib != address(0), "Function not supported");

        (bool success, bytes memory result) = lib.delegatecall(msg.data);
        require(success, "Execution failed");

        assembly {
            return(add(result, 32), mload(result))
        }
    }
}
```

### Solution 5: Timelock for Upgrades

```solidity
contract TimelockProxy {
    address public implementation;
    address public pendingImplementation;
    uint256 public upgradeTimestamp;
    uint256 public constant UPGRADE_DELAY = 2 days;
    address public owner;

    event UpgradeScheduled(address indexed newImplementation, uint256 timestamp);
    event UpgradeExecuted(address indexed newImplementation);

    constructor(address _implementation) {
        require(_implementation != address(0), "Invalid implementation");
        implementation = _implementation;
        owner = msg.sender;
    }

    // Step 1: Schedule upgrade (starts timelock)
    function scheduleUpgrade(address newImplementation) external {
        require(msg.sender == owner, "Only owner");
        require(newImplementation != address(0), "Invalid address");

        pendingImplementation = newImplementation;
        upgradeTimestamp = block.timestamp + UPGRADE_DELAY;

        emit UpgradeScheduled(newImplementation, upgradeTimestamp);
    }

    // Step 2: Execute after delay
    function executeUpgrade() external {
        require(msg.sender == owner, "Only owner");
        require(pendingImplementation != address(0), "No pending upgrade");
        require(block.timestamp >= upgradeTimestamp, "Upgrade not ready");

        implementation = pendingImplementation;
        pendingImplementation = address(0);
        upgradeTimestamp = 0;

        emit UpgradeExecuted(implementation);
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

## Detection Strategy

The detector identifies the following patterns:

### 1. **Function Parameters as Targets**
```solidity
function execute(address target, bytes calldata data) external {
    target.delegatecall(data);  // DETECTED: target is parameter
}
```

### 2. **User-Modifiable Storage**
```solidity
mapping(address => address) public userLibs;

function execute() external {
    address lib = userLibs[msg.sender];  // User-controlled storage
    lib.delegatecall(data);  // DETECTED
}
```

### 3. **Public Upgrade Functions**
```solidity
function upgradeTo(address newImpl) external {  // No access control
    implementation = newImpl;
}
```

### 4. **Calculated Targets from User Input**
```solidity
function execute(uint256 index) external {
    address target = libraries[index];  // Index from user
    target.delegatecall(data);  // DETECTED
}
```

## Real-World Impact

### Historical Vulnerabilities

**Parity Wallet Hack (2017)**
- **Loss**: $280M+ worth of ETH frozen
- **Cause**: Delegatecall to user-controllable library
- **Impact**: Multi-sig wallets permanently frozen
- **Lesson**: Never allow users to control delegatecall targets

**Multiple DeFi Exploits (2020-2024)**
- **Pattern**: Unprotected proxy upgrades
- **Common Attack**: Replace implementation with malicious contract
- **Impact**: Millions in losses across multiple protocols

### Attack Scenarios

**Scenario 1: Direct Execution**
1. User deploys `MaliciousContract` with `selfdestruct`
2. Calls `execute(maliciousContract, abi.encodeWithSignature("destroy()"))`
3. All funds sent to attacker
4. Contract destroyed

**Scenario 2: State Corruption**
1. Attacker analyzes storage layout
2. Deploys contract that writes to critical slots
3. Executes via delegatecall
4. Takes over admin/owner role
5. Drains funds via legitimate functions

**Scenario 3: Proxy Takeover**
1. Finds unprotected `upgradeTo()` function
2. Deploys malicious implementation
3. Calls `upgradeTo(maliciousImpl)`
4. All proxy users now interact with malicious code

## Best Practices

### 1. **Never Allow User-Controlled Targets**
```solidity
// BAD
function execute(address target) external { ... }

// GOOD
address public immutable library;
function execute() external { library.delegatecall(...); }
```

### 2. **Use Whitelists for Multiple Targets**
```solidity
mapping(address => bool) public trustedLibraries;

function execute(address target) external {
    require(trustedLibraries[target], "Not trusted");
    target.delegatecall(data);
}
```

### 3. **Protect Upgrade Functions**
```solidity
function upgradeTo(address newImpl) external onlyOwner {
    require(newImpl != address(0));
    implementation = newImpl;
}
```

### 4. **Use Timelocks for Critical Operations**
- Announce upgrades in advance
- Allow users to exit before upgrade
- Provide transparency

### 5. **Prefer Regular Calls When Possible**
```solidity
// Instead of delegatecall, use regular call if context not needed
(bool success, bytes memory result) = library.call(data);
```

### 6. **Implement Multi-Sig for Upgrades**
```solidity
// Require multiple signatures for proxy upgrades
function upgradeTo(address newImpl) external onlyMultiSig {
    implementation = newImpl;
}
```

## Mitigation Checklist

- [ ] No user input determines delegatecall target
- [ ] All delegatecall targets are immutable or whitelisted
- [ ] Upgrade functions protected by access control
- [ ] Multi-sig required for critical operations
- [ ] Timelock implemented for upgrades
- [ ] Target validation (non-zero, contract exists)
- [ ] Events emitted for all delegatecalls
- [ ] Regular security audits of delegatecall usage
- [ ] Documentation of all delegatecall patterns
- [ ] Emergency pause mechanism

## Testing Recommendations

### Unit Tests
```solidity
function testUserCannotControlTarget() public {
    vm.expectRevert("Not trusted");
    contract.execute(attackerAddress, data);
}

function testOnlyOwnerCanUpgrade() public {
    vm.prank(attacker);
    vm.expectRevert("Only owner");
    proxy.upgradeTo(maliciousImpl);
}

function testWhitelistEnforced() public {
    address untrusted = address(0x123);
    vm.expectRevert("Target not trusted");
    contract.execute(untrusted, data);
}
```

### Integration Tests
- Test upgrade process end-to-end
- Verify timelock delays work correctly
- Test multi-sig approval flow
- Validate whitelist management

### Fuzz Testing
```solidity
function testFuzzDelegatecallTarget(address target) public {
    // Should reject all non-whitelisted addresses
    if (!trustedLibraries[target]) {
        vm.expectRevert();
    }
    contract.execute(target, data);
}
```

## References

- **CWE-829**: Inclusion of Functionality from Untrusted Control Sphere
- **SWC-112**: Delegatecall to Untrusted Callee
- **Parity Wallet Hack**: Post-mortem analysis
- **EIP-1967**: Standard Proxy Storage Slots
- **OpenZeppelin**: Proxy patterns and best practices

## Related Detectors

- `delegatecall-untrusted-library` - Mutable library addresses
- `proxy-upgrade-unprotected` - Unprotected proxy upgrades
- `delegatecall-in-constructor` - Constructor delegatecalls
- `delegatecall-return-ignored` - Unchecked delegatecall returns

## Severity Justification

**HIGH Severity** because:
- Direct path to complete contract takeover
- Fund theft possible
- Trivially exploitable (attacker just needs to deploy malicious contract)
- Affects all contract funds and state
- Real-world precedent (Parity hack)
- Common in vulnerable proxy patterns
- Irreversible damage possible

---

**Last Updated:** 2025-11-11
**Detector Version:** 1.3.4
