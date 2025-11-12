# Delegatecall in Constructor

**Detector ID:** `delegatecall-in-constructor`
**Severity:** MEDIUM
**CWE:** CWE-665 (Improper Initialization)
**Category:** Best Practices, Upgradeable Contracts

## Description

This detector identifies contracts that perform delegatecall operations during construction. Using delegatecall in a constructor introduces significant risks including storage corruption, reentrancy vulnerabilities, user-controlled initialization attacks, and contracts deploying in broken states if initialization fails.

## Vulnerability

Constructors execute only once when a contract is deployed. Performing delegatecall during this critical initialization phase can lead to unpredictable and dangerous behavior because:

1. **Storage is uninitialized**: Delegated code can write to any storage slot before proper initialization
2. **No state guarantees**: Contract state is undefined if delegatecall fails
3. **Reentrancy risk**: Constructor can be reentered before completion
4. **User input**: Constructor parameters often come from untrusted sources
5. **Silent failures**: If delegatecall fails but isn't checked, contract deploys broken

### Attack Vectors

1. **Storage Corruption**: Malicious init logic overwrites critical storage slots
2. **Reentrancy**: Init contract calls back during construction
3. **User-Controlled Target**: User provides malicious init address
4. **Failed Initialization**: Delegatecall fails silently, contract deploys incomplete
5. **Storage Layout Mismatch**: Init code expects different storage layout

### Impact

- **Broken Deployments**: Contracts deploy in invalid states
- **Storage Corruption**: Critical variables overwritten during init
- **Fund Loss**: Ether sent to constructor can be stolen
- **Access Control Bypass**: Owner/admin variables manipulated
- **Unpredictable Behavior**: Contract behavior depends on init code
- **Front-Running**: Attackers can front-run deployment with malicious params

## Vulnerable Code Examples

### Pattern 1: Unchecked Constructor Delegatecall

```solidity
contract UncheckedConstructorDelegatecall {
    address public owner;
    uint256 public value;

    constructor(address initLogic, bytes memory initData) {
        // VULNERABLE: If delegatecall fails, contract still deploys!
        initLogic.delegatecall(initData);

        owner = msg.sender;
    }
}
```

**Risk**: If `initLogic.delegatecall(initData)` fails, the contract deploys anyway but may be in an invalid state. No revert occurs.

### Pattern 2: User-Controlled Constructor Delegatecall

```solidity
contract UserControlledConstructorDelegatecall {
    address public implementation;
    bool public initialized;

    constructor(address userProvidedLogic, bytes memory data) {
        // VULNERABLE: User can provide malicious address!
        (bool success, ) = userProvidedLogic.delegatecall(data);
        require(success, "Init failed");

        implementation = userProvidedLogic;
        initialized = true;
    }
}
```

**Risk**: User controls `userProvidedLogic` parameter. They can deploy with a malicious contract that:
- Overwrites `implementation` with their address
- Sets `initialized` to true prematurely
- Steals any ETH sent to constructor

### Pattern 3: Storage Corruption Risk

```solidity
contract StorageCorruptionConstructor {
    address public admin;  // Slot 0
    uint256 public value;  // Slot 1
    bool public active;    // Slot 2

    constructor(address initContract) {
        // VULNERABLE: initContract can write to any storage slot!
        (bool success, ) = initContract.delegatecall(
            abi.encodeWithSignature("initialize()")
        );
        require(success, "Init failed");

        admin = msg.sender;  // Might be already overwritten by delegatecall
    }
}
```

**Attack**:
```solidity
contract MaliciousInit {
    function initialize() external {
        // Corrupt storage slot 0 (admin variable)
        assembly {
            sstore(0, caller())  // Attacker becomes admin
            sstore(1, 0xdead)    // Corrupt value
        }
    }
}
```

### Pattern 4: Reentrancy During Construction

```solidity
contract ReentrancyConstructorDelegatecall {
    address public token;
    uint256 public balance;

    constructor(address initContract) payable {
        // VULNERABLE: initContract could call back during construction!
        (bool success, ) = initContract.delegatecall{value: msg.value}(
            abi.encodeWithSignature("initialize()")
        );
        require(success, "Init failed");

        balance = address(this).balance;  // Might be wrong due to reentrancy
    }

    function withdraw() external {
        payable(msg.sender).transfer(balance);
        balance = 0;
    }
}
```

**Attack**: Init contract can reenter and call `withdraw()` before constructor completes.

### Pattern 5: Proxy with Constructor Delegatecall

```solidity
contract VulnerableProxyConstructor {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    constructor(address _implementation, bytes memory _data) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, _implementation)
        }

        // VULNERABLE: Delegatecall during construction
        if (_data.length > 0) {
            (bool success, ) = _implementation.delegatecall(_data);
            // VULNERABLE: No rollback if initialization fails!
            require(success, "Initialization failed");
        }
    }

    fallback() external payable {
        bytes32 slot = IMPLEMENTATION_SLOT;
        address impl;
        assembly { impl := sload(slot) }

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

**Risk**: If `_data` triggers complex initialization, storage corruption or reentrancy can occur before proxy is fully deployed.

### Pattern 6: Multiple Constructor Delegatecalls

```solidity
contract MultipleConstructorDelegatecalls {
    address public moduleA;
    address public moduleB;
    bool public initializedA;
    bool public initializedB;

    constructor(address _moduleA, address _moduleB) {
        // VULNERABLE: First delegatecall
        (bool successA, ) = _moduleA.delegatecall(
            abi.encodeWithSignature("initA()")
        );
        require(successA, "Init A failed");
        initializedA = true;
        moduleA = _moduleA;

        // VULNERABLE: Second delegatecall (could interact with first's state)
        (bool successB, ) = _moduleB.delegatecall(
            abi.encodeWithSignature("initB()")
        );
        require(successB, "Init B failed");
        initializedB = true;
        moduleB = _moduleB;
    }
}
```

**Risk**: Second delegatecall can interact with state set by first, leading to unexpected behavior.

### Pattern 7: Constructor Delegatecall Loop

```solidity
contract ConstructorDelegatecallLoop {
    address[] public initializers;
    bool public fullyInitialized;

    constructor(address[] memory _initializers) {
        initializers = _initializers;

        for (uint256 i = 0; i < _initializers.length; i++) {
            // VULNERABLE: Each delegatecall could corrupt state
            (bool success, ) = _initializers[i].delegatecall(
                abi.encodeWithSignature("initialize(uint256)", i)
            );
            require(success, "Init failed");
        }

        fullyInitialized = true;
    }
}
```

**Risk**: Any initializer in the loop can corrupt state, affecting subsequent initializers.

## Secure Implementations

### Solution 1: Direct Initialization (No Delegatecall)

```solidity
contract DirectConstructorInit {
    address public owner;
    uint256 public value;
    bool public initialized;

    event Initialized(address owner, uint256 value);

    // SECURE: Direct initialization, no delegatecall
    constructor(uint256 _value) {
        owner = msg.sender;
        value = _value;
        initialized = true;

        emit Initialized(owner, value);
    }
}
```

**Benefits**:
- No delegatecall risks
- Predictable initialization
- Gas efficient
- Clear initialization logic

### Solution 2: Two-Step Initialization

```solidity
contract SecureConstructor {
    address public owner;
    address public implementation;
    bool private initialized;

    // SECURE: Constructor only sets immutable/basic data
    constructor(address _owner) {
        require(_owner != address(0), "Invalid owner");
        owner = _owner;
    }

    // SECURE: Initialization happens post-deployment
    function initialize(address impl, bytes calldata data) external {
        require(!initialized, "Already initialized");
        require(msg.sender == owner, "Only owner");

        (bool success, ) = impl.delegatecall(data);
        require(success, "Init failed");

        initialized = true;
        implementation = impl;
    }
}
```

**Benefits**:
- Constructor only sets basic state
- Complex initialization happens after deployment
- Can verify contract before initialization
- Reentrancy protection via initialized flag

### Solution 3: Proxy with Post-Deployment Init

```solidity
contract SecureProxyInit {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    bool private initialized;

    // SECURE: Constructor only sets immutable data
    constructor(address _implementation) {
        require(_implementation != address(0), "Invalid implementation");

        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, _implementation)
        }
    }

    // SECURE: Initialize called after deployment (not in constructor)
    function initialize(bytes calldata data) external {
        require(!initialized, "Already initialized");

        bytes32 slot = IMPLEMENTATION_SLOT;
        address impl;
        assembly { impl := sload(slot) }

        (bool success, ) = impl.delegatecall(data);
        require(success, "Initialization failed");

        initialized = true;
    }

    fallback() external payable {
        bytes32 slot = IMPLEMENTATION_SLOT;
        address impl;
        assembly { impl := sload(slot) }

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
- Constructor only sets storage, no delegatecall
- Initialization separate from construction
- Can verify proxy before initializing
- Standard proxy pattern

### Solution 4: Initializable Pattern

```solidity
abstract contract Initializable {
    bool private _initialized;
    bool private _initializing;

    modifier initializer() {
        require(
            _initializing || !_initialized,
            "Already initialized"
        );

        bool isTopLevelCall = !_initializing;
        if (isTopLevelCall) {
            _initializing = true;
            _initialized = true;
        }

        _;

        if (isTopLevelCall) {
            _initializing = false;
        }
    }

    modifier onlyInitializing() {
        require(_initializing, "Not initializing");
        _;
    }
}

contract SecureInitializableContract is Initializable {
    address public owner;
    uint256 public value;

    event Initialized(address owner, uint256 value);

    constructor() {
        // SECURE: Constructor is empty or minimal
    }

    // SECURE: Initialization done post-deployment
    function initialize(address _owner, uint256 _value) external initializer {
        owner = _owner;
        value = _value;

        emit Initialized(_owner, _value);
    }
}
```

**Benefits**:
- OpenZeppelin-style initializer pattern
- Reentrancy protection
- Hierarchical initialization support
- Widely adopted and audited

### Solution 5: Immutable Constructor Pattern

```solidity
contract ImmutableConstructorInit {
    address public immutable owner;
    uint256 public immutable createdAt;
    address public immutable factory;

    // SECURE: All immutable values set in constructor
    constructor(address _owner, uint256 _value) {
        owner = _owner;
        createdAt = block.timestamp;
        factory = msg.sender;
    }
}
```

**Benefits**:
- Only immutable values in constructor
- No storage writes (gas efficient)
- No delegatecall risks
- Clear separation of concerns

## Detection Strategy

The detector identifies the following patterns:

### 1. **Direct Delegatecall in Constructor**
```solidity
constructor() {
    target.delegatecall(data);  // DETECTED
}
```

### 2. **Assembly Delegatecall in Constructor**
```solidity
constructor() {
    assembly {
        let result := delegatecall(...)  // DETECTED
    }
}
```

### 3. **Specific Risk Patterns**

**Unchecked Return:**
```solidity
constructor() {
    target.delegatecall(data);  // No success check
}
```

**User-Controlled Target:**
```solidity
constructor(address userProvided) {
    userProvided.delegatecall(data);  // User controls target
}
```

**Multiple Delegatecalls:**
```solidity
constructor() {
    for (...) {
        targets[i].delegatecall(...);  // Loop delegatecalls
    }
}
```

**Delegatecall with Value:**
```solidity
constructor() payable {
    target.delegatecall{value: msg.value}(data);  // ETH transfer
}
```

### 4. **Safe Pattern Recognition**

The detector excludes known safe patterns:
- EIP-1967 storage slot setting without delegatecall
- Immutable-only constructors
- Pure assembly without delegatecall

## Real-World Impact

### Historical Vulnerabilities

**OpenZeppelin Upgradeable Contracts (Pre-v4.0)**
Early proxy patterns used constructor delegatecalls. Moved to initialize() pattern after identifying risks.

**Diamond Proxy Vulnerabilities (2021)**
Several diamond proxy implementations had constructor delegatecall issues leading to storage corruption.

### Attack Scenarios

**Scenario 1: Malicious Factory**
```solidity
// Vulnerable contract
constructor(address initLogic, bytes memory data) {
    initLogic.delegatecall(data);
}

// Attack
MaliciousFactory.deploy(attackerInit, maliciousData);
// Deployed contract is compromised from the start
```

**Scenario 2: Front-Running Deployment**
1. Victim deploys contract with init params in mempool
2. Attacker sees transaction
3. Attacker frontruns with higher gas, using same factory
4. Attacker's malicious version deploys first
5. Users interact with malicious contract thinking it's legitimate

**Scenario 3: Storage Slot Collision**
```solidity
// Constructor expects init code to set slot 1
constructor(address init) {
    init.delegatecall(abi.encodeWithSignature("setConfig()"));
    owner = msg.sender;  // Slot 0
}

// Malicious init writes to slot 0 instead
function setConfig() external {
    assembly { sstore(0, caller()) }  // Overwrites owner
}
```

## Best Practices

### 1. **Avoid Delegatecall in Constructor**
```solidity
// BAD
constructor() {
    logic.delegatecall(data);
}

// GOOD
constructor() {
    owner = msg.sender;  // Direct initialization
}
```

### 2. **Use Two-Step Initialization**
```solidity
constructor() {
    // Minimal setup only
}

function initialize() external {
    require(!initialized);
    // Complex initialization here
    initialized = true;
}
```

### 3. **Validate All Constructor Parameters**
```solidity
constructor(address _impl) {
    require(_impl != address(0), "Zero address");
    require(_impl.code.length > 0, "Not a contract");
    implementation = _impl;
}
```

### 4. **Use Initializer Modifier**
```solidity
function initialize() external initializer {
    // Protected from reentrancy and multiple calls
}
```

### 5. **Set Immutables in Constructor**
```solidity
address public immutable factory;
uint256 public immutable deployedAt;

constructor() {
    factory = msg.sender;
    deployedAt = block.timestamp;
}
```

### 6. **Document Initialization Flow**
```solidity
/// @notice Two-step initialization required
/// @dev 1. Deploy contract 2. Call initialize() 3. Verify state
constructor() {
    // Minimal setup
}
```

## Mitigation Checklist

- [ ] No delegatecall in constructor
- [ ] Use two-step initialization (constructor + initialize())
- [ ] Implement initializer pattern for reentrancy protection
- [ ] Validate all constructor parameters
- [ ] Set only immutable values in constructor
- [ ] Document initialization sequence
- [ ] Test failed initialization scenarios
- [ ] Verify state after deployment and before use
- [ ] Use factory pattern with verification
- [ ] Emit initialization events

## Testing Recommendations

### Unit Tests
```solidity
function testConstructorDoesNotDelegatecall() public {
    // Verify constructor only sets basic state
    // No external calls during construction
}

function testInitializeOnce() public {
    contract.initialize();
    vm.expectRevert("Already initialized");
    contract.initialize();  // Should fail
}

function testInitializeReentrancy() public {
    // Attempt reentrancy during initialize
    // Should be protected by initializer modifier
}
```

### Integration Tests
- Deploy and verify state before initialization
- Test initialization with various parameters
- Test failed initialization scenarios
- Verify no state corruption possible

### Fuzzing
```solidity
function testFuzzConstructorParams(address init, bytes calldata data) public {
    // Should not accept arbitrary init addresses
    // Should validate all parameters
}
```

## References

- **CWE-665**: Improper Initialization
- **SWC-112**: Delegatecall to Untrusted Callee
- **OpenZeppelin**: Initializable Pattern
- **EIP-1822**: Universal Upgradeable Proxy Standard (UUPS)
- **EIP-1967**: Standard Proxy Storage Slots

## Related Detectors

- `delegatecall-user-controlled` - User input controls delegatecall target
- `delegatecall-untrusted-library` - Mutable library addresses
- `proxy-upgrade-unprotected` - Unprotected proxy upgrades
- `delegatecall-return-ignored` - Unchecked delegatecall returns

## Severity Justification

**MEDIUM Severity** because:
- Requires specific deployment patterns to exploit
- Often caught in testing if initialization fails
- Mitigations well-established (two-step init)
- Less common than other delegatecall issues
- Impact depends on init code complexity

However, severity increases to HIGH if:
- User controls constructor parameters
- Constructor handles valuable assets
- No post-deployment verification
- Used in factory pattern with public access

---

**Last Updated:** 2025-11-11
**Detector Version:** 1.3.4
