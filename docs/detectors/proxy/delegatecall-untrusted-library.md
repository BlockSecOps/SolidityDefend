# Delegatecall to Untrusted Library

**Detector ID:** `delegatecall-untrusted-library`
**Severity:** HIGH
**CWE:** CWE-494 (Download of Code Without Integrity Check)
**Category:** External Calls, Best Practices

## Description

This detector identifies contracts that perform delegatecall to library addresses stored in mutable storage variables. When library addresses can be changed after deployment, it creates a code substitution vulnerability where the contract owner or an attacker with sufficient privileges can replace trusted library code with malicious implementations.

## Vulnerability

When a contract uses delegatecall to invoke library functions, the library code executes in the context of the calling contract, having full access to the contract's storage, balance, and state. If the library address is mutable (stored in a regular storage variable rather than being `immutable` or `constant`), several critical risks emerge:

### Attack Vectors

1. **Library Substitution**: Owner or admin can replace the library with malicious code
2. **Compromised Keys**: If admin keys are compromised, attacker gains code execution
3. **Governance Attacks**: Malicious proposals can change library addresses
4. **Silent Upgrades**: Users have no protection against unauthorized code changes
5. **No Integrity Checks**: No verification that replacement libraries match expected behavior

### Impact

- **Fund Theft**: Malicious library can drain all contract funds
- **Storage Corruption**: Arbitrary storage slot manipulation
- **Access Control Bypass**: Override ownership and permissions
- **State Manipulation**: Alter critical contract state
- **Trust Violation**: Users expect immutable library code

## Vulnerable Code Examples

### Pattern 1: Mutable Library Address

```solidity
contract MutableLibraryDelegatecall {
    address public mathLibrary;  // VULNERABLE: Can be changed!
    address public owner;

    constructor(address _library) {
        mathLibrary = _library;
        owner = msg.sender;
    }

    // VULNERABLE: Owner can replace with malicious library
    function setLibrary(address newLibrary) external {
        require(msg.sender == owner, "Only owner");
        mathLibrary = newLibrary;
    }

    function calculate(bytes calldata data) external returns (uint256) {
        // VULNERABLE: Uses mutable library address
        (bool success, bytes memory result) = mathLibrary.delegatecall(data);
        require(success, "Library call failed");
        return abi.decode(result, (uint256));
    }
}
```

**Risk**: Owner can call `setLibrary()` with a malicious contract address, then any call to `calculate()` will execute attacker's code.

### Pattern 2: Dynamic Library Mapping

```solidity
contract DynamicLibraryMapping {
    mapping(string => address) public libraries;
    address public owner;

    // VULNERABLE: Libraries can be added/changed anytime
    function registerLibrary(string memory name, address library) external {
        require(msg.sender == owner, "Only owner");
        libraries[name] = library;
    }

    // VULNERABLE: Uses library from mutable mapping
    function executeLibrary(string memory name, bytes memory data) external {
        address lib = libraries[name];
        require(lib != address(0), "Library not found");

        (bool success, ) = lib.delegatecall(data);
        require(success, "Call failed");
    }
}
```

**Risk**: Owner can change any library in the mapping between user transactions.

### Pattern 3: Proxy with Mutable Implementation

```solidity
contract MutableImplementationProxy {
    address public implementation;  // VULNERABLE: Not immutable!

    constructor(address _implementation) {
        implementation = _implementation;
    }

    // VULNERABLE: No access control!
    function setImplementation(address newImpl) external {
        implementation = newImpl;
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

**Risk**: Anyone can call `setImplementation()` and take complete control.

### Pattern 4: Version System Without Integrity

```solidity
contract VersionedLibraryNoIntegrity {
    mapping(uint256 => address) public libraryVersions;
    uint256 public currentVersion;
    address public owner;

    // VULNERABLE: New versions can be added freely
    function addVersion(address newLibrary) external {
        require(msg.sender == owner, "Only owner");
        currentVersion++;
        libraryVersions[currentVersion] = newLibrary;  // No integrity check
    }

    function execute(bytes memory data) external {
        address lib = libraryVersions[currentVersion];
        require(lib != address(0), "Version not found");

        // VULNERABLE: Library can change between calls
        (bool success, ) = lib.delegatecall(data);
        require(success, "Execution failed");
    }
}
```

**Risk**: No verification that new library versions maintain expected interface or behavior.

## Secure Implementations

### Solution 1: Immutable Library Address

```solidity
contract ImmutableLibraryDelegatecall {
    address public immutable mathLibrary;  // SECURE: Cannot be changed!

    event LibraryExecuted(bytes data, bytes result);

    constructor(address _library) {
        require(_library != address(0), "Invalid library");
        mathLibrary = _library;  // SECURE: Set once, immutable forever
    }

    function calculate(bytes calldata data) external returns (uint256) {
        // SECURE: Library address is immutable
        (bool success, bytes memory result) = mathLibrary.delegatecall(data);
        require(success, "Library call failed");

        emit LibraryExecuted(data, result);
        return abi.decode(result, (uint256));
    }
}
```

**Benefits**:
- Library address cannot be changed after deployment
- Users can trust the library code won't be substituted
- No admin privilege escalation possible

### Solution 2: Constant Library Address

```solidity
contract ConstantLibraryDelegatecall {
    // SECURE: Known at compile time, truly immutable
    address public constant MATH_LIBRARY = 0x1234567890123456789012345678901234567890;

    function calculate(bytes memory data) external returns (uint256) {
        // SECURE: Uses constant address
        (bool success, bytes memory result) = MATH_LIBRARY.delegatecall(data);
        require(success, "Library call failed");
        return abi.decode(result, (uint256));
    }
}
```

**Benefits**:
- Compile-time constant, no storage slot used
- Absolute guarantee of immutability
- Gas savings from not reading storage

### Solution 3: Code Hash Verification

```solidity
contract IntegrityCheckedLibrary {
    address public immutable library;
    bytes32 public immutable expectedCodeHash;

    event IntegrityVerified(address library, bytes32 codeHash);

    constructor(address _library, bytes32 _expectedCodeHash) {
        require(_library != address(0), "Invalid library");

        // SECURE: Verify code hash at deployment
        bytes32 actualCodeHash;
        assembly {
            actualCodeHash := extcodehash(_library)
        }
        require(actualCodeHash == _expectedCodeHash, "Code hash mismatch");

        library = _library;
        expectedCodeHash = _expectedCodeHash;

        emit IntegrityVerified(_library, actualCodeHash);
    }

    function execute(bytes memory data) external returns (bytes memory) {
        // SECURE: Library is immutable and verified
        (bool success, bytes memory result) = library.delegatecall(data);
        require(success, "Execution failed");
        return result;
    }

    // Allow anyone to verify library integrity
    function verifyIntegrity() external view returns (bool) {
        bytes32 currentCodeHash;
        assembly {
            currentCodeHash := extcodehash(sload(library.slot))
        }
        return currentCodeHash == expectedCodeHash;
    }
}
```

**Benefits**:
- Library address is immutable
- Code hash verification at deployment
- Public verification function for transparency

### Solution 4: UUPS with Immutable Proxy

```solidity
contract ImmutableUUPSProxy {
    // SECURE: Implementation set once, upgrades handled in implementation
    address public immutable initialImplementation;

    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    constructor(address _implementation, bytes memory _data) {
        require(_implementation != address(0), "Invalid implementation");

        initialImplementation = _implementation;
        _setImplementation(_implementation);

        if (_data.length > 0) {
            (bool success, ) = _implementation.delegatecall(_data);
            require(success, "Initialization failed");
        }
    }

    function _setImplementation(address newImplementation) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { sstore(slot, newImplementation) }
    }

    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { impl := sload(slot) }
    }

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
}
```

**Benefits**:
- Initial implementation immutable
- Upgrade logic controlled by implementation, not proxy
- UUPS pattern for controlled upgradeability

## Detection Strategy

The detector identifies the following patterns:

### 1. **Mutable Storage Variables**
- Library addresses declared as regular `address` (not `immutable` or `constant`)
- State variables that can be changed via setter functions
- No immutability guarantees

### 2. **Dynamic Address Sources**
- Mapping lookups: `libraries[name].delegatecall(...)`
- Array access: `libraries[index].delegatecall(...)`
- External registry calls: `IRegistry(registry).getLibrary(...).delegatecall(...)`

### 3. **Conditional Library Selection**
- Ternary operators selecting from storage: `useTest ? testLib : prodLib`
- Storage flags controlling library selection
- Runtime library switching based on contract state

### 4. **Storage-to-Local Delegation**
```solidity
function execute() external {
    address lib = libraryFromStorage;  // Loaded from storage
    lib.delegatecall(data);  // Delegatecall to mutable address
}
```

## Real-World Impact

### Historical Vulnerabilities

**Parity Wallet Hack (2017)**
While not exactly this pattern, demonstrated risks of delegatecall to changeable code. Library self-destruct led to $150M+ loss.

**DeFi Proxy Exploits (2020-2024)**
Multiple incidents where compromised admin keys allowed implementation swaps, leading to fund drainage.

### Attack Scenarios

**Scenario 1: Admin Key Compromise**
1. Attacker compromises owner private key
2. Calls `setLibrary()` with malicious contract
3. Malicious library drains all funds on next user interaction
4. Contract appears normal but executes attacker code

**Scenario 2: Governance Attack**
1. Attacker gains governance votes
2. Proposes library address change
3. Malicious library approved through governance
4. Contract behavior silently changes

**Scenario 3: Time-Delayed Attack**
1. Owner appears benign for months
2. After gaining trust and TVL, owner goes rogue
3. Swaps library for malicious version
4. Drains all funds before users can react

## Best Practices

### 1. **Use Immutable When Possible**
```solidity
address public immutable library;  // Best choice

constructor(address _library) {
    library = _library;  // Set once, never changes
}
```

### 2. **Use Constant for Known Addresses**
```solidity
address public constant LIBRARY = 0x...;  // Compile-time constant
```

### 3. **Verify Library Code Hash**
```solidity
bytes32 expectedHash = 0x...;
require(address(lib).codehash == expectedHash, "Invalid library");
```

### 4. **Document Library Trust Model**
```solidity
/// @notice Library address is immutable and verified at deployment
/// @dev Code hash: 0xabc...def
address public immutable library;
```

### 5. **Controlled Upgradeability**
If upgrades are necessary, use established patterns:
- UUPS (upgrade logic in implementation)
- Transparent Proxy (admin separation)
- Timelock + multisig for changes
- Off-chain governance verification

### 6. **Avoid Multi-Sig Bypass**
Even with multi-sig, mutable libraries create risk:
```solidity
// Still risky even with multisig
function updateLibrary(address newLib) external onlyMultiSig {
    library = newLib;  // Mutable storage
}
```

Better: Make immutable and deploy new proxy if upgrade needed.

## Mitigation Checklist

- [ ] All library addresses marked `immutable` or `constant`
- [ ] No setter functions for library addresses
- [ ] Code hash verification at deployment if applicable
- [ ] Library addresses documented in natspec
- [ ] If upgradeability needed, use established proxy patterns
- [ ] Admin operations protected by timelock
- [ ] Multi-sig required for critical operations
- [ ] Emergency pause mechanism separate from library changes
- [ ] User notification system for any protocol changes
- [ ] Code audit of all library contracts

## Testing Recommendations

### Unit Tests
```solidity
function testLibraryIsImmutable() public {
    // Verify no setter function exists
    // Verify variable is immutable
}

function testCodeHashMatches() public {
    bytes32 expected = 0x...;
    assertEq(address(library).codehash, expected);
}
```

### Integration Tests
- Attempt to change library address (should fail)
- Verify delegatecall target is constant
- Test emergency scenarios don't allow library changes

### Fuzz Tests
- Random call data to library
- Verify behavior consistency
- Check for state corruption

## References

- **CWE-494**: Download of Code Without Integrity Check
- **EIP-1967**: Standard Proxy Storage Slots
- **EIP-1822**: Universal Upgradeable Proxy Standard (UUPS)
- **SWC-112**: Delegatecall to Untrusted Callee
- **OWASP Smart Contracts**: Code Injection via Delegatecall

## Related Detectors

- `delegatecall-user-controlled` - User input controls delegatecall target
- `proxy-upgrade-unprotected` - Proxy upgrades without access control
- `delegatecall-in-constructor` - Delegatecall during construction
- `storage-collision` - Storage layout conflicts in upgrades

## Severity Justification

**HIGH Severity** because:
- Direct path to fund theft
- Complete contract control possible
- Silent code substitution
- Trust model violation
- Real-world exploitation history
- Affects entire contract TVL

---

**Last Updated:** 2025-11-11
**Detector Version:** 1.3.4
