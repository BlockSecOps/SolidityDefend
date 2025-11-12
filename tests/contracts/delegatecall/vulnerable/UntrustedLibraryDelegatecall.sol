// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title UntrustedLibraryDelegatecall
 * @notice VULNERABLE: Delegatecall to mutable library addresses
 * @dev This contract demonstrates the vulnerability of performing delegatecall
 *      to library addresses that can be changed, allowing code substitution attacks.
 *
 * Vulnerability: CWE-494 (Download of Code Without Integrity Check)
 * Severity: HIGH
 * Impact: Code substitution, malicious logic injection, fund theft
 *
 * When library addresses are mutable:
 * 1. Owner/admin can replace library with malicious code
 * 2. No version pinning or integrity checking
 * 3. Users trust library logic that can change at any time
 * 4. Silent upgrades without user consent
 *
 * Real-world impact:
 * - Library upgrade attacks where admin goes rogue
 * - Compromised admin keys lead to malicious library substitution
 * - No user protection against code changes
 *
 * Attack scenario:
 * 1. Contract uses library for critical operations
 * 2. Admin/attacker changes library address to malicious contract
 * 3. Next delegatecall executes attacker's code
 * 4. Funds drained, state corrupted
 */

/**
 * @notice VULNERABLE: Mutable library address in storage
 */
contract MutableLibraryDelegatecall {
    address public mathLibrary;  // VULNERABLE: Can be changed!
    address public owner;

    constructor(address _library) {
        mathLibrary = _library;
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: Library address can be updated
     */
    function setLibrary(address newLibrary) external {
        require(msg.sender == owner, "Only owner");
        // VULNERABLE: Owner can replace with malicious library
        mathLibrary = newLibrary;
    }

    /**
     * @notice Uses mutable library address
     */
    function calculate(bytes calldata data) external returns (uint256) {
        // VULNERABLE: Library address from storage (mutable)
        (bool success, bytes memory result) = mathLibrary.delegatecall(data);
        require(success, "Library call failed");
        return abi.decode(result, (uint256));
    }
}

/**
 * @notice VULNERABLE: Dynamic library selection from mapping
 */
contract DynamicLibraryMapping {
    mapping(string => address) public libraries;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: Anyone with owner access can add/change libraries
     */
    function registerLibrary(string memory name, address library) external {
        require(msg.sender == owner, "Only owner");
        // VULNERABLE: Libraries can be added/changed anytime
        libraries[name] = library;
    }

    /**
     * @notice VULNERABLE: Uses library from mutable mapping
     */
    function executeLibrary(string memory name, bytes memory data) external {
        address lib = libraries[name];
        require(lib != address(0), "Library not found");

        // VULNERABLE: Library address can change between calls
        (bool success, ) = lib.delegatecall(data);
        require(success, "Call failed");
    }
}

/**
 * @notice VULNERABLE: Array of mutable library addresses
 */
contract LibraryArray {
    address[] public libraries;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function addLibrary(address lib) external {
        require(msg.sender == owner, "Only owner");
        libraries.push(lib);
    }

    /**
     * @notice VULNERABLE: Can replace library in array
     */
    function replaceLibrary(uint256 index, address newLib) external {
        require(msg.sender == owner, "Only owner");
        // VULNERABLE: Libraries can be swapped out
        libraries[index] = newLib;
    }

    /**
     * @notice Uses library from mutable array
     */
    function executeLibrary(uint256 index, bytes memory data) external {
        require(index < libraries.length, "Invalid index");

        // VULNERABLE: Library can be changed before execution
        (bool success, ) = libraries[index].delegatecall(data);
        require(success, "Call failed");
    }
}

/**
 * @notice VULNERABLE: Proxy with mutable implementation
 */
contract MutableImplementationProxy {
    address public implementation;  // VULNERABLE: Not immutable!

    constructor(address _implementation) {
        implementation = _implementation;
    }

    /**
     * @notice VULNERABLE: Implementation can be changed without restrictions
     */
    function setImplementation(address newImpl) external {
        // VULNERABLE: No access control, anyone can change!
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

/**
 * @notice VULNERABLE: Storage-based library versioning without integrity
 */
contract VersionedLibraryNoIntegrity {
    mapping(uint256 => address) public libraryVersions;
    uint256 public currentVersion;
    address public owner;

    constructor(address initialLibrary) {
        owner = msg.sender;
        libraryVersions[1] = initialLibrary;
        currentVersion = 1;
    }

    /**
     * @notice VULNERABLE: New versions can be added freely
     */
    function addVersion(address newLibrary) external {
        require(msg.sender == owner, "Only owner");
        currentVersion++;
        // VULNERABLE: No integrity check on new library
        libraryVersions[currentVersion] = newLibrary;
    }

    /**
     * @notice VULNERABLE: Uses version from storage
     */
    function execute(bytes memory data) external {
        address lib = libraryVersions[currentVersion];
        require(lib != address(0), "Version not found");

        // VULNERABLE: Library can change between calls
        (bool success, ) = lib.delegatecall(data);
        require(success, "Execution failed");
    }
}

/**
 * @notice VULNERABLE: Conditional library selection from storage
 */
contract ConditionalLibrarySelection {
    address public productionLibrary;
    address public testLibrary;
    bool public useTestLibrary;
    address public owner;

    constructor(address _prod, address _test) {
        productionLibrary = _prod;
        testLibrary = _test;
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: Can switch between libraries
     */
    function toggleTestMode() external {
        require(msg.sender == owner, "Only owner");
        useTestLibrary = !useTestLibrary;
    }

    /**
     * @notice VULNERABLE: Can update either library
     */
    function updateLibrary(bool isTest, address newLib) external {
        require(msg.sender == owner, "Only owner");
        if (isTest) {
            testLibrary = newLib;
        } else {
            productionLibrary = newLib;
        }
    }

    /**
     * @notice Uses conditionally selected library from storage
     */
    function execute(bytes memory data) external {
        // VULNERABLE: Library selection from mutable storage
        address lib = useTestLibrary ? testLibrary : productionLibrary;
        (bool success, ) = lib.delegatecall(data);
        require(success, "Call failed");
    }
}

/**
 * @notice VULNERABLE: Library address loaded from external source
 */
contract ExternalLibraryLoader {
    address public libraryRegistry;

    constructor(address _registry) {
        libraryRegistry = _registry;
    }

    /**
     * @notice VULNERABLE: Registry can be changed
     */
    function setRegistry(address newRegistry) external {
        libraryRegistry = newRegistry;
    }

    /**
     * @notice VULNERABLE: Library address loaded from external contract
     */
    function executeFromRegistry(string memory name, bytes memory data) external {
        // VULNERABLE: Loads library address from mutable registry
        address lib = ILibraryRegistry(libraryRegistry).getLibrary(name);
        require(lib != address(0), "Library not found");

        (bool success, ) = lib.delegatecall(data);
        require(success, "Execution failed");
    }
}

interface ILibraryRegistry {
    function getLibrary(string memory name) external view returns (address);
}

/**
 * @notice VULNERABLE: Hot-swappable library pattern
 */
contract HotSwappableLibrary {
    address public activeLibrary;
    address public pendingLibrary;
    uint256 public swapDelay = 1 days;
    uint256 public swapTimestamp;
    address public owner;

    constructor(address _library) {
        activeLibrary = _library;
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: Initiate library swap
     */
    function initiateSwap(address newLibrary) external {
        require(msg.sender == owner, "Only owner");
        pendingLibrary = newLibrary;
        swapTimestamp = block.timestamp + swapDelay;
    }

    /**
     * @notice VULNERABLE: Complete library swap
     */
    function completeSwap() external {
        require(msg.sender == owner, "Only owner");
        require(block.timestamp >= swapTimestamp, "Too early");
        require(pendingLibrary != address(0), "No pending swap");

        // VULNERABLE: Library gets swapped without user consent
        activeLibrary = pendingLibrary;
        pendingLibrary = address(0);
    }

    function execute(bytes memory data) external {
        // VULNERABLE: Uses mutable active library
        (bool success, ) = activeLibrary.delegatecall(data);
        require(success, "Execution failed");
    }
}

/**
 * @notice VULNERABLE: Multi-signature library update
 */
contract MultiSigLibraryUpdate {
    address public library;
    address[] public signers;
    mapping(address => bool) public hasApproved;
    address public pendingLibrary;
    uint256 public approvalCount;
    uint256 public requiredApprovals = 2;

    constructor(address _library, address[] memory _signers) {
        library = _library;
        signers = _signers;
    }

    /**
     * @notice VULNERABLE: Even with multi-sig, library is mutable
     */
    function proposeLibraryUpdate(address newLibrary) external {
        pendingLibrary = newLibrary;
        approvalCount = 0;
        for (uint256 i = 0; i < signers.length; i++) {
            hasApproved[signers[i]] = false;
        }
    }

    function approve() external {
        require(!hasApproved[msg.sender], "Already approved");
        hasApproved[msg.sender] = true;
        approvalCount++;

        if (approvalCount >= requiredApprovals) {
            // VULNERABLE: Library still gets replaced
            library = pendingLibrary;
        }
    }

    function execute(bytes memory data) external {
        // VULNERABLE: Uses potentially changed library
        (bool success, ) = library.delegatecall(data);
        require(success, "Execution failed");
    }
}

/**
 * @notice ATTACK CONTRACT - Malicious library
 */
contract MaliciousLibrary {
    /**
     * @notice Malicious function that steals funds
     */
    function calculate(uint256) external returns (uint256) {
        // Drain all ETH to attacker
        payable(msg.sender).transfer(address(this).balance);
        return 0;
    }

    /**
     * @notice Malicious function that corrupts state
     */
    function process(bytes memory) external {
        // Corrupt storage
        assembly {
            sstore(0, 0xdead)
            sstore(1, 0xbeef)
        }
    }
}
