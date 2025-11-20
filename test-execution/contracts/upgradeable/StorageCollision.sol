// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title StorageCollision
 * @notice Test contract for storage collision vulnerabilities in upgrades
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. storage-layout-incompatibility - V2 changes storage layout from V1
 * 2. storage-gap-missing - No storage gap for future upgrades
 * 3. variable-reordering - Variables reordered between versions
 *
 * TEST CATEGORY: upgradeable
 * SEVERITY: critical
 * REFERENCE: OpenZeppelin Upgrades, Storage Layout
 */

contract ImplementationV1 {
    // Initial storage layout
    address public owner;           // Slot 0
    uint256 public totalSupply;     // Slot 1
    mapping(address => uint256) public balances;  // Slot 2
    bool public paused;             // Slot 3

    function initialize(address _owner) public {
        owner = _owner;
        totalSupply = 0;
        paused = false;
    }

    function mint(address to, uint256 amount) public {
        require(msg.sender == owner, "Not owner");
        balances[to] += amount;
        totalSupply += amount;
    }
}

/**
 * @title ImplementationV2Broken
 * @notice VULNERABLE: Storage layout incompatible with V1
 */
contract ImplementationV2Broken {
    // VULNERABILITY 1: New variable inserted before existing ones
    // Expected: storage-layout-incompatibility (CRITICAL)
    uint256 public newFeature;      // Slot 0 - BREAKS EVERYTHING!

    address public owner;           // Slot 1 - WAS Slot 0!
    uint256 public totalSupply;     // Slot 2 - WAS Slot 1!
    mapping(address => uint256) public balances;  // Slot 3 - WAS Slot 2!
    bool public paused;             // Slot 4 - WAS Slot 3!

    // All existing data is now in wrong slots!

    function setNewFeature(uint256 value) public {
        newFeature = value;
    }
}

/**
 * @title ImplementationV2TypeChange
 * @notice VULNERABLE: Changed variable type
 */
contract ImplementationV2TypeChange {
    address public owner;           // Slot 0
    // VULNERABILITY 2: Type change from uint256 to address
    // Expected: storage-type-mismatch (CRITICAL)
    address public totalSupply;     // Slot 1 - WAS uint256!
    mapping(address => uint256) public balances;  // Slot 2
    bool public paused;             // Slot 3
}

/**
 * @title ImplementationV2NoGap
 * @notice VULNERABLE: No storage gap for inherited contracts
 */
contract BaseContract {
    address public admin;
    uint256 public value;
}

contract ImplementationV2NoGap is BaseContract {
    // VULNERABILITY 3: No __gap for future base contract variables
    // Expected: missing-storage-gap (HIGH)
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    bool public paused;

    // If BaseContract adds variables in future, they'll collide!
    // Should have: uint256[50] private __gap;
}

/**
 * @title ImplementationV2Correct
 * @notice CORRECT: Proper upgrade with storage gap
 */
contract ImplementationV2Correct {
    // Maintain exact same layout as V1
    address public owner;           // Slot 0
    uint256 public totalSupply;     // Slot 1
    mapping(address => uint256) public balances;  // Slot 2
    bool public paused;             // Slot 3

    // New variables ONLY at the end
    uint256 public newFeature;      // Slot 4 - SAFE!

    // Storage gap for future upgrades
    uint256[49] private __gap;      // Reserve space

    function setNewFeature(uint256 value) public {
        newFeature = value;
    }
}
