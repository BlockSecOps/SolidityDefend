// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title InitializerVulnerabilities
 * @notice Test contract for initialization vulnerabilities in upgradeable contracts
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. unprotected-initializer - Initializer can be called by anyone
 * 2. missing-initializer-modifier - No initializer modifier used
 * 3. re-initialization-possible - Can be initialized multiple times
 * 4. constructor-in-implementation - Constructor used instead of initializer
 *
 * TEST CATEGORY: upgradeable
 * SEVERITY: critical/high
 */

contract UnprotectedInitializer {
    address public owner;
    bool public initialized;

    // VULNERABILITY 1: Anyone can call and take ownership
    // Expected: unprotected-initializer (CRITICAL)
    function initialize(address _owner) public {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }

    function withdraw() public {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}

contract MissingInitializerModifier {
    address public owner;
    uint256 public initializationCount;

    // VULNERABILITY 2: No initializer modifier, can be called multiple times
    // Expected: re-initialization-possible (HIGH)
    function initialize(address _owner) public {
        // No check if already initialized!
        owner = _owner;
        initializationCount++;
    }
}

contract ConstructorInImplementation {
    address public owner;

    // VULNERABILITY 3: Constructor in implementation (won't work in proxy)
    // Expected: constructor-in-upgradeable (HIGH)
    constructor(address _owner) {
        owner = _owner;
        // This will set owner in implementation, NOT in proxy storage!
    }

    function doSomething() public {
        require(msg.sender == owner, "Not owner");
        // owner will always be address(0) when called through proxy!
    }
}

contract UninitializedImplementation {
    address public owner;
    mapping(address => uint256) public balances;

    // VULNERABILITY 4: No initializer at all
    // Expected: missing-initializer (MEDIUM)

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        // owner is never set, so this modifier fails for everyone
        require(msg.sender == owner, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}

contract FrontRunInitializer {
    address public owner;
    bool private initialized;

    // VULNERABILITY 5: Publicly visible initialization can be front-run
    // Expected: initializer-front-running (HIGH)
    function initialize(address _owner) public {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
        // Attacker can front-run this transaction and set themselves as owner!
    }

    // Better approach: Initialize in constructor of proxy, or use access control
}

contract ChainedInitializers {
    address public owner;
    address public admin;
    bool private ownerInitialized;
    bool private adminInitialized;

    // VULNERABILITY 6: Multiple separate initializers can be called out of order
    // Expected: initialization-order-issue (MEDIUM)
    function initializeOwner(address _owner) public {
        require(!ownerInitialized, "Owner initialized");
        owner = _owner;
        ownerInitialized = true;
    }

    function initializeAdmin(address _admin) public {
        // No check if owner is initialized first!
        require(!adminInitialized, "Admin initialized");
        admin = _admin;
        adminInitialized = true;
    }

    function criticalFunction() public {
        // Assumes both are initialized, but no enforcement
        require(msg.sender == owner || msg.sender == admin, "Not authorized");
    }
}
