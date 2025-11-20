// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title VulnerableTransparentProxy
 * @notice Test contract for Transparent Proxy vulnerabilities
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. proxy-storage-collision - Storage layout collision between proxy and implementation
 * 2. unprotected-upgrade - Missing access control on upgrade function
 * 3. function-selector-clash - Admin functions may clash with implementation
 * 4. delegatecall-to-untrusted - Delegatecall without validation
 *
 * TEST CATEGORY: upgradeable
 * SEVERITY: critical
 * REFERENCE: EIP-1967, OpenZeppelin Transparent Proxy
 */

contract VulnerableTransparentProxy {
    // VULNERABILITY 1: Storage Collision
    // Proxy stores admin and implementation in slots 0 and 1
    // Implementation contract may also use these slots!
    address public admin; // Slot 0 - COLLISION RISK
    address public implementation; // Slot 1 - COLLISION RISK

    // Proxy data that could collide with implementation
    mapping(address => uint256) public balances; // Slot 2 - COLLISION RISK

    constructor(address _implementation) {
        admin = msg.sender;
        implementation = _implementation;
    }

    // VULNERABILITY 2: Unprotected Upgrade Function
    // Expected: unprotected-upgrade, missing-access-control (CRITICAL)
    function upgradeTo(address newImplementation) public {
        // No access control - anyone can upgrade!
        implementation = newImplementation;
    }

    // VULNERABILITY 3: Admin Function Selector Clash
    // If implementation has a function with same selector, confusion occurs
    // Expected: function-selector-clash (HIGH)
    function changeAdmin(address newAdmin) public {
        require(msg.sender == admin, "Not admin");
        admin = newAdmin;
    }

    // VULNERABILITY 4: Delegatecall Without Validation
    // Expected: delegatecall-to-untrusted (CRITICAL)
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

    receive() external payable {}
}

/**
 * @title VulnerableImplementation
 * @notice Implementation contract with storage collision
 */
contract VulnerableImplementation {
    // VULNERABILITY: Storage Collision with Proxy
    // These variables occupy the same slots as proxy variables!
    address public owner; // Slot 0 - COLLIDES WITH admin
    address public treasury; // Slot 1 - COLLIDES WITH implementation
    mapping(address => uint256) public deposits; // Slot 2 - COLLIDES WITH balances

    bool public initialized;

    // VULNERABILITY 5: Unprotected Initializer in Upgradeable Context
    // Expected: unprotected-initializer (CRITICAL)
    function initialize(address _owner) public {
        // No check if already initialized!
        // No access control!
        owner = _owner;
        initialized = true;
    }

    function deposit() public payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(deposits[msg.sender] >= amount, "Insufficient balance");
        deposits[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
