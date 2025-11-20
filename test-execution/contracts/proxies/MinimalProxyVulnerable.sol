// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MinimalProxyVulnerable
 * @notice Test contract for EIP-1167 Minimal Proxy vulnerabilities
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. clone-uninitialized - Clone deployed without initialization
 * 2. clone-initialization-frontrun - Clone initialization can be front-run
 * 3. missing-access-control - No protection on clone creation
 *
 * TEST CATEGORY: proxy
 * SEVERITY: critical/high
 * REFERENCE: EIP-1167
 */

contract MinimalProxyFactory {
    address public implementation;
    address[] public clones;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    // VULNERABILITY 1: Clone created but not initialized in same transaction
    // Expected: clone-uninitialized (CRITICAL)
    function createClone() public returns (address clone) {
        bytes20 targetBytes = bytes20(implementation);
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), targetBytes)
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            clone := create(0, ptr, 0x37)
        }
        clones.push(clone);
        // Clone created but NOT initialized - vulnerable to front-running!
        return clone;
    }

    // VULNERABILITY 2: Separate initialization allows front-running
    // Expected: clone-initialization-frontrun (HIGH)
    function initializeClone(address clone, address owner) public {
        // Anyone can call this on any clone!
        MinimalProxyImplementation(clone).initialize(owner);
    }
}

contract MinimalProxyImplementation {
    address public owner;
    mapping(address => uint256) public balances;
    bool public initialized;

    // VULNERABILITY 3: Unprotected initializer
    // Expected: unprotected-initializer (CRITICAL)
    function initialize(address _owner) public {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(amount);
    }
}
