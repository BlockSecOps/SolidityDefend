// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title TxOriginAuth
 * @notice Test contract for SolidityDefend - tx.origin Authentication
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. tx-origin-authentication - Line 20: Using tx.origin for auth
 * 2. tx-origin-authentication - Line 28: tx.origin in access control
 *
 * TEST CATEGORY: simple
 * SEVERITY: critical
 * REFERENCE: CWE-477 (Use of Obsolete Function)
 * REAL-WORLD: Multiple phishing attacks exploiting tx.origin
 */
contract TxOriginAuth {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABILITY 1: tx.origin for Authentication
    // Expected: tx-origin-authentication (CRITICAL)
    function withdraw() public {
        require(tx.origin == owner, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }

    // VULNERABILITY 2: tx.origin in Modifier
    // Expected: tx-origin-authentication (CRITICAL)
    modifier onlyOwner() {
        require(tx.origin == owner, "Not owner");
        _;
    }

    function emergencyStop() public onlyOwner {
        // Critical function using vulnerable modifier
    }

    receive() external payable {}
}
