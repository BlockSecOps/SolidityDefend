// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AccessControlBasic
 * @notice Test contract for SolidityDefend - Access Control Vulnerabilities
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. missing-access-control - Line 21: withdraw() function lacks access control
 * 2. unprotected-initializer - Line 14: initialize() can be called by anyone
 * 3. missing-access-control - Line 29: emergencyWithdraw() lacks protection
 *
 * TEST CATEGORY: simple
 * SEVERITY: critical
 * REFERENCE: CWE-284 (Improper Access Control)
 */
contract AccessControlBasic {
    address public owner;
    mapping(address => uint256) public balances;
    bool public initialized;

    // VULNERABILITY 1: Unprotected Initializer
    // Expected: unprotected-initializer (CRITICAL)
    function initialize(address _owner) public {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }

    // VULNERABILITY 2: Missing Access Control on Critical Function
    // Expected: missing-access-control (CRITICAL)
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // VULNERABILITY 3: Emergency Function Without Protection
    // Expected: missing-access-control (CRITICAL)
    function emergencyWithdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }

    // VULNERABILITY 4: Change Owner Without Restriction
    // Expected: missing-access-control (HIGH)
    function changeOwner(address newOwner) public {
        owner = newOwner;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
