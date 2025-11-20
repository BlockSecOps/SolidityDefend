// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ReentrancyBasic
 * @notice Test contract for SolidityDefend - Reentrancy Vulnerabilities
 * @dev Contains intentional vulnerabilities for testing
 *
 * EXPECTED VULNERABILITIES:
 * 1. classic-reentrancy - Line 22: withdraw() state update after external call
 * 2. classic-reentrancy - Line 32: withdrawAll() reentrancy via call
 *
 * TEST CATEGORY: simple
 * SEVERITY: critical
 * REFERENCE: CWE-841 (Improper Enforcement of Behavioral Workflow)
 * REAL-WORLD: DAO Hack (2016) - $60M stolen
 */
contract ReentrancyBasic {
    mapping(address => uint256) public balances;

    // VULNERABILITY 1: Classic Reentrancy - State After External Call
    // Expected: classic-reentrancy (CRITICAL)
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call before state update - VULNERABLE
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update after external call - TOO LATE!
        balances[msg.sender] -= amount;
    }

    // VULNERABILITY 2: Reentrancy via withdrawAll
    // Expected: classic-reentrancy (CRITICAL)
    function withdrawAll() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        // External call before state update
        (bool success,) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
