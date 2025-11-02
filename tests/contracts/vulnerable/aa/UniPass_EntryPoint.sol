// SPDX-License-Identifier: MIT
// Based on: UniPass Wallet EntryPoint takeover vulnerability (2023)
// Reference: ERC-4337 white hat discovery
pragma solidity ^0.8.20;

/**
 * @title UniPass-style EntryPoint Takeover Vulnerability
 * @notice Account abstraction wallet with replaceable EntryPoint
 * @dev This contract is VULNERABLE - do not use in production
 *
 * Vulnerability: Attacker can replace trusted EntryPoint to take over account
 * Should trigger: aa-account-takeover detector
 *
 * Attack Vector:
 * 1. UniPass wallet allows EntryPoint to be updated
 * 2. Attacker calls updateEntryPoint with malicious contract
 * 3. Malicious EntryPoint bypasses all validation
 * 4. Attacker executes arbitrary transactions as wallet owner
 * 5. Attacker drains all funds
 */
contract UniPass_Vulnerable_Wallet {
    address public entryPoint;
    address public owner;

    constructor(address _entryPoint, address _owner) {
        entryPoint = _entryPoint;
        owner = _owner;
    }

    // VULNERABILITY: Anyone can update EntryPoint (no access control!)
    // Critical flaw that enables account takeover
    function updateEntryPoint(address newEntryPoint) external {
        // VULNERABLE: Missing access control
        // Should require: msg.sender == owner || msg.sender == address(this)
        entryPoint = newEntryPoint;
    }

    // VULNERABILITY: Trusts the EntryPoint without verification
    function validateUserOp(
        bytes calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        // VULNERABLE: Only checks msg.sender == entryPoint
        // If entryPoint is malicious, all validation bypassed
        require(msg.sender == entryPoint, "Not from EntryPoint");

        // VULNERABLE: No signature verification
        // Malicious EntryPoint can bypass this entirely

        return 0; // Valid
    }

    function execute(address dest, uint256 value, bytes calldata func) external {
        // VULNERABLE: Only requires call from EntryPoint
        // If attacker controls EntryPoint, they control the wallet
        require(msg.sender == entryPoint, "Not from EntryPoint");

        (bool success,) = dest.call{value: value}(func);
        require(success, "Execution failed");
    }

    // VULNERABILITY: No two-step ownership transfer
    function transferOwnership(address newOwner) external {
        // VULNERABLE: Can be called through execute() if attacker controls EntryPoint
        require(msg.sender == owner || msg.sender == address(this));
        owner = newOwner;
    }

    receive() external payable {}
}

/**
 * Expected Detection:
 * - aa-account-takeover: Multiple critical findings
 *   - updateEntryPoint has no access control
 *   - No signature verification in validateUserOp
 *   - EntryPoint can be replaced by attacker
 *   - Single point of failure for wallet security
 *   - No timelock on critical operations
 *   - Missing two-step ownership transfer
 */
