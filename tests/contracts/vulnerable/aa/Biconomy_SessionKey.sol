// SPDX-License-Identifier: MIT
// Based on: Biconomy BatchedSessionRouter vulnerability (April 2024)
// Reference: 0xCommit audit report - Critical vulnerability
pragma solidity ^0.8.20;

/**
 * @title Biconomy-style Session Key Vulnerability
 * @notice Simplified version of the BatchedSessionRouter vulnerability
 * @dev This contract is VULNERABLE - do not use in production
 *
 * Vulnerability: Arbitrary Session Key Manager allows account takeover
 * Should trigger: aa-session-key-vulnerabilities detector
 *
 * Attack Vector:
 * 1. Attacker crafts malicious moduleSignature
 * 2. Attacker deploys modified Session Key Manager
 * 3. Attacker bypasses validateUserOp validation
 * 4. Attacker executes unauthorized operations with victim's account
 * 5. Attacker drains funds or takes control
 */
contract Biconomy_Vulnerable_BatchedSessionRouter {
    struct SessionKeyData {
        address sessionKey;
        uint48 validUntil;
        uint48 validAfter;
        address[] whitelist;
    }

    mapping(address => SessionKeyData) public sessionKeys;

    // VULNERABILITY: No validation of Session Key Manager legitimacy
    // VULNERABILITY: No whitelist of authorized managers
    // VULNERABILITY: Accepts arbitrary moduleSignature

    function validateUserOp(
        address account,
        bytes calldata userOp,
        bytes32 userOpHash,
        bytes calldata moduleSignature  // VULNERABLE: Not validated!
    ) external returns (uint256) {
        // VULNERABILITY: Missing validation that moduleSignature comes from trusted source
        // Attacker can craft their own moduleSignature with malicious manager

        (address sessionKeyManager, bytes memory sessionKeyData) = abi.decode(
            moduleSignature,
            (address, bytes)
        );

        // VULNERABILITY: No check if sessionKeyManager is in allowlist
        // Attacker can deploy their own malicious manager

        // VULNERABILITY: Blindly trusts the provided sessionKeyManager
        (bool success, bytes memory result) = sessionKeyManager.call(
            abi.encodeWithSignature(
                "validateSessionKey(address,bytes32,bytes)",
                account,
                userOpHash,
                sessionKeyData
            )
        );

        require(success, "Session validation failed");

        // VULNERABLE: No verification of session key properties
        // No expiration check, no target restrictions, no value limits
        return 0; // Validation passed
    }

    function executeUserOp(
        address account,
        address target,
        uint256 value,
        bytes calldata data,
        address sessionKey
    ) external {
        SessionKeyData memory skData = sessionKeys[sessionKey];

        // VULNERABILITY: Missing critical checks
        // No expiration validation
        // No target whitelist enforcement
        // No value limit enforcement
        // No nonce/replay protection

        // Execute arbitrary call
        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");
    }

    // VULNERABILITY: No proper session key registration validation
    function registerSessionKey(
        address sessionKey,
        uint48 validUntil,
        address[] calldata whitelist
    ) external {
        // VULNERABLE: No access control - anyone can register session keys
        // Should require msg.sender == account owner

        sessionKeys[sessionKey] = SessionKeyData({
            sessionKey: sessionKey,
            validUntil: validUntil,
            validAfter: uint48(block.timestamp),
            whitelist: whitelist
        });
    }
}

/**
 * Expected Detection:
 * - aa-session-key-vulnerabilities: Multiple critical findings
 *   - No validation of Session Key Manager legitimacy
 *   - Missing expiration checks in execution
 *   - No target whitelist enforcement
 *   - No value limits
 *   - Missing nonce/replay protection
 *   - Anyone can register session keys (no owner check)
 */
