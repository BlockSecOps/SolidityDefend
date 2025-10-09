// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Simple Vulnerable Bridge - Missing Message Verification
/// @notice This contract demonstrates missing signature/proof verification
/// @dev Should trigger: bridge-message-verification detector

contract VulnerableBridge {
    event MessageProcessed(bytes32 indexed messageHash);

    /// @notice Process message WITHOUT signature verification
    /// @dev VULNERABILITY: No cryptographic verification of message authenticity
    function processMessage(bytes calldata message) external {
        bytes32 messageHash = keccak256(message);

        // Missing verification - anyone can call this!
        _executeMessage(message);

        emit MessageProcessed(messageHash);
    }

    /// @notice Execute cross-chain message WITHOUT proof verification
    /// @dev VULNERABILITY: No Merkle proof or signature check
    function receiveMessage(
        bytes32 messageHash,
        bytes calldata payload
    ) external {
        // Missing: verification step

        (bool success,) = address(this).call(payload);
        require(success, "Execution failed");

        emit MessageProcessed(messageHash);
    }

    function _executeMessage(bytes calldata message) internal {
        // Internal execution
    }
}
