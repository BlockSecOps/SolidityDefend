// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Simple Vulnerable Bridge - Missing Chain-ID Validation
/// @notice This contract demonstrates a simple vulnerability where chain-ID is not validated
/// @dev Should trigger: missing-chainid-validation detector

contract VulnerableBridge {
    event MessageProcessed(bytes32 indexed messageHash);

    /// @notice Process a cross-chain message WITHOUT validating destination chain-ID
    /// @dev VULNERABILITY: Missing chain-ID validation allows replay on wrong chains
    function processMessage(bytes calldata message) external {
        // Missing: require(destinationChainId == block.chainid, "Wrong chain");

        bytes32 messageHash = keccak256(message);

        // Process the message without checking if it's intended for this chain
        _executeMessage(message);

        emit MessageProcessed(messageHash);
    }

    /// @notice Execute cross-chain message WITHOUT chain validation
    /// @dev VULNERABILITY: No check if message was intended for this chain
    function receiveMessage(
        bytes32 messageHash,
        bytes calldata payload
    ) external {
        // Missing chain-ID validation

        // Execute payload
        (bool success,) = address(this).call(payload);
        require(success, "Execution failed");

        emit MessageProcessed(messageHash);
    }

    function _executeMessage(bytes calldata message) internal {
        // Internal execution logic
    }
}
