// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Secure Cross-Chain Bridge with Chain-ID Validation
/// @notice This contract properly validates chain-ID to prevent cross-chain replay attacks
/// @dev Should NOT trigger: missing-chainid-validation detector

contract SecureBridge {
    mapping(bytes32 => bool) public processedMessages;
    mapping(address => bool) public authorizedRelayers;
    uint256 public immutable deploymentChainId;

    event MessageProcessed(bytes32 indexed messageHash, uint256 chainId);

    constructor() {
        deploymentChainId = block.chainid;
    }

    modifier onlyAuthorized() {
        require(authorizedRelayers[msg.sender], "Not authorized");
        _;
    }

    /// @notice Process message with proper chain-ID validation
    /// @dev SECURE: Validates destination chain-ID matches current chain
    function processMessage(
        uint256 destinationChainId,
        bytes calldata message
    ) external onlyAuthorized {
        // SECURE: Chain-ID validation prevents cross-chain replay
        require(destinationChainId == block.chainid, "Wrong destination chain");

        bytes32 messageHash = keccak256(abi.encodePacked(destinationChainId, message));
        require(!processedMessages[messageHash], "Already processed");

        processedMessages[messageHash] = true;

        _executeMessage(message);

        emit MessageProcessed(messageHash, destinationChainId);
    }

    /// @notice Receive cross-chain message with comprehensive validation
    /// @dev SECURE: Both runtime validation AND chain-ID in hash
    function receiveMessage(
        bytes32 messageHash,
        bytes calldata message,
        uint256 sourceChainId,
        uint256 targetChainId,
        bytes calldata signature
    ) external onlyAuthorized {
        // SECURE: Runtime chain-ID validation
        require(targetChainId == block.chainid, "Invalid target chain");

        // SECURE: Chain-ID also included in hash for additional security
        bytes32 hash = keccak256(abi.encodePacked(
            message,
            sourceChainId,
            targetChainId
        ));
        require(hash == messageHash, "Invalid message hash");

        require(_verifySignature(hash, signature), "Invalid signature");
        require(!processedMessages[hash], "Already processed");

        processedMessages[hash] = true;

        _processMessage(message);

        emit MessageProcessed(hash, targetChainId);
    }

    /// @notice Execute message with chain-ID check using immutable deployment chain
    /// @dev SECURE: Compares against deployment chain-ID
    function executeOnDeploymentChain(bytes calldata payload) external onlyAuthorized {
        // SECURE: Ensure we're on the original deployment chain
        require(block.chainid == deploymentChainId, "Wrong chain");

        (bool success,) = address(this).call(payload);
        require(success, "Execution failed");
    }

    function _executeMessage(bytes calldata message) internal {
        // Safe execution logic
    }

    function _processMessage(bytes calldata message) internal {
        // Safe processing logic
    }

    function _verifySignature(bytes32 hash, bytes calldata signature) internal pure returns (bool) {
        // Signature verification logic
        return signature.length == 65;
    }
}
