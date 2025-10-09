// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Secure Bridge with Proper Message Verification
/// @notice Demonstrates proper signature verification AND replay protection
/// @dev Should NOT trigger: bridge-message-verification detector

contract SecureBridge {
    address public trustedSigner;
    mapping(bytes32 => bool) public processedMessages;

    event MessageExecuted(bytes32 indexed messageHash);

    constructor(address _signer) {
        trustedSigner = _signer;
    }

    /// @notice Process message with BOTH signature verification AND replay protection
    /// @dev SECURE: Has cryptographic verification and prevents replays
    function processMessage(
        bytes32 messageHash,
        bytes calldata message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // SECURE: Replay protection
        require(!processedMessages[messageHash], "Already processed");

        // SECURE: Signature verification
        address signer = ecrecover(messageHash, v, r, s);
        require(signer == trustedSigner, "Invalid signature");

        // Mark as processed
        processedMessages[messageHash] = true;

        _executeMessage(message);

        emit MessageExecuted(messageHash);
    }

    /// @notice Execute with Merkle proof AND replay protection
    /// @dev SECURE: Verifies proof and prevents replay attacks
    function executeWithProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes calldata payload
    ) external {
        // SECURE: Replay protection
        require(!processedMessages[leaf], "Already executed");

        // SECURE: Merkle proof verification
        require(verifyMerkleProof(root, leaf, proof), "Invalid proof");

        // Mark as executed
        processedMessages[leaf] = true;

        (bool success,) = address(this).call(payload);
        require(success, "Execution failed");

        emit MessageExecuted(leaf);
    }

    function verifyMerkleProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = keccak256(abi.encodePacked(computedHash, proof[i]));
        }
        return computedHash == root;
    }

    function _executeMessage(bytes calldata message) internal {
        // Safe execution logic
    }
}
