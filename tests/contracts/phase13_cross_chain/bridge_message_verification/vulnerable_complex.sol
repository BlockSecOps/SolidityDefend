// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Complex Vulnerable Bridge - Has Signature Verification but Missing Replay Protection
/// @notice Demonstrates signature verification without replay protection
/// @dev Should trigger: bridge-message-verification detector (missing replay protection)

contract ComplexBridge {
    address public trustedSigner;

    event MessageExecuted(bytes32 indexed messageHash);

    constructor(address _signer) {
        trustedSigner = _signer;
    }

    /// @notice Process message with signature verification but NO replay protection
    /// @dev VULNERABILITY: Valid signatures can be replayed multiple times
    function processMessage(
        bytes32 messageHash,
        bytes calldata message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Good: Has signature verification
        address signer = ecrecover(messageHash, v, r, s);
        require(signer == trustedSigner, "Invalid signature");

        // VULNERABILITY: Missing replay protection
        // Should have: require(!processedMessages[messageHash]);

        _executeMessage(message);

        // Missing: processedMessages[messageHash] = true;

        emit MessageExecuted(messageHash);
    }

    /// @notice Merkle proof verification without replay protection
    /// @dev VULNERABILITY: Proofs can be reused
    function executeWithProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes calldata payload
    ) external {
        // Good: Has Merkle verification
        require(verifyMerkleProof(root, leaf, proof), "Invalid proof");

        // VULNERABILITY: No replay protection

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
        // Execution logic
    }
}
